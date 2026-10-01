"""Leak scanning for brushpass.

``scan`` walks the places a token realistically escapes to — files, git
history, shell history — and answers one question: is this string a token
brushpass issued?

The answer comes from the fingerprint database, never from the shape of the
string. A candidate becomes a *report line* only after its HMAC fingerprint
matches a stored one, which means every line printed is a credential this
machine actually minted. Nothing brushpass did not issue is ever printed,
and no token plaintext is printed even for leaks that are confirmed.

Tokens minted before v0.3.0 have no fingerprint: brushpass stored only a
hash and discarded the plaintext, so there is nothing to derive a
fingerprint from. Those are reported as *unscannable* in the summary rather
than quietly ignored, or worse, presented as covered.
"""

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from . import detect, sources
from .detect import Candidate, FingerprintIndex
from .models import TokenRecord
from .scanner import Scanner
from .store import TokenStore

# Exit codes. 2 is the documented "live leak found" signal, distinct from
# 1 (error) and 0 (clean), so a CI job can gate on a leak alone.
EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_LEAK = 2

# Recommended actions.
ACTION_REVOKE = "revoke now"
ACTION_DEAD = "already revoked/expired"
UNSCANNABLE_REASON = "unscannable (minted before leak detection)"

# How much of a fingerprint is shown. It identifies a record for the
# operator and is not itself a credential.
FINGERPRINT_DISPLAY_CHARS = 12


class ScanError(Exception):
    """A scan could not be performed."""


@dataclass(frozen=True)
class Finding:
    """One leaked token, located. Holds no plaintext by construction."""

    record: TokenRecord
    fingerprint_prefix: str
    location: str  # "file:line"
    source: str  # which source was scanned: file, git-log, history, ...
    how: str  # which detection route matched: raw, base64, whitespace
    action: str
    live: bool

    def to_dict(self) -> dict:
        return {
            "id": self.record.id,
            "label": self.record.label,
            "scope": self.record.scope,
            "fingerprint": self.fingerprint_prefix,
            "location": self.location,
            "source": self.source,
            "detected_by": self.how,
            "issued_at": self.record.issued_at.isoformat(),
            "expires_at": self.record.expires_at.isoformat(),
            "action": self.action,
            "live": self.live,
        }


@dataclass
class ScanReport:
    """Everything a scan found, in a form both renderers can consume."""

    findings: list[Finding] = field(default_factory=list)
    unscannable: list[TokenRecord] = field(default_factory=list)
    revoked: list[str] = field(default_factory=list)
    blobs_scanned: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    leaks_verified: int = 0

    @property
    def live_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.live]

    @property
    def leaked_ids(self) -> list[str]:
        """Distinct leaked token ids, in report order."""
        return list(dict.fromkeys(f.record.id for f in self.findings))

    def count_skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "unscannable": [
                {
                    "id": r.id,
                    "label": r.label,
                    "scope": r.scope,
                    "issued_at": r.issued_at.isoformat(),
                    "reason": UNSCANNABLE_REASON,
                }
                for r in self.unscannable
            ],
            "revoked": self.revoked,
            "live_leaks": len(self.live_findings),
            "stats": {
                "blobs_scanned": self.blobs_scanned,
                "skipped": dict(self.skipped),
                "leaks_verified": self.leaks_verified,
                "notes": list(self.notes),
            },
        }


def scan_blobs(
    blobs: Iterable[sources.Blob],
    store: TokenStore,
    scanner: Scanner,
    now: datetime | None = None,
) -> ScanReport:
    """Run the candidate -> verify pipeline over ``blobs``.

    Every candidate is checked against the fingerprint database. Candidates
    brushpass never issued are dropped without appearing anywhere in the
    report, which is what keeps the output free of false positives.
    """
    moment = now or datetime.now(UTC)
    index = FingerprintIndex(store.list_all(), scanner.key)
    report = ScanReport()

    for blob in blobs:
        if blob.is_skip:
            report.count_skip(blob.skipped or "unknown")
            continue
        if blob.note:
            report.notes.append(f"{blob.location}: {blob.note}")

        report.blobs_scanned += 1
        for candidate in detect.find_candidates(blob.data or b"", blob.source):
            record = index.lookup(candidate.token)
            if record is None:
                continue
            report.leaks_verified += 1
            report.findings.append(
                _finding(record, candidate, blob, moment)
            )

    report.unscannable = [r for r in store.list_all() if not r.fingerprint]
    return report


def _finding(
    record: TokenRecord,
    candidate: Candidate,
    blob: sources.Blob,
    now: datetime,
) -> Finding:
    """Build a Finding. The candidate plaintext goes no further."""
    live = not record.revoked and not record.is_expired(now)
    return Finding(
        record=record,
        fingerprint_prefix=(record.fingerprint or "")[:FINGERPRINT_DISPLAY_CHARS],
        location=f"{blob.location}:{candidate.line}",
        source=blob.source,
        how=candidate.source,
        action=ACTION_REVOKE if live else ACTION_DEAD,
        live=live,
    )


def fix_findings(store: TokenStore, report: ScanReport) -> ScanReport:
    """Revoke every live leaked token. Idempotent.

    Already-dead tokens are left alone: there is nothing to revoke, and
    reporting them as newly revoked would be a lie about what changed.
    Returns the same report, with ``revoked`` populated.
    """
    for token_id in report.leaked_ids:
        record = store.find_by_id(token_id)
        if record is None or record.revoked:
            continue
        if store.revoke(token_id):
            report.revoked.append(token_id)
    return report


def render_text(report: ScanReport) -> str:
    """Render the report as text. Never contains a token plaintext."""
    lines: list[str] = []

    if report.findings:
        lines.append("LEAKED TOKENS")
        lines.append("-" * 80)
        for finding in report.findings:
            label = finding.record.label or "-"
            state = "LIVE" if finding.live else "dead"
            lines.append(f"{finding.record.id}  {finding.record.scope}  [{state}]")
            lines.append(f"  label:       {label}")
            lines.append(f"  fingerprint: {finding.fingerprint_prefix}...")
            lines.append(
                f"  location:    {finding.location}"
                f" (via {finding.how}, source {finding.source})"
            )
            lines.append(f"  issued_at:   {finding.record.issued_at.isoformat()}")
            lines.append(f"  action:      {finding.action}")
            lines.append("")
    else:
        lines.append("No leaked brushpass tokens found.")
        lines.append("")

    if report.revoked:
        lines.append("REVOKED BY --fix")
        lines.append("-" * 80)
        for token_id in report.revoked:
            lines.append(f"  {token_id}")
        lines.append("")

    if report.unscannable:
        lines.append("UNSCANNABLE TOKENS")
        lines.append("-" * 80)
        lines.append(
            f"{len(report.unscannable)} token(s) carry no fingerprint, so no scan "
            "can match them."
        )
        for record in report.unscannable:
            label = record.label or "-"
            lines.append(f"  {record.id}  {record.scope}  label={label}")
            lines.append(f"    -> {UNSCANNABLE_REASON}")
        lines.append("")
        lines.append(
            "These predate leak detection and still verify normally. Revoke one if "
            "you cannot account for where it went."
        )
        lines.append("")

    if report.notes:
        lines.append("NOTES")
        lines.append("-" * 80)
        lines.extend(f"  {note}" for note in report.notes)
        lines.append("")

    skipped = ", ".join(f"{count} {reason}" for reason, count in sorted(report.skipped.items()))
    lines.append(
        f"Scanned {report.blobs_scanned} file(s) or stream(s)"
        + (f"; skipped {skipped}" if skipped else "")
        + f"; {report.leaks_verified} verified leak(s)."
    )

    if report.live_findings:
        lines.append(
            f"{len(report.live_findings)} live leak(s). "
            "Run 'brushpass scan --fix' to revoke them."
        )
    elif report.findings:
        lines.append("All leaked tokens are already revoked or expired.")
    else:
        lines.append("Clean: no live leaks.")

    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    """Render the report as JSON. Never contains a token plaintext."""
    return json.dumps(report.to_dict(), indent=2)


def exit_code(report: ScanReport, fixed: bool = False) -> int:
    """0 when clean or fixed, 2 when live leaks remain.

    After ``--fix`` the exit code is 0: the credential is dead, which is the
    state a CI gate was asking for.
    """
    if fixed:
        return EXIT_CLEAN
    return EXIT_LEAK if report.live_findings else EXIT_CLEAN


def collect_blobs(
    paths: list[Path],
    git: bool,
    history: bool,
    state_dir: Path,
    cwd: Path | None = None,
) -> Iterator[sources.Blob]:
    """Gather every blob the requested sources produce.

    Raises:
        ScanSourceError: if a requested source cannot be read.
    """
    if paths:
        yield from sources.scan_paths(paths, state_dir)
    if git:
        yield from sources.scan_git(cwd, state_dir)
    if history:
        yield from sources.scan_history()
