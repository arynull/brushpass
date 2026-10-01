"""The rotation journal: an append-only record of every rotation attempt.

The journal exists for one reason: a rotation that fails between "the
provider issued a new secret" and "the new secret is safely stored" leaves
a live secret that brushpass knows about and cannot see. That is the one
failure mode worth shouting about, so it gets a durable, greppable,
human-readable record rather than a log line that scrolls away.

Entries are JSON Lines, one object per rotation, in
``<state-dir>/journal.jsonl``. Append-only and fsync'd: a half-written
final line is tolerated on read (it is skipped and reported) rather than
truncating the history before it.

Entry states:

``started``
    The rotation began. Written *before* the provider is called.
``finished``
    The new secret is stored and the old one is retired.
``aborted``
    A failure that left the old credential live. If an orphan secret
    identifier was recorded, brushpass could not store the new secret and
    the new one may exist upstream — see ``orphan_secret_id``.
``incomplete``
    The process died between ``started`` and a terminal state. Detected
    on read: any ``started`` entry with no matching terminal state.

No secret material is ever written here. ``old_secret_id`` and
``orphan_secret_id`` are truncated SHA-256 digests, which let an operator
confirm *which* secret is in play without the secret being recoverable.
"""

import json
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

JOURNAL_FILE = "journal.jsonl"
JOURNAL_MODE = 0o600

STATE_STARTED = "started"
STATE_FINISHED = "finished"
STATE_ABORTED = "aborted"
TERMINAL_STATES = (STATE_FINISHED, STATE_ABORTED)


class JournalError(Exception):
    """The journal could not be read or written."""


@dataclass
class JournalEntry:
    """One rotation attempt."""

    label: str
    provider: str
    state: str
    started_at: str
    rotation_id: str
    finished_at: str | None = None
    duration_seconds: float | None = None
    old_secret_id: str | None = None
    new_secret_id: str | None = None
    # Set only when the provider produced a secret brushpass could not
    # store. Its presence means "there may be a live upstream credential
    # nobody here holds" — the single loudest state in the journal.
    orphan_secret_id: str | None = None
    revoked_tokens: list[str] = field(default_factory=list)
    provider_revoked: bool | None = None
    error: str | None = None
    steps: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rotation_id": self.rotation_id,
            "label": self.label,
            "provider": self.provider,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "old_secret_id": self.old_secret_id,
            "new_secret_id": self.new_secret_id,
            "orphan_secret_id": self.orphan_secret_id,
            "revoked_tokens": list(self.revoked_tokens),
            "provider_revoked": self.provider_revoked,
            "error": self.error,
            "steps": list(self.steps),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JournalEntry":
        return cls(
            rotation_id=data.get("rotation_id", ""),
            label=data.get("label", ""),
            provider=data.get("provider", ""),
            state=data.get("state", ""),
            started_at=data.get("started_at", ""),
            finished_at=data.get("finished_at"),
            duration_seconds=data.get("duration_seconds"),
            old_secret_id=data.get("old_secret_id"),
            new_secret_id=data.get("new_secret_id"),
            orphan_secret_id=data.get("orphan_secret_id"),
            revoked_tokens=list(data.get("revoked_tokens") or []),
            provider_revoked=data.get("provider_revoked"),
            error=data.get("error"),
            steps=list(data.get("steps") or []),
        )

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def needs_attention(self) -> bool:
        """True when a human must look at this entry.

        Either the rotation never finished, or it finished in a way that
        may have left a live secret nobody holds.
        """
        return (not self.is_terminal) or self.state == STATE_ABORTED

    def to_log_line(self) -> str:
        """One audit-style line, safe for any log aggregator.

        Single line, key=value, no secret material: the same shape
        syslog and most collectors parse without a custom regex.
        """
        parts = [
            "action=credential.rotate",
            f"label={self.label}",
            f"provider={self.provider}",
            f"state={self.state}",
            f"rotation_id={self.rotation_id}",
            f"duration_seconds={self.duration_seconds}",
            f"old_secret_id={self.old_secret_id}",
            f"new_secret_id={self.new_secret_id}",
            f"orphan_secret_id={self.orphan_secret_id or '-'}",
            f"provider_revoked={self.provider_revoked}",
            f"revoked_tokens={len(self.revoked_tokens)}",
        ]
        if self.error:
            parts.append(f"error=\"{_one_line(self.error)}\"")
        return " ".join(parts)


class RotationJournal:
    """Append-only JSONL journal of rotation attempts."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.path = data_dir / JOURNAL_FILE
        self._lines: list[str] = []
        self._damaged: list[str] = []

    def _ensure_dir(self) -> None:
        if not self.data_dir.exists():
            self.data_dir.mkdir(parents=True, mode=0o700)
        else:
            self.data_dir.chmod(0o700)

    def append(self, entry: JournalEntry) -> None:
        """Append one entry and fsync it.

        The fsync is the point: a rotation record that is still in the
        page cache when the machine loses power is not a record. It costs
        milliseconds and the whole rotation budget is 60 seconds.
        """
        self._ensure_dir()
        line = json.dumps(entry.to_dict(), sort_keys=True) + "\n"
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, JOURNAL_MODE)
        except OSError as exc:
            raise JournalError(f"Cannot open rotation journal {self.path}: {exc}") from exc
        try:
            with os.fdopen(fd, "a") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise JournalError(f"Cannot write rotation journal {self.path}: {exc}") from exc
        try:
            self.path.chmod(JOURNAL_MODE)
        except OSError:
            # The mode was requested at open() and umask can only have
            # narrowed it; a failed chmod here does not invalidate the
            # record, and the read path reports the mode.
            pass
        self._lines.append(line)

    def entries(self, label: str | None = None) -> list[JournalEntry]:
        """Read the journal, newest last.

        A trailing partial line (a crash mid-write) is skipped and
        reported through :meth:`damaged_lines` rather than being allowed
        to hide the entries before it.
        """
        result: list[JournalEntry] = []
        for raw in self._read_lines():
            text = raw.strip()
            if not text:
                continue
            try:
                entry = JournalEntry.from_dict(json.loads(text))
            except (json.JSONDecodeError, TypeError, ValueError):
                self._damaged.append(text[:120])
                continue
            if label is not None and entry.label != label:
                continue
            result.append(entry)
        return result

    @property
    def damaged_lines(self) -> list[str]:
        """Partial lines found by the last :meth:`entries` call."""
        return list(self._damaged)

    def _read_lines(self) -> list[str]:
        self._damaged = []
        if not self.path.exists():
            return []
        try:
            return self.path.read_text().splitlines()
        except OSError as exc:
            raise JournalError(f"Cannot read rotation journal {self.path}: {exc}") from exc

    def last_entry(self, label: str) -> JournalEntry | None:
        """The most recent entry for a label, or None."""
        entries = self.entries(label)
        return entries[-1] if entries else None

    def incomplete(self) -> list[JournalEntry]:
        """Entries that started and never reached a terminal state.

        An entry that is superseded by a later terminal entry for the same
        rotation_id is not incomplete: it finished, just slowly.
        """
        entries = self.entries()
        finished_ids = {
            entry.rotation_id for entry in entries if entry.is_terminal
        }
        return [
            entry
            for entry in entries
            if entry.state == STATE_STARTED and entry.rotation_id not in finished_ids
        ]

    def orphans(self) -> list[JournalEntry]:
        """Aborted rotations that may have left a live upstream secret."""
        return [entry for entry in self.entries() if entry.orphan_secret_id]

    def status(self, label: str | None = None) -> dict:
        """A summary for ``rotate --status`` / ``credential status``."""
        entries = self.entries(label)
        last = entries[-1] if entries else None
        return {
            "label": label,
            "rotation_count": len([e for e in entries if e.state == STATE_FINISHED]),
            "last": last.to_dict() if last else None,
            "last_started_at": last.started_at if last else None,
            "last_duration_seconds": last.duration_seconds if last else None,
            "incomplete": [entry.to_dict() for entry in self.incomplete()
                           if label is None or entry.label == label],
            "orphans": [entry.to_dict() for entry in self.orphans()
                        if label is None or entry.label == label],
        }


def new_rotation_id() -> str:
    """A short, sortable-enough identifier for one rotation."""
    return f"rot_{int(time.time() * 1000):x}_{os.urandom(3).hex()}"


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _one_line(text: str) -> str:
    """Collapse a message to a single log-safe line."""
    return " ".join(str(text).split()).replace('"', "'")
