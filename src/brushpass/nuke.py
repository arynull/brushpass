"""Break-glass: `brushpass nuke --yes`.

This is the command you run when you believe a credential or a token is
in someone else's hands and you do not have time to work out which. It
exists to be blunt, and its bluntness is the point — but bluntness with
no guardrails is how an operator loses an afternoon of live tokens over
a typo, so the guardrails are the design:

* ``--yes`` is **required**. Without it the command prints exactly what
  it would do, changes nothing, and exits non-zero. There is no
  interactive prompt, because the one situation where a prompt is
  dangerous is the one where brushpass is being run from a script or a
  cron job with nobody watching — and there, an unattended `input()`
  either blocks forever or, worse, reads the next line of somebody
  else's stdin.
* Everything that dies is listed first: token ids, credential labels,
  the epoch before and after.
* One audit record covers the whole event, so `audit verify` still
  passes afterwards and the break-glass itself is on the record.

What it does, in order:

1. Revoke every live token and advance the revocation epoch by one, so
   anything still holding a token minted before this call is denied even
   if it cannot enumerate the ids.
2. Write a "rotation required" journal entry for every root credential.
   brushpass cannot rotate a credential it has not been told how to
   reach, so it does not pretend to: the journal records the obligation
   and ``rotate --status`` surfaces it until a human clears it.
3. ``--rotate-all`` then attempts a real provider rotation for each
   credential. A ``manual`` credential prints its instructions and is
   skipped with a warning unless stdin is a TTY — a non-interactive nuke
   must never block on a prompt nobody is there to answer.
4. Write one ``nuke`` audit record naming what was retired.

The one thing this cannot do is revoke anything at the *provider*.
brushpass kills its own tokens; the long-lived upstream credential dies
only when the provider is told, which is what step 2 and step 3 are
about. `nuke` says so in its output rather than letting a clean exit be
read as "the credential is gone".
"""

import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .journal import (
    STATE_STARTED,
    JournalEntry,
    JournalError,
    RotationJournal,
    new_rotation_id,
    now_iso,
)
from .store import TokenStore

# The reason recorded against a credential a nuke left needing rotation.
ROTATION_REQUIRED_REASON = "rotation required: break-glass nuke"

# Manual credentials need a human at a keyboard. Without one they are
# reported and skipped, never waited on.
MANUAL_PROVIDER = "manual"


class NukeError(Exception):
    """A break-glass could not be completed."""


@dataclass
class NukeResult:
    """What a nuke did. Rendered by the CLI and asserted in tests."""

    ran: bool = False
    tokens_revoked: list[str] = field(default_factory=list)
    epoch_before: int = 0
    epoch_after: int = 0
    credentials_flagged: list[str] = field(default_factory=list)
    rotated: list[str] = field(default_factory=list)
    rotation_failures: dict[str, str] = field(default_factory=dict)
    manual_skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def token_count(self) -> int:
        return len(self.tokens_revoked)

    @property
    def credential_count(self) -> int:
        return len(self.credentials_flagged)

    def to_dict(self) -> dict:
        return {
            "ran": self.ran,
            "tokens_revoked": list(self.tokens_revoked),
            "tokens_revoked_count": self.token_count,
            "epoch_before": self.epoch_before,
            "epoch_after": self.epoch_after,
            "credentials_flagged": list(self.credentials_flagged),
            "rotated": list(self.rotated),
            "rotation_failures": dict(self.rotation_failures),
            "manual_skipped": list(self.manual_skipped),
            "errors": list(self.errors),
        }

    def details(self) -> dict:
        """The audit ``details`` payload. Ids and labels only."""
        return {
            "tokens_revoked": self.token_count,
            "token_ids": list(self.tokens_revoked),
            "epoch_before": self.epoch_before,
            "epoch_after": self.epoch_after,
            "credentials_flagged": self.credential_count,
            "credential_labels": list(self.credentials_flagged),
            "rotated": list(self.rotated),
            "manual_skipped": list(self.manual_skipped),
        }


def plan(tokens: TokenStore, credentials=None) -> dict:
    """Describe what a nuke would do, changing nothing.

    Used for the refused (no ``--yes``) path and for the header a real
    nuke prints. Reading the store is enough: the token list and the
    epoch are both on disk, so a plan is accurate up to the instant it is
    acted on.

    The credential labels are read straight off ``credentials.json``
    rather than through :class:`~brushpass.credentials.CredentialStore`.
    Constructing that store *creates* an empty file when none exists —
    which would mean the path promising to change nothing had just
    written to the state directory. A plan that touches the disk is not a
    plan, so this reads the file and nothing else.
    """
    now = datetime.now(UTC)
    live = [
        record for record in tokens.list_all()
        if not record.revoked and not record.is_expired(now)
    ]
    return {
        "live_tokens": [r.id for r in live],
        "epoch": tokens.epoch,
        "credentials": _credential_labels(credentials),
    }


def _credential_labels(credentials) -> list[str]:
    """Credential labels, or an empty list if they cannot be read.

    Read straight off ``credentials.json`` rather than through
    :meth:`CredentialStore.list_all`. Constructing that store *creates* an
    empty file when none exists, so the path promising to change nothing
    would have just written to the state directory. Reading the JSON is
    enough for labels, which is all a plan reports.

    Best effort by design: the token half of a nuke works with no
    credential store at all, and a plan must not fail for want of one.
    """
    if credentials is None:
        return []

    path = None
    if isinstance(credentials, (str, Path)):
        # A path to credentials.json. Lets a caller ask what would die
        # without constructing a store, which would create the file.
        path = Path(credentials)
    else:
        path = getattr(credentials, "credentials_file", None)
        if path is None:
            # Not a CredentialStore (a test double, or a future backend):
            # ask it directly.
            try:
                return [record.label for record in credentials.list_all()]
            except Exception:  # noqa: BLE001 - a plan must always render
                return []

    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, AttributeError):
        # No file, or unreadable. Either way: no credentials to name, and
        # emphatically not a reason to fail the plan.
        return []

    entries = raw.get("credentials") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        return []
    return [str(entry["label"]) for entry in entries if "label" in entry]


def nuke(
    tokens: TokenStore,
    credentials=None,
    journal: RotationJournal | None = None,
    audit=None,
    rotate_all: bool = False,
    stdin=None,
    rotate_label=None,
) -> NukeResult:
    """Run the break-glass. Returns what it did.

    ``rotate_label`` is the rotation engine's ``rotate`` callable,
    injected so that nuke does not import the engine (and therefore the
    providers) unless ``--rotate-all`` actually asks for it.
    ``stdin`` is checked for ``isatty`` before any manual credential is
    attempted; when it is not a TTY, manual credentials are skipped with
    a warning instead of being waited on.

    Raises:
        NukeError: if the token revocation could not be committed. The
            journal and audit writes below it are best effort, so a
            journal write never aborts a nuke that has already killed
            the tokens — the tokens being dead is the important part.
    """
    now = datetime.now(UTC)
    result = NukeResult()
    result.epoch_before = tokens.epoch

    # (1) Revoke every live token and advance the generation.
    revoked = tokens.revoke_all_live(now)
    result.tokens_revoked = list(revoked)
    result.epoch_after = tokens.epoch

    # (2) Flag every credential as needing rotation.
    records = list(credentials.list_all()) if credentials is not None else []
    if records and journal is not None:
        for record in records:
            _flag_rotation_required(journal, record.label, record.provider, result)
        result.credentials_flagged = [r.label for r in records]

    # (3) Optionally rotate, per credential.
    if rotate_all and records:
        _rotate_each(
            records,
            result,
            rotate_label=rotate_label,
            stdin=stdin,
        )

    # (4) One audit record for the whole event.
    if audit is not None:
        try:
            audit.record("nuke", result.details())
        except Exception as exc:  # noqa: BLE001 - never undo a nuke
            result.errors.append(f"could not write the audit record: {exc}")

    result.ran = True
    return result


def _flag_rotation_required(
    journal: RotationJournal, label: str, provider: str, result: NukeResult
) -> None:
    """Record the obligation, degrading to a printed warning on failure.

    A journal write failure must not abort a nuke whose tokens are
    already dead — but it must not be silent either, because then the
    rotation would look handled when it was not.
    """
    entry = JournalEntry(
        rotation_id=new_rotation_id(),
        label=label,
        provider=provider,
        state=STATE_STARTED,
        started_at=now_iso(),
        error=ROTATION_REQUIRED_REASON,
    )
    try:
        journal.append(entry)
    except JournalError as exc:
        message = (
            f"could not journal '{label}' as needing rotation ({exc}). Rotate it "
            "by hand: 'brushpass rotate <label>'"
        )
        result.errors.append(message)
        print(f"WARNING: {message}", file=sys.stderr, flush=True)


def _rotate_each(
    records,
    result: NukeResult,
    rotate_label,
    stdin=None,
) -> None:
    """Attempt a real rotation per credential. Never raises."""
    interactive = _stdin_is_tty(stdin)

    for record in records:
        if record.provider == MANUAL_PROVIDER and not interactive:
            # The instructions are printed so the work is not lost, and
            # the credential is reported as outstanding rather than
            # silently skipped or, worse, waited on forever.
            result.manual_skipped.append(record.label)
            print(
                f"WARNING: '{record.label}' uses the manual provider and stdin is "
                "not a terminal. brushpass will not wait for a prompt it cannot "
                "read. Rotate it yourself: 'brushpass rotate "
                f"{record.label}' (or re-run nuke --yes --rotate-all from a shell)",
                file=sys.stderr,
                flush=True,
            )
            continue

        if rotate_label is None:
            result.rotation_failures[record.label] = "rotation is unavailable"
            continue

        try:
            rotate_label(record.label)
            result.rotated.append(record.label)
        except Exception as exc:  # noqa: BLE001 - one failure must not stop the rest
            reason = f"{type(exc).__name__}: {exc}"
            result.rotation_failures[record.label] = reason
            result.errors.append(f"rotation of '{record.label}' failed: {reason}")
            print(
                f"WARNING: rotation of '{record.label}' failed: {reason}",
                file=sys.stderr,
                flush=True,
            )


def _stdin_is_tty(stdin) -> bool:
    """Whether a human is there to answer a prompt."""
    handle = stdin if stdin is not None else sys.stdin
    try:
        return bool(handle.isatty())
    except (AttributeError, ValueError, OSError):
        # A closed or replaced stdin is not a terminal, and treating it
        # as one is how a process blocks forever on input().
        return False
