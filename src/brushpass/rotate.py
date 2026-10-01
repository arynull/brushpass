"""The rotation engine, and the atomicity contract it enforces.

The contract, in one sentence: **a live secret is never untracked.**

A rotation moves a credential from secret A to secret B. There are two
ways to get that wrong, and both are handled explicitly:

* **Losing B.** The provider issued B, and then storing it failed. If B
  was never written down, B is a live upstream credential that nobody
  holds and nobody can revoke. Step (b) therefore persists B *before*
  anything retires A, retries three times, and if it still cannot, it
  records B's identifier in the journal as an orphan and aborts loudly
  with a non-zero exit — rather than continuing and pretending.
* **Killing the only working one.** If step (b) failed, A must stay
  live. The engine aborts before ``provider.revoke`` and before any
  linked token is revoked, so A continues to work while the operator
  deals with the orphan.

The ordering, and why:

1. ``provider.rotate`` -> B. Timed. Nothing has changed yet, so a
   failure here is free.
2. Persist B to the encrypted store, retry 3x. This is the commit
   point. After it succeeds, both A and B are known to brushpass.
3. Only then ``provider.revoke(A)`` where the provider can do it, and
   revoke every live ephemeral token linked to this credential. A
   failure here is *not* fatal: B is stored and live, so the rotation
   succeeded and the stale A is an operational loose end that gets
   reported and alerted.
4. Write the terminal journal entry and the audit log line.

Every run is timed. The end-to-end budget is 60 seconds, which is a
product requirement (a rotation is an operational action someone is
waiting on), and the measured duration is printed and asserted in tests.
"""

import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .credentials import CredentialError, CredentialStore, digests_equal, secret_digest
from .journal import (
    STATE_ABORTED,
    STATE_FINISHED,
    STATE_STARTED,
    JournalEntry,
    JournalError,
    RotationJournal,
    new_rotation_id,
    now_iso,
)
from .providers.base import ConfigError, Provider, ProviderError, RotationResult, Step
from .store import TokenStore

# Attempts at the persist step. Three is deliberate: a transient disk
# error should not abort a rotation, and a persistent one must not be
# retried forever while an orphan sits live upstream.
PERSIST_ATTEMPTS = 3

# The operator-facing budget for one end-to-end rotation.
ROTATION_BUDGET_SECONDS = 60.0

# Per-attempt timeout for the best-effort webhook notification.
WEBHOOK_TIMEOUT = 5.0


class RotationError(Exception):
    """A rotation could not complete. Always carries the reason."""


class PersistFailedError(RotationError):
    """The new secret could not be stored; the old one is still live.

    Attributes:
        orphan_secret_id: identifier of the secret the provider issued,
            which brushpass could not store.
        attempts: how many persist attempts were made.
        last_error: the underlying failure.
    """

    def __init__(self, message: str, orphan_secret_id: str, attempts: int, last_error: str):
        super().__init__(message)
        self.orphan_secret_id = orphan_secret_id
        self.attempts = attempts
        self.last_error = last_error


class RevokeFailedError(RotationError):
    """The new secret is live, but an old one could not be fully retired.

    Not fatal: the credential works. This is the loose end that must be
    reported loudly, because a superseded secret that outlives its
    rotation is exactly the thing rotation exists to prevent.
    """


@dataclass
class RotationOutcome:
    """The result of one rotation attempt, for rendering and testing."""

    label: str
    provider: str
    state: str
    rotation_id: str
    dry_run: bool = False
    duration_seconds: float = 0.0
    old_secret_id: str | None = None
    new_secret_id: str | None = None
    orphan_secret_id: str | None = None
    revoked_tokens: list[str] = field(default_factory=list)
    provider_revoked: bool | None = None
    provider_revoke_supported: bool = True
    steps: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    notify_error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.state == STATE_FINISHED

    @property
    def within_budget(self) -> bool:
        return self.duration_seconds < ROTATION_BUDGET_SECONDS

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "provider": self.provider,
            "state": self.state,
            "rotation_id": self.rotation_id,
            "dry_run": self.dry_run,
            "duration_seconds": round(self.duration_seconds, 3),
            "within_budget": self.within_budget,
            "old_secret_id": self.old_secret_id,
            "new_secret_id": self.new_secret_id,
            "orphan_secret_id": self.orphan_secret_id,
            "revoked_tokens": list(self.revoked_tokens),
            "provider_revoked": self.provider_revoked,
            "provider_revoke_supported": self.provider_revoke_supported,
            "steps": list(self.steps),
            "errors": list(self.errors),
            "alerts": list(self.alerts),
            "notify_error": self.notify_error,
        }


@dataclass(frozen=True)
class RotationContext:
    """What a provider is told about the credential it is rotating."""

    label: str
    provider: str
    config: dict
    record: object = None


class RotationEngine:
    """Runs rotations: plan, rotate, persist, revoke, journal, notify."""

    def __init__(
        self,
        credentials: CredentialStore,
        tokens: TokenStore,
        journal: RotationJournal,
        provider_registry: Callable[[str], Provider],
        notifier=None,
    ):
        self.credentials = credentials
        self.tokens = tokens
        self.journal = journal
        self._provider_registry = provider_registry
        self._notifier = notifier

    # ---- planning -----------------------------------------------------

    def plan(self, label: str) -> RotationOutcome:
        """Build the dry-run plan. Performs no I/O against any provider.

        The plan is the same shape as the real run so that what an
        operator reviews is what actually happens.
        """
        started = time.monotonic()
        record = self.credentials.get(label)
        provider = self._provider_registry(record.provider)
        # Config is validated during planning: `rotate --dry-run` is the
        # cheapest place to discover a broken config, and discovering it
        # before any secret moves is the entire point of a dry run.
        values = provider.validate_config(record.config)

        context = RotationContext(
            label=label, provider=record.provider, config=values, record=record
        )
        provider_steps = list(provider.plan(context))
        revoke_supported, revoke_note = self._revoke_capability(provider, values)
        # Appended to the provider's own steps rather than spliced into the
        # middle of them: a note inserted by index would split one
        # provider's numbered instructions apart.
        if not revoke_supported and revoke_note:
            provider_steps.append(
                Step(f"Note: {revoke_note}", destructive=False)
            )

        planned = [
            *provider_steps,
            *self._token_steps(label),
            Step("Write the rotation journal entry and an audit log line"),
        ]

        # Render last, so numbering always reflects the final order.
        steps = [step.render(index) for index, step in enumerate(planned, start=1)]

        return RotationOutcome(
            label=label,
            provider=record.provider,
            state=STATE_FINISHED,
            rotation_id="(dry-run, no rotation)",
            dry_run=True,
            duration_seconds=time.monotonic() - started,
            old_secret_id=record.secret_id,
            provider_revoke_supported=revoke_supported,
            steps=steps,
        )

    def _token_steps(self, label: str) -> list:
        """Steps for the linked tokens this rotation will revoke."""
        linked = self._linked_tokens(label)
        if not linked:
            return [
                Step("Revoke ephemeral tokens linked to this credential (none)")
            ]
        return [
            Step(
                f"Revoke {len(linked)} live ephemeral token(s) linked to "
                f"'{label}': {', '.join(record.id for record in linked)}",
                destructive=True,
            )
        ]

    def _linked_tokens(self, label: str) -> list:
        """Live tokens carrying this credential label.

        Only tokens minted with ``--credential <label>`` are affected.
        A token minted without one is untethered by design and survives
        any rotation; see the README.
        """
        now = datetime.now(UTC)
        return [
            record
            for record in self.tokens.list_all()
            if record.credential_label == label
            and not record.revoked
            and not record.is_expired(now)
        ]

    def _revoke_capability(self, provider: Provider, config: dict) -> tuple[bool, str]:
        """Whether this provider can revoke, and why not if it cannot."""
        checker = getattr(provider, "can_revoke", None)
        if callable(checker):
            if checker(config):
                return True, ""
            return False, provider.revoke_note or (
                "this credential's config names no revoke endpoint, so the old "
                "secret can only be retired by whatever the provider does on "
                "its own (usually its expiry)"
            )
        if provider.supports_revoke:
            return True, ""
        return False, provider.revoke_note or (
            f"provider '{provider.name}' offers no way to revoke the old "
            "secret; it stays valid until the provider expires it"
        )

    # ---- execution ----------------------------------------------------

    def rotate(
        self,
        label: str,
        dry_run: bool = False,
        notify_stream: Callable[[str], None] | None = None,
    ) -> RotationOutcome:
        """Rotate one credential, honouring the atomicity contract."""
        if dry_run:
            return self.plan(label)

        started_monotonic = time.monotonic()
        started_at = now_iso()
        record = self.credentials.get(label)
        provider = self._provider_registry(record.provider)
        values = provider.validate_config(record.config)
        rotation_id = new_rotation_id()
        old_secret = self.credentials.get_secret(label)
        old_id = secret_digest(old_secret)[:12]

        entry = JournalEntry(
            rotation_id=rotation_id,
            label=label,
            provider=record.provider,
            state=STATE_STARTED,
            started_at=started_at,
            old_secret_id=old_id,
        )
        self._append(entry)

        if hasattr(provider, "label"):
            # The manual provider uses this for its prompt wording only.
            provider.label = label

        # (a) Rotate. Nothing has changed yet, so a failure here is free.
        try:
            result = provider.rotate(old_secret, values)
        except (ProviderError, ConfigError) as exc:
            outcome = self._abort(
                entry, label, record.provider, started_monotonic, str(exc),
                orphan=None,
            )
            self._notify(outcome, notify_stream)
            raise RotationError(str(exc)) from exc

        new_secret = result.new_secret if isinstance(result, RotationResult) else result
        new_id = secret_digest(new_secret)[:12]

        # (b) Persist. The commit point.
        try:
            self._persist_new_secret(label, new_secret)
        except PersistFailedError as exc:
            outcome = self._abort(
                entry, label, record.provider, started_monotonic, str(exc),
                orphan=new_id,
            )
            self._notify(outcome, notify_stream)
            raise

        if digests_equal(old_id, new_id):
            # The provider handed back the same secret. Storing it is a
            # no-op, but reporting a rotation would be a lie.
            outcome = self._abort(
                entry, label, record.provider, started_monotonic,
                f"Provider '{record.provider}' returned the same secret; "
                "nothing was rotated",
                orphan=new_id,
            )
            self._notify(outcome, notify_stream)
            raise RotationError(str(outcome.errors[-1]))

        # (c) Only now may the old secret and its tokens be retired.
        revoke_supported, revoke_note = self._revoke_capability(provider, values)
        provider_revoked: bool | None = None
        errors: list[str] = []

        if revoke_supported:
            try:
                provider.revoke(old_secret, values)
                provider_revoked = True
            except ProviderError as exc:
                # The new secret is stored and live; the rotation worked.
                # The stale old secret is a loose end, not a failure.
                provider_revoked = False
                errors.append(f"Could not revoke the old secret upstream: {exc}")
        elif revoke_note:
            errors.append(f"Upstream revocation not performed: {revoke_note}")

        revoked = self._revoke_linked_tokens(label)

        duration = time.monotonic() - started_monotonic
        entry.state = STATE_FINISHED
        entry.finished_at = now_iso()
        entry.duration_seconds = round(duration, 3)
        entry.new_secret_id = new_id
        entry.revoked_tokens = revoked
        entry.provider_revoked = provider_revoked
        entry.error = "; ".join(errors) if errors else None
        self._append(entry)
        self._audit(entry)

        outcome = RotationOutcome(
            label=label,
            provider=record.provider,
            state=STATE_FINISHED,
            rotation_id=rotation_id,
            duration_seconds=duration,
            old_secret_id=old_id,
            new_secret_id=new_id,
            revoked_tokens=revoked,
            provider_revoked=provider_revoked,
            provider_revoke_supported=revoke_supported,
            errors=errors,
            alerts=list(errors),
        )
        if not outcome.within_budget:
            outcome.errors.append(
                f"Rotation took {duration:.1f}s, over the "
                f"{ROTATION_BUDGET_SECONDS:.0f}s budget"
            )
            outcome.alerts.append(outcome.errors[-1])
        self._notify(outcome, notify_stream)
        return outcome

    # ---- steps --------------------------------------------------------

    def _persist_new_secret(self, label: str, new_secret: str) -> None:
        """Store the new secret, retrying up to :data:`PERSIST_ATTEMPTS`.

        Raises:
            PersistFailedError: after every attempt failed. The old secret is
                untouched and still live; the caller records the orphan.
        """
        last_error = ""
        for attempt in range(1, PERSIST_ATTEMPTS + 1):
            try:
                self.credentials.replace_secret(label, new_secret)
                return
            except (CredentialError, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < PERSIST_ATTEMPTS:
                    # No sleep: a rotation is interactive and the budget
                    # is 60s. Retrying immediately is right for a
                    # transient ENOSPC/EBUSY, and the third attempt is
                    # what decides, not a backoff curve.
                    continue

        raise PersistFailedError(
            f"Could not store the new secret after {PERSIST_ATTEMPTS} attempts "
            f"({last_error}). The old credential for '{label}' is STILL LIVE "
            "and unchanged. brushpass aborted before revoking anything, so "
            "your old secret still works — but the provider may have issued "
            f"a new one (identifier {secret_digest(new_secret)[:12]}) that "
            "brushpass does not hold. Revoke it at the provider, or fix the "
            "store and re-run the rotation.",
            orphan_secret_id=secret_digest(new_secret)[:12],
            attempts=PERSIST_ATTEMPTS,
            last_error=last_error,
        )

    def _revoke_linked_tokens(self, label: str) -> list[str]:
        """Revoke every live token carrying this credential label."""
        revoked: list[str] = []
        for record in self._linked_tokens(label):
            if self.tokens.revoke(record.id):
                revoked.append(record.id)
        return revoked

    def _abort(
        self,
        entry: JournalEntry,
        label: str,
        provider_name: str,
        started_monotonic: float,
        error: str,
        orphan: str | None,
    ) -> RotationOutcome:
        """Record an aborted rotation and build its outcome.

        The old credential is untouched in every path through here: the
        engine only calls this before step (c).
        """
        duration = time.monotonic() - started_monotonic
        entry.state = STATE_ABORTED
        entry.finished_at = now_iso()
        entry.duration_seconds = round(duration, 3)
        entry.error = error
        entry.orphan_secret_id = orphan
        entry.new_secret_id = None if orphan else entry.new_secret_id
        self._append(entry)
        self._audit(entry)

        alerts = [
            f"ROTATION ABORTED for '{label}': {error}",
            "The old credential is still live and unchanged; nothing was revoked.",
        ]
        if orphan:
            alerts.append(
                f"ORPHANED SECRET {orphan}: the provider issued a new secret that "
                "brushpass could not store. Revoke it at the provider, or fix "
                "the store and re-run 'brushpass rotate'."
            )
        return RotationOutcome(
            label=label,
            provider=provider_name,
            state=STATE_ABORTED,
            rotation_id=entry.rotation_id,
            duration_seconds=duration,
            old_secret_id=entry.old_secret_id,
            new_secret_id=entry.new_secret_id,
            orphan_secret_id=orphan,
            errors=[error],
            alerts=alerts,
        )

    def _append(self, entry: JournalEntry) -> None:
        """Append to the journal, degrading to a printed alert on failure.

        The journal is the record that makes a failure recoverable, so a
        failure to write it must not mask the original error — but it must
        not be silent either.
        """
        try:
            self.journal.append(entry)
        except JournalError as exc:
            print(f"WARNING: could not write the rotation journal: {exc}", flush=True)

    def _audit(self, entry: JournalEntry) -> None:
        """Print the audit-style log line for a terminal entry.

        stderr, not stdout: stdout is the command's data channel, and a
        log line there corrupts ``--json`` for anything parsing it.
        """
        print(f"brushpass: {entry.to_log_line()}", file=sys.stderr, flush=True)

    # ---- notification -------------------------------------------------

    def _notify(
        self,
        outcome: RotationOutcome,
        notify_stream: Callable[[str], None] | None,
    ) -> None:
        """Best-effort webhook. Never fails a rotation.

        A notification that cannot be delivered is recorded on the
        outcome as ``notify_error`` and printed as a warning. The
        rotation itself is already committed by the time this runs.
        """
        if self._notifier is None:
            return
        try:
            self._notifier(outcome)
        except Exception as exc:  # noqa: BLE001 - notification is best effort
            message = f"webhook notification failed: {type(exc).__name__}: {exc}"
            outcome.notify_error = message
            outcome.alerts.append(message)
            print(f"WARNING: {message}", flush=True)


def send_webhook(url: str, payload: dict, timeout: float = WEBHOOK_TIMEOUT) -> None:
    """POST a JSON summary to a webhook URL.

    Raises:
        urllib.error.URLError: on any delivery failure. Callers treat
            every exception as best-effort.
    """
    import json

    data = json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "brushpass/0.4"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        if response.status >= 300:
            raise urllib.error.URLError(f"webhook returned HTTP {response.status}")
