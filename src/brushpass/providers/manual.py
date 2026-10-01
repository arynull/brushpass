"""Rotation for credentials with no rotation API.

Some credentials cannot be rotated by a program: a classic GitHub PAT, an
AWS IAM access key, a database password on a box you do not control. The
only rotation path is a human doing it in a web UI, then pasting the
result back.

This provider says so. It prints the steps, waits for the new secret on
stdin, and hands it to the same rotation engine everything else uses — so
the persist-before-revoke contract, the journal, the linked-token
revocation, and the timing all still apply. What it does not do is
pretend to be automation. There is no API call here, and
``supports_revoke`` is False: whether the old secret dies is up to what
the operator just did in the provider's UI, and brushpass says exactly
that rather than reporting a revocation that did not happen.

The new secret is read from stdin (never argv, never a prompt argument),
one line, with echo suppressed via :func:`getpass` when stdin is a TTY.
"""

import sys
from getpass import getpass

from .base import Provider, ProviderError, RotationResult, Step


# Overridable so tests and non-interactive callers can supply the secret.
# The CLI passes a callable reading from a stream; this is the default.
def read_secret_from_stdin(prompt: str, stream=None) -> str:
    """Read one line from stdin without echoing it on a TTY.

    On a pipe (``brushpass rotate ... < file``, a CI job, a test) there is
    no echo to suppress, so it is a plain read.
    """
    handle = stream or sys.stdin
    if not handle.isatty():
        line = handle.readline()
        if not line:
            raise ProviderError(
                "manual: no new secret on stdin. Create the new credential in "
                "the provider's UI, then pipe it in "
                "(printf '%s\\n' \"$NEW\" | brushpass rotate <label>)"
            )
        return line.strip()

    try:
        return getpass(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        raise ProviderError(
            "manual: no new secret supplied. The old credential is untouched"
        ) from None


class ManualProvider(Provider):
    """Human-driven rotation: instructions in, new secret on stdin."""

    name = "manual"
    description = (
        "For credentials with no rotation API (classic PATs, IAM keys, "
        "database passwords). Prints step-by-step instructions and reads the "
        "new secret from stdin."
    )
    required_config = ()
    optional_config = ("instructions", "revoke_hint")
    supports_revoke = False
    revoke_note = (
        "Revoking a manual credential happens in the provider's own UI, if at "
        "all. brushpass cannot confirm it, so it does not claim to have done it. "
        "Revoke the old credential yourself as part of the rotation."
    )

    def __init__(self, reader=None, writer=None):
        """``reader`` reads the new secret, ``writer`` prints instructions."""
        self._reader = reader or read_secret_from_stdin
        # Instructions go to stderr: they are operator guidance, and
        # stdout has to stay a clean data channel for `rotate --json`.
        self._writer = writer or (
            lambda line: print(line, file=sys.stderr, flush=True)
        )

    def can_revoke(self, config: dict) -> bool:
        return False

    def plan(self, context) -> list[Step]:
        steps = [Step("Print rotation instructions for the operator", destructive=False)]
        steps.extend(Step(text) for text in self.instructions(context))
        steps.append(Step("Read the new secret from stdin (never from argv)"))
        steps.append(Step("Store the new secret encrypted, replacing the old one"))
        return steps

    def instructions(self, context) -> list[str]:
        """Operator steps, from config or a sensible default."""
        configured = (context.config or {}).get("instructions")
        if configured:
            return [str(line) for line in configured]
        return [
            f"Open the provider's UI for the credential '{context.label}'.",
            "Create a NEW credential with the same or narrower permissions.",
            "Copy the new secret.",
            "Paste it at the prompt below (or pipe it on stdin).",
            "Revoke the OLD credential in the same UI, once this rotation "
            "has finished successfully.",
        ]

    def rotate(self, old_secret: str, config: dict) -> RotationResult:
        """Emit instructions, then read and return the new secret.

        ``old_secret`` is never printed, never sent anywhere, and never
        passed to the reader: the operator already has the provider's UI.
        """
        for line in self.instructions(_Context(config, self.label or "credential")):
            self._writer(f"  {line}")
        self._writer("")
        new_secret = self._reader(
            f"Paste the new secret for '{self.label or 'credential'}': "
        )
        if not new_secret or not new_secret.strip():
            raise ProviderError(
                "manual: the new secret was empty. The old credential is still "
                "live and unchanged"
            )
        if new_secret.strip() == old_secret:
            raise ProviderError(
                "manual: the new secret is identical to the old one. Nothing "
                "was rotated; the old credential is untouched"
            )
        return RotationResult(
            new_secret=new_secret.strip(),
            detail="supplied by the operator",
        )

    def revoke(self, secret: str, config: dict) -> None:
        """Always refused: see :attr:`revoke_note`."""
        raise ProviderError(
            "manual: brushpass cannot revoke this credential upstream. "
            + self.revoke_note
        )


class _Context:
    """Minimal context for ``instructions`` when called outside the engine."""

    def __init__(self, config: dict, label: str):
        self.config = config or {}
        self.label = label
        self.provider = "manual"
        self.record = None
