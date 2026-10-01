"""Scoped agent handoff for brushpass.

Mint an ephemeral token, inject it into exactly one agent subprocess, and
revoke it the moment that agent goes away: clean exit, crash, or a signal
delivered to brushpass.

Two invariants drive the design:

* **Least privilege on the way in.** The child inherits a scrubbed
  environment (a small allowlist + the token vars + explicitly
  ``--keep-env``-ed names). The parent environment never leaks in.
* **Least privilege on the way out.** The token is revoked on every exit
  path. The single unfixable case is SIGKILL delivered to brushpass
  itself: SIGKILL cannot be caught, so no handler can run. That is
  documented in the README and bounded by using a short TTL.
"""

import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .models import TokenRecord
from .scope import Scope, ScopeError
from .store import TokenStore

# Names brushpass owns inside the child environment.
TOKEN_ENV_VAR = "BRUSHPASS_TOKEN"
TOKEN_ID_ENV_VAR = "BRUSHPASS_TOKEN_ID"
RESERVED_ENV_VARS = (TOKEN_ENV_VAR, TOKEN_ID_ENV_VAR)

# The only parent variables a child inherits by default.
ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TERM",
    "TZ",
    "TMPDIR",
)

# Signals handled so that a signalled brushpass still revokes its token.
HANDOFF_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)

# How long a signalled agent is given to exit before it is killed.
SIGNAL_GRACE_SECONDS = 2.0

# How often the child is polled while waiting, in seconds.
_WAIT_POLL_SECONDS = 0.05

# Conventional shell exit statuses (POSIX / bash).
EXIT_NOT_EXECUTABLE = 126
EXIT_CMD_NOT_FOUND = 127

Notify = Callable[[str], None]


class HandoffError(Exception):
    """A handoff cannot be performed."""


@dataclass(frozen=True)
class HandoffSession:
    """A minted token plus the context needed to run and retire it."""

    record: TokenRecord
    plaintext: str
    ttl_capped_by_parent: bool = False

    @property
    def token_id(self) -> str:
        return self.record.id


def validate_keep_env(names: Iterable[str]) -> list[str]:
    """Validate ``--keep-env`` names and return them de-duplicated, in order.

    Raises:
        HandoffError: on a malformed name, or one that collides with the
            token variables brushpass injects.
    """
    validated: list[str] = []
    for raw in names:
        name = raw.strip()
        if not name or "=" in name or "\0" in name:
            raise HandoffError(
                f"Invalid --keep-env variable name: '{raw}'. "
                "Expected a plain environment variable name"
            )
        if name in RESERVED_ENV_VARS:
            raise HandoffError(
                f"--keep-env '{name}' collides with a brushpass token variable. "
                f"{TOKEN_ENV_VAR} and {TOKEN_ID_ENV_VAR} are set by brushpass "
                "and cannot be overridden"
            )
        if name not in validated:
            validated.append(name)
    return validated


def build_child_env(
    parent_env: Mapping[str, str],
    plaintext_token: str,
    token_id: str,
    keep_env: Iterable[str] = (),
) -> dict[str, str]:
    """Build the scrubbed environment for the agent subprocess.

    Contains the allowlist (only the names actually set in the parent),
    the ``--keep-env`` variables, and the two token variables. Nothing
    else from the parent environment is inherited.

    Raises:
        HandoffError: on a bad ``--keep-env`` name, or when a kept
            variable is not set in the parent environment.
    """
    keep = validate_keep_env(keep_env)
    child: dict[str, str] = {}

    for name in ENV_ALLOWLIST:
        value = parent_env.get(name)
        if value is not None:
            child[name] = value

    for name in keep:
        value = parent_env.get(name)
        if value is None:
            raise HandoffError(
                f"--keep-env variable '{name}' is not set in the parent environment"
            )
        child[name] = value

    child[TOKEN_ENV_VAR] = plaintext_token
    child[TOKEN_ID_ENV_VAR] = token_id
    return child


def resolve_live_parent(store: TokenStore, parent_id: str, now: datetime) -> TokenRecord:
    """Look up a parent token by ID and require it to be live.

    Raises:
        HandoffError: if the parent is unknown, revoked, or expired.
    """
    parent = store.find_by_id(parent_id)
    if parent is None:
        raise HandoffError(f"Parent token '{parent_id}' not found")
    if parent.revoked:
        raise HandoffError(f"Parent token '{parent_id}' has been revoked")
    if parent.is_expired(now):
        raise HandoffError(f"Parent token '{parent_id}' has expired")
    return parent


def require_narrowing(parent: TokenRecord, child_scope: Scope) -> None:
    """Require that ``child_scope`` is covered by the parent's scope.

    Raises:
        HandoffError: if the child's scope is not covered, i.e. if the
            handoff would widen rather than narrow the credential.
    """
    try:
        parent_scope = Scope.parse(parent.scope)
    except ScopeError as exc:
        raise HandoffError(
            f"Parent token {parent.id} has an unparseable scope '{parent.scope}'"
        ) from exc

    if not parent_scope.covers(child_scope):
        raise HandoffError(
            f"Scope widening rejected: parent token {parent.id} grants "
            f"'{parent.scope}', which does not cover '{child_scope}'. "
            "A derived token may only narrow its parent's scope"
        )


def mint_handoff_token(
    store: TokenStore,
    scope: Scope,
    ttl_delta: timedelta,
    label: str | None = None,
    parent_id: str | None = None,
    now: datetime | None = None,
) -> tuple[HandoffSession, TokenRecord | None]:
    """Mint the token a handoff will inject. Returns (session, parent).

    When ``parent_id`` is given the child's scope must be covered by the
    parent's scope and the child can never outlive the parent.

    Raises:
        HandoffError: if the parent is unusable or the scope widens.
    """
    issued_at = now or datetime.now(UTC)
    expires_at = issued_at + ttl_delta
    capped = False
    parent = None

    if parent_id is not None:
        parent = resolve_live_parent(store, parent_id, issued_at)
        require_narrowing(parent, scope)
        if expires_at > parent.expires_at:
            expires_at = parent.expires_at
            capped = True

    plaintext = TokenRecord.generate_token()
    record, _ = TokenRecord.create(
        plaintext_token=plaintext,
        scope=str(scope),
        label=label,
        issued_at=issued_at,
        expires_at=expires_at,
        parent_id=parent.id if parent else None,
    )
    store.add(record)
    return HandoffSession(record=record, plaintext=plaintext, ttl_capped_by_parent=capped), parent


def run_handoff(
    store: TokenStore,
    session: HandoffSession,
    agent_cmd: Sequence[str],
    child_env: Mapping[str, str],
    notify: Notify | None = None,
    grace: float = SIGNAL_GRACE_SECONDS,
) -> int:
    """Run ``agent_cmd`` with the token injected; revoke on every exit path.

    Returns the agent's exit status. An agent that exited normally
    propagates unchanged; one killed by a signal propagates as the shell
    convention 128+signal (what a shell itself would report), never as a
    negative number — negative exit values are truncated modulo 256 by the
    kernel and would reach the caller as 247 for SIGKILL.
    """
    say: Notify = notify or (lambda _message: None)
    command = list(agent_cmd)
    child: subprocess.Popen | None = None
    received: list[int] = []
    revoked = False

    def revoke_now() -> bool:
        """Revoke once. Returns True if this call performed the revocation."""
        nonlocal revoked
        if revoked:
            return False
        revoked = True
        return store.revoke(session.token_id)

    def on_signal(signum: int, _frame: object) -> None:
        # Revoke first: the credential dies the moment we are signalled,
        # whether or not the child cooperates with the forwarded signal.
        received.append(signum)
        revoke_now()
        if child is not None and child.poll() is None:
            try:
                os.kill(child.pid, signum)
            except (ProcessLookupError, PermissionError):
                pass

    previous = _install_signal_handlers(on_signal)
    returncode = 0
    try:
        # Flush our own buffers so the handoff header cannot appear after
        # the agent's output when stdout is a pipe.
        flush_stdio()
        try:
            child = subprocess.Popen(command, env=dict(child_env))
        except FileNotFoundError:
            say(f"brushpass: command not found: {command[0]}")
            returncode = EXIT_CMD_NOT_FOUND
        except OSError as exc:
            say(f"brushpass: cannot execute {command[0]}: {exc}")
            returncode = EXIT_NOT_EXECUTABLE
        else:
            returncode = _wait_for_child(child, lambda: bool(received), grace)
    finally:
        # The signal handler may have revoked already; `revoke_now` is
        # idempotent, so either path converges on "token is dead".
        revoke_now()
        _restore_signal_handlers(previous)
        say(f"brushpass: token {session.token_id} revoked ({_reason(received)})")

    if received:
        # brushpass itself was signalled: die the same way so the caller's
        # shell sees the signal, not an invented status.
        _exit_by_signal(received[0])

    return _shell_status(returncode)


def _shell_status(returncode: int) -> int:
    """Normalise a subprocess returncode into a shell exit status.

    ``Popen.wait`` reports death-by-signal as a negative number, which is
    a Python convention, not a shell one. Exit statuses are 0-255, so a
    negative value would be truncated (SIGKILL's -9 becomes 247). Report
    128+signal instead, which is what a shell reports for the same death.
    """
    if returncode < 0:
        return 128 + abs(returncode)
    return returncode


def _reason(received: Sequence[int]) -> str:
    """Human-readable cause of revocation, for the operator log."""
    if not received:
        return "agent exited"
    names = ", ".join(signal.Signals(s).name for s in dict.fromkeys(received))
    return f"agent exited after signal {names}"


def _wait_for_child(
    child: subprocess.Popen,
    is_signalled: Callable[[], bool],
    grace: float,
    poll: float = _WAIT_POLL_SECONDS,
) -> int:
    """Wait for the agent, killing it if it ignores a forwarded signal."""
    deadline: float | None = None
    while True:
        try:
            return child.wait(timeout=poll)
        except subprocess.TimeoutExpired:
            pass
        if is_signalled():
            if deadline is None:
                deadline = time.monotonic() + grace
            elif time.monotonic() >= deadline:
                child.kill()
                return child.wait()


def _install_signal_handlers(handler: Callable[[int, object], None]) -> dict:
    """Install ``handler`` for every handoff signal. Best effort."""
    if threading.current_thread() is not threading.main_thread():
        return {}
    installed: dict = {}
    for sig in HANDOFF_SIGNALS:
        try:
            installed[sig] = signal.signal(sig, handler)
        except (OSError, ValueError):
            continue
    return installed


def _restore_signal_handlers(previous: Mapping) -> None:
    for sig, prior in previous.items():
        try:
            signal.signal(sig, prior)
        except (OSError, ValueError):
            continue


def _exit_by_signal(signum: int) -> None:
    """Exit the way the signal meant us to, after handlers have run."""
    signal.signal(signum, signal.SIG_DFL)
    flush_stdio()
    os.kill(os.getpid(), signum)
    os._exit(128 + signum)  # pragma: no cover - only if the signal is blocked


def flush_stdio() -> None:
    """Flush stdio so nothing buffered is lost when we die by signal."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            continue
