"""Token material rendering for shells that cannot use `handoff` directly.

`handoff` is the safe path: the token lives only in a child's environment
and is revoked the moment the agent exits. Some shells and launchers
cannot be wrapped that way, so `env` prints the material for them to
`eval` / dot-source. That is strictly weaker — the token lands in the
caller's environment and can outlive the shell — so:

* the token must be live (fail-closed on revoked / expired), and
* a warning about the secret material goes to stderr, always, while
  stdout stays clean enough to `eval`.

Note on ``--id``: brushpass stores token *hashes* only, so a token
identified by ID cannot be re-emitted by a later process — the plaintext
no longer exists anywhere. That is the storage guarantee working as
intended, not a bug. ``env`` therefore reads the token from stdin or
``--from-env`` (never argv — trust boundary 2) and uses the record
behind it for the fail-closed liveness checks.
"""

import json
from datetime import datetime

from .models import TokenRecord
from .store import TokenStore

FORMAT_EXPORT = "export"
FORMAT_JSON = "json"
FORMAT_POWERSHELL = "powershell"
ENV_FORMATS = (FORMAT_EXPORT, FORMAT_JSON, FORMAT_POWERSHELL)

TOKEN_VAR = "BRUSHPASS_TOKEN"
TOKEN_ID_VAR = "BRUSHPASS_TOKEN_ID"

SECRET_WARNING = (
    "Warning: this output contains secret token material. "
    "Prefer 'brushpass handoff', which revokes the token when the agent exits."
)


class EnvError(Exception):
    """Token material cannot be rendered."""


def require_live(record: TokenRecord, now: datetime | None = None) -> TokenRecord:
    """Require a record to be live (fail-closed).

    Raises:
        EnvError: if the token is revoked or expired.
    """
    if record.revoked:
        raise EnvError(f"Token '{record.id}' has been revoked")
    if record.is_expired(now):
        raise EnvError(f"Token '{record.id}' has expired")
    return record


def find_live_by_token(
    store: TokenStore, plaintext_token: str, now: datetime | None = None
) -> TokenRecord:
    """Resolve a plaintext token to a live record.

    Raises:
        EnvError: unknown, revoked, or expired token.
    """
    record = store.find_by_token(plaintext_token)
    if record is None:
        raise EnvError("Token not found")
    return require_live(record, now)


def require_live_by_id(store: TokenStore, token_id: str, now: datetime | None = None):
    """Resolve a token ID to a live record.

    Raises:
        EnvError: unknown, revoked, or expired token.
    """
    record = store.find_by_id(token_id)
    if record is None:
        raise EnvError(f"Token '{token_id}' not found")
    return require_live(record, now)


def render(record: TokenRecord, plaintext: str, fmt: str) -> str:
    """Render token material in the requested shell format.

    Raises:
        EnvError: on an unsupported format.
    """
    if fmt not in ENV_FORMATS:
        raise EnvError(
            f"Unknown format '{fmt}'. Expected one of: {', '.join(ENV_FORMATS)}"
        )

    if fmt == FORMAT_EXPORT:
        return (
            f"export {TOKEN_VAR}={_sh_quote(plaintext)}\n"
            f"export {TOKEN_ID_VAR}={_sh_quote(record.id)}\n"
        )
    if fmt == FORMAT_POWERSHELL:
        return (
            f"$env:{TOKEN_VAR}={_ps_quote(plaintext)}\n"
            f"$env:{TOKEN_ID_VAR}={_ps_quote(record.id)}\n"
        )
    return json.dumps(
        {
            TOKEN_VAR: plaintext,
            TOKEN_ID_VAR: record.id,
            "scope": record.scope,
            "label": record.label,
            "parent_id": record.parent_id,
            "issued_at": record.issued_at.isoformat(),
            "expires_at": record.expires_at.isoformat(),
        },
        indent=2,
    )


def _sh_quote(value: str) -> str:
    """Single-quote a POSIX shell word."""
    return "'" + value.replace("'", "'\\''") + "'"


def _ps_quote(value: str) -> str:
    """Single-quote a PowerShell string literal (' escapes by doubling)."""
    return "'" + value.replace("'", "''") + "'"
