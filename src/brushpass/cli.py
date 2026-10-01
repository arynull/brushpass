#!/usr/bin/env python3
"""Command-line interface for brushpass."""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .config import Config
from .credentials import CredentialError, CredentialKeyError, CredentialStore
from .envout import (
    ENV_FORMATS,
    FORMAT_EXPORT,
    SECRET_WARNING,
    EnvError,
    find_live_by_token,
    render,
    require_live_by_id,
)
from .handoff import (
    TOKEN_ENV_VAR,
    TOKEN_ID_ENV_VAR,
    HandoffError,
    build_child_env,
    mint_handoff_token,
    run_handoff,
    validate_keep_env,
)
from .models import TokenRecord
from .providers import (
    ConfigError,
    ProviderError,
    available_providers,
    get_provider,
)
from .rotate import PersistFailedError, RotationError
from .scan import (
    ScanError,
    collect_blobs,
    exit_code,
    fix_findings,
    render_json,
    render_text,
    scan_blobs,
)
from .scanner import Scanner, ScannerKeyError, load_scanner
from .scope import Scope, ScopeError
from .sources import ScanSourceError
from .store import TokenStore
from .ttl import TTLError, format_expiry, parse_ttl

# Commands that mint or match token material, and therefore need the
# scanner key that fingerprints it.
SCANNER_COMMANDS = frozenset({"mint", "handoff", "scan"})


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="brushpass",
        description="Local credential broker for automated tooling - ephemeral token minting",
    )
    parser.add_argument(
        "--version", action="version", version=f"brushpass {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # mint command
    mint_parser = subparsers.add_parser(
        "mint", help="Mint a new ephemeral token"
    )
    mint_parser.add_argument(
        "--scope", required=True, help="Scope for the token (provider:resource:permission)"
    )
    mint_parser.add_argument(
        "--ttl", default=None, help="Time-to-live (e.g., 30m, 2h, 7d). Default: 2h, Max: 24h"
    )
    mint_parser.add_argument(
        "--label", default=None, help="Optional label for the token"
    )
    mint_parser.add_argument(
        "--credential",
        dest="credential_label",
        default=None,
        help=(
            "Root credential this token is minted from. The label must "
            "already exist; rotating it revokes every live token carrying it"
        ),
    )
    mint_parser.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    # verify command
    verify_parser = subparsers.add_parser(
        "verify", help="Verify a token"
    )
    verify_parser.add_argument(
        "token", help="Token to verify"
    )
    verify_parser.add_argument(
        "--scope", required=True, help="Required scope to check"
    )
    verify_parser.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    # list command
    list_parser = subparsers.add_parser(
        "list", help="List all tokens"
    )
    list_parser.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    # revoke command
    revoke_parser = subparsers.add_parser(
        "revoke", help="Revoke a token"
    )
    revoke_parser.add_argument(
        "token_id", help="Token ID to revoke"
    )
    revoke_parser.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    # prune command
    prune_parser = subparsers.add_parser(
        "prune", help="Delete expired/revoked tokens older than 7 days"
    )
    prune_parser.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    # handoff command
    handoff_parser = subparsers.add_parser(
        "handoff",
        help="Mint a scoped token, run an agent with it, revoke on exit",
    )
    handoff_parser.add_argument(
        "--scope", required=True, help="Scope for the token (provider:resource:permission)"
    )
    handoff_parser.add_argument(
        "--ttl", default=None, help="Time-to-live (e.g., 30m, 2h). Default: 2h, Max: 24h"
    )
    handoff_parser.add_argument(
        "--label", default=None, help="Optional label for the token"
    )
    handoff_parser.add_argument(
        "--parent",
        default=None,
        help="Parent token ID to derive from; the new scope may only narrow it",
    )
    handoff_parser.add_argument(
        "--keep-env",
        action="append",
        default=[],
        metavar="VAR",
        help="Pass a parent env var through to the agent (repeatable)",
    )
    handoff_parser.add_argument(
        "agent",
        nargs=argparse.REMAINDER,
        help="Agent command after '--' (e.g. -- my-agent --flag)",
    )

    # scan command
    scan_parser = subparsers.add_parser(
        "scan", help="Scan files, git history and shell history for leaked tokens"
    )
    scan_parser.add_argument(
        "paths",
        nargs="*",
        metavar="path",
        help="Files or directories to scan recursively (default: current directory)",
    )
    scan_parser.add_argument(
        "--fix",
        action="store_true",
        help="Revoke every live leaked token found",
    )
    scan_parser.add_argument(
        "--git",
        action="store_true",
        help=(
            "Also scan git history (log -p --all), staged and unstaged "
            "diffs, and untracked worktree files"
        ),
    )
    scan_parser.add_argument(
        "--history",
        action="store_true",
        help="Also scan shell history files (honours $HISTFILE)",
    )
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # credential command
    credential_parser = subparsers.add_parser(
        "credential", help="Manage root credentials (encrypted at rest)"
    )
    credential_sub = credential_parser.add_subparsers(dest="subcommand", help="Subcommands")

    cred_add = credential_sub.add_parser("add", help="Store a new root credential")
    cred_add.add_argument("--provider", required=True, help="Provider that can rotate it")
    cred_add.add_argument("--label", required=True, help="Unique label for the credential")
    cred_add.add_argument(
        "--from-env",
        dest="from_env",
        default=None,
        metavar="VAR",
        help="Read the secret from this environment variable instead of stdin",
    )
    cred_add.add_argument(
        "--set",
        dest="config_pairs",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Provider config entry (repeatable)",
    )
    cred_add.add_argument("--json", action="store_true", help="Output as JSON")

    cred_list = credential_sub.add_parser("list", help="List root credentials")
    cred_list.add_argument("--json", action="store_true", help="Output as JSON")

    cred_remove = credential_sub.add_parser("remove", help="Delete a root credential")
    cred_remove.add_argument("label", help="Label of the credential to remove")
    cred_remove.add_argument("--yes", action="store_true", help="Skip the confirmation")

    cred_status = credential_sub.add_parser(
        "status", help="Show rotation history for a credential"
    )
    cred_status.add_argument("label", help="Label of the credential")
    cred_status.add_argument("--json", action="store_true", help="Output as JSON")

    # provider command
    provider_parser = subparsers.add_parser(
        "provider", help="Inspect available rotation providers"
    )
    provider_sub = provider_parser.add_subparsers(dest="subcommand", help="Subcommands")
    provider_list = provider_sub.add_parser("list", help="Show available providers")
    provider_list.add_argument("--json", action="store_true", help="Output as JSON")
    provider_show = provider_sub.add_parser("show", help="Show one provider's schema")
    provider_show.add_argument("name", help="Provider name")
    provider_show.add_argument("--json", action="store_true", help="Output as JSON")

    # rotate command
    rotate_parser = subparsers.add_parser(
        "rotate", help="Rotate a root credential and revoke what it backs"
    )
    rotate_parser.add_argument(
        "label", nargs="?", default=None, help="Credential label to rotate"
    )
    rotate_parser.add_argument(
        "--dry-run", action="store_true", help="Print the plan and change nothing"
    )
    rotate_parser.add_argument(
        "--status", action="store_true", help="Show rotation history and problems"
    )
    rotate_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # env command
    env_parser = subparsers.add_parser(
        "env", help="Print token material in shell format"
    )
    env_parser.add_argument(
        "--id", dest="token_id", default=None, help="Token ID (see note below)"
    )
    env_parser.add_argument(
        "--format",
        choices=ENV_FORMATS,
        default=FORMAT_EXPORT,
        help="Output format (default: export)",
    )
    env_parser.add_argument(
        "--token",
        dest="token",
        default=None,
        help="Plaintext token; resolves the record for liveness checks",
    )

    return parser


def _require_scanner(scanner: Scanner | None) -> Scanner:
    """Return the loaded scanner key.

    ``main`` loads the key for every command in ``SCANNER_COMMANDS`` and
    fails closed if it is unusable, so a mint that reaches this point
    always has one. Minting without it would produce tokens that no future
    scan could recognise, which is worse than not minting at all.
    """
    if scanner is None:  # pragma: no cover - unreachable via main()
        raise ScanError(
            "Internal error: no scanner key loaded for a minting command. "
            "The scanner key is required to fingerprint new tokens"
        )
    return scanner


def cmd_mint(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """Mint a new token."""
    try:
        # Parse and validate scope
        scope = Scope.parse(args.scope)
    except ScopeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Parse TTL
    ttl_str = args.ttl or config.default_ttl
    try:
        ttl_delta = parse_ttl(ttl_str)
    except TTLError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Resolve the credential this token hangs off, before minting
    # anything: a linkage to a credential that does not exist must not
    # leave a live token behind.
    credential_label = getattr(args, "credential_label", None)
    if credential_label:
        try:
            CredentialStore(config.data_dir).get(credential_label)
        except CredentialError as e:
            print(f"Error: {e}", file=sys.stderr)
            print(
                "Add it first: 'brushpass credential add --provider <name> "
                f"--label {credential_label}'",
                file=sys.stderr,
            )
            return 1

    # Opportunistic prune on mint
    store.prune()

    # Generate token
    plaintext = TokenRecord.generate_token()
    now = datetime.now(UTC)
    expires_at = now + ttl_delta

    token_record, _ = TokenRecord.create(
        plaintext_token=plaintext,
        scope=str(scope),
        label=args.label,
        issued_at=now,
        expires_at=expires_at,
        fingerprint=_require_scanner(scanner).fingerprint(plaintext),
        credential_label=credential_label,
    )

    # Store the record
    store.add(token_record)

    # Output
    if args.json:
        output = {
            "id": token_record.id,
            "token": plaintext,
            "scope": token_record.scope,
            "label": token_record.label,
            "credential_label": token_record.credential_label,
            "issued_at": token_record.issued_at.isoformat(),
            "expires_at": token_record.expires_at.isoformat(),
            "expires_in": format_expiry(expires_at, now),
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Token: {plaintext}")
        print(f"ID: {token_record.id}")
        print(f"Scope: {token_record.scope}")
        if token_record.label:
            print(f"Label: {token_record.label}")
        if token_record.credential_label:
            print(f"Credential: {token_record.credential_label}")
        print(f"Expires: {expires_at.isoformat()} ({format_expiry(expires_at, now)})")
        print()
        if token_record.credential_label:
            print(
                f"Rotating credential '{token_record.credential_label}' will revoke "
                "this token."
            )
        print("Store this token securely - it will not be shown again.")

    return 0


def cmd_verify(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """Verify a token."""
    # Parse required scope
    try:
        required_scope = Scope.parse(args.scope)
    except ScopeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Find token
    record = store.find_by_token(args.token)
    if not record:
        if args.json:
            print(json.dumps({"valid": False, "reason": "unknown_token"}))
        else:
            print("Token not found", file=sys.stderr)
        return 1

    now = datetime.now(UTC)

    # Check revoked
    if record.revoked:
        if args.json:
            print(json.dumps({"valid": False, "reason": "revoked"}))
        else:
            print("Token has been revoked", file=sys.stderr)
        return 1

    # Check expiry (fail-closed)
    if record.is_expired(now):
        if args.json:
            print(json.dumps({"valid": False, "reason": "expired"}))
        else:
            print("Token has expired", file=sys.stderr)
        return 1

    # Check scope
    granted_scope = Scope.parse(record.scope)
    if not granted_scope.covers(required_scope):
        if args.json:
            print(json.dumps({
                "valid": False,
                "reason": "scope_mismatch",
                "granted_scope": record.scope,
                "required_scope": str(required_scope),
            }))
        else:
            print(
                f"Scope mismatch: token has '{record.scope}', "
                f"required '{required_scope}'",
                file=sys.stderr,
            )
        return 1

    # Success
    if args.json:
        output = {
            "valid": True,
            "id": record.id,
            "scope": record.scope,
            "label": record.label,
            "issued_at": record.issued_at.isoformat(),
            "expires_at": record.expires_at.isoformat(),
            "expires_in": format_expiry(record.expires_at, now),
        }
        print(json.dumps(output, indent=2))
    else:
        print("Token valid")
        print(f"ID: {record.id}")
        print(f"Scope: {record.scope}")
        if record.label:
            print(f"Label: {record.label}")
        print(f"Expires in: {format_expiry(record.expires_at, now)}")

    return 0


def cmd_list(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """List all tokens."""
    records = store.list_all()
    now = datetime.now(UTC)

    if args.json:
        output = {
            "tokens": [
                {
                    "id": r.id,
                    "scope": r.scope,
                    "label": r.label,
                    "parent_id": r.parent_id,
                    "credential_label": r.credential_label,
                    "issued_at": r.issued_at.isoformat(),
                    "expires_at": r.expires_at.isoformat(),
                    "expires_in": format_expiry(r.expires_at, now),
                    "revoked": r.revoked,
                    "expired": r.is_expired(now),
                }
                for r in sorted(records, key=lambda x: x.issued_at, reverse=True)
            ]
        }
        print(json.dumps(output, indent=2))
    else:
        if not records:
            print("No tokens found")
            return 0

        print(
            f"{'ID':<8} {'SCOPE':<35} {'LABEL':<15} "
            f"{'CREDENTIAL':<15} {'EXPIRES':<12} {'STATUS'}"
        )
        print("-" * 100)

        for r in sorted(records, key=lambda x: x.issued_at, reverse=True):
            status = "revoked" if r.revoked else ("expired" if r.is_expired(now) else "active")
            label = r.label or "-"
            credential = r.credential_label or "-"
            expires_in = format_expiry(r.expires_at, now)
            print(
                f"{r.id:<8} {r.scope:<35} {label:<15} {credential:<15} "
                f"{expires_in:<12} {status}"
            )

    return 0


def cmd_revoke(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """Revoke a token."""
    success = store.revoke(args.token_id)

    if args.json:
        output = {
            "revoked": success,
            "token_id": args.token_id,
        }
        print(json.dumps(output, indent=2))
    else:
        if success:
            print(f"Token {args.token_id} revoked")
        else:
            print(f"Token {args.token_id} not found or already revoked", file=sys.stderr)

    return 0 if success else 1


def cmd_prune(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """Prune expired/revoked tokens."""
    count = store.prune()

    if args.json:
        output = {
            "pruned": count,
        }
        print(json.dumps(output, indent=2))
    else:
        if count:
            print(f"Pruned {count} expired/revoked token(s)")
        else:
            print("No tokens to prune")

    return 0


def cmd_handoff(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """Mint a scoped token, run an agent with it, revoke on exit."""
    # Split the leading '--' argparse leaves in REMAINDER.
    agent_cmd = [a for a in (args.agent or []) if a != "--"]
    if not agent_cmd:
        print(
            "Error: no agent command given. Usage: "
            "brushpass handoff --scope <scope> --ttl 2h --label <label> -- <agent-cmd>",
            file=sys.stderr,
        )
        return 1

    try:
        scope = Scope.parse(args.scope)
    except ScopeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    ttl_str = args.ttl or config.default_ttl
    try:
        ttl_delta = parse_ttl(ttl_str)
    except TTLError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Validate --keep-env before minting anything: a bad request must not
    # leave a live token behind.
    try:
        keep = validate_keep_env(args.keep_env)
    except HandoffError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    try:
        session, parent = mint_handoff_token(
            store,
            scope=scope,
            ttl_delta=ttl_delta,
            label=args.label,
            parent_id=args.parent,
            fingerprint_of=_require_scanner(scanner).fingerprint,
        )
    except HandoffError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    try:
        child_env = build_child_env(
            os.environ, session.plaintext, session.token_id, keep
        )
    except HandoffError as e:
        # Could not build the environment; never leave the token live.
        store.revoke(session.token_id)
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Handoff: token {session.token_id} (scope {session.record.scope})")
    if parent is not None:
        print(f"Derived from parent token {parent.id} ({parent.scope})")
    print(f"Expires: {session.record.expires_at.isoformat()}")
    print(f"Running: {' '.join(agent_cmd)}")
    if session.ttl_capped_by_parent:
        print("TTL capped to the parent token's expiry.")
    print(f"{TOKEN_ENV_VAR} and {TOKEN_ID_ENV_VAR} are injected; parent env is scrubbed.")
    print()

    return run_handoff(
        store, session, agent_cmd, child_env, notify=_stderr_notify
    )


def _read_secret(args) -> str:
    """Read a root secret from stdin or ``--from-env``.

    Never from argv: the process table is world-readable, so a secret on
    the command line is a secret in every shell history and every ``ps``
    on the box. ``--from-env`` is safe because env vars are not in argv,
    though they are visible to anything that can read ``/proc``.

    Raises:
        CredentialError: if the source is missing or empty.
    """
    if args.from_env:
        value = os.environ.get(args.from_env)
        if value is None:
            raise CredentialError(
                f"Environment variable '{args.from_env}' is not set. Export it, "
                "or omit --from-env to paste the secret on stdin"
            )
        return value

    if sys.stdin.isatty():
        from getpass import getpass

        try:
            return getpass("Secret: ")
        except (EOFError, KeyboardInterrupt):
            raise CredentialError("No secret supplied") from None
    return sys.stdin.readline()


def _parse_config(pairs) -> dict:
    """Parse ``--set KEY=VALUE`` pairs into a config mapping.

    Raises:
        CredentialError: on a pair with no ``=`` or an empty key.
    """
    config: dict = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise CredentialError(
                f"Invalid --set '{pair}'. Expected KEY=VALUE, e.g. "
                "--set app_id=123456"
            )
        key, _, value = pair.partition("=")
        key = key.strip()
        if not key:
            raise CredentialError(f"Invalid --set '{pair}': the key is empty")
        config[key] = value
    return config


def _parse_typed_config(pairs) -> dict:
    """Like :func:`_parse_config` but coerces JSON-ish scalars.

    ``--set app_id=123456`` should reach the provider as the integer
    ``123456``, not the string, because providers type-check their config.
    A value that is not valid JSON is kept as a string, so a secret or a
    URL survives untouched.
    """
    raw = _parse_config(pairs)
    config: dict = {}
    for key, value in raw.items():
        try:
            config[key] = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            config[key] = value
    return config


def cmd_credential(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """credential add | list | remove | status."""
    if not getattr(args, "subcommand", None):
        print(
            "Error: choose a subcommand: "
            "brushpass credential {add,list,remove,status}",
            file=sys.stderr,
        )
        return 1

    try:
        credentials = CredentialStore(config.data_dir)
    except CredentialError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    handlers = {
        "add": _cred_add,
        "list": _cred_list,
        "remove": _cred_remove,
        "status": _cred_status,
    }
    return handlers[args.subcommand](args, config, credentials, store)


def _cred_add(args, config, credentials, store) -> int:
    """Store a new root credential, encrypted at rest."""
    try:
        provider = get_provider(args.provider)
        values = provider.validate_config(_parse_typed_config(args.config_pairs))
        secret = _read_secret(args)
        record = credentials.add(
            label=args.label,
            provider=provider.name,
            secret=secret,
            config=values,
        )
    except (ConfigError, ProviderError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except CredentialError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"added": True, **record.to_dict()}, indent=2, default=str))
    else:
        print(f"Stored credential '{record.label}' (provider: {record.provider})")
        print(f"Secret ID: {record.secret_id}")
        print(f"Added: {record.added_at.isoformat()}")
        print()
        print("Encrypted at rest; the plaintext is never written to disk.")
        print(f"Link tokens to it with: brushpass mint --credential {record.label} ...")
    return 0


def _cred_list(args, config, credentials, store) -> int:
    """List root credentials. Metadata only, never plaintext."""
    records = credentials.list_all()

    if args.json:
        print(
            json.dumps(
                {"credentials": [r.to_dict() for r in records]},
                indent=2,
                default=str,
            )
        )
        return 0

    if not records:
        print("No credentials found")
        print()
        print("Add one with:")
        print("  brushpass credential add --provider <name> --label <label>")
        return 0

    print(f"{'LABEL':<20} {'PROVIDER':<15} {'ADDED':<26} {'ROTATIONS':<10} {'SECRET ID'}")
    print("-" * 90)
    for record in records:
        print(
            f"{record.label:<20} {record.provider:<15} "
            f"{record.added_at.isoformat():<26} {record.rotation_count:<10} "
            f"{record.secret_id}"
        )
    print()
    print("Secrets are never displayed. Rotate with: brushpass rotate <label>")
    return 0


def _cred_remove(args, config, credentials, store) -> int:
    """Delete a root credential, with confirmation unless ``--yes``."""
    if not credentials.has(args.label):
        print(f"Error: no credential labelled '{args.label}'", file=sys.stderr)
        return 1

    record = credentials.get(args.label)
    linked = [
        r.id
        for r in store.list_all()
        if r.credential_label == args.label and not r.revoked
    ]

    if not args.yes:
        print(f"About to delete credential '{record.label}' (provider: {record.provider}).")
        print("The stored secret will be destroyed. This cannot be undone.")
        if linked:
            print(f"{len(linked)} live token(s) still reference it: {', '.join(linked)}")
            print("They will keep working until they expire or are revoked.")
        answer = input("Type the label to confirm: ")
        if answer.strip() != record.label:
            print("Not confirmed; nothing was deleted.", file=sys.stderr)
            return 1

    credentials.remove(args.label)
    print(f"Deleted credential '{args.label}'")
    if linked:
        print(f"Note: {len(linked)} live token(s) still reference it and were not revoked.")
        print("Revoke them with: brushpass revoke <token-id>")
    return 0


def _cred_status(args, config, credentials, store) -> int:
    """Show rotation history for one credential."""
    if not credentials.has(args.label):
        print(f"Error: no credential labelled '{args.label}'", file=sys.stderr)
        return 1
    _render_status(credentials, args.label, args.json)
    return 0


def _stderr_notify(message: str) -> None:
    print(message, file=sys.stderr)


def _render_status(credentials, label: str | None, as_json: bool) -> None:
    """Render rotation status for one label, or for everything."""
    from .journal import RotationJournal

    journal = RotationJournal(credentials.data_dir)
    status = journal.status(label)

    if as_json:
        print(json.dumps(status, indent=2, default=str))
        return

    print(f"ROTATION STATUS{' for ' + label if label else ''}")
    print("-" * 70)

    if status["last"] is None:
        print("No rotations recorded yet.")
    else:
        last = status["last"]
        print(f"Last rotation:   {last['started_at']}")
        duration = last.get("duration_seconds")
        print(f"Duration:        {duration}s" if duration is not None else "Duration:        -")
        print(f"State:           {last['state']}")
        print(f"Provider:        {last['provider']}")
        print(f"Old secret ID:   {last.get('old_secret_id')}")
        print(f"New secret ID:   {last.get('new_secret_id') or '-'}")
        print(f"Revoked tokens:  {len(last.get('revoked_tokens') or [])}")
        print(f"Finished:        {status['rotation_count']} successful rotation(s)")

    problems = list(status["incomplete"]) + list(status["orphans"])
    if problems:
        print()
        print("NEEDS ATTENTION")
        print("-" * 70)
        for entry in problems:
            reason = (
                "orphaned secret (may still be live upstream)"
                if entry.get("orphan_secret_id")
                else "started but never finished"
            )
            print(f"  rotation {entry['rotation_id']}: {reason}")
            if entry.get("error"):
                print(f"    {entry['error']}")
    print()
    print("Fix an orphaned rotation by revoking the orphaned secret at the")
    print("provider, then re-running 'brushpass rotate <label>'.")


def cmd_provider(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """provider list | show."""
    subcommand = getattr(args, "subcommand", None) or "list"
    # `provider` with no subcommand resolves to `list`, and that
    # synthesised subcommand never went through argparse, so --json has
    # no default to fall back on.
    as_json = getattr(args, "json", False)

    if subcommand == "list":
        providers = available_providers()
        if as_json:
            print(
                json.dumps(
                    {
                        "providers": [
                            {
                                "name": p.name,
                                "description": p.description,
                                "required_config": list(p.required_config),
                                "optional_config": list(p.optional_config),
                                "supports_revoke": bool(p.supports_revoke),
                            }
                            for p in providers
                        ]
                    },
                    indent=2,
                )
            )
            return 0

        print(f"{'NAME':<16} {'REVOKE':<10} REQUIRED CONFIG")
        print("-" * 80)
        for p in providers:
            revoke = "yes" if p.supports_revoke else "no"
            required = ", ".join(p.required_config) or "(none)"
            print(f"{p.name:<16} {revoke:<10} {required}")
        print()
        print("See one provider's detail: brushpass provider show <name>")
        return 0

    try:
        provider = get_provider(args.name)
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if as_json:
        print(
            json.dumps(
                {
                    "name": provider.name,
                    "description": provider.description,
                    "required_config": list(provider.required_config),
                    "optional_config": list(provider.optional_config),
                    "supports_revoke": bool(provider.supports_revoke),
                    "revoke_note": provider.revoke_note,
                },
                indent=2,
            )
        )
        return 0

    print(f"Provider: {provider.name}")
    print()
    print(provider.description)
    print()
    print(f"Required config: {provider.describe_config()}")
    if provider.optional_config:
        print(f"Optional config: {', '.join(provider.optional_config)}")
    print(f"Upstream revoke: {'yes' if provider.supports_revoke else 'no'}")
    if provider.revoke_note:
        print()
        print(provider.revoke_note)
    return 0


def cmd_rotate(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """rotate <label> [--dry-run] | rotate --status."""
    from .journal import RotationJournal
    from .notify import WebhookNotifier
    from .rotate import RotationEngine

    if args.status:
        if args.label:
            if not CredentialStore(config.data_dir).has(args.label):
                print(f"Error: no credential labelled '{args.label}'", file=sys.stderr)
                return 1
        _render_status(CredentialStore(config.data_dir), args.label, args.json)
        return 0

    if not args.label:
        print("Error: give a credential label, or use --status", file=sys.stderr)
        print("Usage: brushpass rotate <label> [--dry-run]", file=sys.stderr)
        return 1

    try:
        credentials = CredentialStore(config.data_dir)
    except CredentialError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    engine = RotationEngine(
        credentials=credentials,
        tokens=store,
        journal=RotationJournal(config.data_dir),
        provider_registry=get_provider,
        notifier=WebhookNotifier.from_config(config),
    )

    if args.dry_run:
        try:
            outcome = engine.plan(args.label)
        except (CredentialError, ConfigError, ProviderError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        _render_plan(outcome, args.json)
        return 0

    try:
        outcome = engine.rotate(args.label)
    except PersistFailedError as e:
        _render_failure(e, args.json)
        return 2
    except (RotationError, ConfigError, ProviderError, CredentialError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    _render_outcome(outcome, args.json)
    return 0


def _render_plan(outcome, as_json: bool) -> None:
    """Print a dry-run plan. Nothing was changed."""
    if as_json:
        print(json.dumps(outcome.to_dict(), indent=2, default=str))
        return
    print(f"ROTATION PLAN (dry run) for '{outcome.label}'")
    print(f"Provider: {outcome.provider}")
    print(f"Current secret ID: {outcome.old_secret_id}")
    print()
    print("Steps that WOULD run:")
    for step in outcome.steps:
        print(f"  {step}")
    if not outcome.provider_revoke_supported:
        print()
        print("  Note: this provider cannot revoke the old secret upstream.")
    print()
    print("No changes were made. Re-run without --dry-run to rotate.")


def _render_failure(error: PersistFailedError, as_json: bool) -> int:
    """Render the loud failure the atomicity contract demands."""
    print("=" * 70, file=sys.stderr)
    print("ROTATION ABORTED - A NEW SECRET COULD NOT BE STORED", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(str(error), file=sys.stderr)
    print("", file=sys.stderr)
    print(
        f"Orphaned secret ID: {error.orphan_secret_id}", file=sys.stderr
    )
    print(
        "This identifier is in the rotation journal. It is a digest, so the "
        "secret\nitself is not recoverable from it.", file=sys.stderr
    )
    if as_json:
        print(
            json.dumps(
                {
                    "state": "aborted",
                    "orphan_secret_id": error.orphan_secret_id,
                    "attempts": error.attempts,
                    "error": error.last_error,
                    "old_credential_live": True,
                },
                indent=2,
            )
        )
    return 2


def _render_outcome(outcome, as_json: bool) -> None:
    """Print the rotation summary. Always printed, JSON or not."""
    if as_json:
        print(json.dumps(outcome.to_dict(), indent=2, default=str))
    else:
        print()
        print("ROTATION COMPLETE" if outcome.succeeded else "ROTATION FINISHED WITH WARNINGS")
        print(f"  Credential:      {outcome.label}")
        print(f"  Provider:        {outcome.provider}")
        print(f"  Old secret ID:   {outcome.old_secret_id}")
        print(f"  New secret ID:   {outcome.new_secret_id}")
        print(f"  Duration:        {outcome.duration_seconds:.3f}s")
        if outcome.revoked_tokens:
            print(f"  Revoked tokens:  {', '.join(outcome.revoked_tokens)}")
        else:
            print("  Revoked tokens:  none")
        if outcome.provider_revoked is True:
            print("  Old secret:      revoked upstream")
        elif outcome.provider_revoked is False:
            print("  Old secret:      NOT revoked (see warnings below)")
        else:
            print("  Old secret:      not revocable via this provider")
        print(f"  Rotation ID:     {outcome.rotation_id}")

        if outcome.errors:
            print()
            print("WARNINGS:")
            for error in outcome.errors:
                print(f"  - {error}")

    if outcome.notify_error:
        print(f"\nNote: {outcome.notify_error}")


def cmd_env(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """Print token material in shell format."""
    if not args.token and not args.token_id:
        print(
            "Error: supply --token <plaintext> or --id <token-id>",
            file=sys.stderr,
        )
        return 1

    now = datetime.now(UTC)
    try:
        if args.token:
            record = find_live_by_token(store, args.token, now)
        else:
            # --id alone can confirm liveness but cannot re-emit the
            # plaintext: storage holds hashes only, by design.
            record = require_live_by_id(store, args.token_id, now)
            print(
                f"Error: token {record.id} is live, but brushpass stores only "
                "hashes, so it cannot reprint the token. Pass the plaintext "
                "with --token, or use 'brushpass handoff' to inject one.",
                file=sys.stderr,
            )
            return 1
        plaintext = args.token
    except EnvError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    try:
        output = render(record, plaintext, args.format)
    except EnvError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(SECRET_WARNING, file=sys.stderr)
    print(output, end="")
    return 0


def cmd_scan(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """Scan for leaked tokens across files, git history and shell history."""
    scanner = _require_scanner(scanner)

    # With --git or --history and no explicit paths, brushpass scans those
    # sources only. Falling back to the whole working tree as well would be
    # surprising and, on a large repo, slow.
    if args.paths:
        paths = [Path(p) for p in args.paths]
    elif args.git or args.history:
        paths = []
    else:
        paths = [Path.cwd()]
    try:
        report = scan_blobs(
            collect_blobs(
                paths,
                git=args.git,
                history=args.history,
                state_dir=config.data_dir,
            ),
            store,
            scanner,
        )
    except (ScanSourceError, ScanError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.fix:
        fix_findings(store, report)

    print(render_json(report) if args.json else render_text(report))
    return exit_code(report, fixed=args.fix)


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Initialize config and store
    config = Config()
    store = TokenStore(config.data_dir)

    # Minting and matching both need the scanner key, which fingerprints
    # the token so a later scan can recognise it. Fail closed if it is
    # missing or too widely readable: minting without a fingerprint would
    # produce tokens no scan could ever find.
    scanner: Scanner | None = None
    if args.command in SCANNER_COMMANDS:
        try:
            scanner = load_scanner(config.data_dir)
        except ScannerKeyError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    # Dispatch command
    commands = {
        "mint": cmd_mint,
        "verify": cmd_verify,
        "list": cmd_list,
        "revoke": cmd_revoke,
        "prune": cmd_prune,
        "handoff": cmd_handoff,
        "env": cmd_env,
        "scan": cmd_scan,
        "credential": cmd_credential,
        "provider": cmd_provider,
        "rotate": cmd_rotate,
    }

    handler = commands.get(args.command)
    if handler:
        try:
            return handler(args, config, store, scanner)
        except (CredentialKeyError, CredentialError) as e:
            # The credential store refuses to guess about a key it cannot
            # trust; that refusal must reach the operator, not a
            # traceback.
            print(f"Error: {e}", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
