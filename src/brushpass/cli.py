#!/usr/bin/env python3
"""Command-line interface for brushpass."""

import argparse
import json
import os
import sys
from datetime import UTC, datetime

from . import __version__
from .config import Config
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
from .scope import Scope, ScopeError
from .store import TokenStore
from .ttl import TTLError, format_expiry, parse_ttl


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="brushpass",
        description="Local credential broker for AI agents - ephemeral token minting",
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


def cmd_mint(args: argparse.Namespace, config: Config, store: TokenStore) -> int:
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

    # Opportunistic prune on mint
    store.prune()

    # Generate token
    plaintext = TokenRecord.generate_token()
    now = datetime.now(UTC)
    expires_at = now + ttl_delta

    record, _ = TokenRecord.create(
        plaintext_token=plaintext,
        scope=str(scope),
        label=args.label,
        issued_at=now,
        expires_at=expires_at,
    )

    # Store the record
    store.add(record)

    # Output
    if args.json:
        output = {
            "id": record.id,
            "token": plaintext,
            "scope": record.scope,
            "label": record.label,
            "issued_at": record.issued_at.isoformat(),
            "expires_at": record.expires_at.isoformat(),
            "expires_in": format_expiry(expires_at, now),
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Token: {plaintext}")
        print(f"ID: {record.id}")
        print(f"Scope: {record.scope}")
        if record.label:
            print(f"Label: {record.label}")
        print(f"Expires: {expires_at.isoformat()} ({format_expiry(expires_at, now)})")
        print()
        print("Store this token securely - it will not be shown again.")

    return 0


def cmd_verify(args: argparse.Namespace, config: Config, store: TokenStore) -> int:
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


def cmd_list(args: argparse.Namespace, config: Config, store: TokenStore) -> int:
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

        print(f"{'ID':<8} {'SCOPE':<35} {'LABEL':<15} {'EXPIRES':<12} {'STATUS'}")
        print("-" * 80)

        for r in sorted(records, key=lambda x: x.issued_at, reverse=True):
            status = "revoked" if r.revoked else ("expired" if r.is_expired(now) else "active")
            label = r.label or "-"
            expires_in = format_expiry(r.expires_at, now)
            print(f"{r.id:<8} {r.scope:<35} {label:<15} {expires_in:<12} {status}")

    return 0


def cmd_revoke(args: argparse.Namespace, config: Config, store: TokenStore) -> int:
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


def cmd_prune(args: argparse.Namespace, config: Config, store: TokenStore) -> int:
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


def cmd_handoff(args: argparse.Namespace, config: Config, store: TokenStore) -> int:
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


def _stderr_notify(message: str) -> None:
    print(message, file=sys.stderr)


def cmd_env(args: argparse.Namespace, config: Config, store: TokenStore) -> int:
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

    # Dispatch command
    commands = {
        "mint": cmd_mint,
        "verify": cmd_verify,
        "list": cmd_list,
        "revoke": cmd_revoke,
        "prune": cmd_prune,
        "handoff": cmd_handoff,
        "env": cmd_env,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args, config, store)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
