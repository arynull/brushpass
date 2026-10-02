#!/usr/bin/env python3
"""Command-line interface for brushpass."""

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .audit import (
    DEFAULT_TAIL,
    EVENT_CREDENTIAL_ADD,
    EVENT_CREDENTIAL_REMOVE,
    EVENT_LEAK_FOUND,
    EVENT_ROTATE_FINISHED,
    EVENT_ROTATE_STARTED,
    EVENT_TOKEN_CONSUMED,
    EVENT_TOKEN_EXPIRE,
    EVENT_TOKEN_MINT,
    EVENT_TOKEN_REVOKE,
    EVENT_VERIFY_DENIED,
    EVENTS,
    AuditError,
    AuditLog,
    check_key_permissions,
    parse_since,
)
from .config import Config, resolve_data_dir
from .credentials import (
    CREDENTIALS_FILE_NAME,
    CredentialError,
    CredentialKeyError,
    CredentialStore,
    is_secret_config_key,
    is_secret_config_value,
)
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
from .models import LabelError, TokenRecord, validate_label
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
from .store import StorageError, TokenStore
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
        "--once",
        action="store_true",
        help=(
            "Issue a single-use token: the first successful verify spends "
            "it and every later verify is denied as 'consumed'"
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
        "--from-env",
        dest="from_env",
        default=None,
        metavar="VAR",
        help=(
            "Read the token from this environment variable instead of "
            "stdin. The token is never accepted on argv: argv is "
            "world-readable in ps and shell history."
        ),
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
        help=(
            "Provider config entry (repeatable). A value of the form "
            "env:VARNAME is resolved from the environment — use this for "
            "secret values, never a literal secret on the command line "
            "(argv is world-readable)"
        ),
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
        "--from-env",
        dest="from_env",
        default=None,
        metavar="VAR",
        help=(
            "Read the token from this environment variable instead of "
            "stdin. The token is never accepted on argv: argv is "
            "world-readable in ps and shell history."
        ),
    )

    # audit command
    audit_parser = subparsers.add_parser(
        "audit", help="Inspect and verify the tamper-evident audit log"
    )
    audit_sub = audit_parser.add_subparsers(dest="subcommand", help="Subcommands")

    audit_verify = audit_sub.add_parser(
        "verify", help="Replay the hash chain from seq 0"
    )
    audit_verify.add_argument("--json", action="store_true", help="Output as JSON")

    audit_log = audit_sub.add_parser("log", help="Show recent audit records")
    audit_log.add_argument(
        "--event",
        dest="event",
        default=None,
        help=f"Only this event type. One of: {', '.join(EVENTS)}",
    )
    audit_log.add_argument(
        "--since",
        dest="since",
        default=None,
        metavar="DURATION",
        help="Only records newer than this (e.g. 30m, 24h, 7d)",
    )
    audit_log.add_argument(
        "--tail",
        dest="tail",
        type=int,
        default=DEFAULT_TAIL,
        metavar="N",
        help=f"Show at most N records, after filtering (default: {DEFAULT_TAIL})",
    )
    audit_log.add_argument("--json", action="store_true", help="Output as JSON")

    # nuke command
    nuke_parser = subparsers.add_parser(
        "nuke",
        help=(
            "Break-glass: revoke every live token and flag every credential for "
            "rotation. Requires --yes"
        ),
    )
    nuke_parser.add_argument(
        "--yes",
        action="store_true",
        help="Actually do it. Without this, prints the plan and exits non-zero",
    )
    nuke_parser.add_argument(
        "--rotate-all",
        action="store_true",
        help="Also attempt a real provider rotation for each credential",
    )
    nuke_parser.add_argument(
        "--json", action="store_true", help="Output the plan as JSON"
    )

    return parser


def _audit(config: Config) -> AuditLog:
    """The audit log for this data dir. Cheap; constructs no keys.

    Constructing an :class:`AuditLog` only binds a path — the signing key
    is generated on the first *write*, and a read-only command that never
    records never grows one.
    """
    return AuditLog(config.data_dir)


def _record(audit: AuditLog, event: str, details: dict | None = None) -> None:
    """Write one audit record. Best effort, never fatal.

    A broken, damaged or unwritable audit log must not abort a mint, a
    verify or a revoke: the log is where you look *afterwards*, not a gate
    that decides whether the operation happens. If it cannot be written,
    say so loudly on stderr and carry on — the tampering surfaces in
    ``brushpass audit verify``, which is the check.

    Callers pass ids, labels, fingerprints and scopes. Never a token: the
    plaintext a mint just printed is exactly the string that must not end
    up on disk a second time.
    """
    try:
        audit.record(event, details or {})
    except AuditError as e:
        print(f"WARNING: audit write failed: {e}", file=sys.stderr)


def cmd_audit(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """audit verify | log."""
    subcommand = getattr(args, "subcommand", None)
    if subcommand == "verify":
        return _audit_verify(args, config)
    if subcommand == "log":
        return _audit_log(args, config)

    print(
        "Error: choose a subcommand: brushpass audit {verify,log}",
        file=sys.stderr,
    )
    return 1


def _audit_verify(args, config) -> int:
    """Replay the chain. Exit 0 only if every record verifies."""
    try:
        result = _audit(config).verify()
    except AuditError as e:
        print(f"Error: cannot read the audit log: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    elif result.ok:
        print(f"OK ({result.records} records)")
    elif result.error:
        # The chain was not checked — a key this command cannot trust is
        # an operational problem, not tamper. No "TAMPERED", no backup
        # advice: restoring a backup cannot fix a file mode.
        print(f"Error: cannot verify the audit log: {result.reason}",
              file=sys.stderr)
    else:
        print(f"TAMPERED: record {result.broken_seq}: {result.reason}", file=sys.stderr)
        print(
            "Every record from this point on is unreliable. Restore the log "
            "from a backup, or treat everything after it as unaccounted for",
            file=sys.stderr,
        )
    return 0 if result.ok else 1


def _audit_log(args, config) -> int:
    """Print a tail of the log, filters applied before the limit."""
    try:
        check_key_permissions(config.data_dir)
    except AuditError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    if args.event is not None and args.event not in EVENTS:
        print(
            f"Error: unknown event '{args.event}'. Expected one of: "
            f"{', '.join(EVENTS)}",
            file=sys.stderr,
        )
        return 1

    try:
        since = parse_since(args.since) if args.since else None
    except AuditError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.tail < 0:
        print("Error: --tail cannot be negative", file=sys.stderr)
        return 1

    try:
        records = _audit(config).tail(
            event=args.event, since=since, limit=args.tail
        )
    except AuditError as e:
        print(f"Error: cannot read the audit log: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps([r.to_dict() for r in records], indent=2))
        return 0

    if not records:
        print("No records match.")
        return 0

    for record in records:
        print(f"{record.seq:<6} {record.ts_utc:<32} {record.event:<28} {record.describe()}")

    # The head hash of the last record shown. Ship it somewhere the
    # operator who edits this file cannot reach — a collector, a backup —
    # and a truncated tail stops being invisible. See audit.py's docstring:
    # nothing local can detect a truncation that leaves the chain
    # internally consistent.
    print()
    print(f"head: {records[-1].record_hash}")
    print(f"({len(records)} record(s); anchor the head hash out of band)")
    return 0


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

    try:
        validate_label(args.label)
    except LabelError as e:
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
    audit = _audit(config)
    # One record for the whole prune, naming what it deleted rather than
    # only counting it — an id in the log is what you can go and check.
    if store.last_pruned:
        _record(
            audit,
            EVENT_TOKEN_EXPIRE,
            {"token_ids": list(store.last_pruned), "count": len(store.last_pruned)},
        )

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
        single_use=args.once,
    )

    # Store the record
    store.add(token_record)

    # The epoch is stamped by store.add, so record what was actually
    # stamped rather than what the store read a moment ago.
    _record(
        audit,
        EVENT_TOKEN_MINT,
        {
            "token_id": token_record.id,
            "scope": token_record.scope,
            "label": token_record.label,
            "credential_label": token_record.credential_label,
            "expires_at": token_record.expires_at.isoformat(),
            "epoch": token_record.effective_epoch,
        },
    )

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
            "single_use": token_record.single_use,
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
        if token_record.single_use:
            print(
                "Single-use token: the first successful verify spends it, and every "
                "later verify is denied as 'consumed'."
            )
        print("Store this token securely - it will not be shown again.")

    return 0


def cmd_verify(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """Verify a token.

    Verify *successes* are not audited, only denials. That is a deliberate
    sampling choice: the log is a forensic record of things that were
    refused, not traffic accounting. A successful verify is the common case
    and writes nothing an investigator needs; logging it would double the
    log's size and bury the denials. See the README's Audit section.

    Every denial is audited, including one for a token brushpass has never
    heard of — an unknown token is exactly what an attacker produces, and
    a fingerprint is enough to correlate the attempt without ever holding
    the plaintext.
    """
    audit = _audit(config)

    def deny(reason: str, message: str, record=None, **extra) -> int:
        """Record a refusal, print it, and return the deny exit code.

        ``message`` is what a human sees; ``reason`` is the machine-readable
        one in ``--json``. They are separate because "Token not found" and
        "this token was never minted by this machine" are the same event
        with two audiences.
        """
        details = {"reason": reason}
        if record is not None:
            details["token_id"] = record.id
        details.update(extra)
        _record(audit, EVENT_VERIFY_DENIED, details)

        if args.json:
            print(json.dumps({"valid": False, **details}))
        else:
            print(message, file=sys.stderr)
        return 1

    # The token enters via stdin or --from-env, never argv. Argv is
    # world-readable in ps and shell history; a token on the command
    # line is a token in every process table on the box. This is trust
    # boundary 2 in THREAT_MODEL.md.
    try:
        token = _read_token(args)
    except TokenInputError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Parse required scope
    try:
        required_scope = Scope.parse(args.scope)
    except ScopeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Find token
    record = store.find_by_token(token)
    if not record:
        # No record, so no id to log. A sha256 of the presented string is
        # stable across attempts and identifies the token without ever
        # storing it — the same digest the store itself holds.
        return deny(
            "unknown_token",
            "Token not found",
            fingerprint=hashlib.sha256(token.encode()).hexdigest(),
        )

    now = datetime.now(UTC)

    def refuse_if_dead(rec) -> int | None:
        """Run every denial check against a record.

        Returns the deny exit code, or None when the record is live.
        Used twice: once on the first read, and again on a fresh read
        when a single-use consume loses its race — the token may have
        died a *different* death in between (operator revoke, nuke,
        expiry), and the audit trail must name the true one instead
        of assuming it was consumed.
        """
        # Check revoked. A consumed token is flagged revoked too (that is
        # how it denies), so this branch has to name the more precise reason
        # first: "consumed" tells the caller the token did exactly one
        # useful thing and is now spent, where "revoked" would suggest
        # someone killed it while it was still good.
        if rec.revoked:
            if rec.consumed:
                return deny("consumed", "Token already consumed (single-use)", rec)
            return deny("revoked", "Token has been revoked", rec)

        # Check the revocation epoch, before expiry. A token minted before any
        # generation bump is denied here even though its own `revoked` flag is
        # still False. That is the propagation guarantee: a cache anywhere that
        # is holding "this token is fine" is wrong the moment the counter moves,
        # without anyone having to enumerate ids.
        if store.is_stale(rec):
            token_epoch, store_epoch = rec.effective_epoch, store.epoch
            return deny(
                "stale_epoch",
                f"Token was minted in epoch {token_epoch}, but the store is now at "
                f"epoch {store_epoch}. It was retired by a revocation that did not "
                "name it individually",
                rec,
                token_epoch=token_epoch,
                store_epoch=store_epoch,
            )

        # Check expiry (fail-closed)
        if rec.is_expired(now):
            return deny("expired", "Token has expired", rec)

        # Check scope
        granted_scope = Scope.parse(rec.scope)
        if not granted_scope.covers(required_scope):
            return deny(
                "scope_mismatch",
                f"Scope mismatch: token has '{rec.scope}', required "
                f"'{required_scope}'",
                rec,
                granted_scope=rec.scope,
                required_scope=str(required_scope),
            )
        return None

    denial = refuse_if_dead(record)
    if denial is not None:
        return denial

    # Spend the token, for a single-use one, before reporting success.
    #
    # Placement is the whole design: every denial above has returned
    # already, so a refused verify (wrong scope, expired, unknown) never
    # reaches this line and therefore never consumes. That is what stops
    # an attacker from spending somebody else's token by presenting it
    # with bad inputs — a denial is free.
    #
    # Consumption is the last thing before the success print, so what
    # gets printed is what the store now holds. If it fails, the verify
    # fails: the operator must never be told a token is good when the
    # store could not take it.
    consumed = False
    if record.single_use:
        try:
            consumed = store.consume(record.id, now)
        except StorageError as e:
            print(f"Error: could not consume single-use token: {e}", file=sys.stderr)
            return 1
        if not consumed:
            # Someone else got there first: the token died between the
            # checks above and the write. Re-read it and name the true
            # death — an operator revoke (or nuke, or expiry) racing this
            # verify must not be mislabelled "consumed", or the audit
            # trail answers the wrong forensic question.
            fresh = store.find_by_id(record.id)
            if fresh is None:
                # Practically impossible (prune only deletes long-dead
                # records), but fail closed on the vague side rather than
                # crash.
                return deny("consumed", "Token already consumed (single-use)", record)
            recheck = refuse_if_dead(fresh)
            if recheck is not None:
                return recheck
            # A live record here would mean consume() lied; it cannot
            # happen (revoked never un-revokes, the epoch never goes
            # down, expiry never un-expires), so report the spend.
            return deny("consumed", "Token already consumed (single-use)", fresh)
        # A consumption is audited even though verify successes are not
        # (see the module docstring): this is the moment a capability
        # stops existing. Ids, scope and label — never the plaintext.
        _record(
            audit,
            EVENT_TOKEN_CONSUMED,
            {
                "token_id": record.id,
                "scope": record.scope,
                "label": record.label,
            },
        )

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
            "single_use": record.single_use,
            "consumed": consumed,
        }
        print(json.dumps(output, indent=2))
    else:
        print("Token valid")
        print(f"ID: {record.id}")
        print(f"Scope: {record.scope}")
        if record.label:
            print(f"Label: {record.label}")
        print(f"Expires in: {format_expiry(record.expires_at, now)}")
        if consumed:
            print("Single-use token consumed - this verify was the last one it allows.")

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
                    "single_use": r.single_use,
                    "consumed": r.consumed,
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
            # "consumed" outranks "revoked": a spent single-use token is
            # also flagged revoked (that is how it denies), but the
            # operator's question differs. "once" rides along on a token
            # that is still spendable, so its status says what will
            # happen to it rather than only what it is now.
            if r.consumed:
                status = "consumed"
            elif r.revoked:
                status = "revoked"
            else:
                status = "expired" if r.is_expired(now) else "active"
                if r.single_use:
                    status = f"{status} once"
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

    if success:
        # store.revoke is precise: only this token's `revoked` flag is
        # set. Sibling tokens are untouched (single revoke does not bump
        # the revocation epoch — that is the nuke primitive's job).
        _record(_audit(config), EVENT_TOKEN_REVOKE, {"token_id": args.token_id})

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

    # One record naming what went, not just how many. Skipped on a no-op:
    # a `token.expire` with an empty list is noise, and an operator reading
    # the log should be able to assume a record means something happened.
    if store.last_pruned:
        _record(
            _audit(config),
            EVENT_TOKEN_EXPIRE,
            {"token_ids": list(store.last_pruned), "count": count},
        )

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


def cmd_nuke(
    args: argparse.Namespace,
    config: Config,
    store: TokenStore,
    scanner: Scanner | None,
) -> int:
    """nuke --yes [--rotate-all]: the break-glass."""
    from .journal import RotationJournal
    from .nuke import NukeError, plan
    from .nuke import nuke as run_nuke

    # Nothing is constructed here. Opening a CredentialStore *creates* an
    # empty credentials.json when none exists, and `nuke` without --yes
    # promises to change nothing — a promise it would break by merely
    # looking. `plan` reads the labels off the file itself when given a
    # path, so the refusal path can name credentials without writing.
    planned = plan(store, config.data_dir / CREDENTIALS_FILE_NAME)

    if not args.yes:
        # The refusal path prints the plan and stops. Deliberately before
        # any header: one plan, once, and no chance of it being misread as
        # "this already ran".
        if args.json:
            print(json.dumps(planned, indent=2))
        else:
            _render_nuke_plan(planned, planned_only=True)
            print()

        print(
            "Nothing was changed. Re-run with --yes to actually do this.\n"
            "There is no interactive prompt: a nuke from a cron job has "
            "nobody to answer one.",
            file=sys.stderr,
        )
        return 1

    # Past this point the nuke is running for real, so opening (and if need
    # be creating) the credential store is correct.
    credentials = None
    credential_error: str | None = None
    try:
        credentials = CredentialStore(config.data_dir)
    except CredentialError as e:
        # A credential store brushpass cannot open is not a reason to skip
        # the revocation: the tokens in `store` are exactly what a nuke
        # exists to kill, and killing them needs no credential key. Report
        # it and continue with the token half rather than leaving live
        # tokens behind because the credential file is unhappy.
        credential_error = str(e)

    if credential_error:
        print(
            f"WARNING: cannot read the credential store ({credential_error}). "
            "Proceeding with token revocation only; no credential will be "
            "flagged for rotation",
            file=sys.stderr,
        )

    # A real nuke prints what is about to die *before* it does, so the
    # record in the operator's scrollback matches the action. With --json
    # stdout carries the result and the header goes to stderr, leaving the
    # JSON parseable.
    if args.json:
        print(json.dumps(planned, indent=2), file=sys.stderr)
    _render_nuke_plan(planned, planned_only=False, to_stderr=args.json)

    # Annotated rather than left to inference: the plain nuke path passes
    # None here, and only the --rotate-all branch builds the callable.
    rotate: Callable[[str], None] | None = None
    if args.rotate_all:
        if credentials is None:
            # Nothing to rotate, and no store to rotate it from. Not an
            # error: the tokens are still dead, which is the part that was
            # urgent.
            print(
                "WARNING: --rotate-all requested but there is no readable "
                "credential store; no credential was rotated",
                file=sys.stderr,
            )
        else:
            # Imported here, not at module scope: the plain nuke path must
            # not pull in the rotation engine and its providers in order to
            # revoke nothing but tokens.
            from .notify import WebhookNotifier
            from .rotate import RotationEngine

            engine = RotationEngine(
                credentials=credentials,
                tokens=store,
                journal=RotationJournal(config.data_dir),
                provider_registry=get_provider,
                notifier=WebhookNotifier.from_config(config),
            )

            def rotate(label: str) -> None:
                engine.rotate(label)

    try:
        result = run_nuke(
            tokens=store,
            credentials=credentials,
            journal=RotationJournal(config.data_dir),
            audit=_audit(config),
            rotate_all=args.rotate_all,
            stdin=sys.stdin,
            rotate_label=rotate,
        )
    except NukeError as e:
        # Only the token revocation itself is fatal. A journal or audit
        # failure degrades to a warning inside nuke(), because tokens
        # that are already dead stay dead.
        print(f"Error: {e}", file=sys.stderr)
        return 1

    _render_nuke_result(result, as_json=args.json)
    return 0 if result.ran else 1


def _render_nuke_plan(planned: dict, planned_only: bool, to_stderr: bool = False) -> None:
    """Print what a nuke will kill. Printed before anything happens.

    Goes to stdout unless the caller is producing JSON, in which case it
    moves to stderr so the machine-readable output stays parseable. A
    header split across two streams interleaves unpredictably on a
    terminal, so the whole plan goes to one stream or the other — never
    both.
    """
    stream = sys.stderr if to_stderr else sys.stdout

    def say(line: str = "") -> None:
        print(line, file=stream)

    say("=" * 70)
    say("NUKE PLAN (nothing changed)" if planned_only else "NUKE")
    say("=" * 70)

    tokens = planned.get("live_tokens") or []
    if tokens:
        say(f"Live tokens to revoke ({len(tokens)}): {', '.join(tokens)}")
    else:
        say("Live tokens to revoke: none")

    epoch = planned.get("epoch", 0)
    # The epoch advances only if this nuke actually revokes something —
    # say so rather than promising a bump that may not happen.
    if tokens:
        say(f"Revocation epoch: {epoch} -> {epoch + 1}")
    else:
        say(f"Revocation epoch: {epoch} (unchanged: no live tokens to retire)")

    labels = planned.get("credentials") or []
    if labels:
        say(f"Credentials to flag for rotation ({len(labels)}): {', '.join(labels)}")
    else:
        say("Credentials to flag for rotation: none")

    if not planned_only:
        say()
        say("This is not reversible and it is not specific to one credential.")
        say(
            "brushpass kills its own tokens; the upstream secrets die only "
            "when the\nprovider is told. Every credential above needs a "
            "rotation, not just a token revoke."
        )
    say("=" * 70)


def _render_nuke_result(result, as_json: bool) -> None:
    """Render what the break-glass did."""
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return

    print()
    print("NUKE COMPLETE")
    print(f"  Tokens revoked:   {result.token_count}")
    if result.tokens_revoked:
        print(f"  Token ids:        {', '.join(result.tokens_revoked)}")
    print(f"  Epoch:            {result.epoch_before} -> {result.epoch_after}")
    if result.credentials_flagged:
        print(
            f"  Flagged to rotate: {result.credential_count} "
            f"({', '.join(result.credentials_flagged)})"
        )
    else:
        print("  Flagged to rotate: none")

    if result.rotated:
        print(f"  Rotated now:      {', '.join(result.rotated)}")
    if result.manual_skipped:
        print(
            f"  Manual skipped:  {', '.join(result.manual_skipped)} "
            "(stdin was not a terminal; rotate by hand)"
        )
    if result.rotation_failures:
        print("  Rotation failures:")
        for label, reason in result.rotation_failures.items():
            print(f"    {label}: {reason}")

    print()
    print("Every token minted before this call is now behind the current epoch")
    print("and will be denied, whatever its own revoked flag says.")
    if result.credentials_flagged:
        print("Upstream credentials are NOT revoked by this command:")
        for label in result.credentials_flagged:
            print(f"  brushpass rotate {label}")

    if result.errors:
        print()
        print("ERRORS:")
        for error in result.errors:
            print(f"  - {error}")


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

    # The handoff label is rendered in `list` like any other label, so it
    # gets the same validation as `mint --label` (S3 row-spoofing applies
    # here too).
    try:
        validate_label(args.label)
    except LabelError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    audit = _audit(config)
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

    # The handoff token's lifecycle is audited like any minted token's:
    # a handoff that left no trace would be a gap in the forensic record.
    _record(
        audit,
        EVENT_TOKEN_MINT,
        {
            "token_id": session.token_id,
            "scope": session.record.scope,
            "label": session.record.label,
            "via": "handoff",
            "expires_at": session.record.expires_at.isoformat(),
            "epoch": session.record.effective_epoch,
        },
    )

    try:
        child_env = build_child_env(
            os.environ, session.plaintext, session.token_id, keep
        )
    except HandoffError as e:
        # Could not build the environment; never leave the token live.
        if store.revoke(session.token_id):
            _record(
                audit,
                EVENT_TOKEN_REVOKE,
                {"token_id": session.token_id, "via": "handoff"},
            )
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

    returncode = run_handoff(
        store,
        session,
        agent_cmd,
        child_env,
        notify=_stderr_notify,
        # Fires inside run_handoff when the revocation is performed — on
        # the normal path and the signal paths alike. A record written
        # after run_handoff returns would be skipped on the signal paths,
        # which never return.
        on_revoke=lambda: _record(
            audit, EVENT_TOKEN_REVOKE, {"token_id": session.token_id, "via": "handoff"}
        ),
    )
    return returncode


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

    # Piped stdin. readline (not read) so a trailing newline from
    # `printf '%s\n' "$SECRET" | brushpass credential add` is stripped,
    # not part of the secret — exactly like _read_token.
    return sys.stdin.readline().strip()


class TokenInputError(Exception):
    """The token was not supplied via stdin or --from-env."""


def _read_token(args) -> str:
    """Read a token from stdin or ``--from-env``.

    Never from argv: the process table is world-readable (``/proc/<pid>/
    cmdline`` is mode 0444), so a token on the command line is visible to
    every other user on the box and persists in shell history. This is
    trust boundary 2 in THREAT_MODEL.md.

    Raises:
        TokenInputError: if no token was supplied.
    """
    if getattr(args, "from_env", None):
        value = os.environ.get(args.from_env)
        if value is None:
            raise TokenInputError(
                f"Environment variable '{args.from_env}' is not set. Export it, "
                "or omit --from-env to pipe the token on stdin"
            )
        token = value.strip()
        if not token:
            raise TokenInputError(
                f"Environment variable '{args.from_env}' is empty"
            )
        return token

    if sys.stdin.isatty():
        from getpass import getpass

        try:
            token = getpass("Token: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise TokenInputError("No token supplied") from None
        if not token:
            raise TokenInputError("No token supplied")
        return token

    # Piped stdin. readline (not read) so a trailing newline from
    # `echo "$TOKEN" | brushpass verify` is stripped, not part of the token.
    token = sys.stdin.readline().strip()
    if not token:
        raise TokenInputError(
            "No token on stdin. Pipe the token, e.g. "
            "`echo \"$TOKEN\" | brushpass verify --scope ...`, or use --from-env VAR"
        )
    return token


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

    A value of the form ``env:VARNAME`` is resolved from the environment
    *before* coercion and is always kept as a string: this is the non-argv
    path for secret config values (trust boundary 2 — argv is
    world-readable). A missing or empty variable is a hard error; the
    literal ``env:...`` text is never stored.
    """
    raw = _parse_config(pairs)
    config: dict = {}
    warned = False
    for key, value in raw.items():
        if isinstance(value, str) and value.startswith("env:"):
            var_name = value[4:]
            env_value = os.environ.get(var_name)
            if not env_value:
                raise CredentialError(
                    f"--set {key}=env:{var_name}: environment variable "
                    f"'{var_name}' is not set or is empty. Export it first, "
                    "e.g. `export VARNAME=...`; the literal 'env:...' is "
                    "never stored"
                )
            config[key] = env_value
            continue
        if not warned and (
            is_secret_config_key(key) or is_secret_config_value(value)
        ):
            # Same class as the argv token ban (trust boundary 2): a live
            # secret on the command line is world-readable in ps and
            # shell history. This checks the *literal* argv value, so a
            # properly-sourced env:VARNAME never triggers it. Warn once.
            print(
                "WARNING: --set "
                f"'{key}' looks like a secret but was given literally on "
                "the command line; it is visible in ps and shell history. "
                f"Use --set '{key}=env:VARNAME' instead",
                file=sys.stderr,
            )
            warned = True
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
        validate_label(args.label, what="credential label")
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
    except LabelError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Label and provider only. The secret is in `record.secret_id` as a
    # digest and does not belong in the audit log even hashed — if you
    # hold the plaintext you can rotate; an audit trail is the wrong place
    # to keep it.
    _record(
        _audit(config),
        EVENT_CREDENTIAL_ADD,
        {"label": record.label, "provider": record.provider},
    )

    if args.json:
        print(
            json.dumps(
                {"added": True, **credentials.render_record(record.label)},
                indent=2,
                default=str,
            )
        )
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
                {
                    "credentials": [
                        credentials.render_record(r.label) for r in records
                    ]
                },
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
    _record(
        _audit(config),
        EVENT_CREDENTIAL_REMOVE,
        {"label": args.label, "provider": record.provider},
    )
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
    from .journal import RotationJournal, new_rotation_id
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

    # A real rotation only. --dry-run and --status are reads; a log that
    # records rotations that never touched a provider is a log that lies
    # about what happened to the secrets.
    audit = _audit(config)
    rotation_id = new_rotation_id()
    _record(
        audit,
        EVENT_ROTATE_STARTED,
        {"label": args.label, "rotation_id": rotation_id},
    )

    try:
        outcome = engine.rotate(args.label)
    except PersistFailedError as e:
        _render_failure(e, args.json)
        return 2
    except (RotationError, ConfigError, ProviderError, CredentialError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # The engine mints its own rotation_id for its journal entry; this
    # record carries the one generated here plus the engine's, so a
    # half-finished rotation can be joined up from either side.
    _record(
        audit,
        EVENT_ROTATE_FINISHED,
        {
            "label": outcome.label,
            "rotation_id": rotation_id,
            "engine_rotation_id": outcome.rotation_id,
            "state": outcome.state,
            "new_secret_id": outcome.new_secret_id,
            "old_secret_id": outcome.old_secret_id,
            "revoked_tokens": len(outcome.revoked_tokens),
            "provider_revoked": outcome.provider_revoked,
            "duration_seconds": round(outcome.duration_seconds, 3),
        },
    )

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
    """Print token material in shell format.

    The token enters via stdin or --from-env, never argv (trust boundary
    2). --id resolves a record by ID but cannot re-emit the plaintext:
    storage holds hashes only, by design.
    """
    now = datetime.now(UTC)
    try:
        if args.token_id:
            # --id alone can confirm liveness but cannot re-emit the
            # plaintext: storage holds hashes only, by design.
            record = require_live_by_id(store, args.token_id, now)
            print(
                f"Error: token {record.id} is live, but brushpass stores only "
                "hashes, so it cannot reprint the token. Pipe the plaintext "
                "on stdin, or use 'brushpass handoff' to inject one.",
                file=sys.stderr,
            )
            return 1
        # No --id: the token comes from stdin or --from-env.
        try:
            plaintext = _read_token(args)
        except TokenInputError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        record = find_live_by_token(store, plaintext, now)
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

    # One record per finding, at the point the CLI has both the finding and
    # the decision about it. The `path` is the leak's location, not a
    # secret; `action` says whether --fix revoked it or it was merely
    # found. Note a token found in many places produces many records
    # naming the same id — the number of occurrences is itself the signal.
    audit = _audit(config)
    for finding in report.findings:
        details = {
            "path": finding.location,
            "token_id": finding.record.id,
            "fingerprint": finding.fingerprint_prefix,
            "source": finding.source,
            "live": finding.live,
            "action": "revoked" if finding.record.id in report.revoked else "found",
        }
        _record(audit, EVENT_LEAK_FOUND, details)

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
    data_dir = resolve_data_dir()
    if data_dir.exists() and not data_dir.is_dir():
        print(
            f"Error: state path {data_dir} exists and is not a "
            "directory. Point BRUSHPASS_DATA_DIR at a directory.",
            file=sys.stderr,
        )
        return 1
    config = Config()
    try:
        store = TokenStore(config.data_dir)
    except StorageError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

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
        "audit": cmd_audit,
        "nuke": cmd_nuke,
    }

    handler = commands.get(args.command)
    if handler:
        try:
            return handler(args, config, store, scanner)
        except (CredentialKeyError, CredentialError, StorageError) as e:
            # Operational failures — an untrusted key, a corrupt store —
            # must reach the operator as an error line, not a traceback.
            print(f"Error: {e}", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
