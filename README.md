# brushpass

A local credential broker for AI agents. Mint short-lived, narrowly-scoped tokens so agents never touch your real, long-lived keys.

## Overview

brushpass generates ephemeral tokens with specific scopes and TTLs. Tokens are stored as SHA-256 hashes — the plaintext is shown once at mint time and never again. This limits exposure if a token leaks or an agent misbehaves.

## Installation

```bash
pip install brushpass
```

Or from source:

```bash
git clone https://github.com/rayanalpha/brushpass.git
cd brushpass
pip install -e .
```

## Quick Start

```bash
# Mint a token for GitHub read access
brushpass mint --scope github:rayanalpha/*:read --label "CI agent"

# Verify a token (used by your application)
brushpass verify bp_xK9... --scope github:rayanalpha/repo:read

# List all tokens
brushpass list

# Revoke a token
brushpass revoke abc12345

# Hand a scoped token to an agent, revoked the moment it exits
brushpass handoff --scope github:rayanalpha/brushpass:read --ttl 1h \
  --label "docs agent" -- sh -c 'curl -H "Authorization: Bearer $BRUSHPASS_TOKEN" ...'

# Clean up old expired/revoked tokens
brushpass prune
```

## Commands

### mint

Create a new ephemeral token.

```bash
brushpass mint --scope <provider:resource:permission> [--ttl <duration>] [--label <name>]
```

**Arguments:**
- `--scope` (required): The scope triple defining what this token can access
- `--ttl`: Time-to-live. Default: 2h, Maximum: 24h
- `--label`: Optional human-readable label

**Examples:**

```bash
# GitHub read access to all repos under rayanalpha
brushpass mint --scope github:rayanalpha/*:read

# AWS S3 full access to a specific bucket, expires in 4 hours
brushpass mint --scope aws:s3/backup-bucket:* --ttl 4h --label "backup job"

# Stripe customer read access, expires in 30 minutes
brushpass mint --scope stripe:customers:read --ttl 30m
```

**Output:**

```
Token: bp_xK9mN2pQ8sT3vW5yZ7aB9cD1eF3gH5jK7lM9nO1p
ID: abc12345
Scope: github:rayanalpha/*:read
Label: CI agent
Expires: 2026-10-01T16:09:00Z (2h)

Store this token securely - it will not be shown again.
```

The token ID (first 8 chars of the SHA-256 hash) is used for `list` and `revoke` operations. The plaintext token is used for `verify`.

### verify

Check if a token is valid and has the required scope.

```bash
brushpass verify <token> --scope <required-scope>
```

**Exit codes:**
- `0`: Token is valid
- `1`: Token invalid (unknown, expired, revoked, or scope mismatch)

**Examples:**

```bash
# Check if token has read access to a specific repo
brushpass verify bp_xK9... --scope github:rayanalpha/specific-repo:read

# Check for write access (will fail if token only has read)
brushpass verify bp_xK9... --scope github:rayanalpha/repo:write
```

**JSON output:**

```bash
brushpass verify bp_xK9... --scope github:rayanalpha/repo:read --json
```

```json
{
  "valid": true,
  "id": "abc12345",
  "scope": "github:rayanalpha/*:read",
  "label": "CI agent",
  "issued_at": "2026-10-01T14:09:00Z",
  "expires_at": "2026-10-01T16:09:00Z",
  "expires_in": "1h45m"
}
```

### list

Show all tokens (never shows plaintext tokens).

```bash
brushpass list [--json]
```

**Output:**

```
ID       SCOPE                                LABEL           EXPIRES      STATUS
--------------------------------------------------------------------------------
abc12345 github:rayanalpha/*:read             CI agent        1h45m        active
def67890 stripe:customers:read                -               expired      expired
ghi11111 aws:s3:bucket:*                      backup          12h          revoked
```

### revoke

Immediately invalidate a token.

```bash
brushpass revoke <token-id>
```

**Example:**

```bash
brushpass revoke abc12345
```

After revocation, `verify` will deny the token even if it hasn't expired.

### prune

Delete expired and revoked tokens older than 7 days.

```bash
brushpass prune
```

This also runs automatically when you mint a new token (opportunistic cleanup).

### handoff

Mint a scoped token, run an agent with it, and revoke it the moment that
agent goes away.

```bash
brushpass handoff --scope <scope> [--ttl <duration>] [--label <name>]
                  [--parent <token-id>] [--keep-env VAR ...] -- <agent-cmd> [args...]
```

**Arguments:**
- `--scope` (required): The scope triple for the token handed to the agent
- `--ttl`: Time-to-live. Default: 2h, Maximum: 24h
- `--label`: Optional human-readable label
- `--parent`: Derive from an existing token; the new scope may only narrow it
- `--keep-env VAR`: Pass one parent environment variable through (repeatable)
- Everything after `--` is the agent command, run as a subprocess

The token is injected as `BRUSHPASS_TOKEN` (the credential) and
`BRUSHPASS_TOKEN_ID` (its short ID, for `list` / `revoke`). Nothing else
from your environment crosses over.

#### A full session

```console
$ brushpass mint --scope 'github:rayanalpha/*:read' --ttl 4h --label supervisor
Token: bp_7Kq2mNpX4vR8tL1wY6bE3gH5jK9zQ7sF2dA4cU0oI6nMx
ID: 7b59e883
Scope: github:rayanalpha/*:read
Label: supervisor
Expires: 2026-10-01T18:34:37+00:00 (4h)

Store this token securely - it will not be shown again.

$ SECRET_PARENT=do-not-leak MODEL=model-x AWS_SECRET_ACCESS_KEY=AKIA-realsecret \
  brushpass handoff --scope 'github:rayanalpha/brushpass:read' --ttl 1h \
    --label 'docs agent' --parent 7b59e883 --keep-env MODEL -- \
    sh -c 'echo "  token present: ${BRUSHPASS_TOKEN:+yes}"
           echo "  token id:     $BRUSHPASS_TOKEN_ID"
           echo "  MODEL:        $MODEL"
           echo "  SECRET_PARENT seen as [${SECRET_PARENT}]"
           echo "  AWS key seen as [${AWS_SECRET_ACCESS_KEY}]"'

Handoff: token 71ffcfe9 (scope github:rayanalpha/brushpass:read)
Derived from parent token 7b59e883 (github:rayanalpha/*:read)
Expires: 2026-10-01T15:34:37+00:00
Running: sh -c echo "  token present: ..."
BRUSHPASS_TOKEN and BRUSHPASS_TOKEN_ID are injected; parent env is scrubbed.

  token present: yes
  token id:     71ffcfe9
  MODEL:        model-x
  SECRET_PARENT seen as []
  AWS key seen as []
brushpass: token 71ffcfe9 revoked (agent exited)

$ echo $?
0

$ brushpass list
ID       SCOPE                            LABEL       EXPIRES      STATUS
--------------------------------------------------------------------------------
71ffcfe9 github:rayanalpha/brushpass:read docs agent   59m          revoked
7b59e883 github:rayanalpha/*:read         supervisor  3h59m        active
```

The agent saw its token and the one variable you named with `--keep-env`.
The other two secrets in the parent environment were simply not there —
they are empty strings in the agent, not inherited values.

#### Revoke on exit

The token is revoked when the agent exits, on **every** path:

| Exit path | Revoked |
|-----------|---------|
| Normal exit (any status) | yes |
| Agent crashes / uncaught exception | yes |
| Agent killed by a signal | yes |
| SIGTERM / SIGINT to brushpass | yes |
| Python exception inside brushpass | yes |
| **SIGKILL to brushpass itself** | **no — see below** |

The agent's exit status is propagated unchanged, so `handoff` composes in
scripts. An agent killed by a signal reports `128 + signal` (137 for
SIGKILL), which is what a shell reports for the same death.

When brushpass itself is signalled it revokes, forwards the signal to the
agent, and then dies by that same signal, so your shell sees the signal
rather than a fabricated status.

#### The SIGKILL limitation

**SIGKILL sent to brushpass cannot be caught.** No handler runs, no
`finally` block executes, and the token is left live until it expires.
This is a property of POSIX signals, not something brushpass can fix —
no program can trap SIGKILL.

The mitigation is a short TTL. If the worst happens, the token is dead
`--ttl` seconds later:

```bash
# Worst case exposure after a SIGKILL: the TTL, nothing more
brushpass handoff --scope github:repo:read --ttl 60 -- your-agent
```

A derived token (`--parent`) is additionally capped to its parent's
expiry, so the blast radius stays bounded by the credential it came from.

#### Environment scrubbing

The child process starts from an **allowlist**, not from your
environment. It inherits only these names, and only if they are set:

```
PATH  HOME  USER  LOGNAME  LANG  LC_ALL  TERM  TZ  TMPDIR
```

...plus:

- `BRUSHPASS_TOKEN` — the credential
- `BRUSHPASS_TOKEN_ID` — the token's short ID
- any variable you named with `--keep-env`

Everything else is dropped. `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`,
`OPENAI_API_KEY`, `LD_PRELOAD`, and every other parent variable are
simply absent from the child — an agent cannot read a credential it was
never handed.

`--keep-env` is the deliberate, explicit way to widen this. It refuses to
run if the name collides with a token variable (`BRUSHPASS_TOKEN` or
`BRUSHPASS_TOKEN_ID`), so you cannot accidentally overwrite the
credential you are handing over, and it fails before anything is minted
if the variable is not set in the parent.

#### Delegation and least privilege

`--parent` makes credential derivation explicit. The new token's scope
must be **covered by** its parent's scope — derived tokens may narrow,
never widen:

```console
$ brushpass handoff --scope 'github:rayanalpha/brushpass:read' \
    --parent 7b59e883 -- your-agent          # narrower: allowed

$ brushpass handoff --scope 'github:*:*' --parent 7b59e883 -- your-agent
Error: Scope widening rejected: parent token 7b59e883 grants
'github:rayanalpha/*:read', which does not cover 'github:*:*'.
A derived token may only narrow its parent's scope
```

The parent must itself be live: expired and revoked parents are refused.
A child can never outlive its parent — its expiry is capped to the
parent's. The linkage is recorded, so `list --json` shows the tree:

```console
$ brushpass list --json
{
  "tokens": [
    {
      "id": "71ffcfe9",
      "scope": "github:rayanalpha/brushpass:read",
      "label": "docs agent",
      "parent_id": "7b59e883",
      "revoked": true,
      "expired": false
    }
  ]
}
```

A supervisor agent can therefore hold a broad token and hand each worker
only what that worker needs — and `list` shows the whole lineage.

### env

Print token material in a shell format, for launchers you cannot wrap in
`handoff`.

```bash
brushpass env --token <plaintext-token> [--format export|json|powershell]
brushpass env --id <token-id> [--format export|json|powershell]
```

**Arguments:**
- `--token`: The plaintext token. Resolves the record behind it and
  performs the fail-closed liveness checks
- `--id`: A token ID, for the same liveness checks
- `--format`: `export` (default), `json`, or `powershell`

**Example:**

```console
$ brushpass mint --scope stripe:customers:read --ttl 30m
Token: bp_xK9mN2pQ8sT3vW5yZ7aB9cD1eF3gH5jK7lM9nO1pQ
ID: a1b2c3d4
...

$ brushpass env --token bp_xK9mN2pQ8sT3vW5yZ7aB9cD1eF3gH5jK7lM9nO1pQ
Warning: this output contains secret token material. Prefer
'brushpass handoff', which revokes the token when the agent exits.
export BRUSHPASS_TOKEN='bp_xK9mN2pQ8sT3vW5yZ7aB9cD1eF3gH5jK7lM9nO1pQ'
export BRUSHPASS_TOKEN_ID='a1b2c3d4'

$ eval "$(brushpass env --token bp_xK9...)"
```

PowerShell:

```console
PS> brushpass env --token bp_xK9... --format powershell
$env:BRUSHPASS_TOKEN='bp_xK9mN2pQ8sT3vW5yZ7aB9cD1eF3gH5jK7lM9nO1pQ'
$env:BRUSHPASS_TOKEN_ID='a1b2c3d4'
```

JSON:

```console
$ brushpass env --token bp_xK9... --format json
{
  "BRUSHPASS_TOKEN": "bp_xK9mN2pQ8sT3vW5yZ7aB9cD1eF3gH5jK7lM9nO1pQ",
  "BRUSHPASS_TOKEN_ID": "a1b2c3d4",
  "scope": "stripe:customers:read",
  "label": null,
  "parent_id": null,
  "issued_at": "2026-10-01T14:09:00+00:00",
  "expires_at": "2026-10-01T14:39:00+00:00"
}
```

The warning always goes to stderr, so stdout stays clean to `eval`.

**Fail-closed**: `env` refuses to print material for a revoked or expired
token.

**On `--id`**: brushpass stores token *hashes* only, so a token
identified by ID cannot be re-emitted by a later process — the plaintext
no longer exists anywhere. `--id` therefore performs the liveness checks
and then explains that it cannot reprint the token, rather than printing a
hash that would not authenticate. That is the storage guarantee working
as intended. Use `--token`, or use `handoff`.

**Prefer `handoff`.** `env` puts the token in *your* current shell, where
it persists until the shell exits and is never automatically revoked.
`handoff` scopes it to one subprocess and revokes it on exit.

## Scope Language

Scopes define what a token can access. Format: `<provider>:<resource>:<permission>`

### Components

- **provider**: The service or system (e.g., `github`, `aws`, `stripe`). No wildcards allowed.
- **resource**: The specific resource or resource pattern. `*` matches anything.
- **permission**: The action or permission level. `*` matches anything.

### Examples

| Scope | Meaning |
|-------|---------|
| `github:rayanalpha/repo:read` | Read access to a specific GitHub repo |
| `github:rayanalpha/*:read` | Read access to all repos under rayanalpha |
| `github:*:*` | Full access to all GitHub resources (single-segment resources only) |
| `github:*/*:*` | Full access to all GitHub resources, multi-segment too |
| `aws:s3/backup-bucket:*` | Full access to a specific S3 bucket |
| `stripe:customers:read` | Read-only access to Stripe customers |
| `stripe:*:*` | Full access to all Stripe resources |

### Matching Rules

When verifying, the issued scope must cover the required scope:

- Provider must match exactly (no wildcards, never)
- Resource and permission: split on `/`; both sides must have the
  same number of segments, and each issued segment must either
  equal the required segment or be exactly `*` (which matches any
  single segment)

**Examples:**

| Issued Scope | Required Scope | Result |
|--------------|----------------|--------|
| `github:org/*:read` | `github:org/repo:read` | ✓ Yes |
| `github:org/*:read` | `github:org/repo:write` | ❌ No (permission mismatch) |
| `github:org/*:read` | `github:org/repo/issues:read` | ❌ No (segment count differs) |
| `github:org/*/settings:read` | `github:org/repo/settings:read` | ✓ Yes |
| `github:*:*` | `github:repo:read` | ✓ Yes |
| `github:*:*` | `github:org/repo:read` | ❌ No (segment count differs) |
| `github:*/*:*` | `github:org/repo:read` | ✓ Yes |
| `github:*:read` | `github:any-repo:read` | ✓ Yes |
| `github:repo:*` | `github:repo:write` | ✓ Yes |
| `github:repo:read` | `github:repo:write` | ❌ No |

## TTL (Time-to-Live)

Supported formats: `30s`, `15m`, `2h`, `7d`, `1w`

- Default: 2 hours
- Maximum: 24 hours

Tokens cannot outlive their TTL. Expired tokens are always denied (fail-closed).

## Configuration

Configuration is stored in `~/.brushpass/config.yaml`. Set the data directory with the `BRUSHPASS_DATA_DIR` environment variable.

**Default config:**

```yaml
default_ttl: 2h
max_ttl: 24h
```

## Security

### Hash-Only Storage

brushpass stores only the SHA-256 hash of tokens. The plaintext token is shown exactly once at mint time and never persisted. If you lose the token, it cannot be recovered — revoke it and mint a new one.

### Fail-Closed

All verification failures return a non-zero exit code:
- Unknown token → deny
- Expired token → deny
- Revoked token → deny
- Scope mismatch → deny

### File Permissions

The tokens file (`~/.brushpass/tokens.json`) is created with mode `0600`. brushpass refuses to run if this file is group or world readable. This prevents accidental credential exposure on shared systems.

### Constant-Time Comparison

Token lookup uses `hmac.compare_digest` for constant-time hash comparison, mitigating timing attacks.

## Data Storage

All data is stored locally in `~/.brushpass/` (or `$BRUSHPASS_DATA_DIR`):

```
~/.brushpass/
├── config.yaml      # Configuration
└── tokens.json      # Token records (hashes only, mode 0600)
```

## License

MIT License. See LICENSE file.
