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
brushpass mint --scope aws:s3:my-bucket:* --ttl 4h --label "backup job"

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
| `github:*:*` | Full access to all GitHub resources |
| `aws:s3:my-bucket:*` | Full access to a specific S3 bucket |
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
| `github:*:read` | `github:any-repo:read` | ✓ Yes |
| `github:repo:*` | `github:repo:write` | ✓ Yes |
| `github:*:*` | `github:repo:read` | ✓ Yes |
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
