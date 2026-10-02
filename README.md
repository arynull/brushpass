# brushpass

A local credential broker for automated tooling. Mint short-lived, narrowly-scoped tokens so callers never touch your real, long-lived keys.

## Overview

brushpass generates ephemeral tokens with specific scopes and TTLs. Tokens are stored as SHA-256 hashes — the plaintext is shown once at mint time and never again. This limits exposure if a token leaks or an agent misbehaves.

If a token does leak, `brushpass scan` finds it: every minted token carries a keyed fingerprint, so a scan can recognise a token it issued on your disk, in your git history, or in your shell history — and tell you exactly where, without ever printing the token.

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
echo "$TOKEN" | brushpass verify --scope github:rayanalpha/repo:read

# List all tokens
brushpass list

# Revoke a token
brushpass revoke abc12345

# Hand a scoped token to an agent, revoked the moment it exits
brushpass handoff --scope github:rayanalpha/brushpass:read --ttl 1h \
  --label "docs agent" -- sh -c 'curl -H "Authorization: Bearer $BRUSHPASS_TOKEN" ...'

# Clean up old expired/revoked tokens
brushpass prune

# Find out whether any of your tokens leaked, and revoke what is still live
brushpass scan ~/projects --fix

# Check the audit log has not been tampered with
brushpass audit verify

# Emergency: revoke every live token (plan first, then --yes)
brushpass nuke
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
- `--label`: Optional human-readable label. Plain text only — no control
  characters, and nothing shaped like a token (`bp_` + 20 or more base64
  chars is rejected, since it would suppress the audit record). The
  `bp_` prefix is reserved for tokens.

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
Token: bp_EXAMPLE_TOKEN_HERE
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
# The token enters via stdin (or --from-env) — never argv. Argv is
# world-readable in ps and shell history; a token on the command line
# is a token in every process table on the box.
echo "$TOKEN" | brushpass verify --scope <required-scope>
brushpass verify --from-env MY_TOKEN --scope <required-scope>
```

**Exit codes:**
- `0`: Token is valid
- `1`: Token invalid (unknown, expired, revoked, or scope mismatch)

**Examples:**

```bash
# Check if token has read access to a specific repo
echo "$TOKEN" | brushpass verify --scope github:rayanalpha/specific-repo:read

# Check for write access (will fail if token only has read)
echo "$TOKEN" | brushpass verify --scope github:rayanalpha/repo:write
```

**JSON output:**

```bash
echo "$TOKEN" | brushpass verify --scope github:rayanalpha/repo:read --json
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

Immediately invalidate a single token.

```bash
brushpass revoke <token-id>
```

**Example:**

```bash
brushpass revoke abc12345
```

After revocation, `verify` will deny the token even if it hasn't expired.
Revoking one token affects only that token — sibling tokens keep working.
(To retire *everything* at once, see `nuke`, which bumps the revocation
epoch.)

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
Token: bp_EXAMPLE_TOKEN_HEREMx
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
credential you are handing over. If a named variable is not set in the
parent, the handoff aborts: the token is minted, then immediately
revoked again — none is left live — and both the mint and the revoke
are in the audit log.

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
# The token enters via stdin (or --from-env) — never argv. Argv is
# world-readable in ps and shell history.
echo "$TOKEN" | brushpass env [--format export|json|powershell]
brushpass env --from-env MY_TOKEN [--format export|json|powershell]
brushpass env --id <token-id> [--format export|json|powershell]
```

**Arguments:**
- `--from-env`: Read the token from this environment variable instead of stdin
- `--id`: A token ID, for the same liveness checks (cannot re-emit the plaintext)
- `--format`: `export` (default), `json`, or `powershell`

**Example:**

```console
$ brushpass mint --scope stripe:customers:read --ttl 30m
Token: bp_EXAMPLE_TOKEN_HERE
ID: a1b2c3d4
...

$ echo "$TOKEN" | brushpass env
Warning: this output contains secret token material. Prefer
'brushpass handoff', which revokes the token when the agent exits.
export BRUSHPASS_TOKEN='bp_EXAMPLE_TOKEN_HERE'
export BRUSHPASS_TOKEN_ID='a1b2c3d4'

$ eval "$(echo "$TOKEN" | brushpass env)"
```

PowerShell:

```console
PS> $TOKEN | brushpass env --format powershell
$env:BRUSHPASS_TOKEN='bp_EXAMPLE_TOKEN_HERE'
$env:BRUSHPASS_TOKEN_ID='a1b2c3d4'
```

JSON:

```console
$ echo "$TOKEN" | brushpass env --format json
{
  "BRUSHPASS_TOKEN": "bp_EXAMPLE_TOKEN_HERE",
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

## Leak detection

Every token minted by this version carries a keyed **fingerprint** — a
truncated HMAC of the token, under a key stored alongside your records.
That fingerprint is what a scan matches against, not the shape of the
string. So a scan answers exactly one question: *did brushpass issue this?*
A `bp_`-shaped string brushpass never minted is discarded in silence, and
the report cannot be made to cry wolf.

### scan

```bash
brushpass scan [path ...] [--git] [--history] [--fix] [--json]
```

**Arguments:**
- `path`: files or directories to scan recursively. Default: the current
  directory. The brushpass state directory is never scanned.
- `--git`: also scan this repository — the commit log (`git log -p --all`),
  the staged diff, the unstaged diff, and untracked worktree files
- `--history`: also scan shell history files, honouring `$HISTFILE`
- `--fix`: revoke every live leaked token found. Idempotent.
- `--json`: machine-readable output

**Exit codes:**
- `0`: no live leaks (also after `--fix` — the credential is dead)
- `2`: at least one live leak found, suitable for a CI gate
- `1`: error (unreadable path, not a git repository, git missing)

**What it looks for.** Three passes over each blob, then verification:

| Detected by | What it catches |
|-------------|-----------------|
| `raw` | the token written out plainly |
| `base64` | the token inside a pasted base64 payload (both alphabets, padding optional) |
| `whitespace` | the token wrapped across lines, spaces or tabs |

**Output:**

```console
$ brushpass scan ~/projects
LEAKED TOKENS
--------------------------------------------------------------------------------
a1b2c3d4  github:rayanalpha/*:read  [LIVE]
  label:       CI agent
  fingerprint: 9f2c1a7be004...
  location:    /home/you/projects/app/config.env:3 (via raw, source file)
  issued_at:   2026-10-01T14:09:00+00:00
  action:      revoke now

Scanned 128 file(s) or stream(s); skipped 2 binary; 1 verified leak(s).
1 live leak(s). Run 'brushpass scan --fix' to revoke them.
```

No token plaintext appears in the report, in either format, even for
confirmed leaks. A skipped file is always counted in the summary — a quiet
skip reads as an all-clear, and an all-clear that isn't one is worse than
no scanner at all.

Tokens minted before leak detection existed carry no fingerprint, so no
scan can match them. Rather than ignore them, the report lists them as
`UNSCANNABLE`; they still verify normally, and you can revoke one if you
cannot account for where it went.

**`live_leaks` semantics.** In `--json` output the field `live_leaks` is a
count of *live findings* — token-at-a-location pairs — not a count of
distinct tokens. One token pasted into three files is three findings
(three places to clean up), and `leaked_ids` lists the distinct token ids
behind them. The text renderer says the same thing as "N live leak(s)".

#### Limitations

brushpass matches tokens that are recognisable as tokens. It is a leak
*finder*, not a defence against a determined obfuscator. These evasions
are **not caught**, by design and by documented scope:

- **A deliberately mangled copy — junk or non-whitespace characters
  inserted between the token's characters.** The raw pass needs 43
  contiguous characters; the whitespace pass removes whitespace only. So
  `bp_AAAA…\x01\x02…ZZZZ` never reassembles and is not found.
- **Double-encoded tokens.** Exactly one decode pass is applied, not a
  recursive chase. base64(base64(token)) is not found.
- **Truncated tokens.** A prefix is not a token; the pattern requires all
  43 characters.
- **Rearranged token bodies.** A reversed body *is* collected as a
  candidate — the shape is identical — but its fingerprint matches no
  stored record, so it never reaches the report. It is verification, not
  pattern-matching, that makes this safe.
- **Compressed and archived files.** A zip or gzip file is detected as
  binary and skipped, so a token inside it is not found. The skip is
  counted in the summary, never silently dropped — but it is a skip.
- **Files excluded by `.gitignore`,** under `scan --git`. Gitignored
  content is not listed by git, so it is not scanned there. Scan the path
  directly to cover it.
- **Content that no longer exists on this machine.** A leak that was
  copied elsewhere, pushed to a remote, or already `prune`d away cannot
  be found here. Note that `prune` deletes expired/revoked records, and a
  fingerprint is only useful while its record exists: a leaked token past
  that point reads as clean.

Verification is the safety net that makes the first four acceptable: a
string brushpass never issued can never be reported, so widening coverage
cannot produce a false positive.

## Credential rotation

Minting a token is only half the problem. A long-lived credential that
hands out those tokens has to be replaced eventually, and replacing it
means the tokens already outstanding become stale.

brushpass closes that loop: it stores the root credential itself
(encrypted), rotates it through a provider, and revokes every ephemeral
token minted from it.

### The atomicity contract

One sentence: **a live secret is never untracked.**

A rotation moves a credential from secret A to secret B. There are two
ways to get that wrong, and both are handled explicitly.

**Losing B.** The provider issued B, and then storing B failed. If B was
never written down, B is a live upstream credential that nobody holds and
nobody can revoke. So persisting B happens *before* anything retires A,
and it retries three times. If it still cannot be stored, brushpass
records B's identifier in the rotation journal as an **orphan**, aborts
loudly, and exits non-zero:

```console
$ brushpass rotate ci-deploy
======================================================================
ROTATION ABORTED - A NEW SECRET COULD NOT BE STORED
======================================================================
Could not store the new secret after 3 attempts (CredentialError: Failed to
save credentials: [Errno 28] No space left on device). The old credential for
'ci-deploy' is STILL LIVE and unchanged. brushpass aborted before revoking
anything, so your old secret still works - but the provider may have issued
a new one (identifier 1e0722bf6b54) that brushpass does not hold. Revoke it at
the provider, or fix the store and re-run the rotation.

Orphaned secret ID: 1e0722bf6b54
This identifier is in the rotation journal. It is a digest, so the secret
itself is not recoverable from it.
$ echo $?
2
```

The linked token is untouched too, which is the point:

```console
$ brushpass list --json
{"tokens": [{"id": "a00307c5", "credential_label": "ci-deploy", "revoked": false, ...}]}
```

**Killing the only working one.** If persisting B failed, A must stay
live. The engine aborts *before* `provider.revoke` and before any linked
token is revoked, so A continues to work while you deal with the orphan.

So the order is fixed, and it is the whole design:

| # | Step | If it fails |
|---|------|-------------|
| 1 | `provider.rotate` → new secret B | Nothing has changed. Abort; A is untouched. |
| 2 | **Persist B, retrying 3×** | Abort loudly, record B's id as an orphan, exit 2. **A stays live.** |
| 3 | `provider.revoke(A)`, then revoke linked tokens | B is already stored and live, so the rotation *succeeded*; a stale A is reported as a warning, not a failure. |
| 4 | Journal entry + audit log line | The journal is the recovery record; a write failure there degrades to a printed warning. |

Step 2 is the commit point. Note that step 3 failing is deliberately
*not* fatal: with B stored, the credential works, and a superseded
secret that outlives its rotation is an operational loose end worth
reporting rather than a reason to roll back a change that is already good.

Rotations are timed end to end against a 60-second budget, and the
measured duration is printed and recorded in the journal.

### credential add / list / remove

```bash
brushpass credential add --provider <name> --label <label> [--from-env VAR] [--set KEY=VALUE ...]
brushpass credential list [--json]
brushpass credential remove <label> [--yes]
brushpass credential status <label> [--json]
```

The secret is read from **stdin** or from the environment variable named
by `--from-env` — never from an argument. There is no `--secret` flag,
and that is deliberate: argv is world-readable in `ps` and is recorded in
every shell history. `--from-env` is the better option of the two in
scripts, since an env var does not land in the history.

`credential list` shows labels, providers, timestamps and a short
SHA-256 identifier for each secret — never secret material. Removing a
credential asks you to type its label, unless you pass `--yes`.

Secrets are encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256,
from `cryptography`). The data key lives in `credentials.key`, mode
`0600`, and brushpass **refuses to run** if it is readable by group or
other — the same fail-closed refusal as the scanner key, and likewise
never auto-repaired.

### Linking tokens to a credential

```bash
brushpass mint --scope <scope> --credential <label>
```

The label must already exist; minting against an unknown credential is
rejected before anything is minted, so a bad label never leaves a live
token behind. The label is recorded on the token and shown by
`list --json`.

A rotation of that credential revokes every live token carrying the
label. **Tokens minted without `--credential` are unaffected** — they are
untethered by design, and keep working until they expire or you revoke
them yourself.

### rotate

```bash
brushpass rotate <label> [--dry-run] [--json]
brushpass rotate --status [--json]
```

`--dry-run` prints the full plan — provider, every step, and which
ephemeral tokens would be revoked — and changes nothing at all.

### A full rotation

Every line below is real output, captured from a scratch state directory.

```console
$ printf '%s\n' "$SECRET_OLD" | brushpass credential add \
      --provider manual --label ci-deploy
Stored credential 'ci-deploy' (provider: manual)
Secret ID: 406b699fe2be
Added: 2026-10-01T15:52:26.090842+00:00

Encrypted at rest; the plaintext is never written to disk.
Link tokens to it with: brushpass mint --credential ci-deploy ...

$ grep -r 'OLD-root-credential-value-000' ~/.brushpass
(no matches - the secret is encrypted at rest)

$ brushpass mint --scope github:rayanalpha/brushpass:read --ttl 2h \
      --credential ci-deploy --label 'release agent'
Token: bp_EXAMPLE_TOKEN_HERE
ID: a3e5b5f2
Scope: github:rayanalpha/brushpass:read
Label: release agent
Credential: ci-deploy
Expires: 2026-10-01T17:52:26.322427+00:00 (2h)

Rotating credential 'ci-deploy' will revoke this token.
Store this token securely - it will not be shown again.

$ brushpass rotate ci-deploy --dry-run
ROTATION PLAN (dry run) for 'ci-deploy'
Provider: manual
Current secret ID: 406b699fe2be

Steps that WOULD run:
  1. Print rotation instructions for the operator
  2. Open the provider's UI for the credential 'ci-deploy'.
  3. Create a NEW credential with the same or narrower permissions.
  4. Copy the new secret.
  5. Paste it at the prompt below (or pipe it on stdin).
  6. Revoke the OLD credential in the same UI, once this rotation has finished successfully.
  7. Read the new secret from stdin (never from argv)
  8. Store the new secret encrypted, replacing the old one
  9. Note: Revoking a manual credential happens in the provider's own UI, if at all. brushpass cannot confirm it, so it does not claim to have done it. Revoke the old credential yourself as part of the rotation.
  10. Revoke 1 live ephemeral token(s) linked to 'ci-deploy': a3e5b5f2 (irreversible)
  11. Write the rotation journal entry and an audit log line

  Note: this provider cannot revoke the old secret upstream.

No changes were made. Re-run without --dry-run to rotate.

$ # the state directory is byte-for-byte identical before and after
$ printf '%s\n' "$SECRET_NEW" | brushpass rotate ci-deploy
  Open the provider's UI for the credential 'ci-deploy'.
  Create a NEW credential with the same or narrower permissions.
  Copy the new secret.
  Paste it at the prompt below (or pipe it on stdin).
  Revoke the OLD credential in the same UI, once this rotation has finished successfully.

brushpass: action=credential.rotate label=ci-deploy provider=manual state=finished rotation_id=rot_1a0f82ac158_024717 duration_seconds=0.025 old_secret_id=406b699fe2be new_secret_id=28529f772272 orphan_secret_id=- provider_revoked=None revoked_tokens=1 error="Upstream revocation not performed: ..."

ROTATION COMPLETE
  Credential:      ci-deploy
  Provider:        manual
  Old secret ID:   406b699fe2be
  New secret ID:   28529f772272
  Duration:        0.025s
  Revoked tokens:  a3e5b5f2
  Old secret:      not revocable via this provider
  Rotation ID:     rot_1a0f82ac158_024717

WARNINGS:
  - Upstream revocation not performed: Revoking a manual credential happens in the provider's own UI, if at all. brushpass cannot confirm it, so it does not claim to have done it. Revoke the old credential yourself as part of the rotation.

$ grep -c 'NEW-root-credential-value-999' ~/.brushpass/credentials.json
0

$ brushpass credential list
LABEL                PROVIDER        ADDED                       ROTATIONS  SECRET ID
------------------------------------------------------------------------------------------
ci-deploy            manual          2026-10-01T15:52:26.090842+00:00 1          28529f772272

Secrets are never displayed. Rotate with: brushpass rotate <label>

$ brushpass list
ID       SCOPE                               LABEL           CREDENTIAL      EXPIRES      STATUS
----------------------------------------------------------------------------------------------------
a3e5b5f2 github:rayanalpha/brushpass:read    release agent   ci-deploy       1h59m        revoked
```

The audit line goes to **stderr**, so stdout stays a clean data channel
and `rotate --json` output can be parsed directly.

### Rotation status

```bash
brushpass rotate --status
brushpass credential status <label>
```

```console
$ brushpass credential status ci-deploy
ROTATION STATUS for ci-deploy
----------------------------------------------------------------------
Last rotation:   2026-10-01T15:52:26.712633+00:00
Duration:        0.025s
State:           finished
Provider:        manual
Old secret ID:   406b699fe2be
New secret ID:   28529f772272
Revoked tokens:  1
Finished:        1 successful rotation(s)
```

Status also surfaces anything that needs a human: rotations that started
and never finished, and orphaned secret identifiers from a failed
persist.

### The rotation journal

Every rotation writes an append-only JSON Lines record to
`~/.brushpass/journal.jsonl` (mode `0600`, fsync'd). Two entries per
rotation, `started` and then a terminal one:

```json
{"rotation_id": "rot_1a0f82ac158_024717", "label": "ci-deploy", "state": "started", "started_at": "2026-10-01T15:52:26.712633+00:00", "old_secret_id": "406b699fe2be"}
{"rotation_id": "rot_1a0f82ac158_024717", "label": "ci-deploy", "state": "finished", "finished_at": "2026-10-01T15:52:26.737519+00:00", "duration_seconds": 0.025, "new_secret_id": "28529f772272", "revoked_tokens": ["a3e5b5f2"]}
```

No secret material is ever written there. `old_secret_id` and
`orphan_secret_id` are truncated SHA-256 digests, which let you confirm
*which* secret is in play without being able to recover it.

## Audit

Everything security-relevant brushpass does is written to
`~/.brushpass/audit.log` (mode `0600`) as JSON Lines: a token minted or
revoked, a token that expired and was pruned, a verify that was refused,
a leak found on disk, a credential added or removed, a rotation starting
and finishing, a nuke.

```bash
brushpass audit verify          # replay the chain, exit non-zero on tamper
brushpass audit log             # the last 50 records
brushpass audit log --event token.revoke --since 24h --tail 10
```

### A record

```json
{"seq": 4, "ts_utc": "2026-10-01T20:31:04.118472+00:00", "event": "token.revoke", "details": {"token_id": "a3e5b5f2"}, "prev_hash": "b776e2752f0121830e5d851a6f9035703f72f5d176999ab55ab5d37e7f1e8f14", "record_hash": "4f1c…", "signature": "kQ8B…"}
```

`details` carries ids, labels, scopes, fingerprints and digests — never
token plaintext. That is enforced, not merely intended: `record()` walks
the details and refuses anything shaped like a token, so "do not log
secrets" cannot be broken by a careless call site.

### What the chain proves

Each record is chained and signed. `record_hash` is SHA-256 over the
canonical JSON of the record with `prev_hash` **inside** the preimage, so
a record commits to its own position; `prev_hash` links it to the one
before; `signature` is Ed25519 over the hash under `~/.brushpass/audit.key`.

`audit verify` replays from seq 0 and reports the **first** broken seq —
the only number an incident responder needs. Wiping the log is not a
way around it: an existing-but-empty log file verifies TAMPERED, and a
deleted log file verifies TAMPERED while the signing key survives —
only a never-used state dir honestly reports "0 records".

Three outcomes, three meanings: `OK` (chain intact), `TAMPERED` (a
record was edited, deleted or reordered — the exact first-broken seq is
named), and a plain `Error` (the log was **not checked**: the signing
key is missing, unreadable, or group/world-readable). A key the command
cannot trust is an operational problem, never a tamper claim — and
restoring a backup cannot fix a file mode.

```console
$ brushpass audit verify
OK (128 records)

$ brushpass audit verify
TAMPERED: record 64: record_hash does not match its contents (stored 4f1c8a…, computed 9b2e07…)
Every record from this point on is unreliable. Restore the log from a backup, or treat everything after it as unaccounted for
```

Now the honest part. This proves the log has not been altered **by anyone
without `audit.key`**. The key sits in the same `0700` directory as the
log, so this is tamper-evidence against disclosure of a single artefact,
a leaked backup, or another account on the box — the same boundary the
encrypted credential store draws.

Two deletions the log *does* catch locally:

- **Wiping is detected.** An existing-but-empty log file verifies as
  TAMPERED (nothing in brushpass ever creates an empty log), and a
  missing log with a surviving key verifies as TAMPERED. Only a
  never-used state dir verifies clean as "0 records".
- **Tail truncation is detected.** Every append also writes
  `audit.counter`, a high-water mark holding the `(seq, record_hash)` of
  the last record written. `audit verify` compares the log's actual tail
  against it: a log shorter than the mark names the first missing
  sequence. (A mark lost to a crash — the log append made it, the counter
  write didn't — is *not* flagged: the log is the truth there, and verify
  repairs the counter on the way out.) Appending to a truncated log is
  refused outright — the write would move the mark forward and launder
  the deletion, so brushpass stops instead and tells you to restore
  from backup.

What it does **not** prove is completeness against an attacker who owns
the whole state dir: someone who can consistently rewrite the log *and*
the counter (or steal `audit.key` and forge the chain outright) defeats
local verification. That is the same boundary as full account compromise,
and it is out of scope — anchor the head hash somewhere they cannot
reach (off-machine backups) if you need that.

`audit log` prints the head hash of the last record shown for exactly
this reason:

```console
$ brushpass audit log --tail 3
63     2026-10-01T20:31:02.881+00:00  token.mint                  token_id=7b59e883 scope=github:repo:read label=supervisor epoch=2
64     2026-10-01T20:31:04.118+00:00  token.revoke                token_id=a3e5b5f2
65     2026-10-01T20:33:51.402+00:00  nuke                        tokens_revoked=2 epoch_before=2 epoch_after=3

head: 4f1c8a9e77b0d3f5a1c2e8b6d0f4a9c3e7b1d5f8a2c6e0b4d9f3a7c1e5b8d2f6a
(3 record(s); anchor the head hash out of band)
```

Ship that hash to a log collector or keep it in your own notes. Later,
`audit verify` proves the log is still the log you anchored.

### Filters

`--event` takes one of the `EVENTS` values and is validated against the
list — a typo is an error, not a silently empty result. `--since` takes
`30s`, `15m`, `24h`, `7d`, `2w`. Both are applied **before** `--tail`, so
`--event token.revoke --tail 5` is the last five revokes rather than the
last five records of which some were revokes.

### Verify successes are not logged

Only denials are recorded. A successful verify writes nothing.

This is a deliberate sampling choice. The log is a forensic record of
things that were *refused* — the attempts an investigator wants — not
traffic accounting. Successful verifies are the overwhelmingly common
case and carry no information an investigator needs; logging them would
roughly double the log's size and bury the denials, which is the exact
failure mode of logging everything.

Denials are logged on every path, including the one with no record to
name:

| Reason | Logged |
|---|---|
| `revoked` | `token_id` |
| `stale_epoch` | `token_id`, `token_epoch`, `store_epoch` |
| `expired` | `token_id` |
| `scope_mismatch` | `token_id`, `granted_scope`, `required_scope` |
| `unknown_token` | `fingerprint` (sha256 of what was presented) |

An unknown token is exactly what an attacker produces, so it is worth
recording; the sha256 lets you correlate repeated attempts without ever
storing what was presented.

Audit writes are **best effort**. A damaged or unwritable log prints
`WARNING: audit write failed: …` and the operation continues — a mint
still mints, a revoke still revokes. The log is where you look
afterwards, not a gate that decides whether things happen.

## Revocation epoch

`tokens.json` carries an integer `revocation_epoch`, and every token
records the generation it was minted in. A token whose generation is
behind the store's is denied, in addition to the `revoked` flag and its
expiry.

**What bumps it:** `nuke` (via `revoke_all_live`) — exactly once per
operation, not once per token. A break-glass retires a *generation*,
and a caller reading the counter sees one consistent jump rather than a
hundred. Single-token `revoke`, `scan --fix`, rotation and handoff-exit
do **not** bump it: they set per-token `revoked` flags, so only the
named tokens die.

**Why it defeats stale caches.** A revoked *flag* is a per-token fact: it
says "this one token is dead" and says nothing about any other. A broker
that cached "this token is fine" stays wrong about every other token, and
stays wrong until it happens to re-read. An epoch bump is a *generation*
change: everything minted before it is behind the current generation, so
one number retires a whole class of tokens. Nobody has to enumerate what
was outstanding, which is the situation a break-glass exists for.

```console
$ echo "$TOKEN" | brushpass verify --scope github:repo:read --json
{"valid": false, "reason": "stale_epoch", "token_id": "a3e5b5f2", "token_epoch": 2, "store_epoch": 3}
```

The store is never cached: every public read re-reads the file. Two
brushpass processes are two `TokenStore` objects with two separate memory
maps, and a revoke in one is visible to a verify in the other on the very
next call — no signal, no IPC, no shared object.

**Pre-epoch tokens.** Tokens minted before v0.5.0 have no generation
stamp and count as generation 0. That is the safe direction: they verify
normally until the first bump, and the first bump retires them. Upgrading
the version does not by itself kill anything; the next revoke does.

## nuke — the break-glass

> ### ⚠️ `brushpass nuke --yes` revokes **every live token**, everywhere
>
> This is not scoped to one credential, one label, or one token. It is
> the "a credential is in someone else's hands and I do not have time to
> work out which" button, and it kills all of them. There is no undo:
> tokens must be re-minted, and any in-flight job holding one fails.
>
> It also **does not revoke anything upstream**. brushpass kills its own
> tokens; the long-lived provider secret dies only when the provider is
> told. A clean exit here is not "the credential is gone".

```bash
brushpass nuke               # prints the plan, changes nothing, exits non-zero
brushpass nuke --yes         # do it
brushpass nuke --yes --rotate-all   # and attempt a real provider rotation
```

`--yes` is **required**. There is no interactive prompt, deliberately:
the one situation where a prompt is dangerous is the one where brushpass
is run from a script or a cron job with nobody watching, and there an
unattended `input()` either blocks forever or reads the next line of
somebody else's stdin. Without `--yes` you get the plan and a non-zero
exit:

```console
$ brushpass nuke
======================================================================
NUKE PLAN (nothing changed)
======================================================================
Live tokens to revoke (2): a3e5b5f2, 7b59e883
Revocation epoch: 2 -> 3
Credentials to flag for rotation (1): ci-deploy
======================================================================
```

With `--yes`, the same header prints first, then what happened:

```console
$ brushpass nuke --yes
======================================================================
NUKE
======================================================================
Live tokens to revoke (2): a3e5b5f2, 7b59e883
Revocation epoch: 2 -> 3
Credentials to flag for rotation (1): ci-deploy

This is not reversible and it is not specific to one credential.
brushpass kills its own tokens; the upstream secrets die only when the
provider is told. Every credential above needs a rotation, not just a token revoke.
======================================================================

NUKE COMPLETE
  Tokens revoked:   2
  Token ids:        a3e5b5f2, 7b59e883
  Epoch:            2 -> 3
  Flagged to rotate: 1 (ci-deploy)

Every token minted before this call is now behind the current epoch
and will be denied, whatever its own revoked flag says.
Upstream credentials are NOT revoked by this command:
  brushpass rotate ci-deploy
```

What it does, in order:

1. Revokes every live token and advances the epoch by one, so anything
   still holding a pre-nuke token is denied even if it cannot enumerate
   ids.
2. Writes a "rotation required" journal entry for every root credential.
   brushpass cannot rotate a credential it has not been told how to reach,
   so it does not pretend to: the journal records the obligation and
   `rotate --status` surfaces it until a human clears it.
3. `--rotate-all` then attempts a real provider rotation per credential.
   A `manual` credential prints its instructions and is **skipped with a
   warning** unless stdin is a TTY — an unattended nuke must never block
   on a prompt nobody is there to answer.
4. Writes one `nuke` audit record naming what was retired, so
   `audit verify` still passes afterwards and the break-glass itself is
   on the record.

Only the token revocation is fatal. If the journal or audit write fails,
you get a warning and the tokens stay dead — being dead is the part that
mattered.

## Providers

A provider is the only part of brushpass that talks to a third-party
service. It is a small object behind a two-method interface, so adding a
service means adding one file.

```bash
brushpass provider list
brushpass provider show <name>
```

```console
$ brushpass provider list
NAME             REVOKE     REQUIRED CONFIG
--------------------------------------------------------------------------------
generic-http     yes        url
github-app       no         app_id, private_key_path, installation_id
manual           no         (none)

See one provider's detail: brushpass provider show <name>
```

### github-app

Mints a fresh GitHub App **installation access token** via
`POST /app/installations/{id}/access_tokens`, authenticated with a
short-lived RS256 JWT signed with the App's private key (9-minute
lifetime, GitHub's 10-minute ceiling).

Config: `app_id`, `private_key_path` (must be absolute and mode `0600`),
`installation_id`. Optional: `api_url`, `repository`, `expires_in`.

**The old token is not revoked, and cannot be.** GitHub supersedes
installation tokens implicitly when a new one is issued, and there is no
API call that deletes an outstanding one. brushpass reports
`supports_revoke = False` and says so plainly instead of pretending the
old token died; it remains usable until its own expiry (1 hour by
default). The practical consequence: rotating the *stored* credential is
safe, but the linked ephemeral tokens brushpass minted are revoked
immediately, which is the part that matters.

### generic-http

The escape hatch for internal secret services. POSTs to a configured URL
and reads the new secret out of the JSON response.

| Config key | Required | Meaning |
|------------|----------|---------|
| `url` | yes | Absolute http(s) URL |
| `method` | no | `POST` (default), `PUT`, `PATCH` |
| `headers` | no | Header map; `{old_secret}` is substituted |
| `body` | no | Extra JSON fields; `{old_secret}` is substituted |
| `old_secret_placement` | no | `body` (default), `header`, `query`, `none` |
| `old_secret_header` | if placement is `header` | Header name |
| `old_secret_query` | if placement is `query` | Query parameter name |
| `new_secret_path` | no | Dot-separated path, default `token` |
| `revoke_url` | no | If set, `revoke` POSTs here |
| `timeout` | no | Seconds, 0–60 |

Config is validated strictly, before any network call: a mistyped
endpoint should fail as a config error, not as a confusing HTTP 401 from
somewhere further along. `timeout` is capped at 60 seconds so a hung
endpoint cannot blow the rotation budget.

The validator also rejects a `headers` entry carrying `{old_secret}`
when `old_secret_placement` is `body` — that is almost always a mistake,
and it would otherwise put a live secret somewhere you did not choose:

```console
generic-http: config 'headers'['X-Cur'] interpolates {old_secret} but
'old_secret_placement' is not 'header'. Set the placement to 'header' or
remove the placeholder, so a live secret is not sent somewhere you did not choose
```

`--from-env` is the right way to supply a bearer token here, since it
keeps the secret out of shell history.

```bash
brushpass credential add --provider generic-http --label vault-write \
  --set url=https://secrets.internal/v1/rotate \
  --set new_secret_path=data.token \
  --set revoke_url=https://secrets.internal/v1/revoke \
  --set headers.X-Vault-Token='hvs.example' \
  --set old_secret_placement=header \
  --set old_secret_header=X-Current-Token
```

### manual

For credentials with no rotation API — classic GitHub PATs, IAM access
keys, a database password on a box you do not control. It prints
step-by-step instructions, reads the new secret from stdin, and hands it
to the same engine, so the persist-before-revoke contract, the journal,
linked-token revocation, and the timing all still apply.

What it does not do is pretend to be automation. There is no API call,
and `supports_revoke` is `False`: whether the old secret dies is up to
what you just did in the provider's UI, and brushpass reports it as
"not revocable via this provider" rather than claiming a revocation that
did not happen.

### Writing a provider

Subclass `Provider` and register it. That is the whole interface:

```python
from brushpass.providers import Provider, RotationResult, register

class AcmeProvider(Provider):
    name = "acme"
    description = "Rotate an Acme service token"
    required_config = ("api_url", "account_id")
    supports_revoke = True

    def check_config(self, config: dict) -> None:
        # Optional: type/value checks, raising ConfigError.
        if not str(config["api_url"]).startswith("https://"):
            from brushpass.providers import ConfigError
            raise ConfigError("acme: 'api_url' must be https")

    def rotate(self, old_secret: str, config: dict) -> RotationResult:
        # Do the upstream work; raise ProviderError on refusal.
        # Never return an empty string, never return the old secret back.
        status, body = request(
            f"{config['api_url']}/rotate",
            method="POST",
            headers={"Authorization": f"Bearer {old_secret}"},
            body={"account": config["account_id"]},
        )
        if status != 200:
            raise ProviderError(f"acme: rotate returned HTTP {status}")
        return RotationResult(new_secret=body["token"], expires_at=body.get("expires_at"))

    def revoke(self, secret: str, config: dict) -> None:
        # Omit supports_revoke (or set it False) if you cannot do this.
        status, _ = request(
            f"{config['api_url']}/revoke",
            method="POST",
            headers={"Authorization": f"Bearer {secret}"},
        )
        if status not in (200, 204):
            raise ProviderError(f"acme: revoke returned HTTP {status}")

register(AcmeProvider())
```

Two rules every provider inherits:

1. **Config is validated before the network is touched.** A typo in a
   config key must fail as a config error, not as a confusing HTTP 401.
2. **Secrets never travel through argv or an exception message.** They go
   in request headers or bodies, and any `ProviderError` is phrased so
   that interpolating it into a log cannot leak one.

Override `plan(context)` if you want your steps to appear in
`rotate --dry-run`, and `can_revoke(config)` instead of `supports_revoke`
when revocation depends on the credential's config (as `generic-http`
does).

### Webhook notifications

If `notifications.webhook_url` is set, brushpass POSTs a JSON summary
after each rotation.

```yaml
notifications:
  webhook_url: https://hooks.example.com/services/T000/B000/XXXX
```

The payload is the same structure `rotate --json` prints, plus
`"event": "credential.rotation"`. It carries identifiers and durations
only — no secret material.

Delivery is **best effort and can never fail a rotation**. The
credential change is already committed by the time the webhook is sent,
so a chat server outage reports itself as a warning on the outcome
instead of turning a successful rotation into a failure:

```console
$ brushpass rotate ci-deploy
...
Note: webhook notification failed: NotificationError: <urlopen error timed out>
$ echo $?
0
```

The rotation is committed before the webhook is attempted, so a chat
server outage cannot turn a good rotation into a failed one.

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

Supported units: `s`, `m`, `h`, `d`, `w` — e.g. `30s`, `15m`, `2h`.

- Default: 2 hours
- Maximum: 24 hours (`7d` and `1w` parse but always exceed the maximum
  and are rejected)

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
- Token from a retired generation (`stale_epoch`) → deny

### File Permissions

Everything under the state directory is created mode `0600` (directory
`0700`). Two different policies apply when brushpass finds a file that
has become group- or world-readable:

- **Key files refuse to run.** `credentials.key`, `scanner.key` and
  `audit.key` hold key material: a key that was readable by others may
  already be disclosed, so brushpass exits with an error telling you to
  `chmod 0600` it instead of silently continuing.
- **Data files are repaired.** `tokens.json`, `credentials.json`,
  `audit.log` and `journal.jsonl` hold only hashes, ciphertexts and
  signed records — never plaintext secrets — so brushpass quietly
  restores them to `0600` and carries on. (The file being readable meant
  whatever could read it already did; refusing would add theatre, not
  safety.)

### Constant-Time Comparison

Token lookup uses `hmac.compare_digest` for constant-time hash comparison, mitigating timing attacks.

## Data Storage

All data is stored locally in `~/.brushpass/` (or `$BRUSHPASS_DATA_DIR`):

```
~/.brushpass/
├── config.yaml         # Configuration
├── tokens.json         # Token records + revocation_epoch (hashes only, mode 0600)
├── credentials.json    # Root credentials, Fernet-encrypted (mode 0600)
├── credentials.key     # Credential data key (mode 0600)
├── scanner.key         # Token fingerprinting key (mode 0600)
├── journal.jsonl       # Append-only rotation journal (mode 0600)
├── audit.log           # Hash-chained, Ed25519-signed audit log (mode 0600)
└── audit.key           # Audit signing key, Ed25519 seed (mode 0600)
```

## Verified end-to-end examples

Every block below is executed by the project's quality gate in a scratch
environment (`$BRUSHPASS_DATA_DIR` points at a fresh temp dir), so these
are not just documentation — they are tested on every release.

Mint, verify, narrow-check, and revoke one token:

```bash-test
TOKEN_JSON=$(brushpass mint --scope github:rayanalpha/repo:read --ttl 1h --json)
TOKEN=$(python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" <<< "$TOKEN_JSON")
TOKEN_ID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" <<< "$TOKEN_JSON")
echo "$TOKEN" | brushpass verify --scope github:rayanalpha/repo:read > /dev/null
if echo "$TOKEN" | brushpass verify --scope github:rayanalpha/repo:write > /dev/null 2>&1; then
  echo "FAIL: write scope should have been denied"; exit 1
fi
brushpass list | grep -q "github:rayanalpha/repo:read"
brushpass revoke "$TOKEN_ID" > /dev/null
if echo "$TOKEN" | brushpass verify --scope github:rayanalpha/repo:read > /dev/null 2>&1; then
  echo "FAIL: revoked token should have been denied"; exit 1
fi
echo "mint/verify/revoke cycle OK"
```

Plant a leak, find it, fix it:

```bash-test
LEAKDIR=$(mktemp -d)
LEAK_JSON=$(brushpass mint --scope github:rayanalpha/repo:read --label leak-test --json)
LEAK_TOKEN=$(python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" <<< "$LEAK_JSON")
echo "token=$LEAK_TOKEN" > "$LEAKDIR/app.env"
if brushpass scan "$LEAKDIR" > /dev/null 2>&1; then
  echo "FAIL: scan should have exited 2 on a live leak"; exit 1
fi
brushpass scan --fix "$LEAKDIR" > /dev/null
if brushpass verify --scope github:rayanalpha/repo:read "$LEAK_TOKEN" > /dev/null 2>&1; then
  echo "FAIL: fixed leak should have been revoked"; exit 1
fi
echo "scan/--fix cycle OK"
```

The audit chain verifies after normal operation:

```bash-test
brushpass mint --scope github:rayanalpha/repo:read > /dev/null
brushpass audit verify
```

A rotation dry-run changes nothing:

```bash-test
printf '%s\n' "old-secret" | brushpass credential add --provider manual --label drytest > /dev/null
brushpass rotate --dry-run drytest | grep -q "ROTATION PLAN"
echo "rotate dry-run OK"
```

## Publishing to PyPI (maintainer)

PyPI publication is a **human step**, never automated. When a release is
cut (signed tag on `main`, quality gate green, red-team SHIP):

```bash
python -m build
twine upload dist/*
```

The package metadata (`pyproject.toml`) is stable from 1.0.0 on: the name
`brushpass`, the `brushpass` console script, and the `BRUSHPASS_DATA_DIR`
contract do not change without a major version.

## License

MIT License. See LICENSE file.
