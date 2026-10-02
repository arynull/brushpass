# brushpass — Threat Model

What brushpass protects, from whom, and what it explicitly does not
promise. If you operate brushpass, read this before trusting it.

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Ephemeral tokens (plaintext) | Nowhere at rest. Issued once at `mint`, then only in the operator's hands | SHA-256 hashes in `tokens.json`; the plaintext is never written to disk by brushpass |
| Root credentials (long-lived upstream secrets) | `credentials.json`, Fernet-encrypted (AES-128-CBC + HMAC-SHA256) | Data key in `credentials.key` (0600); never logged, never in argv |
| Scanner key | `scanner.key` (0600) | Lets an attacker *test guesses*, never recover tokens |
| Audit signing key | `audit.key` (0600), Ed25519 seed | Tamper-evidence for the audit log |
| Audit log | `audit.log`, hash-chained + signed | Any edit, deletion, or reorder of records is detected by `audit verify`, which names the exact first-broken sequence. Wiping the log to empty is detected (an existing-but-empty log file is TAMPERED); deleting the file outright is detected while the signing key survives (a key with no log is TAMPERED). Only a never-used state dir verifies clean as "0 records" |
| Rotation journal | `journal.jsonl`, append-only | Crash recovery: a killed rotation is visible in `rotate --status`, never silent |

## Trust boundaries

1. **The state directory** (`~/.brushpass/`, mode 0700, files 0600) is the
   trust root. Everything inside it is trusted; everything outside is
   not. An attacker who can read the whole directory recovers root
   credentials (key + ciphertext sit side by side) — this is
   encryption-at-rest against disclosure of a *single* artefact or a
   backup, not against full account compromise.
2. **The operator's shell.** Secrets enter via stdin or `--from-env`,
   never argv (argv is world-readable in `ps` and shell history).
3. **Provider APIs.** The only network brushpass ever makes is to
   user-configured provider endpoints during rotation.
4. **The OS clock.** Token expiry is wall-clock expiry. A machine whose
   clock is rolled back past a token's issuance will read an expired
   token as valid again. There is no defence against a hostile clock
   below the OS; NTP/authenticated time is an operator responsibility.

## Attacker capabilities assumed

- Can present arbitrary strings to `verify` (forgery, truncation,
  bit-flips, wrong prefixes).
- Can request any scope string (injection, unicode, case games,
  wildcard abuse — the scope grammar rejects all of these at parse).
- Can read any brushpass *output* (help, errors, JSON, scan reports):
  no plaintext secret may appear there. Audit denials record hashes,
  never the presented string.
- Can kill any process at any time (`kill -9` mid-handoff, mid-rotation):
  the handoff token is revoked by signal handlers and, failing that,
  bounded by its TTL; a killed rotation stays visible in the journal as
  needing attention.
- Can race concurrent operations (two rotations, rotation vs mint):
  atomic saves use unique temp files; the journal is append-only.
- Can tamper with `audit.log` offline: detected at the exact sequence.
- Can plant obfuscated token copies (base64, split lines, binary):
  the scanner's three passes catch raw, base64 (padding optional), and
  whitespace-split copies. Deliberately mangled copies (junk characters
  inserted *inside* the token) are a documented limitation, not a miss.

## What brushpass does NOT defend against

- **Full compromise of the account running brushpass.** Read the state
  dir and you hold the keys. Use full-disk encryption and keep the
  account clean.
- **A hostile or backdoored provider API.** Rotation trusts the
  provider's responses; a lying provider can hand you a dead "new"
  secret. Verify out-of-band for high-value credentials.
- **Memory forensics.** Plaintext tokens and secrets exist in process
  memory while in use. brushpass does not mlock/mlockall or scrub
  aggressively; a cold-boot or ptrace attacker is out of scope.
- **Side channels.** No constant-time guarantees beyond digest
  comparison; timing attacks against local verification are out of scope.
- **Determined obfuscation of leaked tokens.** See the scanner's
  documented limitations in the README.
- **Clock attacks.** See trust boundary 4.

## Residual risks (accepted)

1. `verify` successes are not audited (only denials) — a deliberate
   sampling choice; the log stays a forensic record of refusals.
2. Pre-v0.3.0 tokens have no fingerprint and cannot be scan-matched;
   they are reported as UNSCANNABLE, not silently covered.
3. The `manual` provider cannot revoke upstream; rotation reports this
   instead of pretending.
4. Webhook notifications are best-effort; a failed webhook never fails
   a rotation.

## Security contacts

This is a personal open-source project. Report vulnerabilities by
opening a GitHub issue on `rayanalpha/brushpass` — do not include live
credentials in the report.
