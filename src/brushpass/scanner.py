"""Scanner key management for brushpass leak detection.

Leak detection needs to answer one question about an arbitrary string found
on disk: *is this one of the tokens brushpass issued?* A plain SHA-256 hash
cannot answer it from a stored fingerprint database, because the token
plaintext is never persisted anywhere.

A keyed fingerprint can. At mint time brushpass computes

    fingerprint = HMAC-SHA256(token_plaintext, scanner_key)

and stores only that. Scanning recomputes the same HMAC for every candidate
string it finds and compares against the stored fingerprints. A string
brushpass never issued simply does not match, so it is discarded with no
false positive; a string brushpass did issue matches exactly.

The scanner key is a 256-bit secret stored at ``<state-dir>/scanner.key``
with mode 0600. It is *not* a second copy of the tokens: possessing it lets
an attacker test guesses, never recover an issued token (that would require
the token's own 256 bits of entropy). Losing it does not endanger existing
tokens — it only makes the fingerprints unverifiable, and tokens already
minted keep working.
"""

import hmac
import os
import secrets
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

SCANNER_KEY_NAME = "scanner.key"
SCANNER_KEY_BYTES = 32  # 256 bits
SCANNER_KEY_MODE = 0o600

# Fingerprints are truncated to 128 bits of the HMAC digest: collision
# resistance far beyond any realistic token count, and short enough that a
# fingerprint in a report is still useful to a human.
FINGERPRINT_CHARS = 32


class ScannerKeyError(Exception):
    """The scanner key is missing, malformed, or too widely readable."""


@dataclass(frozen=True)
class Scanner:
    """A loaded scanner key, able to fingerprint and match tokens."""

    key: bytes
    path: Path

    def fingerprint(self, plaintext_token: str) -> str:
        """Return the stored fingerprint for a plaintext token."""
        digest = hmac.new(
            self.key, plaintext_token.encode(), sha256
        ).hexdigest()
        return digest[:FINGERPRINT_CHARS]

    def matches(self, plaintext_token: str, fingerprint: str) -> bool:
        """Constant-time check of a candidate against a stored fingerprint."""
        return hmac.compare_digest(self.fingerprint(plaintext_token), fingerprint)


def load_scanner(data_dir: Path) -> Scanner:
    """Load the scanner key for ``data_dir``, creating it on first use.

    Raises:
        ScannerKeyError: if the key cannot be created, cannot be read, is
            the wrong length, or is readable by group or other. The last
            case is fail-closed and never auto-repaired: an overly
            permissive key means something else on this machine has had a
            legitimate reason to look at it, and brushpass will not guess.
    """
    path = data_dir / SCANNER_KEY_NAME

    if not path.exists():
        return _create_scanner_key(path)

    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise ScannerKeyError(
            f"Refusing to run: scanner key {path} has mode {mode:04o}, which is "
            "readable by group or others. Fix it with: "
            f"chmod 0600 {path}"
        )

    try:
        key = path.read_bytes()
    except OSError as exc:
        raise ScannerKeyError(f"Cannot read scanner key {path}: {exc}") from exc

    if len(key) != SCANNER_KEY_BYTES:
        raise ScannerKeyError(
            f"Refusing to run: scanner key {path} is {len(key)} bytes, expected "
            f"{SCANNER_KEY_BYTES} (256 bits). Restore a valid backup or remove "
            "the file to generate a new key; existing tokens keep working either "
            "way, but fingerprints will no longer verify"
        )

    return Scanner(key=key, path=path)


def _create_scanner_key(path: Path) -> Scanner:
    """Create a fresh scanner key with 0600 permissions."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, SCANNER_KEY_MODE)
    except FileExistsError:
        # Another brushpass won the race; use whatever it wrote.
        return load_scanner(path.parent)
    except OSError as exc:
        raise ScannerKeyError(f"Cannot create scanner key {path}: {exc}") from exc

    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(SCANNER_KEY_BYTES))
    except OSError as exc:
        path.unlink(missing_ok=True)
        raise ScannerKeyError(f"Cannot write scanner key {path}: {exc}") from exc

    # os.open's mode is masked by umask; force the mode we promised.
    try:
        path.chmod(SCANNER_KEY_MODE)
    except OSError as exc:
        raise ScannerKeyError(f"Cannot set permissions on {path}: {exc}") from exc

    return load_scanner(path.parent)
