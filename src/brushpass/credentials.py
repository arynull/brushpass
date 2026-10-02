"""Root credential store: the long-lived secrets brushpass rotates.

Tokens (v0.1.0-v0.3.0) are ephemeral and stored as SHA-256 hashes: the
plaintext never touches disk, because there is nothing to recover when it
leaks — you mint a new one. A *root credential* is the opposite case. It
is a long-lived upstream secret (a GitHub App key, an internal service
token) that brushpass must be able to **re-use and hand onward**, so
hash-only storage would make it useless. Those secrets are therefore
encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256, from
``cryptography``) rather than stored in the clear.

The data key lives at ``<state-dir>/credentials.key``, mode 0600, and is
refused — never auto-repaired — if it is readable by group or other,
exactly like the scanner key. The ciphertext file
(``<state-dir>/credentials.json``) is 0600 as well.

Threat model, stated plainly:

* An attacker who reads the ciphertext file without the key gets Fernet
  tokens and nothing else.
* An attacker who reads *both* files (they sit in the same directory,
  both 0600, same as the scanner key) recovers the plaintext. This is
  encryption-at-rest against disclosure of a single artefact or a
  backup, not against full compromise of the account running brushpass.
  Protecting the directory from that is `0700`, which the store enforces.

Secret ingestion never touches argv: ``credential add`` reads the secret
from stdin or from a named environment variable, because argv is world
readable in ``ps`` and in shell history.
"""

import hashlib
import hmac
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


def _fernet_types():
    """Import the Fernet primitives on demand.

    ``cryptography`` is a hard dependency of ``credential add``, but not
    of ``mint``, ``verify`` or ``scan`` — a scrubbed environment running
    ``brushpass scan`` (a CI gate, a pre-commit hook) should not fail on
    an import it never uses. Keeping it lazy means the dependency is paid
    for exactly where a secret is actually encrypted, and nowhere else.
    """
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError as exc:
        raise CredentialError(
            "Storing root credentials needs the 'cryptography' package "
            "(pip install 'cryptography>=42'). Minting, verifying and "
            "scanning tokens do not."
        ) from exc
    return Fernet, InvalidToken

CREDENTIALS_KEY_NAME = "credentials.key"
CREDENTIALS_FILE_NAME = "credentials.json"
CREDENTIALS_KEY_MODE = 0o600
CREDENTIALS_FILE_MODE = 0o600

# Labels become dict keys and appear in journal entries, so they are held
# to a conservative shape: no separators, no traversal, no control
# characters. 1-64 chars, [A-Za-z0-9._-].
LABEL_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

MAX_SECRET_BYTES = 64 * 1024


class CredentialError(Exception):
    """A credential cannot be stored, read, or removed."""


class CredentialKeyError(CredentialError):
    """The credential data key is missing, malformed, or too widely readable."""


def validate_label(label: str) -> str:
    """Validate a credential label and return it stripped.

    Raises:
        CredentialError: if the label is empty, too long, or contains
            anything outside ``[A-Za-z0-9._-]``.
    """
    candidate = (label or "").strip()
    if not candidate:
        raise CredentialError("Credential label cannot be empty")
    if not LABEL_PATTERN.match(candidate):
        raise CredentialError(
            f"Invalid credential label: '{label}'. Use 1-64 characters from "
            "[A-Za-z0-9._-] — no spaces, slashes, or colons, so a label is "
            "safe to use as a storage key and in a journal entry"
        )
    if candidate in {".", ".."}:
        raise CredentialError(f"Invalid credential label: '{label}'")
    return candidate


def validate_secret(secret: str) -> str:
    """Validate a root secret and return it with trailing newline stripped.

    Raises:
        CredentialError: if it is empty or implausibly large. A secret is
            not length-limited in practice; 64 KiB is generous while
            still refusing to buffer a mis-piped file.
    """
    if secret is None:
        raise CredentialError("Secret is empty")
    value = secret.strip()
    if not value:
        raise CredentialError(
            "Secret is empty. Paste the secret on one line, or set the "
            "environment variable named by --from-env"
        )
    if "\0" in value:
        raise CredentialError("Secret contains a NUL byte")
    if len(value.encode()) > MAX_SECRET_BYTES:
        raise CredentialError(
            f"Secret is larger than {MAX_SECRET_BYTES} bytes; refusing to store it"
        )
    return value


def secret_digest(secret: str) -> str:
    """SHA-256 of a secret, stored so a rotation can be seen to have changed it.

    This is a one-way digest, exactly like the token store's: it proves
    *the secret changed* without being able to recover it. Comparison is
    constant-time so a comparison cannot leak the digest byte by byte.
    """
    return hashlib.sha256(secret.encode()).hexdigest()


def digests_equal(left: str, right: str) -> bool:
    """Constant-time digest comparison."""
    return hmac.compare_digest(left, right)


@dataclass(frozen=True)
class CredentialRecord:
    """Metadata about a stored root credential. Never holds plaintext."""

    label: str
    provider: str
    added_at: datetime
    secret_id: str
    secret_digest: str
    rotated_at: datetime | None = None
    rotation_count: int = 0
    config: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "provider": self.provider,
            "added_at": self.added_at.isoformat(),
            "secret_id": self.secret_id,
            "secret_digest": self.secret_digest,
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "rotation_count": self.rotation_count,
            "config": self.config,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CredentialRecord":
        return cls(
            label=data["label"],
            provider=data["provider"],
            added_at=datetime.fromisoformat(data["added_at"]),
            secret_id=data["secret_id"],
            secret_digest=data["secret_digest"],
            rotated_at=(
                datetime.fromisoformat(data["rotated_at"]) if data.get("rotated_at") else None
            ),
            rotation_count=int(data.get("rotation_count", 0)),
            config=dict(data.get("config") or {}),
        )


def load_data_key(data_dir: Path) -> bytes:
    """Load the Fernet data key, creating it on first use.

    Raises:
        CredentialKeyError: if it cannot be created or read, is not a
            valid Fernet key, or is readable by group or other. The last
            case is fail-closed and never auto-repaired, mirroring the
            scanner key: a key that became world-readable means something
            else on this machine had a reason to look at it, and
            brushpass will not silently re-establish trust.
    """
    path = data_dir / CREDENTIALS_KEY_NAME

    if not path.exists():
        return _create_data_key(path)

    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise CredentialKeyError(
            f"Refusing to run: credential key {path} has mode {mode:04o}, which "
            "is readable by group or others. Fix it with: "
            f"chmod 0600 {path}"
        )

    try:
        key = path.read_bytes().strip()
    except OSError as exc:
        raise CredentialKeyError(f"Cannot read credential key {path}: {exc}") from exc

    if not key:
        raise CredentialKeyError(
            f"Refusing to run: credential key {path} is empty. Restore a valid "
            "backup, or remove the file to generate a new key. Existing secrets "
            "cannot be decrypted with a new key — they must be re-added"
        )
    return key


def _create_data_key(path: Path) -> bytes:
    """Create a fresh Fernet key with 0600 permissions."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, CREDENTIALS_KEY_MODE)
    except FileExistsError:
        # Another brushpass won the race; use whatever it wrote.
        return load_data_key(path.parent)
    except OSError as exc:
        raise CredentialKeyError(f"Cannot create credential key {path}: {exc}") from exc

    fernet_cls, _ = _fernet_types()
    key = fernet_cls.generate_key()
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
    except OSError as exc:
        path.unlink(missing_ok=True)
        raise CredentialKeyError(f"Cannot write credential key {path}: {exc}") from exc

    # os.open's mode is masked by umask; force the mode we promised.
    try:
        path.chmod(CREDENTIALS_KEY_MODE)
    except OSError as exc:
        raise CredentialKeyError(f"Cannot set permissions on {path}: {exc}") from exc

    return key


class CredentialStore:
    """Encrypted, at-rest storage for root credentials.

    Mirrors :class:`~brushpass.store.TokenStore` (same directory, same
    0700/0600 enforcement, same temp-file-then-rename atomic write) so the
    two halves of brushpass fail the same way and are debugged the same
    way.
    """

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.credentials_file = data_dir / CREDENTIALS_FILE_NAME
        self.key_path = data_dir / CREDENTIALS_KEY_NAME
        self._records: dict[str, CredentialRecord] = {}
        self._secrets: dict[str, str] = {}
        self._ciphertexts: dict[str, str] = {}
        self._ensure_storage()

    # ---- lifecycle ----------------------------------------------------

    def _ensure_storage(self) -> None:
        if not self.data_dir.exists():
            self.data_dir.mkdir(parents=True, mode=0o700)
        else:
            self.data_dir.chmod(0o700)

        if self.credentials_file.exists():
            mode = self.credentials_file.stat().st_mode & 0o777
            if mode != CREDENTIALS_FILE_MODE:
                self.credentials_file.chmod(CREDENTIALS_FILE_MODE)
            self._load()
        else:
            # Write an empty file so the store exists with a known shape.
            self._save()

    def _load(self) -> None:
        try:
            raw = json.loads(self.credentials_file.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise CredentialError(f"Failed to load credentials: {exc}") from exc

        key = load_data_key(self.data_dir)
        records: dict[str, CredentialRecord] = {}
        secrets: dict[str, str] = {}
        ciphertexts: dict[str, str] = {}
        try:
            entries = raw.get("credentials", [])
        except AttributeError as exc:
            raise CredentialError(
                f"Credential store {self.credentials_file} is malformed: "
                "expected a JSON object with a 'credentials' list"
            ) from exc

        for entry in entries:
            record = CredentialRecord.from_dict(entry)
            ciphertext = entry.get("ciphertext", "")
            records[record.label] = record
            ciphertexts[record.label] = ciphertext
            secrets[record.label] = self._decrypt(ciphertext, key, record.label)

        self._records = records
        self._secrets = secrets
        self._ciphertexts = ciphertexts

    def _save(self) -> None:
        """Write the store atomically: unique temp file, then replace.

        The temp name is unique per call (mkstemp): two writers sharing
        one state dir must never share a temp name, or one can rename
        the other's file away mid-write and the loser crashes with
        FileNotFoundError — exactly the failure a rotation racing a
        mint used to hit. mkstemp creates the file mode 0600 already.
        """
        data = {
            "version": 1,
            "credentials": [
                {**record.to_dict(), "ciphertext": self._ciphertexts.get(record.label, "")}
                for record in self._records.values()
            ],
        }
        fd, temp_name = tempfile.mkstemp(
            dir=self.data_dir, prefix=".credentials-", suffix=".tmp"
        )
        temp_file = Path(temp_name)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(data, indent=2))
            os.replace(temp_file, self.credentials_file)
        except OSError as exc:
            temp_file.unlink(missing_ok=True)
            raise CredentialError(f"Failed to save credentials: {exc}") from exc

    # ---- crypto helpers ----------------------------------------------

    def _fernet(self):
        fernet_cls, _ = _fernet_types()
        return fernet_cls(load_data_key(self.data_dir))

    def _decrypt(self, ciphertext: str, key: bytes, label: str) -> str:
        fernet_cls, invalid_token = _fernet_types()
        try:
            return fernet_cls(key).decrypt(ciphertext.encode()).decode()
        except (invalid_token, ValueError, UnicodeDecodeError) as exc:
            raise CredentialError(
                f"Cannot decrypt credential '{label}'. The ciphertext does not "
                "match the data key, so either the key was rotated away or the "
                "store was tampered with. brushpass will not continue with a "
                "secret it cannot read"
            ) from exc

    def _encrypt(self, secret: str, label: str) -> str:
        try:
            return self._fernet().encrypt(secret.encode()).decode()
        except Exception as exc:  # noqa: BLE001 - surfaced as CredentialError
            raise CredentialError(f"Failed to encrypt credential '{label}': {exc}") from exc

    # ---- public API ---------------------------------------------------

    def add(
        self,
        label: str,
        provider: str,
        secret: str,
        config: dict | None = None,
        now: datetime | None = None,
    ) -> CredentialRecord:
        """Store a new root credential, encrypted at rest.

        Raises:
            CredentialError: on a duplicate label or a bad label/secret.
        """
        label = validate_label(label)
        secret = validate_secret(secret)
        if label in self._records:
            raise CredentialError(
                f"Credential '{label}' already exists. Rotate it with "
                f"'brushpass rotate {label}', or remove it first with "
                f"'brushpass credential remove {label}'"
            )

        record = CredentialRecord(
            label=label,
            provider=provider,
            added_at=now or datetime.now(UTC),
            secret_id=secret_digest(secret)[:12],
            secret_digest=secret_digest(secret),
            config=dict(config or {}),
        )
        # Encrypt first: an encryption failure must not leave a metadata
        # entry in memory that has no secret behind it.
        ciphertext = self._encrypt(secret, label)
        self._ciphertexts[label] = ciphertext
        self._secrets[label] = secret
        try:
            self._commit(record)
        except CredentialError:
            self._ciphertexts.pop(label, None)
            self._secrets.pop(label, None)
            raise
        return record

    def get(self, label: str) -> CredentialRecord:
        """Return a record's metadata (never its plaintext).

        Raises:
            CredentialError: if the label is unknown.
        """
        record = self._records.get(label)
        if record is None:
            raise CredentialError(
                f"No credential labelled '{label}'. See 'brushpass credential list'"
            )
        return record

    def get_secret(self, label: str) -> str:
        """Return the decrypted secret.

        Only the rotation engine and provider config paths need this; it
        is never rendered by a listing command.

        Raises:
            CredentialError: if the label is unknown or unreadable.
        """
        if label not in self._records:
            raise CredentialError(
                f"No credential labelled '{label}'. See 'brushpass credential list'"
            )
        return self._secrets[label]

    def list_all(self) -> list[CredentialRecord]:
        """All records, oldest first, metadata only."""
        return sorted(self._records.values(), key=lambda r: r.added_at)

    def remove(self, label: str) -> CredentialRecord:
        """Delete a credential and its ciphertext.

        Raises:
            CredentialError: if the label is unknown. Callers that want a
                friendly exit code check ``has`` first.
        """
        record = self.get(label)
        if record is None:  # pragma: no cover - get() raises instead
            raise CredentialError(f"No credential labelled '{label}'")
        del self._records[label]
        self._secrets.pop(label, None)
        self._ciphertexts.pop(label, None)
        self._save()
        return record

    def replace_secret(
        self,
        label: str,
        new_secret: str,
        now: datetime | None = None,
    ) -> CredentialRecord:
        """Atomically swap in a rotated secret, keeping history.

        This is the step the whole rotation contract is built around: it
        either leaves the store fully readable with the new secret in
        place, or raises with the previous secret still live. The write is
        a temp file plus rename, so a crash mid-write cannot leave a
        half-updated store.

        Raises:
            CredentialError: if the label is unknown or the new secret is
                invalid — in both cases the old secret remains live.
        """
        record = self.get(label)
        new_secret = validate_secret(new_secret)
        updated = CredentialRecord(
            label=record.label,
            provider=record.provider,
            added_at=record.added_at,
            secret_id=secret_digest(new_secret)[:12],
            secret_digest=secret_digest(new_secret),
            rotated_at=now or datetime.now(UTC),
            rotation_count=record.rotation_count + 1,
            config=record.config,
        )
        # Encrypt before touching state, and let _commit roll memory back
        # if the write fails: either the new secret is fully live or the
        # old one is untouched. Never a half-updated store.
        previous_ciphertext = self._ciphertexts[label]
        previous_secret = self._secrets[label]
        self._ciphertexts[label] = self._encrypt(new_secret, label)
        self._secrets[label] = new_secret
        try:
            self._commit(updated)
        except CredentialError:
            self._ciphertexts[label] = previous_ciphertext
            self._secrets[label] = previous_secret
            raise
        return updated

    def set_config(self, label: str, config: dict) -> CredentialRecord:
        """Attach provider configuration to an existing credential."""
        record = self.get(label)
        updated = CredentialRecord(
            label=record.label,
            provider=record.provider,
            added_at=record.added_at,
            secret_id=record.secret_id,
            secret_digest=record.secret_digest,
            rotated_at=record.rotated_at,
            rotation_count=record.rotation_count,
            config=dict(config or {}),
        )
        self._commit(updated)
        return updated

    def has(self, label: str) -> bool:
        return label in self._records

    # ---- atomic commit ------------------------------------------------

    def _commit(self, record: CredentialRecord) -> None:
        """Make ``record`` the live state for its label, atomically.

        On-disk first, then memory. If the write fails, both the file and
        the in-memory maps are left untouched, so the secret that was live
        a moment ago is still the secret that is live now. That property
        is the reason :meth:`replace_secret` is safe to retry.
        """
        ciphertext = self._ciphertexts.get(record.label)
        if ciphertext is None:
            raise CredentialError(
                f"Internal error: no ciphertext held for '{record.label}'"
            )
        previous_record = self._records.get(record.label)
        previous_secret = self._secrets.get(record.label)

        self._records[record.label] = record
        try:
            self._save()
        except CredentialError:
            # Roll memory back to whatever the file still holds.
            if previous_record is None:
                self._records.pop(record.label, None)
            else:
                self._records[record.label] = previous_record
            if previous_secret is None:
                self._secrets.pop(record.label, None)
            else:
                self._secrets[record.label] = previous_secret
            raise
