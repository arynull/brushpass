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
readable in ``ps`` and in shell history. The same rule covers *provider
config*: a secret-shaped ``--set`` value must arrive as ``env:VARNAME``,
which is resolved from the environment at add time and stored encrypted —
never as a literal on the command line.

Config follows the same three faces:

* it enters non-argv (``env:`` interpolation), so no live secret is ever
  world-readable in ``/proc/<pid>/cmdline`` or in shell history;
* it is redacted out of every rendered record, so no output carries
  secret material; and
* it is Fernet-encrypted at rest alongside the root secret, so
  ``credentials.json`` holds no plaintext provider credential.
"""

import hashlib
import hmac
import json
import os
import re
import tempfile
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

from .models import TOKEN_MATERIAL_PATTERN


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

# The marker every redaction path uses: audit records, scan-report
# locations and rendered credential config all say exactly this, so one
# redacted string means one thing across the whole tool.
REDACTED = "<redacted>"

# Config keys whose *value* is a secret. Matched case-insensitively
# against each segment of a key, so a dot-path like
# ``headers.X-Vault-Token`` and a nested ``{"client_secret": ...}`` are
# both caught. Deliberately a name list rather than a value test: a URL
# and an org name are non-secrets that happen to be stored in config,
# while a key called ``token`` is a secret whatever it holds.
SECRET_CONFIG_KEY_PARTS = frozenset(
    {
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "bearer",
        "authorization",
        "api_key",
        "apikey",
        "private_key",
        "privatekey",
        "client_secret",
    }
)

# Config keys whose value is *not* a secret even though they are named
# like one. Without this, ``old_secret_header`` (a header *name*, checked
# by the generic-http provider) and ``new_secret_path`` (a JSON pointer)
# would be encrypted and redacted as though they carried live material,
# which hides the provider config an operator needs to debug a rotation.
SECRET_CONFIG_KEY_EXEMPT = frozenset(
    {
        "old_secret_header",
        "old_secret_query",
        "new_secret_path",
        "old_secret_placement",
    }
)

# A config key segment is compared after stripping separators, so
# ``X-Vault-Token``, ``x_vault_token`` and ``vault-token`` all reduce to
# the same word.
_KEY_SPLIT = re.compile(r"[.\-_/]+")


def _key_segments(key: str) -> list[str]:
    """Split a (possibly dotted) config key into lower-cased segments."""
    return [segment for segment in _KEY_SPLIT.split(key.lower()) if segment]


def is_secret_config_key(key: str) -> bool:
    """True if a config key names a secret value.

    An exempt key (``old_secret_header`` and friends) is checked first,
    so a config that names the *location* of a secret stays readable; a
    path whose other segments are secret-ish is still secret-ish, since
    the exemption is for the whole key and not for its parts.

    The whole key is checked as well as its segments: ``api_key`` must
    match even though splitting on separators would break it into
    ``api`` + ``key``, neither of which is secret-ish on its own.
    """
    lowered = key.lower()
    if lowered in SECRET_CONFIG_KEY_EXEMPT:
        return False
    if lowered in SECRET_CONFIG_KEY_PARTS:
        return True
    return any(segment in SECRET_CONFIG_KEY_PARTS for segment in _key_segments(key))


def is_secret_config_value(value: object) -> bool:
    """True if a config *value* is shaped like secret material.

    The same pattern the audit writer and the scan report redact with
    (``TOKEN_MATERIAL_PATTERN``), so one definition of "this looks like
    a token" governs redaction on every path.
    """
    return isinstance(value, str) and bool(TOKEN_MATERIAL_PATTERN.search(value))


def split_config(config: dict) -> tuple[dict, dict]:
    """Split a config mapping into (plaintext, secret) halves.

    A value is secret when its key names a secret or its value is
    token-shaped. Nested mappings are walked so ``headers`` keeps its
    shape on both sides: ``{"headers": {"X-Vault-Token": ...}}``
    becomes ``{"headers": {}}`` plus ``{"headers": {"X-Vault-Token": ...}}``.

    Raises:
        CredentialError: if config is not a mapping.
    """
    if not isinstance(config, dict):
        raise CredentialError(
            f"Credential config must be a mapping, got {type(config).__name__}"
        )
    plain: dict = {}
    secret: dict = {}
    for key, value in config.items():
        name = str(key)
        if isinstance(value, dict):
            nested_plain, nested_secret = split_config(value)
            if is_secret_config_key(name):
                # The whole subtree is secret: keep it intact on the
                # secret side so it merges back exactly as supplied.
                secret[name] = value
                plain[name] = {}
            else:
                plain[name] = nested_plain
                if nested_secret:
                    secret[name] = nested_secret
            continue
        if is_secret_config_key(name) or is_secret_config_value(value):
            secret[name] = value
        else:
            plain[name] = value
    return plain, secret


def merge_config(plain: dict, secret: dict) -> dict:
    """Recombine the two halves of a split config into one mapping."""
    merged = dict(plain or {})
    for key, value in (secret or {}).items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_config(merged[key], value)
        else:
            merged[key] = value
    return merged


def redact_config(config: dict) -> dict:
    """Replace every secret config value with ``<redacted>``.

    Key shape decides first, then value shape, exactly as
    :func:`split_config` decides what gets encrypted — so a value that
    would be stored encrypted is never rendered. Non-secret config
    (URLs, paths, placement names) stays visible, because a listing
    that hides everything is useless for debugging a rotation.
    """
    if not isinstance(config, dict):
        return config
    out: dict = {}
    for key, value in config.items():
        name = str(key)
        if isinstance(value, dict):
            out[key] = redact_config(value)
        elif is_secret_config_key(name) or is_secret_config_value(value):
            out[key] = REDACTED
        else:
            out[key] = value
    return out


class CredentialError(Exception):
    """A credential cannot be stored, read, or removed."""


class CredentialKeyError(CredentialError):
    """The credential data key is missing, malformed, or too widely readable."""


def validate_label(label: str) -> str:
    """Validate a credential label and return it stripped.

    Raises:
        CredentialError: if the label is empty, too long, contains
            anything outside ``[A-Za-z0-9._-]``, or is shaped like a token.
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
    if TOKEN_MATERIAL_PATTERN.search(candidate):
        # A token-shaped credential label would make the audit writer
        # refuse the nuke record naming it, leaving the break-glass
        # without a forensic trace. Fail closed at input.
        raise CredentialError(
            f"Invalid credential label: '{label}'. Labels must not contain "
            "anything shaped like a brushpass token (the 'bp_' prefix is "
            "reserved for tokens)"
        )
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
        """Render for output. Secret config values are redacted.

        Every renderer reaches a record through this method — ``credential
        list --json``, ``credential add --json``, anything that prints a
        credential — so redacting here is what keeps secret material out of
        brushpass output. Storage does *not* use this method; it uses
        :meth:`_to_storage_dict`, which writes the plaintext config half
        only. Never call this to persist a record.
        """
        return self._as_dict(redact=True)

    def _to_storage_dict(self) -> dict:
        """Serialize for on-disk storage.

        Does not redact: ``config`` here is the *public* half of the split
        (see :func:`split_config`), so every value in it is already
        non-secret by construction. The secret half is encrypted
        separately and written alongside by :meth:`CredentialStore._save`.
        """
        return self._as_dict(redact=False)

    def _as_dict(self, redact: bool) -> dict:
        return {
            "label": self.label,
            "provider": self.provider,
            "added_at": self.added_at.isoformat(),
            "secret_id": self.secret_id,
            "secret_digest": self.secret_digest,
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "rotation_count": self.rotation_count,
            "config": redact_config(self.config) if redact else self.config,
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
    try:
        # Validate the shape now: a truncated or corrupted key must fail
        # here as CredentialKeyError, not deep inside an encrypt/decrypt
        # call as a bare ValueError. This is the "not a valid Fernet key"
        # case the docstring promises.
        _fernet_types()[0](key)
    except ValueError as exc:
        raise CredentialKeyError(
            f"Refusing to run: credential key {path} is not a valid Fernet "
            f"key ({exc}). Restore a valid backup, or remove the file to "
            "generate a new key"
        ) from exc
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
        # Decrypted secret halves of provider config, keyed by label.
        # Mirrors _secrets: plaintext lives here in memory only; _save
        # encrypts each half into the entry's "secret_config" field.
        self._secret_configs: dict[str, dict] = {}
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

        secret_configs: dict[str, dict] = {}
        needs_migration = False
        for entry in entries:
            record = CredentialRecord.from_dict(entry)
            ciphertext = entry.get("ciphertext", "")
            records[record.label] = record
            ciphertexts[record.label] = ciphertext
            secrets[record.label] = self._decrypt(ciphertext, key, record.label)
            secret_half = self._decrypt_secret_config(
                entry.get("secret_config", ""), key, record.label
            )
            # v1 migration: the plaintext "config" of an old entry may
            # still hold secret entries. Pull them into the encrypted
            # half; v2 entries already store only the public half, so
            # split_config finds nothing and this is a no-op for them.
            plain_half, found_secret = split_config(record.config)
            if found_secret:
                secret_half = merge_config(secret_half, found_secret)
                records[record.label] = replace(record, config=plain_half)
                needs_migration = True
            secret_configs[record.label] = secret_half

        self._records = records
        self._secrets = secrets
        self._ciphertexts = ciphertexts
        self._secret_configs = secret_configs
        if needs_migration:
            # The secrets are encrypted in memory above; write them back
            # now so the plaintext leaves the disk on this load. If the
            # write fails we raise rather than continue with secrets we
            # could not persist.
            self._save()

    def _decrypt_secret_config(
        self, raw_ciphertext: str, key: bytes, label: str
    ) -> dict:
        """Decrypt a credential entry's secret config half.

        Empty (or missing) means the entry has no secret config.
        Decryption failure is fail-closed — same as a bad root-secret
        ciphertext, brushpass will not run with config it cannot read.
        """
        if not raw_ciphertext:
            return {}
        try:
            decoded = self._decrypt(raw_ciphertext, key, label)
            parsed = json.loads(decoded)
        except (CredentialError, json.JSONDecodeError) as exc:
            raise CredentialError(
                f"Cannot decrypt config for credential '{label}'. The "
                "ciphertext does not match the data key, so either the "
                "key was rotated away or the store was tampered with. "
                "brushpass will not continue with config it cannot read"
            ) from exc
        if not isinstance(parsed, dict):
            raise CredentialError(
                f"Credential store {self.credentials_file} is malformed: "
                f"secret config for '{label}' is not a mapping"
            )
        return parsed

    def _save(self) -> None:
        """Write the store atomically: unique temp file, then replace.

        The temp name is unique per call (mkstemp): two writers sharing
        one state dir must never share a temp name, or one can rename
        the other's file away mid-write and the loser crashes with
        FileNotFoundError — exactly the failure a rotation racing a
        mint used to hit. mkstemp creates the file mode 0600 already.
        """
        data = {
            "version": 2,
            "credentials": [
                {
                    **record._to_storage_dict(),
                    "ciphertext": self._ciphertexts.get(record.label, ""),
                    "secret_config": self._encrypt_secret_config(record.label),
                }
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

        # Split provider config: the public half lives on the record in
        # plaintext, the secret half is encrypted at rest. Split before
        # encrypting anything, so a bad config never leaves a ciphertext
        # behind.
        plain_config, secret_half = split_config(dict(config or {}))
        record = CredentialRecord(
            label=label,
            provider=provider,
            added_at=now or datetime.now(UTC),
            secret_id=secret_digest(secret)[:12],
            secret_digest=secret_digest(secret),
            config=plain_config,
        )
        # Encrypt first: an encryption failure must not leave a metadata
        # entry in memory that has no secret behind it.
        ciphertext = self._encrypt(secret, label)
        self._ciphertexts[label] = ciphertext
        self._secrets[label] = secret
        self._secret_configs[label] = secret_half
        try:
            self._commit(record)
        except CredentialError:
            self._ciphertexts.pop(label, None)
            self._secrets.pop(label, None)
            self._secret_configs.pop(label, None)
            raise
        return record

    def _encrypt_secret_config(self, label: str) -> str:
        """Encrypt a label's secret config half for storage.

        Returns "" when the label has no secret config, keeping the file
        readable. Encryption failure raises CredentialError — _save must
        never write a store it cannot fully protect.
        """
        secret_half = self._secret_configs.get(label) or {}
        if not secret_half:
            return ""
        return self._encrypt(json.dumps(secret_half, sort_keys=True), label)

    def get_config(self, label: str) -> dict:
        """Return the full provider config for a label.

        The public half from the record merged with the decrypted secret
        half. This is the only path providers should read config through;
        ``record.config`` alone is the public half and must never be
        treated as complete.
        """
        record = self.get(label)
        return merge_config(record.config, self._secret_configs.get(label) or {})

    def render_record(self, label: str) -> dict:
        """Display rendering of a credential for CLI output.

        Unlike ``record.to_dict()`` — which only sees the public half —
        this shows every configured key with secret values replaced by
        ``<redacted>``, so an operator debugging a rotation can see
        *what* is configured without ever seeing live material.
        """
        record = self.get(label)
        rendered = record.to_dict()
        rendered["config"] = redact_config(self.get_config(label))
        return rendered

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
        self._secret_configs.pop(label, None)
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
        """Attach provider configuration to an existing credential.

        The config is split like in :meth:`add`: secret entries are
        encrypted at rest, the public half stays on the record.
        """
        record = self.get(label)
        plain_config, secret_half = split_config(dict(config or {}))
        previous_secret_config = self._secret_configs.get(label)
        self._secret_configs[label] = secret_half
        updated = replace(
            record,
            config=plain_config,
        )
        try:
            self._commit(updated)
        except CredentialError:
            if previous_secret_config is None:
                self._secret_configs.pop(label, None)
            else:
                self._secret_configs[label] = previous_secret_config
            raise
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
        previous_secret_config = self._secret_configs.get(record.label)

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
            if previous_secret_config is None:
                self._secret_configs.pop(record.label, None)
            else:
                self._secret_configs[record.label] = previous_secret_config
            raise
