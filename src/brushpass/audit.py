"""Tamper-evident audit log for brushpass.

Everything security-relevant brushpass does — minting, revoking, expiry,
a leak found on disk, a rotation starting and finishing, a credential
added or removed, a nuke — is written to ``<state-dir>/audit.log`` as
JSON Lines, append-only, mode ``0600``.

The file is not just a log. A plain log can be edited: an attacker with
write access deletes the line that shows them minting a token, and the
record of the compromise disappears. So every record is *chained* and
*signed*:

``record_hash``
    SHA-256 over the canonical JSON of the record with ``record_hash`` and
    ``signature`` removed. Canonical means sorted keys and no whitespace,
    so two runs that produce the same facts produce the same bytes.

    ``prev_hash`` is **inside** the preimage. That is deliberate: it makes
    each record commit to its own position in the chain, so a reordered
    or re-pointed link is caught at the record where it was touched
    rather than one later.

``signature``
    Ed25519 over the 32 bytes of ``record_hash``, under a per-install key
    at ``<state-dir>/audit.key`` (mode ``0600``), base64-encoded. A
    rewrite that leaves ``record_hash`` intact still fails here, because
    the attacker does not have the signing key.

``prev_hash``
    The previous record's ``record_hash``; all zeros for ``seq 0``. This
    is what makes the log a chain: changing record *k* invalidates every
    link after it, so a tamper cannot be silently repaired.

``brushpass audit verify`` replays the chain from ``seq 0`` and reports
the **first** broken sequence number, which is the only number an
incident responder actually needs.

What this does and does not prove, stated plainly:

* It proves the log has not been altered **by anyone without
  ``audit.key``**. The key sits in the same 0700 directory as the log,
  so this is tamper-evidence against disclosure of a single artefact, a
  backup, or another account on the box — the same boundary the encrypted
  credential store draws.
* It does **not** prove the log is complete. An attacker who can rewrite
  the whole file can truncate the tail, and no local structure can
  detect that: the chain is still internally consistent. To catch
  truncation, anchor the last ``record_hash`` somewhere the attacker
  cannot reach — ship it to a log collector, or keep it out of band.
  ``brushpass audit log`` prints the head hash of what it shows, for
  exactly this purpose.
* Deleting the log entirely also cannot be detected locally. Verify the
  file's existence in whatever monitoring you have; ``audit verify``
  reports a missing log as zero records, which is true of a fresh
  install and equally true of a deleted one.

**No secret material is ever written here.** Token plaintext is refused
outright — :func:`_reject_token_material` walks the details and raises if
any value looks like a brushpass token — and root secrets never reach
this module at all, because the code that holds them (the credential
store, the rotation engine) passes only labels and truncated digests.
"""

import base64
import fcntl
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

AUDIT_LOG_NAME = "audit.log"
AUDIT_KEY_NAME = "audit.key"
AUDIT_LOG_MODE = 0o600
AUDIT_KEY_MODE = 0o600
AUDIT_KEY_BYTES = 32  # an Ed25519 seed

# prev_hash of seq 0. A chain has to start somewhere, and "somewhere" is
# not a hash of anything.
GENESIS_HASH = "0" * 64

# `brushpass audit log` shows this many records unless told otherwise.
DEFAULT_TAIL = 50

# Fields excluded from the hash preimage: they *are* the hash.
_HASH_EXCLUDED = ("record_hash", "signature")

# Events. Dotted, lowercase, past-tense verbs, so the set reads as a list
# of things that happened rather than a set of nouns.
EVENT_TOKEN_MINT = "token.mint"
EVENT_TOKEN_REVOKE = "token.revoke"
EVENT_TOKEN_EXPIRE = "token.expire"
EVENT_VERIFY_DENIED = "token.verify_denied"
EVENT_LEAK_FOUND = "leak.found"
EVENT_CREDENTIAL_ADD = "credential.add"
EVENT_CREDENTIAL_REMOVE = "credential.remove"
EVENT_ROTATE_STARTED = "credential.rotate_started"
EVENT_ROTATE_FINISHED = "credential.rotate_finished"
EVENT_NUKE = "nuke"

EVENTS = (
    EVENT_TOKEN_MINT,
    EVENT_TOKEN_REVOKE,
    EVENT_TOKEN_EXPIRE,
    EVENT_VERIFY_DENIED,
    EVENT_LEAK_FOUND,
    EVENT_CREDENTIAL_ADD,
    EVENT_CREDENTIAL_REMOVE,
    EVENT_ROTATE_STARTED,
    EVENT_ROTATE_FINISHED,
    EVENT_NUKE,
)

# A brushpass token is `bp_` plus 43 URL-safe characters. Any value
# matching this is treated as live credential material and refused,
# which turns "do not log token plaintext" from a convention into an
# enforced invariant.
TOKEN_MATERIAL_PATTERN = re.compile(r"bp_[A-Za-z0-9_-]{20,}")

# `--since 24h`, `--since 7d`, ... Unlike a TTL this is unbounded: the
# question "what happened last week" has no ceiling.
SINCE_PATTERN = re.compile(r"^(?P<value>\d+)(?P<unit>[smhdw])$")
SINCE_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class AuditError(Exception):
    """The audit log could not be read, written, or trusted."""


class AuditKeyError(AuditError):
    """The audit signing key is missing, malformed, or too widely readable."""


class AuditVerifyError(AuditError):
    """The chain did not verify. Carries the first broken seq and why."""

    def __init__(self, reason: str, broken_seq: int | None, checked: int):
        super().__init__(reason)
        self.reason = reason
        self.broken_seq = broken_seq
        self.checked = checked


@dataclass(frozen=True)
class AuditRecord:
    """One chained, signed audit record."""

    seq: int
    ts_utc: str
    event: str
    details: dict
    prev_hash: str
    record_hash: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "ts_utc": self.ts_utc,
            "event": self.event,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditRecord":
        return cls(
            seq=int(data["seq"]),
            ts_utc=str(data["ts_utc"]),
            event=str(data["event"]),
            details=dict(data.get("details") or {}),
            prev_hash=str(data.get("prev_hash") or ""),
            record_hash=str(data.get("record_hash") or ""),
            signature=str(data.get("signature") or ""),
        )

    def describe(self) -> str:
        """One line, ``key=value`` pairs. Never contains secret material."""
        parts = [f"{key}={_scalar(value)}" for key, value in self.details.items()]
        return " ".join(parts) if parts else "-"


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of replaying the chain."""

    ok: bool
    records: int
    broken_seq: int | None = None
    reason: str | None = None
    # True when verification could not run at all — the signing key is
    # missing, unreadable, or has unsafe permissions. The log was NOT
    # checked, so this is not a tamper claim: "TAMPERED" would name a
    # broken sequence that was never examined, and backup advice would
    # send the operator chasing the wrong problem.
    error: bool = False

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "records": self.records,
            "broken_seq": self.broken_seq,
            "error": self.error,
            "reason": self.reason,
        }


# --------------------------------------------------------------------------
# Canonical form and hashing
# --------------------------------------------------------------------------


def canonical_json(payload: dict) -> str:
    """Serialise deterministically: sorted keys, no incidental whitespace.

    Two processes that agree on the facts must agree on the bytes, or a
    signature would mean nothing.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_preimage(record: dict) -> dict:
    """The record with its own hash and signature removed."""
    return {key: value for key, value in record.items() if key not in _HASH_EXCLUDED}


def compute_record_hash(record: dict) -> str:
    """SHA-256 over the canonical preimage of ``record``.

    Hashes *whatever keys are present* rather than a fixed field list, so
    a field injected into the JSON by an attacker changes the hash and is
    caught like any other edit.
    """
    payload = canonical_json(hash_preimage(record)).encode()
    return hashlib.sha256(payload).hexdigest()


def signing_message(record_hash: str) -> bytes:
    """What Ed25519 actually signs: the raw digest, not its hex text."""
    try:
        return bytes.fromhex(record_hash)
    except ValueError as exc:
        raise AuditError(f"record_hash is not valid hex: {record_hash!r}") from exc


def _ed25519() -> tuple[type, type]:
    """Import the Ed25519 primitives on demand, as a pair of classes.

    Returns ``(private_key_cls, public_key_cls)``. ``cryptography`` is
    required to *sign* and *verify*, but the audit module is imported by
    the CLI unconditionally, so a top-level import here would make every
    mint, verify and scan fail on an install that has the scanner key but
    not the crypto library. It is a declared dependency, so this is a
    belt-and-braces path, not a way to make it optional: a missing package
    becomes an ``AuditError`` rather than a ``ModuleNotFoundError``
    traceback.

    Mirrors the same pattern in ``credentials.py``.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise AuditError(
            "The audit log needs the 'cryptography' package (pip install "
            "'cryptography>=42'). Without it, records cannot be signed or "
            "verified. Other brushpass commands still work"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey


def _invalid_signature() -> type[BaseException]:
    """The exception ``Ed25519PublicKey.verify`` raises on a bad signature.

    Returned rather than imported so the exception clause above evaluates
    to a real class even when the import inside :func:`_ed25519` has not
    happened yet on this code path.
    """
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError:  # pragma: no cover - dependency is declared
        # Without cryptography, load_verifying_key above has already
        # failed and returned before reaching a signature check.
        return AuditError
    return InvalidSignature


# --------------------------------------------------------------------------
# Signing key
# --------------------------------------------------------------------------


def load_signing_key(data_dir: Path) -> "Ed25519PrivateKey":
    """Load the audit signing key, generating it on first audit write.

    Raises:
        AuditKeyError: if the key cannot be created or read, has the
            wrong length, or is readable by group or other. The last is
            fail-closed and never auto-repaired, exactly like the scanner
            and credential keys: a key that became world-readable means
            something else on this machine had a reason to read the
            machine's entire audit history, and brushpass will not
            silently re-establish trust.
    """
    private_key_cls, _ = _ed25519()
    path = data_dir / AUDIT_KEY_NAME
    if not path.exists():
        return _create_signing_key(path)

    seed = _read_seed(path)
    try:
        return private_key_cls.from_private_bytes(seed)
    except ValueError as exc:
        raise AuditKeyError(
            f"Refusing to run: audit key {path} is not a valid Ed25519 seed. "
            "Restore a backup, or remove the file to generate a new key. Note "
            "that a new key cannot verify records signed by the old one, so "
            "the existing audit log will read as unverifiable until it is gone"
        ) from exc


def check_key_permissions(data_dir: Path) -> None:
    """Refuse when the audit key exists but is group/world-readable.

    Read-only commands such as ``audit log`` never load the key, but the
    audit subsystem's trust root is that key: presenting log output as
    normal while the signing key may be disclosed would be a lie by
    omission. A missing key is fine — a fresh state dir has no log yet.
    """
    path = data_dir / AUDIT_KEY_NAME
    if path.exists():
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise AuditKeyError(
                f"Refusing to run: audit key {path} has mode {mode:04o}, "
                f"which is readable by group or others. Fix it with: "
                f"chmod 0600 {path}"
            )


def load_verifying_key(data_dir: Path) -> "Ed25519PublicKey":
    """The public half, for ``audit verify``. Never creates the key.

    Raises:
        AuditKeyError: if the key is missing or too widely readable.
    """
    # The on-disk artefact is an Ed25519 *seed*, so verification derives
    # the public half from it rather than loading a public key directly.
    private_key_cls, _ = _ed25519()
    path = data_dir / AUDIT_KEY_NAME
    if not path.exists():
        raise AuditKeyError(
            f"Cannot verify: audit key {path} does not exist, so no signature in "
            "the log can be checked. If this is a fresh install there is "
            "nothing to verify yet; otherwise the key was removed, and the "
            "log is unverifiable rather than proven good"
        )
    seed = _read_seed(path)
    try:
        return private_key_cls.from_private_bytes(seed).public_key()
    except ValueError as exc:
        raise AuditKeyError(
            f"Refusing to run: audit key {path} is not a valid Ed25519 seed"
        ) from exc


def _read_seed(path: Path) -> bytes:
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise AuditKeyError(
            f"Refusing to run: audit key {path} has mode {mode:04o}, which is "
            f"readable by group or others. Fix it with: chmod 0600 {path}"
        )
    try:
        seed = path.read_bytes()
    except OSError as exc:
        raise AuditKeyError(f"Cannot read audit key {path}: {exc}") from exc
    if len(seed) != AUDIT_KEY_BYTES:
        raise AuditKeyError(
            f"Refusing to run: audit key {path} is {len(seed)} bytes, expected "
            f"{AUDIT_KEY_BYTES} (an Ed25519 seed)"
        )
    return seed


def _create_signing_key(path: Path) -> "Ed25519PrivateKey":
    """Generate a fresh Ed25519 key with 0600 permissions."""
    private_key_cls, _ = _ed25519()
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise AuditKeyError(f"Cannot create state directory {parent}: {exc}") from exc

    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, AUDIT_KEY_MODE)
    except FileExistsError:
        # Another brushpass won the race; use whatever it wrote.
        return load_signing_key(parent)
    except OSError as exc:
        raise AuditKeyError(f"Cannot create audit key {path}: {exc}") from exc

    key = private_key_cls.generate()
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key.private_bytes_raw())
    except OSError as exc:
        path.unlink(missing_ok=True)
        raise AuditKeyError(f"Cannot write audit key {path}: {exc}") from exc

    # os.open's mode is masked by umask; force what we promised.
    try:
        path.chmod(AUDIT_KEY_MODE)
    except OSError as exc:
        raise AuditKeyError(f"Cannot set permissions on {path}: {exc}") from exc

    return key


# --------------------------------------------------------------------------
# Secret-material refusal
# --------------------------------------------------------------------------


def _reject_token_material(details: dict, path: str = "details") -> None:
    """Raise if any string under ``details`` looks like a token plaintext.

    This is the enforcement behind "the audit log never contains token
    plaintext". A reviewer can rely on it rather than on auditing every
    call site by hand.
    """
    for key, value in details.items():
        where = f"{path}.{key}"
        if isinstance(value, str):
            if TOKEN_MATERIAL_PATTERN.search(value):
                raise AuditError(
                    f"Refusing to write audit {where}: it contains something shaped "
                    "like a brushpass token. The audit log records ids, labels and "
                    "fingerprints only — never token material"
                )
        elif isinstance(value, dict):
            _reject_token_material(value, where)
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                if isinstance(item, str) and TOKEN_MATERIAL_PATTERN.search(item):
                    raise AuditError(
                        f"Refusing to write audit {where}[{index}]: it contains "
                        "something shaped like a brushpass token"
                    )
                if isinstance(item, dict):
                    _reject_token_material(item, f"{where}[{index}]")


def _jsonable(details: dict) -> dict:
    """Coerce details to something json can hold, refusing the rest."""
    if details is None:
        return {}
    if not isinstance(details, dict):
        raise AuditError(f"Audit details must be a mapping, got {type(details).__name__}")
    _reject_token_material(details)
    try:
        json.dumps(details)
    except (TypeError, ValueError) as exc:
        raise AuditError(f"Audit details are not JSON-serialisable: {exc}") from exc
    return details


def _scalar(value: object) -> str:
    """Render a detail value compactly for the human-readable log."""
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ",".join(_scalar(item) for item in value) if value else "-"
    if isinstance(value, dict):
        return canonical_json(value)
    return str(value)


# --------------------------------------------------------------------------
# The log
# --------------------------------------------------------------------------


class AuditLog:
    """Append-only, hash-chained, Ed25519-signed audit log."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.path = data_dir / AUDIT_LOG_NAME

    # ---- writing -------------------------------------------------------

    def record(self, event: str, details: dict | None = None) -> AuditRecord:
        """Append one record and return it.

        The tail is read, hashed and written under an exclusive lock, so
        two brushpass processes appending at the same moment still produce
        one correctly linked chain rather than two records claiming the
        same ``seq``.

        Raises:
            AuditError: if the chain cannot be continued — a damaged final
                line, a gap, or details that would carry secret material.
                Appending after a damaged tail would launder the tamper,
                so brushpass stops instead.
        """
        payload = _jsonable(details or {})
        self._ensure_dir()
        key = None
        # O_RDWR, not O_WRONLY: the tail is read back from this same
        # descriptor under the lock, so no other process can append
        # between our read and our write and make the chain disagree
        # with itself.
        fd = os.open(
            self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, AUDIT_LOG_MODE
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            # The key is generated on first audit *write*, so an install
            # that only ever reads its log never grows one.
            key = load_signing_key(self.data_dir)
            prev_hash, next_seq = self._chain_tail(fd)
            data = {
                "seq": next_seq,
                "ts_utc": datetime.now(UTC).isoformat(),
                "event": event,
                "details": payload,
                "prev_hash": prev_hash,
            }
            record_hash = compute_record_hash(data)
            data["record_hash"] = record_hash
            data["signature"] = base64.b64encode(
                key.sign(signing_message(record_hash))
            ).decode()
            line = (json.dumps(data, sort_keys=True) + "\n").encode()
            os.write(fd, line)
            os.fsync(fd)
        except OSError as exc:
            raise AuditError(f"Cannot append to audit log {self.path}: {exc}") from exc
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

        try:
            self.path.chmod(AUDIT_LOG_MODE)
        except OSError:
            # The mode was requested at open() and umask can only have
            # narrowed it. The read path reports the real mode.
            pass

        return AuditRecord.from_dict(data)

    def _ensure_dir(self) -> None:
        if self.data_dir.exists():
            self.data_dir.chmod(0o700)
            return
        self.data_dir.mkdir(parents=True, mode=0o700)

    def _chain_tail(self, fd: int) -> tuple[str, int]:
        """Return ``(prev_hash, next_seq)``, refusing a damaged chain."""
        lines = self._raw_lines(fd)
        if not lines:
            return GENESIS_HASH, 0

        last = lines[-1]
        try:
            data = json.loads(last)
        except (json.JSONDecodeError, ValueError) as exc:
            raise AuditError(
                f"Refusing to append to {self.path}: the final record is not valid "
                f"JSON ({exc}). An unreadable tail means the log has been truncated "
                "or edited; run 'brushpass audit verify' to see where it breaks"
            ) from exc
        if not isinstance(data, dict) or "record_hash" not in data:
            raise AuditError(
                f"Refusing to append to {self.path}: the final record is malformed. "
                "Run 'brushpass audit verify' to see where the chain breaks"
            )
        expected_seq = len(lines) - 1
        try:
            tail_seq = int(data["seq"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuditError(
                f"Refusing to append to {self.path}: the final record has no usable "
                "sequence number"
            ) from exc
        if tail_seq != expected_seq:
            raise AuditError(
                f"Refusing to append to {self.path}: the final record claims seq "
                f"{tail_seq} but is record {expected_seq}. The log has been "
                "truncated or reordered; run 'brushpass audit verify'"
            )
        return str(data["record_hash"]), tail_seq + 1

    def _raw_lines(self, fd: int | None = None) -> list[str]:
        """Every non-blank line, in order."""
        try:
            if fd is None:
                if not self.path.exists():
                    return []
                text = self.path.read_text()
            else:
                os.lseek(fd, 0, os.SEEK_SET)
                chunks = []
                while True:
                    chunk = os.read(fd, 1 << 16)
                    if not chunk:
                        break
                    chunks.append(chunk)
                text = b"".join(chunks).decode(errors="replace")
        except OSError as exc:
            raise AuditError(f"Cannot read audit log {self.path}: {exc}") from exc
        return [line.strip() for line in text.splitlines() if line.strip()]

    # ---- reading -------------------------------------------------------

    def records(self) -> list[AuditRecord]:
        """Every parseable record, oldest first.

        Raises:
            AuditError: if any line is unparseable. A silently skipped
                line would let an attacker hide an event in plain sight,
                so reading a damaged log is an error, not a short list.
        """
        parsed: list[AuditRecord] = []
        for index, line in enumerate(self._raw_lines()):
            try:
                data = json.loads(line)
                parsed.append(AuditRecord.from_dict(data))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise AuditError(
                    f"Record {index} in {self.path} is unreadable: {exc}. The log "
                    "has been altered; run 'brushpass audit verify'"
                ) from exc
        return parsed

    def verify(self) -> VerifyResult:
        """Replay the chain from seq 0. Never raises for a tampered log.

        Checks, in order at each record: the sequence number, the
        ``record_hash``, the Ed25519 signature, then the ``prev_hash``
        link. Stopping at the first failure is the point — an incident
        responder needs one number, not a list of everything downstream
        of the hole.
        """
        lines = self._raw_lines()
        if not lines:
            if self.path.exists():
                # Nothing in brushpass ever creates an empty audit log: the
                # first record creates the file with content. A file that
                # exists but holds no records was wiped.
                return VerifyResult(
                    ok=False,
                    records=0,
                    broken_seq=0,
                    reason=(
                        "the audit log exists but contains no records: it "
                        "was wiped. Restore the log from a backup, or treat "
                        "every action since the last verified backup as "
                        "unaccounted for"
                    ),
                )
            if (self.data_dir / "audit.key").exists():
                # The signing key is created inside record(), before the
                # first append: a key with no log file means the log was
                # deleted outright.
                return VerifyResult(
                    ok=False,
                    records=0,
                    broken_seq=0,
                    reason=(
                        "the audit signing key exists but the audit log is "
                        "missing: the log was deleted. Restore it from a "
                        "backup"
                    ),
                )
            return VerifyResult(ok=True, records=0)

        try:
            key = load_verifying_key(self.data_dir)
        except AuditKeyError as exc:
            # The log was not checked — a key this command cannot trust is
            # an operational error, not a broken chain. Reporting it as
            # TAMPERED would name a sequence that was never examined.
            return VerifyResult(
                ok=False, records=len(lines), reason=str(exc), error=True
            )

        previous = GENESIS_HASH
        for index, line in enumerate(lines):
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise ValueError("record is not an object")
                seq = int(data["seq"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                return VerifyResult(
                    ok=False,
                    records=len(lines),
                    broken_seq=index,
                    reason=f"record is not valid JSON: {exc}",
                )

            if seq != index:
                return VerifyResult(
                    ok=False,
                    records=len(lines),
                    broken_seq=index,
                    reason=f"out of order: expected seq {index}, found {seq}",
                )

            stored = str(data.get("record_hash") or "")
            computed = compute_record_hash(data)
            if computed != stored:
                return VerifyResult(
                    ok=False,
                    records=len(lines),
                    broken_seq=seq,
                    reason=(
                        f"record_hash does not match its contents "
                        f"(stored {stored[:16]}..., computed {computed[:16]}...)"
                    ),
                )

            try:
                signature = base64.b64decode(str(data.get("signature") or ""), validate=True)
            except (ValueError, TypeError) as exc:
                return VerifyResult(
                    ok=False,
                    records=len(lines),
                    broken_seq=seq,
                    reason=f"signature is not valid base64: {exc}",
                )
            try:
                key.verify(signature, signing_message(stored))
            except _invalid_signature():
                return VerifyResult(
                    ok=False,
                    records=len(lines),
                    broken_seq=seq,
                    reason="signature does not verify under the audit key",
                )

            linked = str(data.get("prev_hash") or "")
            if linked != previous:
                return VerifyResult(
                    ok=False,
                    records=len(lines),
                    broken_seq=seq,
                    reason=(
                        f"prev_hash does not match record {seq - 1} "
                        f"(expected {previous[:16]}..., found {linked[:16]}...)"
                    ),
                )

            previous = stored

        return VerifyResult(ok=True, records=len(lines))

    def tail(
        self,
        event: str | None = None,
        since: timedelta | None = None,
        limit: int = DEFAULT_TAIL,
    ) -> list[AuditRecord]:
        """The most recent records, newest last, after filtering.

        ``limit`` applies *after* filtering, so ``--event mint --limit 5``
        is the last five mints rather than five records of which some are
        mints. A limit of 0 means "show nothing" — ``records()`` with no
        limit would otherwise hand back the whole log, which is the
        opposite of what ``--tail 0`` asks for.
        """
        selected = self.records()
        if event is not None:
            selected = [r for r in selected if r.event == event]
        if since is not None:
            cutoff = datetime.now(UTC) - since
            selected = [r for r in selected if _parsed_ts(r) >= cutoff]
        if limit is not None and limit >= 0:
            selected = selected[-limit:] if limit else []
        return selected


def parse_since(text: str) -> timedelta:
    """Parse a ``--since`` duration: ``30s``, ``15m``, ``24h``, ``7d``, ``2w``.

    Raises:
        AuditError: on a malformed or zero duration.
    """
    match = SINCE_PATTERN.match((text or "").strip())
    if not match:
        raise AuditError(
            f"Invalid --since value '{text}'. Expected a duration like "
            "30m, 24h or 7d"
        )
    seconds = int(match.group("value")) * SINCE_UNIT_SECONDS[match.group("unit")]
    if seconds <= 0:
        raise AuditError("--since must be a positive duration")
    return timedelta(seconds=seconds)


def _parsed_ts(record: AuditRecord) -> datetime:
    """The record's timestamp as an aware datetime, UTC on anything odd."""
    try:
        moment = datetime.fromisoformat(record.ts_utc)
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
