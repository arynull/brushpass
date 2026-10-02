"""Data models for brushpass tokens."""

import hashlib
import re
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime


class LabelError(Exception):
    """A label contains characters it must not."""


# Anything shaped like token material. Deliberately broader than the exact
# 43-char token shape: even a fragment must never reach the audit log
# (audit._reject_token_material uses this same pattern), and a label
# carrying it would suppress the audit record for the operation.
TOKEN_MATERIAL_PATTERN = re.compile(r"bp_[A-Za-z0-9_-]{20,}")


def validate_label(label: str | None, what: str = "label") -> None:
    """Reject control/format characters and token-shaped content in a label.

    Labels are rendered verbatim in ``list`` and ``audit log`` tables. A
    newline or ANSI escape smuggled into a label can spoof table rows
    (fake a status line) or hide output with cursor movements, so labels
    are plain text.

    Rejected, by Unicode general category:
    - Cc (control) and DEL: newlines, escapes, tabs.
    - Cf (format): U+202E RIGHT-TO-LEFT OVERRIDE reverses the trailing
      columns in a bidi-aware terminal, so a *revoked* token's STATUS
      column can visually read "active"; U+200B ZERO WIDTH SPACE makes
      distinct labels look identical.
    - Zl/Zp (line/paragraph separators): U+2028/U+2029 break rows.
    - Cs (surrogates): malformed by definition.

    Zs (spaces, including no-break) stays allowed: "backup job" is a
    legitimate label. Co (private use) stays allowed: visible glyphs,
    not a spoofing vector.

    A label shaped like a token (``bp_`` + 20 or more base64 chars) is
    rejected too: it is either a pasted token — which must never be stored
    as a label — or an attempt to make the audit writer refuse the record
    for the operation, leaving no forensic trace. The ``bp_`` prefix is
    brushpass's token namespace; labels must not use it.
    """
    if label is None:
        return
    if any(
        unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs")
        or ord(ch) == 0x7F
        for ch in label
    ):
        raise LabelError(
            f"Invalid {what}: control and format characters (newlines, "
            "escape codes, tabs, bidi overrides, zero-width or line "
            "separators) are not allowed in labels"
        )
    if TOKEN_MATERIAL_PATTERN.search(label):
        raise LabelError(
            f"Invalid {what}: labels must not contain anything shaped like "
            "a brushpass token (the 'bp_' prefix is reserved for tokens)"
        )


# Characters that must never reach terminal output unescaped, by Unicode
# general category: the same set validate_label rejects. Paths (unlike
# labels) cannot be rejected at input — they are filesystem facts — so
# they are sanitized at render time instead.
_UNSAFE_FOR_DISPLAY = ("Cc", "Cf", "Zl", "Zp", "Cs")


def sanitize_for_display(value: str) -> str:
    """Replace terminal-unsafe characters with U+FFFD.

    File paths are attacker-influenced and rendered verbatim in scan
    reports and audit output; a newline fakes report lines and ANSI
    escapes erase them. The stored data keeps the true value — this is
    for human-readable rendering only.
    """
    return "".join(
        "\ufffd"
        if unicodedata.category(ch) in _UNSAFE_FOR_DISPLAY or ord(ch) == 0x7F
        else ch
        for ch in value
    )


@dataclass
class TokenRecord:
    """Stored record for a minted token (hash only, never plaintext)."""

    id: str  # Short ID for user reference (first 8 chars of hash)
    token_hash: str  # SHA-256 hash of the plaintext token
    scope: str
    label: str | None
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
    parent_id: str | None = None  # Set when derived via `handoff --parent`
    # HMAC-SHA256 of the plaintext under the scanner key, truncated. None
    # for tokens minted before v0.3.0: they predate leak detection and
    # cannot be matched by a scan. See scanner.py for why this is
    # verifiable without storing the plaintext.
    fingerprint: str | None = None
    # Label of the root credential this token was minted from, set by
    # `mint --credential <label>`. A rotation of that credential revokes
    # every live token carrying the label; a token minted without one is
    # untethered and survives rotations (documented in the README).
    credential_label: str | None = None
    # Revocation generation this token was minted in, stamped by
    # TokenStore.add. None means "before v0.5.0", which the store reads
    # as generation 0 — so the first epoch bump retires it. A token
    # whose epoch differs from the store's is denied even when its
    # revoked flag is still False.
    epoch: int | None = None

    @classmethod
    def create(
        cls,
        plaintext_token: str,
        scope: str,
        label: str | None,
        issued_at: datetime,
        expires_at: datetime,
        parent_id: str | None = None,
        fingerprint: str | None = None,
        credential_label: str | None = None,
    ) -> tuple["TokenRecord", str]:
        """Create a new token record. Returns (record, plaintext_token)."""
        token_hash = hashlib.sha256(plaintext_token.encode()).hexdigest()
        record_id = token_hash[:8]

        return cls(
            id=record_id,
            token_hash=token_hash,
            scope=scope,
            label=label,
            issued_at=issued_at,
            expires_at=expires_at,
            revoked=False,
            parent_id=parent_id,
            fingerprint=fingerprint,
            credential_label=credential_label,
        ), plaintext_token

    @staticmethod
    def generate_token() -> str:
        """Generate a secure random token: bp_ + 43 chars (256-bit entropy)."""
        random_part = secrets.token_urlsafe(32)  # 32 bytes = 43 chars in base64
        return f"bp_{random_part}"

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if token has expired."""
        if now is None:
            now = datetime.now(UTC)
        return now >= self.expires_at

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON storage."""
        return {
            "id": self.id,
            "token_hash": self.token_hash,
            "scope": self.scope,
            "label": self.label,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "revoked": self.revoked,
            "parent_id": self.parent_id,
            "fingerprint": self.fingerprint,
            "credential_label": self.credential_label,
            "epoch": self.epoch,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TokenRecord":
        """Deserialize from dictionary."""
        return cls(
            id=data["id"],
            token_hash=data["token_hash"],
            scope=data["scope"],
            label=data.get("label"),
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            revoked=data.get("revoked", False),
            parent_id=data.get("parent_id"),
            # Absent on tokens minted before v0.3.0; those stay unscannable
            # rather than being back-filled with a fingerprint brushpass
            # cannot compute (it has no plaintext to hash).
            fingerprint=data.get("fingerprint"),
            # Absent on tokens minted before v0.4.0, which predate
            # credential linkage and so belong to no rotation.
            credential_label=data.get("credential_label"),
            # Absent on tokens minted before v0.5.0, which predate the
            # generation counter. None, not 0: the store decides what
            # generation a record with no stamp counts as, so a bump can
            # retire the whole pre-epoch population.
            epoch=data.get("epoch"),
        )

    @property
    def effective_epoch(self) -> int:
        """This token's generation, with pre-epoch tokens counting as 0."""
        from .store import LEGACY_EPOCH

        return LEGACY_EPOCH if self.epoch is None else self.epoch
