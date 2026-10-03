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
    # Single-use (mint --once): the first *successful* verify consumes it
    # by setting `revoked`. Absent on records minted before v1.1.0 — those
    # default to False and stay multi-use, exactly as they behaved on
    # release. Consumption is a mutation like any other, so the store's
    # lock serialises it (see store.consume).
    single_use: bool = False
    # Set by TokenStore.consume alongside `revoked`, so the two ways a
    # dead single-use token ends stay distinguishable: revoked by
    # someone, or spent by a verify. Both deny identically, but an
    # operator reading `list` is asking a different question about each
    # ("did I kill it?" vs "did it get used?"). Absent on records minted
    # before v1.1.0, which can never have been consumed.
    consumed: bool = False
    # Original budget for bounded-use tokens (mint --max-uses N). None
    # means unbounded (multi-use). Kept alongside `remaining` so a
    # rotation can mint a FRESH token inheriting `max_uses` with FULL
    # remaining — the fresh token is a new capability with its own
    # budget, never a refill of the old record (no path may increase
    # `remaining` on an existing record).
    max_uses: int | None = None
    # Uses left for bounded-use tokens. None means unbounded (multi-use,
    # including every record minted before v1.2.0 that was not single-use).
    # Decremented exactly once per successful verify by TokenStore.spend;
    # never incremented by any path. When it reaches 0 the store also sets
    # `revoked`, so every existing revoked-denial check catches spent
    # tokens.
    remaining: int | None = None

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
        single_use: bool = False,
        max_uses: int | None = None,
    ) -> tuple["TokenRecord", str]:
        """Create a new token record. Returns (record, plaintext_token)."""
        token_hash = hashlib.sha256(plaintext_token.encode()).hexdigest()
        record_id = token_hash[:8]

        # --once is shorthand for --max-uses 1. The CLI rejects passing
        # both; here we resolve the budget defensively so a direct caller
        # cannot mint an inconsistent record.
        resolved_max = max_uses
        if single_use and resolved_max is None:
            resolved_max = 1
        if resolved_max is not None:
            if not isinstance(resolved_max, int) or resolved_max < 1:
                raise ValueError(f"max_uses must be an integer >= 1, got {resolved_max!r}")
            resolved_remaining: int | None = resolved_max
        else:
            resolved_remaining = None

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
            single_use=single_use,
            max_uses=resolved_max,
            remaining=resolved_remaining,
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
            "single_use": self.single_use,
            "consumed": self.consumed,
            "max_uses": self.max_uses,
            "remaining": self.remaining,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TokenRecord":
        """Deserialize from dictionary."""
        single_use = data.get("single_use", False)
        consumed = data.get("consumed", False)
        max_uses = data.get("max_uses")
        remaining = data.get("remaining")
        if max_uses is None and remaining is None:
            # Records minted before v1.2.0 carry neither key. Multi-use
            # records stay unbounded (None); single-use records derive a
            # budget of 1 (0 when already consumed).
            if single_use:
                max_uses = 1
                remaining = 0 if consumed else 1
        elif max_uses is not None and remaining is None:
            # Budget known but no counter stored: the record was never
            # spent (a spent record always writes remaining). A consumed
            # flag without a counter means the budget is gone.
            remaining = 0 if consumed else max_uses
        elif max_uses is None and remaining is not None:
            # Counter without a budget should not happen for new records;
            # keep the counter and recover a budget so rotation can
            # inherit one: live budget implies that budget, spent implies
            # the single-use budget when applicable.
            if remaining is not None and remaining > 0:
                max_uses = remaining
            else:
                max_uses = 1 if single_use else None
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
            # Absent on tokens minted before v1.1.0, which predate
            # single-use tokens. False, not a guess: those records are
            # multi-use and must stay verifiable more than once.
            single_use=single_use,
            # Absent on tokens minted before v1.1.0, which predate
            # single-use tokens and so can never be consumed.
            consumed=consumed,
            # Absent on tokens minted before v1.2.0, which predate
            # bounded-use tokens (derived above).
            max_uses=max_uses,
            remaining=remaining,
        )

    @property
    def effective_epoch(self) -> int:
        """This token's generation, with pre-epoch tokens counting as 0."""
        from .store import LEGACY_EPOCH

        return LEGACY_EPOCH if self.epoch is None else self.epoch
