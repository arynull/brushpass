"""Data models for brushpass tokens."""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime


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

    @classmethod
    def create(
        cls,
        plaintext_token: str,
        scope: str,
        label: str | None,
        issued_at: datetime,
        expires_at: datetime,
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
        )
