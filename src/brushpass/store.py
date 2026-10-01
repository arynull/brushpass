"""Token storage backend for brushpass.

Stores tokens in JSON format with SHA-256 hashes only.
File permissions are strictly enforced (0600).
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import TokenRecord


class StorageError(Exception):
    """Storage operation failed."""
    pass


class TokenStore:
    """Manages persistent token storage."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.tokens_file = data_dir / "tokens.json"
        self._records: dict[str, TokenRecord] = {}
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        """Ensure storage directory and file exist with correct permissions."""
        # Create directory with secure permissions
        if not self.data_dir.exists():
            self.data_dir.mkdir(parents=True, mode=0o700)
        else:
            # Fix permissions if needed
            self.data_dir.chmod(0o700)

        # Load or create tokens file
        if self.tokens_file.exists():
            # Check file permissions (only owner can read/write)
            file_stat = self.tokens_file.stat()
            file_mode = file_stat.st_mode & 0o777
            if file_mode != 0o600:
                # Fix permissions instead of failing
                self.tokens_file.chmod(0o600)
            self._load()
        else:
            self._save()

    def _load(self) -> None:
        """Load tokens from file."""
        try:
            with open(self.tokens_file) as f:
                data = json.load(f)

            self._records = {
                rec["id"]: TokenRecord.from_dict(rec)
                for rec in data.get("tokens", [])
            }
        except (json.JSONDecodeError, KeyError) as e:
            raise StorageError(f"Failed to load tokens: {e}") from e

    def _save(self) -> None:
        """Save tokens to file."""
        data = {
            "version": 1,
            "tokens": [rec.to_dict() for rec in self._records.values()],
        }

        # Write to temp file first, then rename (atomic)
        temp_file = self.tokens_file.with_suffix(".tmp")
        try:
            with open(temp_file, "w") as f:
                json.dump(data, f, indent=2)

            # Set permissions before rename
            temp_file.chmod(0o600)

            # Atomic rename
            temp_file.rename(self.tokens_file)
        except Exception as e:
            temp_file.unlink(missing_ok=True)
            raise StorageError(f"Failed to save tokens: {e}") from e

    def add(self, record: TokenRecord) -> None:
        """Add a new token record."""
        self._records[record.id] = record
        self._save()

    def find_by_token(self, plaintext_token: str) -> TokenRecord | None:
        """Find a token record by plaintext token (constant-time comparison)."""
        token_hash = hashlib.sha256(plaintext_token.encode()).hexdigest()

        # Constant-time comparison using hmac.compare_digest
        import hmac
        for record in self._records.values():
            if hmac.compare_digest(record.token_hash, token_hash):
                return record

        return None

    def find_by_id(self, record_id: str) -> TokenRecord | None:
        """Find a token record by its short ID."""
        return self._records.get(record_id)

    def revoke(self, record_id: str) -> bool:
        """Revoke a token by ID. Returns True if found and revoked."""
        record = self._records.get(record_id)
        if record and not record.revoked:
            record.revoked = True
            self._save()
            return True
        return False

    def list_all(self) -> list[TokenRecord]:
        """List all token records."""
        return list(self._records.values())

    def prune(self, older_than_days: int = 7) -> int:
        """Delete expired+revoked records older than specified days.

        Returns count of deleted records.
        """
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=older_than_days)

        to_delete = []
        for record_id, record in self._records.items():
            if record.revoked and record.expires_at < cutoff:
                to_delete.append(record_id)
            elif record.is_expired(now) and record.expires_at < cutoff:
                to_delete.append(record_id)

        for record_id in to_delete:
            del self._records[record_id]

        if to_delete:
            self._save()

        return len(to_delete)
