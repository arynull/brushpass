"""Token storage backend for brushpass.

Stores tokens in JSON format with SHA-256 hashes only.
File permissions are strictly enforced (0600).

Two things here are about propagation rather than storage.

**The revocation epoch.** The store carries an integer that is bumped on
every revoke, rotation and nuke, and each token records the epoch it was
minted in. A token whose epoch is behind the store's is denied, in
addition to the ``revoked`` flag and its expiry. That matters because a
revoked *flag* is a per-token fact: it says "this one token is dead" and
says nothing about any other. An epoch bump is a *generation* change:
everything minted before the bump is behind the current generation, so
one number retires a whole class of tokens — which is exactly what a
break-glass has to be able to do when nobody has time to enumerate what
was outstanding.

**Nothing here is cached.** Every public read goes back to the file. Two
brushpass processes on the same machine are two :class:`TokenStore`
instances with two separate memory maps, and a revoke in one is visible
to a verify in the other on the very next call, with no signal, no IPC
and no shared object. Caching revocation state would be faster and
wrong: the cache would keep verifying a token that had already been
killed, for as long as the process lived.
"""

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import TokenRecord

# Epoch stamped on tokens minted before v0.5.0, when the counter did not
# exist. Such a token is in generation 0, so the first epoch bump on an
# upgraded install retires it. That is the safe direction: a pre-epoch
# token is treated as older than any bump rather than as current.
LEGACY_EPOCH = 0


class StorageError(Exception):
    """Storage operation failed."""
    pass


class TokenStore:
    """Manages persistent token storage.

    Every public method re-reads the file. See the module docstring: the
    no-cache property is the guarantee, not an optimisation choice.
    """

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.tokens_file = data_dir / "tokens.json"
        self._records: dict[str, TokenRecord] = {}
        self._epoch: int = LEGACY_EPOCH
        # Ids deleted by the most recent prune(), empty until one runs.
        # Initialised here because a caller may legitimately read it
        # before any prune has happened — an audit call site asking "what
        # did you just delete?" must not have to guard against a
        # never-pruned store.
        self.last_pruned: list[str] = []
        self._ensure_storage()

    # ---- lifecycle ----------------------------------------------------

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
            # Absent on stores written before v0.5.0, which had no
            # generation counter. Treated as 0, matching LEGACY_EPOCH.
            self._epoch = int(data.get("revocation_epoch", LEGACY_EPOCH))
        except (json.JSONDecodeError, KeyError) as e:
            raise StorageError(f"Failed to load tokens: {e}") from e
        except (TypeError, ValueError) as e:
            raise StorageError(f"Failed to load tokens: malformed epoch: {e}") from e

    def _reload(self) -> None:
        """Re-read the file, discarding anything held in memory.

        Called at the top of every public read. This is what makes a
        revoke in one process visible to a verify in another: there is no
        shared in-memory state that could be stale.
        """
        if self.tokens_file.exists():
            self._load()

    def _save(self) -> None:
        """Save tokens to file."""
        data = {
            "version": 1,
            "revocation_epoch": self._epoch,
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

    # ---- the revocation epoch ------------------------------------------

    @property
    def epoch(self) -> int:
        """The current revocation generation.

        A token is denied when its own epoch differs from this, so
        ``token.epoch == store.epoch`` is the condition for a token
        minted now to be usable now.
        """
        self._reload()
        return self._epoch

    def current_epoch(self) -> int:
        """The current generation, as a callable. Same as :attr:`epoch`."""
        return self.epoch

    def bump_epoch(self) -> int:
        """Advance the generation by one and return the new value.

        Every token minted before this call is now behind the generation
        and will be denied, whatever its individual ``revoked`` flag says.
        This is the primitive ``nuke`` is built from.
        """
        self._reload()
        self._epoch += 1
        self._save()
        return self._epoch

    # ---- records ------------------------------------------------------

    def add(self, record: TokenRecord) -> None:
        """Add a new token record, stamped with the current epoch.

        A record with no epoch of its own is given the current one, which
        is what makes it *current generation*. Callers minting through
        the CLI never see this: :meth:`store.add` is the single point
        where a live token is born, so it cannot be minted into a stale
        generation by accident.
        """
        self._reload()
        if record.epoch is None:
            record.epoch = self._epoch
        self._records[record.id] = record
        self._save()

    def find_by_token(self, plaintext_token: str) -> TokenRecord | None:
        """Find a token record by plaintext token (constant-time comparison)."""
        self._reload()
        token_hash = hashlib.sha256(plaintext_token.encode()).hexdigest()

        # Constant-time comparison using hmac.compare_digest
        for record in self._records.values():
            if hmac.compare_digest(record.token_hash, token_hash):
                return record

        return None

    def find_by_id(self, record_id: str) -> TokenRecord | None:
        """Find a token record by its short ID."""
        self._reload()
        return self._records.get(record_id)

    def revoke(self, record_id: str) -> bool:
        """Revoke a token by ID. Returns True if found and revoked.

        Bumps the generation as well, so a token this call cannot see —
        one held by another process that has not re-read yet, or one
        pruned out of the file — is still behind the generation and still
        denied.
        """
        self._reload()
        record = self._records.get(record_id)
        if record and not record.revoked:
            record.revoked = True
            self._epoch += 1
            self._save()
            return True
        return False

    def revoke_all_live(self, now: datetime | None = None) -> list[str]:
        """Revoke every token that is neither revoked nor expired.

        Returns the ids that changed. The generation is bumped once, not
        once per token: a break-glass retires a generation, and a caller
        reading the epoch sees one consistent jump rather than a hundred.
        """
        moment = now or datetime.now(UTC)
        self._reload()
        changed: list[str] = []
        for record in self._records.values():
            if record.revoked or record.is_expired(moment):
                continue
            record.revoked = True
            changed.append(record.id)
        if changed:
            self._epoch += 1
            self._save()
        return changed

    def list_all(self) -> list[TokenRecord]:
        """List all token records."""
        self._reload()
        return list(self._records.values())

    def is_stale(self, record: TokenRecord) -> bool:
        """True when a record predates the current generation.

        Takes the store's epoch from the file, so the answer reflects
        revocations performed by other processes.

        Compares against ``effective_epoch``, not ``epoch``: a token minted
        before v0.5.0 has no stamp of its own and counts as generation 0.
        Comparing the raw ``None`` would call every legacy token stale even
        on an install that has never bumped the counter, which would deny
        working tokens after a mere version upgrade.
        """
        return record.effective_epoch != self.epoch

    def prune(self, older_than_days: int = 7) -> int:
        """Delete expired+revoked records older than specified days.

        Returns count of deleted records, and the ids of the records it
        deleted in :attr:`last_pruned`, so the caller can write an audit
        record naming them rather than only counting them.
        """
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=older_than_days)
        self._reload()

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

        self.last_pruned = to_delete
        return len(to_delete)
