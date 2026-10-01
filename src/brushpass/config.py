"""Configuration management for brushpass."""

from pathlib import Path

import yaml

DEFAULT_TTL = "2h"
MAX_TTL = "24h"
DEFAULT_CONFIG = {
    "default_ttl": DEFAULT_TTL,
    "max_ttl": MAX_TTL,
}


class Config:
    """Configuration loaded from ~/.brushpass/config.yaml."""

    def __init__(self, config_dir: Path | None = None):
        self.config_dir = config_dir or self._default_config_dir()
        self.config_file = self.config_dir / "config.yaml"
        self._data: dict = {}
        self._load()

    @staticmethod
    def _default_config_dir() -> Path:
        """Get default config directory."""
        import os
        data_dir = os.environ.get("BRUSHPASS_DATA_DIR")
        if data_dir:
            return Path(data_dir)
        return Path.home() / ".brushpass"

    def _load(self) -> None:
        """Load configuration from file, creating defaults if needed."""
        if self.config_file.exists():
            with open(self.config_file) as f:
                self._data = yaml.safe_load(f) or {}
        else:
            self._data = DEFAULT_CONFIG.copy()
            self._save()

    def _save(self) -> None:
        """Save configuration to file."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, "w") as f:
            yaml.dump(self._data, f, default_flow_style=False)
        # Set restrictive permissions
        self.config_file.chmod(0o600)

    @property
    def default_ttl(self) -> str:
        return self._data.get("default_ttl", DEFAULT_TTL)

    @property
    def max_ttl(self) -> str:
        return self._data.get("max_ttl", MAX_TTL)

    @property
    def webhook_url(self) -> str | None:
        """Rotation webhook URL, or None when unset.

        Read from ``notifications.webhook_url`` so the top level of the
        config stays about token minting and rotation notifications live
        under their own heading.
        """
        notifications = self._data.get("notifications") or {}
        if not isinstance(notifications, dict):
            return None
        url = notifications.get("webhook_url")
        return str(url).strip() if url else None

    @property
    def data_dir(self) -> Path:
        """Get the data directory path."""
        return self.config_dir
