"""GitHub App installation-token rotation.

A GitHub App installs into an account or org as an *installation*.
Installation access tokens are minted on demand by the Apps API and are
already short-lived (1h by default, capped at 24h), which is exactly the
credential shape brushpass brokers.

**The old token is not revoked, and cannot be.** GitHub supersedes
installation tokens implicitly: creating a new one is all it takes, and
the previous token stops being honoured at its next expiry. There is no
Apps API call that deletes an outstanding installation token, so this
provider reports ``supports_revoke = False`` and brushpass says so
plainly instead of pretending the old token was killed. The practical
consequence is that a rotation is safe but not instantaneous: the old
token remains usable for the remainder of its own lifetime, which is why
the stored root credential here should be the *app key*, not a token, and
why the linked ephemeral tokens brushpass minted are revoked immediately.

Auth uses a short-lived JWT signed with the App's private key (RS256),
authenticated as the App, exchanged at::

    POST /app/installations/{installation_id}/access_tokens

The JWT lifetime is 9 minutes, the maximum GitHub accepts, with a clock
skew allowance. The private key is read from disk and never held longer
than the call; it is not logged and not stored by brushpass.
"""

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .base import Provider, ProviderError, RotationResult, Step
from .http import HTTPError, request

# GitHub's API root is configurable so a GitHub Enterprise install, or a
# test, can point somewhere else.
DEFAULT_API_URL = "https://api.github.com"

# GitHub rejects a JWT with more than 10 minutes of life. 9 leaves room
# for the round trip.
JWT_LIFETIME = timedelta(minutes=9)

# A JWT minted before this skew allowance is rejected as "not yet valid";
# 60s is the documented comfort margin.
CLOCK_SKEW = timedelta(seconds=60)

PRIVATE_KEY_MODE = 0o600


class GitHubAppProvider(Provider):
    """Rotate a GitHub App installation access token."""

    name = "github-app"
    description = (
        "Mint a fresh GitHub App installation access token via the Apps API. "
        "The previous token is superseded implicitly by GitHub and cannot be "
        "deleted; see the module docstring."
    )
    required_config = ("app_id", "private_key_path", "installation_id")
    optional_config = ("api_url", "repository", "expires_in")
    supports_revoke = False
    revoke_note = (
        "GitHub supersedes installation tokens implicitly when a new one is "
        "issued; there is no API call that revokes an outstanding token. The "
        "old token dies at its own expiry (1h by default)."
    )

    def check_config(self, config: dict) -> None:
        """Validate ids are integers and the key file is usable.

        Raises:
            ConfigError: on a non-integer id, a relative key path, or a
                key file whose permissions are wider than 0600.
        """
        for key in ("app_id", "installation_id"):
            value = config.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise _config_error(
                    f"config '{key}' must be an integer app/installation id, "
                    f"got {type(value).__name__}"
                )
            if isinstance(value, str) and not value.strip().isdigit():
                raise _config_error(f"config '{key}' must be numeric, got '{value}'")
            if isinstance(value, int) and value <= 0:
                raise _config_error(f"config '{key}' must be positive")

        key_path = Path(str(config["private_key_path"]))
        if not key_path.is_absolute():
            raise _config_error(
                "config 'private_key_path' must be an absolute path, so the "
                "credential does not depend on brushpass's working directory"
            )
        if not key_path.exists():
            raise _config_error(f"config 'private_key_path' does not exist: {key_path}")
        mode = key_path.stat().st_mode & 0o777
        if mode & 0o077:
            raise _config_error(
                f"config 'private_key_path' is {mode:04o}, which is readable by "
                f"group or others; fix it with 'chmod 0600 {key_path}'"
            )
        _require_pem(key_path)

        expires_in = config.get("expires_in")
        if expires_in is not None:
            if isinstance(expires_in, bool) or not isinstance(expires_in, int):
                raise _config_error("config 'expires_in' must be an integer of seconds")
            if not 1 <= expires_in <= 86400:
                raise _config_error(
                    "config 'expires_in' must be between 1 and 86400 seconds"
                )

    def plan(self, context) -> list[Step]:
        return [
            Step(
                "Mint a GitHub App JWT (RS256, 9-minute lifetime) signed with "
                "the configured private key"
            ),
            Step(
                "POST /app/installations/{installation_id}/access_tokens to mint "
                "a new installation token",
            ),
            Step("Store the new installation token encrypted, replacing the old one"),
            Step(
                "Report the superseded old token: GitHub invalidates it implicitly "
                "at its expiry, there is no revoke call",
                destructive=False,
            ),
        ]

    def rotate(self, old_secret: str, config: dict) -> RotationResult:
        """Mint a new installation token.

        ``old_secret`` is not sent anywhere. It is accepted because the
        interface is rotation-shaped, and this provider documents that it
        does not need the previous value.
        """
        values = self.validate_config(config)
        api_url = str(values.get("api_url") or DEFAULT_API_URL).rstrip("/")
        installation_id = values["installation_id"]
        url = f"{api_url}/app/installations/{installation_id}/access_tokens"

        payload: dict = {}
        if values.get("repository"):
            payload["repositories"] = [values["repository"]]
        expires_in = values.get("expires_in")
        if expires_in:
            payload["expires_at"] = _iso(datetime.now(UTC) + timedelta(seconds=expires_in))

        private_key_path = Path(str(values["private_key_path"]))
        jwt = self._mint_jwt(private_key_path, values["app_id"])

        try:
            status, body = request(
                url,
                method="POST",
                headers={
                    "Authorization": f"Bearer {jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                body=payload or {},
            )
        except HTTPError as exc:
            raise ProviderError(
                f"GitHub refused to mint an installation token: {exc}"
            ) from None

        if status not in (200, 201):
            raise ProviderError(
                f"GitHub returned HTTP {status} when minting an installation token"
            )

        token, expires_at = _extract_token(body)
        if not token:
            raise ProviderError(
                "GitHub returned no 'token' field for the installation token"
            )
        return RotationResult(
            new_secret=token,
            expires_at=expires_at,
            detail=f"installation {installation_id}",
            metadata={"api_url": api_url, "installation_id": installation_id},
        )

    def revoke(self, secret: str, config: dict) -> None:
        """Always refused: see the module docstring."""
        raise ProviderError(
            "github-app: installation tokens cannot be revoked through the API. "
            + self.revoke_note
        )

    def _mint_jwt(self, private_key_path: Path, app_id) -> str:
        """Build a short-lived RS256 JWT authenticating as the App.

        Uses ``cryptography`` for the signature rather than hand-rolled
        RSA, and never logs the key or the resulting token.
        """
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise ProviderError(
                "The 'cryptography' package is required for github-app rotation"
            ) from exc

        key = _read_private_key(private_key_path)
        now = datetime.now(UTC) - CLOCK_SKEW
        payload = {
            "iat": int((now).timestamp()),
            "exp": int((now + JWT_LIFETIME).timestamp()),
            "iss": str(app_id),
        }
        header = {"alg": "RS256", "typ": "JWT"}

        def segment(obj: dict) -> str:
            raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        signing_input = f"{segment(header)}.{segment(payload)}".encode()
        try:
            signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        except Exception as exc:  # noqa: BLE001 - normalised for the operator
            raise ProviderError(
                f"Could not sign the GitHub App JWT with {private_key_path}: {exc}"
            ) from None

        encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        return f"{signing_input.decode()}.{encoded}"


def _read_private_key(path: Path):
    """Load a PEM RSA private key, normalising every failure.

    ``cryptography`` is imported here rather than at module scope so a
    brushpass installation without it can still mint, verify and scan
    tokens; only github-app rotation needs RSA.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except ImportError as exc:
        raise ProviderError(
            "github-app rotation needs the 'cryptography' package "
            "(pip install 'cryptography>=42')"
        ) from exc
    try:
        pem = path.read_bytes()
    except OSError as exc:
        raise _config_error(f"cannot read 'private_key_path' {path}: {exc}") from None
    try:
        key = load_pem_private_key(pem, password=None)
    except Exception as exc:  # noqa: BLE001 - normalised for the operator
        raise _config_error(
            f"'private_key_path' {path} is not a readable PEM private key ({exc})"
        ) from None
    if not isinstance(key, RSAPrivateKey):
        raise _config_error(
            f"'private_key_path' {path} holds a "
            f"{type(key).__name__}; the GitHub Apps API requires an RSA key"
        )
    return key  # type: ignore[return-value]


def _require_pem(path: Path) -> None:
    """Cheap pre-check so a binary blob fails as config, not as a JWT error."""
    try:
        head = path.read_bytes()[:64]
    except OSError as exc:
        raise _config_error(f"cannot read 'private_key_path' {path}: {exc}") from None
    if b"PRIVATE KEY" not in head:
        raise _config_error(
            f"'private_key_path' {path} does not look like a PEM private key"
        )


def _extract_token(body) -> tuple[str | None, str | None]:
    """Pull ``token`` and ``expires_at`` out of an Apps API response."""
    if not isinstance(body, dict):
        return None, None
    token = body.get("token")
    expires = body.get("expires_at")
    token_ok = token if isinstance(token, str) else None
    return token_ok, expires if isinstance(expires, str) else None


def _iso(moment: datetime) -> str:
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _config_error(message: str) -> Exception:
    from .base import ConfigError

    return ConfigError(f"github-app: {message}")
