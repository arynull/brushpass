"""Rotation against an internal secret service over plain HTTP.

Most real rotation endpoints are not a product feature; they are a small
internal service that hands back a new secret when you POST to it. This
provider is the escape hatch that makes them drivable without a bespoke
plugin, and it is deliberately strict about config, because the failure
mode of a mistyped endpoint is a silent no-op in the wrong direction.

Config keys:

``url`` (required)
    Absolute http(s) URL to POST to.
``method`` (optional, default ``POST``)
    HTTP method. Only the methods that take a body are allowed.
``headers`` (optional)
    Mapping of header name to value. ``{old_secret}`` is substituted here.
    Used for auth headers that are *not* the rotated secret.
``old_secret_placement`` (optional, default ``body``)
    Where the current secret goes so the service can identify what to
    rotate. One of ``body``, ``header``, ``query``, or ``none``.
``old_secret_header`` / ``old_secret_query`` (optional)
    The header or query parameter name. Required when the placement is
    ``header`` or ``query``.
``body`` (optional)
    Extra JSON body fields. ``{old_secret}`` is substituted here too.
``new_secret_path`` (optional, default ``token``)
    Dot-separated path into the JSON response holding the new secret, e.g.
    ``data.credentials.secret``.
``revoke_url`` (optional)
    If set, ``revoke`` POSTs here. Without it, :meth:`can_revoke` reports
    False and the engine documents that the old secret stays valid until
    it expires on its own.

**Placeholder expansion is a secret-leak surface, and it is narrowed
here.** ``{old_secret}`` is the only placeholder, and it is substituted
only in the locations named by ``old_secret_placement``. A ``headers``
entry that happens to contain ``{old_secret}`` while the placement is
``body`` is rejected at config time, because that is almost always a
mistake and would put a live secret in a header the operator did not
intend.

Secrets travel in a request header or body field. They never appear in
the URL query when a header or body is available, and any
:class:`ProviderError` raised here names the endpoint and the status,
never the secret or a header value.
"""

import re
import urllib.parse

from .base import ConfigError, Provider, ProviderError, RotationResult, Step
from .http import HTTPError, request

DEFAULT_NEW_SECRET_PATH = "token"
DEFAULT_TIMEOUT = 10.0

# Only body-carrying methods. A rotation that answers to GET is a
# misconfiguration far more often than it is intentional.
ALLOWED_METHODS = ("POST", "PUT", "PATCH")

PLACEMENT_BODY = "body"
PLACEMENT_HEADER = "header"
PLACEMENT_QUERY = "query"
PLACEMENT_NONE = "none"
PLACEMENTS = (PLACEMENT_BODY, PLACEMENT_HEADER, PLACEMENT_QUERY, PLACEMENT_NONE)

_PLACEHOLDER = re.compile(r"\{(old_secret|label|provider|secret_id)\}")

# Header names must look like header names: a value containing a newline
# would let a config smuggle extra headers into the request.
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


class GenericHttpProvider(Provider):
    """Rotate a secret by POSTing to a user-configured endpoint."""

    name = "generic-http"
    description = (
        "Rotate a secret against an internal secret service: POST to a "
        "configured URL and read the new secret out of the JSON response."
    )
    required_config = ("url",)
    optional_config = (
        "method",
        "headers",
        "body",
        "old_secret_placement",
        "old_secret_header",
        "old_secret_query",
        "new_secret_path",
        "revoke_url",
        "timeout",
    )

    def check_config(self, config: dict) -> None:
        """Strictly validate the schema. See the module docstring.

        Raises:
            ConfigError: naming the offending key and what is expected.
        """
        url = str(config["url"])
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ConfigError(
                f"generic-http: config 'url' must be an absolute http(s) URL, "
                f"got '{url}'"
            )
        if not parsed.netloc:
            raise ConfigError(f"generic-http: config 'url' has no host: '{url}'")

        method = str(config.get("method") or "POST").upper()
        if method not in ALLOWED_METHODS:
            raise ConfigError(
                f"generic-http: config 'method' must be one of "
                f"{', '.join(ALLOWED_METHODS)} (a rotation carries a body), "
                f"got '{method}'"
            )

        placement = str(config.get("old_secret_placement") or PLACEMENT_BODY).lower()
        if placement not in PLACEMENTS:
            raise ConfigError(
                f"generic-http: config 'old_secret_placement' must be one of "
                f"{', '.join(PLACEMENTS)}, got '{placement}'"
            )

        if placement == PLACEMENT_HEADER:
            name = config.get("old_secret_header")
            if not name or not _HEADER_NAME.match(str(name)):
                raise ConfigError(
                    "generic-http: 'old_secret_placement: header' requires "
                    "'old_secret_header' to be a valid header name"
                )
        if placement == PLACEMENT_QUERY:
            if not config.get("old_secret_query"):
                raise ConfigError(
                    "generic-http: 'old_secret_placement: query' requires "
                    "'old_secret_query' to name the query parameter"
                )

        headers = config.get("headers") or {}
        if not isinstance(headers, dict):
            raise ConfigError("generic-http: config 'headers' must be a mapping")
        for name, value in headers.items():
            if not _HEADER_NAME.match(str(name)):
                raise ConfigError(
                    f"generic-http: config 'headers' has an invalid header name "
                    f"'{name}'"
                )
            if not isinstance(value, str):
                raise ConfigError(
                    f"generic-http: config 'headers'['{name}'] must be a string"
                )
            if "{old_secret}" in value and placement != PLACEMENT_HEADER:
                raise ConfigError(
                    f"generic-http: config 'headers'['{name}'] interpolates "
                    "{old_secret} but 'old_secret_placement' is not 'header'. "
                    "Set the placement to 'header' or remove the placeholder, "
                    "so a live secret is not sent somewhere you did not choose"
                )

        body = config.get("body") or {}
        if not isinstance(body, dict):
            raise ConfigError("generic-http: config 'body' must be a mapping")
        for key, value in body.items():
            if not isinstance(value, (str, int, float, bool)) and value is not None:
                raise ConfigError(
                    f"generic-http: config 'body'['{key}'] must be a scalar"
                )

        path = config.get("new_secret_path") or DEFAULT_NEW_SECRET_PATH
        if not isinstance(path, str) or not path.strip("."):
            raise ConfigError(
                "generic-http: config 'new_secret_path' must be a non-empty "
                "dot-separated path, e.g. 'data.token'"
            )

        revoke_url = config.get("revoke_url")
        if revoke_url is not None:
            revoke_parsed = urllib.parse.urlparse(str(revoke_url))
            if revoke_parsed.scheme not in ("http", "https") or not revoke_parsed.netloc:
                raise ConfigError(
                    f"generic-http: config 'revoke_url' must be an absolute "
                    f"http(s) URL, got '{revoke_url}'"
                )

        timeout = config.get("timeout")
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                raise ConfigError("generic-http: config 'timeout' must be a number")
            if not 0 < float(timeout) <= 60:
                raise ConfigError(
                    "generic-http: config 'timeout' must be between 0 and 60 "
                    "seconds, so a rotation stays inside its 60s budget"
                )

    def plan(self, context) -> list[Step]:
        values = dict(context.config or {})
        url = values.get("url")
        placement = values.get("old_secret_placement") or PLACEMENT_BODY
        steps = [
            Step(f"POST {url} to request a new secret (placement: {placement})"),
            Step("Store the new secret encrypted, replacing the old one"),
        ]
        if values.get("revoke_url"):
            steps.insert(1, Step(f"POST {values['revoke_url']} to revoke the old secret"))
        return steps

    def can_revoke(self, config: dict) -> bool:
        """True when this credential's config names a revoke endpoint."""
        return bool((config or {}).get("revoke_url"))

    def rotate(self, old_secret: str, config: dict) -> RotationResult:
        """POST to the configured endpoint and extract the new secret."""
        values = self.validate_config(config)
        url = str(values["url"])
        method = str(values.get("method") or "POST").upper()
        placement = str(values.get("old_secret_placement") or PLACEMENT_BODY).lower()

        headers = {
            name: _expand(str(value), old_secret)
            for name, value in (values.get("headers") or {}).items()
        }
        body = {
            key: _expand(value, old_secret)
            for key, value in (values.get("body") or {}).items()
        }
        query = ""

        if placement == PLACEMENT_BODY:
            body["old_secret"] = old_secret
        elif placement == PLACEMENT_HEADER:
            headers[str(values["old_secret_header"])] = old_secret
        elif placement == PLACEMENT_QUERY:
            name = str(values["old_secret_query"])
            query = urllib.parse.urlencode({name: old_secret})
            separator = "&" if urllib.parse.urlparse(url).query else "?"
            url = f"{url}{separator}{query}"

        try:
            status, response = request(
                url,
                method=method,
                headers=headers,
                body=body,
                timeout=float(values.get("timeout") or DEFAULT_TIMEOUT),
            )
        except HTTPError as exc:
            # Redact: with query placement the secret is in the URL, and
            # the HTTP error message embeds the full URL.
            raise ProviderError(
                f"generic-http: rotation request failed: "
                f"{_redact(str(exc)).replace(old_secret, '<redacted>')}"
            ) from None

        if status not in (200, 201, 202, 204):
            raise ProviderError(
                f"generic-http: endpoint returned HTTP {status} for the rotation request"
            )

        path = values.get("new_secret_path") or DEFAULT_NEW_SECRET_PATH
        secret = extract_path(response, path)
        if not secret:
            raise ProviderError(
                f"generic-http: no secret found at '{path}' in the response. "
                "Check 'new_secret_path' against the endpoint's actual "
                "response shape"
            )
        return RotationResult(
            new_secret=str(secret),
            detail=f"HTTP {status} from {_redact(url)}",
        )

    def revoke(self, secret: str, config: dict) -> None:
        """POST to ``revoke_url`` if configured; otherwise refuse.

        Raises:
            ProviderError: if no ``revoke_url`` is configured, or the
                endpoint refuses.
        """
        values = self.validate_config(config)
        revoke_url = values.get("revoke_url")
        if not revoke_url:
            raise ProviderError(
                "generic-http: no 'revoke_url' configured, so brushpass cannot "
                "revoke the old secret upstream. Add 'revoke_url' to this "
                "credential's config, or accept that the old secret remains "
                "valid until it expires on its own"
            )
        headers = {
            name: _expand(str(value), secret)
            for name, value in (values.get("headers") or {}).items()
        }
        try:
            status, _ = request(
                str(revoke_url),
                method=str(values.get("method") or "POST").upper(),
                headers=headers,
                body={"secret": secret},
                timeout=float(values.get("timeout") or DEFAULT_TIMEOUT),
            )
        except HTTPError as exc:
            raise ProviderError(
                f"generic-http: revoke request failed: "
                f"{_redact(str(exc)).replace(secret, '<redacted>')}"
            ) from None
        if status not in (200, 202, 204):
            raise ProviderError(
                f"generic-http: revoke endpoint returned HTTP {status}"
            )


def extract_path(payload, path: str):
    """Read ``path`` out of a JSON payload.

    ``path`` is dot-separated, e.g. ``data.credentials.secret``. Raises
    :class:`ConfigError` if an intermediate step is not an object, since
    that means the config does not match reality.
    """
    current = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _expand(value, old_secret: str) -> str:
    """Substitute ``{old_secret}`` into a config string."""
    return _PLACEHOLDER.sub(lambda m: _placeholder_value(m, old_secret), str(value))


def _placeholder_value(match, old_secret: str) -> str:
    """Resolve one placeholder.

    Only ``old_secret`` is supported. Any other ``{...}`` in a header or
    body is left as literal text rather than expanded to something
    guessed, so a typo shows up in the request instead of silently
    sending a wrong value.
    """
    return old_secret if match.group(1) == "old_secret" else match.group(0)


def _redact(url: str) -> str:
    """Strip query values so an error message cannot echo a secret."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return url
    return urllib.parse.urlunparse(parsed._replace(query="<redacted>"))
