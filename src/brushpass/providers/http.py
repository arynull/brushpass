"""HTTP helper shared by the network providers.

Deliberately built on :func:`urllib.request.urlopen` rather than a
third-party client, for one reason that matters more than ergonomics:
tests mock at the ``urlopen`` level and can then assert on exactly what
would have gone over the wire, without a fake socket.

Nothing here retries. Retrying a credential rotation on a transport
error is how you mint two secrets and lose track of one; the rotation
engine owns retry policy, and only for the *persist* step.
"""

import json
import urllib.error
import urllib.request
from typing import Any

# A rotation is on the critical path of a credential change: it should be
# fast or fail loudly, not hang. 10s per request keeps a whole rotation
# well inside its 60s budget even if every call times out.
DEFAULT_TIMEOUT = 10.0

# Bodies are JSON documents in every shipped provider; anything larger
# than this is a misconfiguration or a hostile endpoint, not a token.
MAX_RESPONSE_BYTES = 1 * 1024 * 1024


class HTTPError(Exception):
    """An HTTP request failed. Carries the status, never the secret."""


def request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, Any]:
    """Perform one HTTP request and return ``(status, parsed_body)``.

    Non-2xx raises :class:`HTTPError` with the status and a short excerpt
    of the response, which is enough to diagnose a misconfigured provider
    without dumping a token into a log.
    """
    data = None
    request_headers = {"Accept": "application/json", "User-Agent": "brushpass/0.4"}
    if headers:
        request_headers.update(headers)
    if body is not None:
        data = json.dumps(body).encode()
        request_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310
            status = response.status
            raw = response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        raise HTTPError(
            f"HTTP {exc.code} from {url}: {_excerpt(exc.read())}"
        ) from None
    except urllib.error.URLError as exc:
        # The reason can echo a URL with an embedded token, so only the
        # transport-level reason is surfaced.
        raise HTTPError(f"Cannot reach {url}: {exc.reason}") from None
    except (TimeoutError, OSError) as exc:
        raise HTTPError(f"Cannot reach {url}: {type(exc).__name__}") from None

    return status, _parse(raw)


def _parse(raw: bytes) -> Any:
    """Parse a JSON body, tolerating an empty one."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")


def _excerpt(raw: bytes, limit: int = 200) -> str:
    """A short, single-line excerpt of an error body."""
    text = raw.decode("utf-8", errors="replace").strip().replace("\n", " ")
    if not text:
        return "(empty body)"
    return text[:limit] + ("..." if len(text) > limit else "")
