"""TTL parsing and time utilities for brushpass.

Supported formats: 30s, 15m, 2h, 7d, 1w
Default: 2h
Maximum: 24h
"""

import re
from datetime import UTC, datetime, timedelta

from .config import MAX_TTL

TTL_PATTERN = re.compile(r"^(?P<value>\d+)(?P<unit>[smhdw])$")

# Unit to seconds mapping
UNIT_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}

# Max TTL in seconds (24 hours)
MAX_TTL_SECONDS = 24 * 3600


class TTLError(Exception):
    """Invalid TTL format or value."""
    pass


def parse_ttl(ttl_str: str) -> timedelta:
    """Parse a TTL string into a timedelta.

    Args:
        ttl_str: TTL string like "30m", "2h", "7d"

    Returns:
        timedelta representing the duration

    Raises:
        TTLError: If format is invalid or TTL exceeds maximum
    """
    match = TTL_PATTERN.match(ttl_str.strip())
    if not match:
        raise TTLError(
            f"Invalid TTL format: '{ttl_str}'. "
            f"Expected: <number><unit> where unit is s/m/h/d/w"
        )

    value = int(match.group("value"))
    unit = match.group("unit")

    if value <= 0:
        raise TTLError("TTL must be positive")

    seconds = value * UNIT_SECONDS[unit]

    if seconds > MAX_TTL_SECONDS:
        raise TTLError(
            f"TTL exceeds maximum of {MAX_TTL} ({MAX_TTL_SECONDS} seconds)"
        )

    return timedelta(seconds=seconds)


def ttl_to_seconds(ttl_str: str) -> int:
    """Parse TTL and return seconds."""
    delta = parse_ttl(ttl_str)
    return int(delta.total_seconds())


def format_expiry(expires_at: datetime, now: datetime | None = None) -> str:
    """Format time until expiry in human-readable form."""
    if now is None:
        now = datetime.now(UTC)

    delta = expires_at - now

    if delta.total_seconds() <= 0:
        return "expired"

    total_seconds = int(delta.total_seconds())

    if total_seconds < 60:
        return f"{total_seconds}s"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        return f"{minutes}m"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        if minutes > 0:
            return f"{hours}h{minutes}m"
        return f"{hours}h"
    else:
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        if hours > 0:
            return f"{days}d{hours}h"
        return f"{days}d"
