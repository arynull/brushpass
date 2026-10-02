"""Scope language parsing and matching for brushpass.

Scope format: <provider>:<resource>:<permission>
- provider: alphanumeric + hyphens/underscores, no wildcards
- resource: any characters except colon (allows slashes, wildcards)
- permission: alphanumeric + hyphens/underscores, * allowed

Examples:
  github:rayanalpha/*:read
  aws:s3:my-bucket/*:*
  stripe:customers:read
"""

import re
import unicodedata
from dataclasses import dataclass

from .models import TOKEN_MATERIAL_PATTERN

# Pattern: provider:resource:permission
# - provider: alphanumeric, hyphens, underscores (no wildcards)
# - resource: anything except colon (allows /, *, etc.)
# - permission: alphanumeric, hyphens, underscores, * (wildcard allowed)
SCOPE_PATTERN = re.compile(
    r"^"
    r"(?P<provider>[a-zA-Z0-9_-]+)"
    r":"
    r"(?P<resource>[^:]+)"
    r":"
    r"(?P<permission>[a-zA-Z0-9_*-]+)"
    r"\Z"  # \Z, not $: $ also matches before a trailing newline, which
    # would admit "github:org/repo:read\n" as a valid scope
)


class ScopeError(Exception):
    """Invalid scope format."""
    pass


@dataclass
class Scope:
    """Parsed scope triple."""
    provider: str
    resource: str
    permission: str

    @classmethod
    def parse(cls, scope_str: str) -> "Scope":
        """Parse and validate a scope string."""
        match = SCOPE_PATTERN.match(scope_str)
        if not match:
            raise ScopeError(
                f"Invalid scope format: '{scope_str}'. "
                f"Expected: <provider>:<resource>:<permission>"
            )

        provider = match.group("provider")
        resource = match.group("resource")
        permission = match.group("permission")

        # Additional validation
        if not provider:
            raise ScopeError("Provider cannot be empty")
        if not resource:
            raise ScopeError("Resource cannot be empty")
        if not permission:
            raise ScopeError("Permission cannot be empty")

        # Scopes are rendered verbatim in `list`, `scan` and `verify`
        # output and land in audit details. A newline/escape/U+202E in
        # the resource would spoof those tables exactly like a hostile
        # label, and token-shaped content would make the audit writer
        # refuse the record — so both are rejected at parse, the same
        # bar labels are held to.
        for part, name in (
            (provider, "provider"),
            (resource, "resource"),
            (permission, "permission"),
        ):
            if any(
                unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs")
                or ord(ch) == 0x7F
                for ch in part
            ):
                raise ScopeError(
                    f"Invalid scope {name}: control and format characters "
                    "are not allowed"
                )
            if TOKEN_MATERIAL_PATTERN.search(part):
                raise ScopeError(
                    f"Invalid scope {name}: must not contain anything shaped "
                    "like a brushpass token"
                )

        return cls(provider=provider, resource=resource, permission=permission)

    def covers(self, required: "Scope") -> bool:
        """Check if this scope covers the required scope.

        Rules:
        - Provider must match exactly (no wildcards)
        - Resource: compared segment-by-segment on '/'; both sides must have
          the same number of segments, and each granted segment must either
          equal the required segment or be exactly '*' (any single segment).
          A bare '*' therefore matches a single-segment resource only.
        - Permission: same segment rule; '*' matches any single permission,
          otherwise the permission must match exactly.

        Examples:
          github:org/*:read        covers github:org/repo:read
          github:org/*:read        NOT    github:org/repo:write
          github:org/*:read        NOT    github:org/repo/issues:read
          github:org/*/settings:read  covers github:org/repo/settings:read
        """
        # Provider must match exactly
        if self.provider != required.provider:
            return False

        # Resource matching
        if not self._segment_covers(self.resource, required.resource):
            return False

        # Permission matching
        if not self._segment_covers(self.permission, required.permission):
            return False

        return True

    @staticmethod
    def _segment_covers(granted: str, required: str) -> bool:
        """Check if a granted segment pattern covers a required segment.

        Both values are split on '/' and must have the same number of
        segments. Each granted segment must either equal the required
        segment or be exactly '*', which matches any single segment.

        Examples:
          org/*      covers org/repo           -> True
          org/*      covers org/repo/issues    -> False (segment count)
          org/*/x    covers org/repo/x         -> True
          *          covers anything           -> True (single segment)
          org/*      covers other/repo         -> False
        """
        granted_parts = granted.split("/")
        required_parts = required.split("/")

        # '*' is a per-segment wildcard, never a multi-segment one.
        if len(granted_parts) != len(required_parts):
            return False

        return all(
            granted_part == "*" or granted_part == required_part
            for granted_part, required_part in zip(granted_parts, required_parts, strict=True)
        )

    def __str__(self) -> str:
        return f"{self.provider}:{self.resource}:{self.permission}"
