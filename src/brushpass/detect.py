"""Candidate extraction and verification for brushpass leak detection.

Two stages, deliberately separate:

1. **Extraction** (:func:`find_candidates`) turns arbitrary bytes into
   *candidates* — strings that look like a brushpass token. This stage
   over-collects on purpose: it is heuristic and cheap.
2. **Verification** (:class:`FingerprintIndex`) answers "did brushpass
   issue this?" by recomputing the candidate's HMAC fingerprint under the
   scanner key and looking it up. This stage is exact, and silent:
   anything brushpass never issued is dropped without a word.

A random ``bp_``-looking string therefore never reaches the report. That
split is the whole point — a scanner that cries wolf gets ignored, and an
ignored scanner is worse than no scanner.
"""

import base64
import binascii
import bisect
import hmac
import re
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256

from .models import TokenRecord
from .scanner import FINGERPRINT_CHARS

# The token shape: "bp_" + 43 url-safe base64 chars (256 bits of entropy).
TOKEN_PATTERN = re.compile(rb"bp_[A-Za-z0-9_-]{43}")

# Base64 blobs worth decoding. 60 chars is long enough that ordinary words
# and short identifiers never qualify, and short enough that any token
# hidden in a pasted payload is still caught.
_B64_STANDARD = re.compile(rb"[A-Za-z0-9+/]{60,}={0,2}")
_B64_URLSAFE = re.compile(rb"[A-Za-z0-9_-]{60,}={0,2}")

# Where a candidate was found. Recorded in the report so the operator can
# tell a pasted token from a committed one.
SOURCE_FILE = "file"
SOURCE_RAW = "raw"
SOURCE_BASE64 = "base64"
SOURCE_WHITESPACE = "whitespace"
SOURCE_GIT_LOG = "git-log"
SOURCE_GIT_STAGED = "git-staged"
SOURCE_GIT_UNSTAGED = "git-unstaged"
SOURCE_HISTORY = "history"

# A NUL byte is the standard "not text" signal. Probed in a prefix only, so
# a text file with a stray NUL near the end is still read.
BINARY_PROBE_BYTES = 8192

# Upper bound on how much of a single file is read. Anything larger is
# reported as skipped rather than read into memory whole.
MAX_FILE_BYTES = 16 * 1024 * 1024

# Whitespace removed for the split-token pass, and the line splitting used
# to map a stripped offset back to a line in the original content.
_WHITESPACE = re.compile(rb"\s+")
_WHITESPACE_BYTES = frozenset(b" \t\n\r\x0b\x0c")


class DetectionError(Exception):
    """A scan source could not be read."""


@dataclass(frozen=True)
class Candidate:
    """A string that looks like a token, before verification.

    Holds the candidate bytes because that is what the scanner found on
    disk. It never reaches the report: a candidate that verifies is
    replaced by its record, and one that does not is discarded.
    """

    token: bytes
    line: int  # 1-based line number within the scanned blob
    source: str


def looks_binary(data: bytes) -> bool:
    """True if the data looks binary (a NUL byte in the leading block)."""
    return b"\x00" in data[:BINARY_PROBE_BYTES]


def too_large(size: int) -> bool:
    """True if a file of ``size`` bytes is above the scan limit."""
    return size > MAX_FILE_BYTES


def find_candidates(data: bytes, source: str = SOURCE_RAW) -> list[Candidate]:
    """Extract token-shaped candidates from a blob of bytes.

    Three passes, matching the documented detection algorithm:

    * ``raw`` — the token pattern applied directly to the content.
    * ``base64`` — long base64 blobs decoded, then the token pattern
      applied to the decoded bytes.
    * ``whitespace`` — the whole blob with all whitespace removed, then the
      token pattern applied, which reassembles a token wrapped across
      lines.

    Candidates are de-duplicated on ``(token, line)``: the same token found
    three ways on one line is one leak, not three.
    """
    if not data:
        return []

    newline_at = [m.start() for m in re.finditer(rb"\n", data)]
    found: dict[tuple[bytes, int], Candidate] = {}

    def add(blob: bytes, label: str) -> None:
        for match in TOKEN_PATTERN.finditer(blob):
            line = bisect.bisect_left(newline_at, match.start()) + 1
            found.setdefault(
                (match.group(), line),
                Candidate(token=match.group(), line=line, source=label),
            )

    add(data, SOURCE_RAW)

    for blob in _base64_blobs(data):
        decoded = _decode_base64(blob)
        if decoded:
            add(decoded, SOURCE_BASE64)

    # Whitespace-stripped pass, to catch a token split across line breaks.
    # Line numbers come from the mapping built while stripping, so the
    # report still points at a real location.
    stripped = _WHITESPACE.sub(b"", data)
    if stripped != data:
        points = _line_points(data)
        for match in TOKEN_PATTERN.finditer(stripped):
            line = _line_at(points, match.start())
            found.setdefault(
                (match.group(), line),
                Candidate(token=match.group(), line=line, source=SOURCE_WHITESPACE),
            )

    return sorted(found.values(), key=lambda c: (c.line, c.token, c.source))


def _base64_blobs(data: bytes) -> Iterable[bytes]:
    """Yield long base64-ish runs, both alphabets, without duplicates."""
    seen: set[bytes] = set()
    for pattern in (_B64_STANDARD, _B64_URLSAFE):
        for match in pattern.finditer(data):
            blob = match.group()
            if blob not in seen:
                seen.add(blob)
                yield blob


def _decode_base64(blob: bytes) -> bytes:
    """Decode a base64 blob, tolerating missing padding.

    Returns empty bytes if the blob is not decodable. Nothing else is
    checked here: what the blob means is decided by verification, once.
    """
    padded = blob + b"=" * (-len(blob) % 4)
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decode(padded)
        except (binascii.Error, ValueError):
            continue
    return b""


def _line_points(data: bytes) -> tuple[list[int], list[int]]:
    """Map offsets in whitespace-stripped ``data`` back to line numbers.

    Returns parallel lists of (stripped offset, line number) with one entry
    per line start. Built in a single pass, so it costs one extra scan of
    the blob and no per-candidate rescans.

    ``str.splitlines`` semantics are deliberately not used here: the line
    numbering elsewhere in this module counts ``\\n`` only, so this must
    count ``\\n`` only too. ``\\r`` alone stays inside the line, exactly as
    it does for the raw pass.
    """
    offsets = [0]
    lines = [1]
    stripped_offset = 0
    line = 1

    for byte in data:
        if byte == 0x0A:  # '\n'
            line += 1
            offsets.append(stripped_offset)
            lines.append(line)
        elif byte not in _WHITESPACE_BYTES:
            stripped_offset += 1

    return offsets, lines


def _line_at(points: tuple[list[int], list[int]], offset: int) -> int:
    """Line number holding ``offset`` in the whitespace-stripped text."""
    offsets, lines = points
    return lines[bisect.bisect_right(offsets, offset) - 1]


class FingerprintIndex:
    """Maps a verified candidate to the token record brushpass issued.

    Lookup recomputes the candidate's HMAC fingerprint under the scanner
    key and looks it up in the stored fingerprint database. A record with
    no fingerprint — one minted before leak detection existed — is absent
    from the index and therefore cannot match anything.

    The lookup is a plain dict access rather than a constant-time scan.
    That is deliberate: the command's entire purpose is to report which
    fingerprints are present, so the timing of this lookup leaks nothing
    the output does not already say.
    """

    def __init__(self, records: Iterable[TokenRecord], key: bytes):
        self._key = key
        self._by_fingerprint = {
            record.fingerprint: record for record in records if record.fingerprint
        }

    def fingerprint(self, plaintext: str) -> str:
        """The fingerprint brushpass would store for a plaintext token."""
        return hmac.new(self._key, plaintext.encode(), sha256).hexdigest()[
            :FINGERPRINT_CHARS
        ]

    def lookup(self, candidate: bytes) -> TokenRecord | None:
        """Return the record for a candidate, or None if never issued."""
        try:
            plaintext = candidate.decode("ascii")
        except UnicodeDecodeError:  # pragma: no cover - pattern is ASCII-only
            return None
        return self._by_fingerprint.get(self.fingerprint(plaintext))
