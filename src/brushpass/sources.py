"""Scan sources for brushpass leak detection.

Three families of source, all funnelling into the same
``bytes -> find_candidates -> FingerprintIndex.lookup`` pipeline:

* **Filesystem** — a recursive walk over the paths given.
* **Git** — ``git log -p --all``, the staged and unstaged diffs, and the
  files that are in the worktree but in no commit yet, so a token that was
  committed and later deleted is still found, and a token in a new file you
  have not staged yet is still found.
* **History** — shell history files, the single most common leak vector
  for a pasted token.

Two exclusions are deliberate:

* The brushpass state directory is never scanned. It holds token records
  and the scanner key, so scanning it would report brushpass's own
  bookkeeping as a leak.
* ``.git/`` object blobs are skipped by the filesystem walk. They are
  compressed, so a raw regex pass over them would find nothing — a false
  all-clear, which is worse than an explicit "use --git". ``scan --git``
  reads that content properly, decompressed, through git itself.

Skipped and truncated content is counted and reported. A scanner that
quietly drops what it could not read is a scanner you cannot trust, so the
summary always says what was *not* looked at.
"""

import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from . import detect

# Git subcommands used by `scan --git`, in the order they are run.
GIT_LOG = ("log", "-p", "--all", "--no-color", "--no-ext-diff")
GIT_DIFF_STAGED = ("diff", "--cached", "--no-color", "--no-ext-diff")
GIT_DIFF_UNSTAGED = ("diff", "--no-color", "--no-ext-diff")

# Untracked worktree files. `-z` NUL-delimits, so paths containing spaces or
# newlines survive; `--exclude-standard` honours .gitignore, so build output
# and vendored dependency trees are not walked.
GIT_UNTRACKED = ("ls-files", "--others", "--exclude-standard", "-z")

# Shell history files scanned by `scan --history`, relative to $HOME.
HISTORY_FILES = (".bash_history", ".zsh_history")

# Pruned from a filesystem walk: directories that cannot hold a useful
# token and are expensive to walk. ``.git`` is here on purpose — see above.
SKIP_DIR_NAMES = frozenset({".git", "__pycache__", "node_modules"})

# Skip reasons recorded per skipped blob.
SKIP_BINARY = "binary"
SKIP_LARGE = "oversized"
SKIP_UNREADABLE = "unreadable"

# Ceiling on how much git output is held in memory. `git log -p --all` on a
# large repository can be enormous; past this the scan reads a prefix and
# says so, rather than dying on memory.
MAX_GIT_BYTES = 64 * 1024 * 1024


class ScanSourceError(Exception):
    """A scan source cannot be read."""


@dataclass(frozen=True)
class Blob:
    """A labelled chunk of bytes to scan, or a note about one skipped.

    A scan blob has ``data`` set; a skip has ``skipped`` set to a reason.
    ``note`` flags partial content (a truncated git stream), which is
    scanned but must be reported as incomplete.
    """

    location: str  # shown in the report, e.g. "notes/todo.md"
    source: str
    data: bytes | None = None
    skipped: str | None = None
    note: str | None = None

    @property
    def is_skip(self) -> bool:
        return self.skipped is not None


def scan_paths(paths: list[Path], state_dir: Path) -> Iterator[Blob]:
    """Yield blobs from a recursive walk of ``paths``.

    Skips binary files (NUL-byte heuristic), files above the size limit, the
    brushpass state directory, and ``.git/``. Symlinked directories are not
    followed, to avoid cycles and escape from the tree being scanned.
    """
    resolved_state = _resolve(state_dir)
    for raw in paths:
        root = Path(raw)
        if not root.exists():
            raise ScanSourceError(f"Path not found: {raw}")

        if root.is_file():
            if resolved_state in _resolve(root).parents:
                continue
            blob = _read_file(root, source=detect.SOURCE_FILE)
            if blob is not None:
                yield blob
            continue

        for path in _walk(root):
            if resolved_state in _resolve(path).parents:
                continue
            blob = _read_file(path, source=detect.SOURCE_FILE)
            if blob is not None:
                yield blob


def _walk(root: Path) -> Iterator[Path]:
    """Depth-first walk yielding files, pruning skipped directories."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = [
            name
            for name in sorted(dirnames)
            if name not in SKIP_DIR_NAMES and not (current / name).is_symlink()
        ]
        for name in sorted(filenames):
            path = current / name
            if not path.is_symlink():
                yield path


def _read_file(path: Path, source: str) -> Blob | None:
    """Read a file into a Blob, or a note about why it was skipped.

    Returns None only when the path is not a regular file at all (a
    directory entry that vanished, a fifo), where a skip note would itself
    be noise.
    """
    location = str(path)
    try:
        size = path.stat().st_size
    except OSError:
        return Blob(location=location, source=source, skipped=SKIP_UNREADABLE)

    if not path.is_file():
        return None

    if detect.too_large(size):
        return Blob(location=location, source=source, skipped=SKIP_LARGE)

    try:
        data = path.read_bytes()
    except OSError:
        return Blob(location=location, source=source, skipped=SKIP_UNREADABLE)

    if detect.looks_binary(data):
        return Blob(location=location, source=source, skipped=SKIP_BINARY)

    return Blob(location=location, source=source, data=data)


def scan_git(
    cwd: Path | None = None, state_dir: Path | None = None
) -> Iterator[Blob]:
    """Yield blobs from a repository's history, index and worktree.

    Four sources, all funnelling into the same candidate -> verify
    pipeline: the commit log, the staged diff, the unstaged diff, and the
    files that are in the worktree but in no commit yet.

    The last one is not redundant with ``git diff``. A diff shows changes to
    *tracked* files, so a token in a brand new file is invisible to it.
    Untracked files are listed by path and read from disk like any other
    file, and their skips (binary, oversized) are counted like any other
    file's. Files excluded by ``.gitignore`` are not listed, matching what
    git would ever hand you.

    Raises:
        ScanSourceError: if the directory is not inside a git repository, if
            git is unavailable, or if a git command fails for any other
            reason.
    """
    _require_repo(cwd)

    for args, source in (
        (GIT_LOG, detect.SOURCE_GIT_LOG),
        (GIT_DIFF_STAGED, detect.SOURCE_GIT_STAGED),
        (GIT_DIFF_UNSTAGED, detect.SOURCE_GIT_UNSTAGED),
    ):
        result = _run_git(args, cwd)
        # git writes to stderr even on success ("LF will be replaced by
        # CRLF..."), so only stdout is content.
        payload = result.stdout.encode(errors="replace")
        note = None
        if len(payload) > MAX_GIT_BYTES:
            note = f"truncated to {MAX_GIT_BYTES} bytes of git output"
            payload = payload[:MAX_GIT_BYTES]
        yield Blob(
            location=f"git:{' '.join(args)}", source=source, data=payload, note=note
        )

    root = cwd or Path.cwd()
    resolved_state = _resolve(state_dir) if state_dir else None
    for relative in _untracked_files(root):
        path = root / relative
        if resolved_state is not None and resolved_state in _resolve(path).parents:
            continue
        blob = _read_file(path, source=detect.SOURCE_GIT_UNSTAGED)
        if blob is not None:
            yield blob


def _untracked_files(root: Path) -> Iterator[Path]:
    """List worktree files git does not track, relative to ``root``."""
    result = _run_git(GIT_UNTRACKED, root)
    for entry in result.stdout.split("\0"):
        if entry:
            yield Path(entry)


def _require_repo(cwd: Path | None) -> None:
    """Fail clearly unless ``cwd`` is inside a git repository."""
    result = _try_git(("rev-parse", "--git-dir"), cwd)
    if result is None:
        raise ScanSourceError(
            "git not found on PATH; `brushpass scan --git` needs git installed"
        )
    if result.returncode != 0:
        where = cwd or Path.cwd()
        raise ScanSourceError(
            f"Not a git repository: {where}. `brushpass scan --git` must run "
            "inside a repository (use plain `brushpass scan <path>` to scan files)"
        )


def _run_git(
    args: tuple[str, ...], cwd: Path | None
) -> subprocess.CompletedProcess[str]:
    """Run a git command that must succeed. Raises ScanSourceError if not."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            # Git history can contain non-UTF8 bytes; strict decoding
            # would traceback. Replacement keeps the scan usable.
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScanSourceError(
            "git not found on PATH; `brushpass scan --git` needs git installed"
        ) from exc
    except OSError as exc:
        raise ScanSourceError(f"Cannot run git {' '.join(args)}: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        message = detail[0] if detail else f"exit status {result.returncode}"
        raise ScanSourceError(f"git {' '.join(args)} failed: {message}")
    return result


def _try_git(
    args: tuple[str, ...], cwd: Path | None
) -> subprocess.CompletedProcess[str] | None:
    """Probe git without raising.

    A missing binary and a non-zero status are both answers here, not
    faults: ``_require_repo`` reports each of them differently.
    """
    try:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return None


def scan_history(home: Path | None = None) -> Iterator[Blob]:
    """Yield blobs from the user's shell history files.

    ``$HISTFILE`` wins when set, since that is where the shell actually
    writes. Otherwise the conventional ``~/.bash_history`` and
    ``~/.zsh_history`` are scanned when they exist. A history file that is
    absent is not reported as a skip — most people use one shell, not both.
    """
    root = home or Path.home()
    histfile = os.environ.get("HISTFILE")
    candidates = (
        [Path(histfile)] if histfile else [root / name for name in HISTORY_FILES]
    )

    seen: set[Path] = set()
    for path in candidates:
        resolved = _resolve(path)
        if resolved in seen or not path.exists():
            continue
        seen.add(resolved)
        blob = _read_file(path, source=detect.SOURCE_HISTORY)
        if blob is not None:
            yield blob


def _resolve(path: Path) -> Path:
    """Fully resolve a path. ``realpath`` never raises on a bad component."""
    return Path(os.path.realpath(path))
