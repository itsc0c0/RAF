"""Safe filesystem walking and per-file detection for R$F Vault.

Scanned content is untrusted:

* symlinks are never followed (files or directories), the scan root itself must
  not be a symlink, and files are opened with ``O_NOFOLLOW``/``O_NONBLOCK`` and
  re-checked with ``fstat`` (no FIFOs or devices, no swapped-in links);
* VCS, dependency and cache directories (.git, node_modules, .venv, ...) and
  virtualenvs (a ``pyvenv.cfg`` marker) are skipped;
* files larger than ``vault.max_file_kb`` and binary files (a NUL byte in the
  first 8 KiB) are skipped and reported;
* at most :data:`MAX_FILES` files are examined per scan.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from raf.products.vault.detectors import Candidate, FileKind, LineView, detect_line

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
    }
)
BINARY_PROBE = 8192
MAX_FILES = 100_000
MAX_SKIPPED_REPORTED = 500
INLINE_MARKERS = ("raf:allow", "raf-vault:ignore")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

_CONFIG_SUFFIXES = frozenset(
    {
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".config",
        ".properties",
        ".xml",
        ".plist",
        ".tf",
        ".tfvars",
        ".hcl",
        ".cnf",
        ".npmrc",
        ".pypirc",
        ".netrc",
    }
)
_CONFIG_NAMES = frozenset(
    {"credentials", "config", "dockerfile", ".npmrc", ".pypirc", ".netrc", ".pgpass", ".dockercfg", ".htpasswd"}
)
_TEST_DIR_RE = re.compile(
    r"(?:^|/)(?:tests?|spec|specs|__tests__|fixtures?|testdata|test_data|examples?|samples?|docs?|mocks?)(?:/|$)",
    re.IGNORECASE,
)
_TEST_NAME_RE = re.compile(
    r"(?:^test_|_test\.|\.test\.|\.spec\.|example|sample|template|\.dist$|\.tpl$)", re.IGNORECASE
)


def classify(rel_path: str) -> FileKind:
    """Decide whether a file is config-like and whether it looks like test/example content."""
    posix = PurePosixPath(rel_path)
    name = posix.name.lower()
    config = (
        name.startswith(".env")
        or name.endswith(".env")
        or posix.suffix.lower() in _CONFIG_SUFFIXES
        or name in _CONFIG_NAMES
        or name.startswith(("docker-compose", "dockerfile"))
    )
    test_like = bool(_TEST_DIR_RE.search(str(posix.parent)) or _TEST_NAME_RE.search(name))
    return FileKind(config=config, test_like=test_like)


@dataclass(slots=True)
class Detection:
    candidate: Candidate
    inline_suppressed: bool


def scan_text(text: str, rel_path: str, entropy_threshold: float) -> list[Detection]:
    """Detect secrets in decoded file content. Line numbers count ``\\n`` separators (editor numbering)."""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    kind = classify(rel_path)
    covered_until = -1
    detections: list[Detection] = []
    for index, line in enumerate(lines):
        if index <= covered_until or not line.strip():
            continue
        found = detect_line(LineView(lines, index, kind, entropy_threshold))
        for candidate in found:
            covered_until = max(covered_until, candidate.end_line - 1)
            marker_line = lines[candidate.line - 1]
            suppressed = any(marker in marker_line for marker in INLINE_MARKERS)
            detections.append(Detection(candidate, suppressed))
    return detections


# --------------------------------------------------------------------------- walking


@dataclass(slots=True)
class Skipped:
    path: str  # relative to the scan root
    reason: str


@dataclass(slots=True)
class WalkReport:
    files_seen: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped_count: int = 0
    skipped: list[Skipped] = field(default_factory=list)
    skipped_files: set[str] = field(default_factory=set)  # absolute paths whose content was not examined
    truncated: bool = False

    def skip(self, root: Path, path: Path, reason: str, *, keep: bool = True) -> None:
        self.skipped_count += 1
        if keep:
            self.skipped_files.add(str(path))
        if len(self.skipped) < MAX_SKIPPED_REPORTED:
            self.skipped.append(Skipped(relative(root, path), reason))


def relative(root: Path, path: Path) -> str:
    if root == path:
        return path.name
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def read_text_file(path: Path, max_bytes: int) -> tuple[str | None, str | None]:
    """Return ``(text, None)`` or ``(None, skip_reason)``. Never follows symlinks, never blocks on FIFOs."""
    try:
        info = path.lstat()
    except OSError as exc:
        return None, f"unreadable ({exc.strerror or type(exc).__name__})"
    if stat.S_ISLNK(info.st_mode):
        return None, "symlink (not followed)"
    if not stat.S_ISREG(info.st_mode):
        return None, "not a regular file"
    if info.st_size > max_bytes:
        return None, f"larger than vault.max_file_kb ({max_bytes // 1024} KiB)"
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _NONBLOCK)
    except OSError as exc:
        return None, f"unreadable ({exc.strerror or type(exc).__name__})"
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode):
            return None, "not a regular file"
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        return None, f"larger than vault.max_file_kb ({max_bytes // 1024} KiB)"
    if b"\x00" in data[:BINARY_PROBE]:
        return None, "binary"
    return data.decode("utf-8", "replace"), None


def _keep_dir(base: Path, name: str, root: Path, report: WalkReport) -> bool:
    if name in SKIP_DIRS:
        return False
    full = base / name
    if full.is_symlink():
        report.skip(root, full, "symlinked directory (not followed)", keep=False)
        return False
    return not (full / "pyvenv.cfg").is_file()


def iter_files(root: Path, report: WalkReport) -> Iterator[Path]:
    """Files under ``root`` in deterministic order, without following symlinks."""
    if root.is_file():
        yield root
        return

    def on_error(error: OSError) -> None:
        location = Path(error.filename) if error.filename else root
        report.skip(root, location, f"unreadable directory ({error.strerror or type(error).__name__})")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_error):
        base = Path(dirpath)
        dirnames[:] = [d for d in sorted(dirnames) if _keep_dir(base, d, root, report)]
        for name in sorted(filenames):
            yield base / name
