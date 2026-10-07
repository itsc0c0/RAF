"""Safe handling of untrusted input files.

* size limits are checked before reading;
* lines are read with a hard length limit (a missing newline cannot exhaust memory);
* hashing streams in chunks;
* paths are validated against traversal and symlink tricks when they come from
  untrusted metadata (archive members, bundle manifests).
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import IO

from raf.core.errors import InvalidInputError, NotFoundError, ResourceLimitExceeded, SecurityViolation

CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def check_input_file(path: Path, max_bytes: int) -> os.stat_result:
    """Validate a user-supplied input file: exists, regular, within size limits."""
    try:
        info = path.stat()
    except FileNotFoundError as exc:
        raise NotFoundError(f"{path} does not exist.") from exc
    except OSError as exc:
        raise InvalidInputError(f"Cannot access {path}.", reason=str(exc)) from exc
    if not stat.S_ISREG(info.st_mode):
        raise InvalidInputError(f"{path} is not a regular file.")
    if info.st_size > max_bytes:
        raise ResourceLimitExceeded(
            f"{path.name} is {info.st_size / 1e6:.1f} MB, above the configured limit of {max_bytes / 1e6:.0f} MB.",
            hint="Raise ingest.max_file_mb if this input is expected.",
        )
    return info


def read_head(path: Path, size: int = 65536) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


@dataclass(slots=True)
class Line:
    number: int
    text: str | None  # None when the line exceeded the limit
    length: int


def iter_lines(stream: IO[bytes], max_bytes: int) -> Iterator[Line]:
    """Yield decoded lines with a hard per-line byte limit."""
    number = 0
    while True:
        chunk = stream.readline(max_bytes + 1)
        if not chunk:
            return
        number += 1
        if len(chunk) > max_bytes and not chunk.endswith(b"\n"):
            total = len(chunk)
            # discard the remainder of the oversized line
            while True:
                rest = stream.readline(CHUNK)
                total += len(rest)
                if not rest or rest.endswith(b"\n"):
                    break
            yield Line(number, None, total)
            continue
        text = chunk.decode("utf-8", "replace").rstrip("\r\n")
        if number == 1 and text.startswith("﻿"):
            text = text[1:]
        yield Line(number, text, len(chunk))


def safe_member_path(name: str) -> PurePosixPath:
    """Validate a path from untrusted metadata (archive member, manifest entry)."""
    if not name or "\x00" in name:
        raise SecurityViolation("Empty or NUL-containing path in archive.")
    if "\\" in name or PureWindowsPath(name).drive:
        raise SecurityViolation(f"Windows-style or drive path rejected: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute():
        raise SecurityViolation(f"Absolute path rejected: {name!r}")
    if any(part in ("..", "") for part in path.parts) or name.startswith("./.."):
        raise SecurityViolation(f"Path traversal rejected: {name!r}")
    if len(name) > 1024:
        raise SecurityViolation("Archive member path is too long.")
    return path


def resolve_within(root: Path, relative: PurePosixPath) -> Path:
    """Join ``relative`` under ``root`` and verify the result stays inside ``root``."""
    base = root.resolve()
    candidate = (base / Path(*relative.parts)).resolve()
    if not candidate.is_relative_to(base):
        raise SecurityViolation(f"Path escapes its destination: {relative}")
    return candidate


def iter_directory(root: Path, *, max_files: int) -> Iterator[Path]:
    """Walk a directory without following symlinks (deterministic order)."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__", ".venv"}]
        for name in sorted(filenames):
            count += 1
            if count > max_files:
                raise ResourceLimitExceeded(
                    f"{root} contains more than {max_files} files.",
                    hint="Import a narrower directory or raise the limit.",
                )
            yield Path(dirpath) / name
