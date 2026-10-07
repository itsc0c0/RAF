"""Shared model and helpers for manifest and lockfile parsers.

Parsers are pure functions over text (no I/O except :func:`read_text`) and treat
their input as untrusted: they never execute or evaluate it, they tolerate
malformed entries (recorded as warnings) and they never follow symlinks.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from raf.core.errors import InvalidInputError, ResourceLimitExceeded
from raf.products.dependency.names import normalize_name

SCOPES = ("runtime", "optional", "dev")
SCOPE_RANK = {"runtime": 0, "optional": 1, "dev": 2}

PkgRef = tuple[str, str, str]  # (ecosystem, normalized name, version)

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class ParseError(InvalidInputError):
    code = "raf.dependency.parse"


@dataclass(slots=True)
class Declared:
    """A dependency as declared in a manifest (a constraint, not an installed version)."""

    ecosystem: str
    name: str  # normalized
    constraint: str
    scope: str
    manifest: str  # path relative to the scan root
    line: int | None = None
    group: str | None = None
    exact: str | None = None  # the version when the constraint is an exact pin
    raw_name: str | None = None


@dataclass(slots=True)
class Locked:
    """A resolved package version (from a lockfile or an exact pin)."""

    ecosystem: str
    name: str  # normalized
    version: str
    manifest: str
    scope: str | None = None
    direct: bool | None = None  # None: the file does not say
    line: int | None = None

    @property
    def ref(self) -> PkgRef:
        return (self.ecosystem, self.name, self.version)


@dataclass(slots=True)
class ManifestResult:
    path: str
    kind: str
    ecosystem: str
    declared: list[Declared] = field(default_factory=list)
    locked: list[Locked] = field(default_factory=list)
    edges: list[tuple[PkgRef, PkgRef]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        if len(self.warnings) < 50:
            self.warnings.append(f"{self.path}: {message}"[:300])


def stronger_scope(a: str | None, b: str | None) -> str | None:
    if a is None or b is None:
        return a or b
    return a if SCOPE_RANK.get(a, 0) <= SCOPE_RANK.get(b, 0) else b


def read_text(path: Path, max_bytes: int) -> str:
    """Read a manifest: regular file only (no symlinks, FIFOs or devices), bounded size, UTF-8."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise ParseError(f"Cannot read {path.name}.", reason=exc.strerror or type(exc).__name__) from exc
    if not stat.S_ISREG(info.st_mode):
        raise ParseError(f"{path.name} is not a regular file (symlinks are not followed).")
    if info.st_size > max_bytes:
        raise ResourceLimitExceeded(
            f"{path.name} is larger than {max_bytes // (1024 * 1024)} MB.",
            hint="Raise ingest.max_json_document_mb if this manifest is expected.",
        )
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _NONBLOCK)
    except OSError as exc:
        raise ParseError(f"Cannot read {path.name}.", reason=exc.strerror or type(exc).__name__) from exc
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ResourceLimitExceeded(f"{path.name} grew beyond the size limit while being read.")
    return data.decode("utf-8", "replace").removeprefix("﻿")


def find_line(lines: list[str], ecosystem: str, name: str, start: int = 0) -> int | None:
    """Best-effort 1-based line on which a dependency name appears (TOML/JSON give no positions)."""
    target = normalize_name(ecosystem, name)
    pattern = re.escape(name)
    if ecosystem == "pypi":
        pattern = "[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", name))
    regex = re.compile(rf"(?<![\w.\-/@]){pattern}(?![\w.\-/])", re.IGNORECASE)
    for index in range(max(0, start), len(lines)):
        for match in regex.finditer(lines[index]):
            if normalize_name(ecosystem, match.group(0)) == target:
                return index + 1
    return None


_PY_EXACT_RE = re.compile(r"^\s*===?\s*([0-9][^\s,;*]*)\s*$")
_SEMVER_EXACT_RE = re.compile(r"^\s*=?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?)\s*$")
_CARGO_EXACT_RE = re.compile(r"^\s*=\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?)\s*$")
_BARE_RE = re.compile(r"^\s*(?:==?\s*)?v?(\d[0-9A-Za-z.\-+]*)\s*$")


def exact_version(ecosystem: str, constraint: str, *, bare_is_exact: bool = False) -> str | None:
    """The pinned version when ``constraint`` allows exactly one version, else None."""
    text = constraint.strip()
    if not text:
        return None
    if ecosystem == "pypi":
        match = _PY_EXACT_RE.match(text) or (_BARE_RE.match(text) if bare_is_exact else None)
        return match.group(1) if match else None
    if ecosystem == "npm":
        match = _SEMVER_EXACT_RE.match(text)
        return match.group(1) if match else None
    if ecosystem == "cargo":
        match = _CARGO_EXACT_RE.match(text)
        return match.group(1) if match else None
    if ecosystem == "go":
        return text if re.match(r"^v\d", text) else None
    if ecosystem in ("rubygems", "packagist"):
        match = _BARE_RE.match(text)
        return match.group(1) if match else None
    return None
