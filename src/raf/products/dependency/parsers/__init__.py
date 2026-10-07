"""Manifest and lockfile parsers for R$F Dependency.

Supported files (ecosystem):

* requirements*.txt (also ``requirements/*.txt``), pyproject.toml (PEP 621 dependencies and
  optional-dependencies, PEP 735 dependency-groups, Poetry), poetry.lock, Pipfile.lock (pypi)
* package.json, package-lock.json / npm-shrinkwrap.json (v1, v2, v3), yarn.lock (v1, Berry) (npm)
* go.mod (go), Cargo.toml and Cargo.lock (cargo), Gemfile.lock (rubygems), composer.lock (packagist)
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import PurePosixPath

from raf.products.dependency.parsers.base import ManifestResult
from raf.products.dependency.parsers.javascript import parse_package_json, parse_package_lock, parse_yarn_lock
from raf.products.dependency.parsers.other import (
    parse_cargo_lock,
    parse_cargo_toml,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_go_mod,
)
from raf.products.dependency.parsers.python import parse_pipfile_lock, parse_poetry_lock, parse_pyproject

Parser = Callable[[str, str], ManifestResult]

PARSERS: dict[str, Parser] = {
    "pyproject.toml": parse_pyproject,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "go.mod": parse_go_mod,
    "Cargo.toml": parse_cargo_toml,
    "Cargo.lock": parse_cargo_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
}
REQUIREMENTS = "requirements"
_REQUIREMENTS_RE = re.compile(r"^(?:.*[-_.])?requirements(?:[-_.].*)?\.txt$", re.IGNORECASE)


def detect_kind(rel_path: str) -> str | None:
    """The parser key for a file, ``"requirements"`` for pip requirement files, or None."""
    path = PurePosixPath(rel_path)
    if path.name in PARSERS:
        return path.name
    if _REQUIREMENTS_RE.match(path.name) or (path.parent.name == "requirements" and path.suffix == ".txt"):
        return REQUIREMENTS
    return None


__all__ = ["PARSERS", "REQUIREMENTS", "ManifestResult", "detect_kind"]
