"""Ecosystems, package-name normalization and package URLs (purl)."""

from __future__ import annotations

import re
from urllib.parse import quote, unquote

ECOSYSTEMS: tuple[str, ...] = ("pypi", "npm", "go", "cargo", "rubygems", "packagist")

_OSV_TO_ECOSYSTEM = {
    "pypi": "pypi",
    "npm": "npm",
    "go": "go",
    "crates.io": "cargo",
    "rubygems": "rubygems",
    "packagist": "packagist",
}
ECOSYSTEM_TO_OSV = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
}
_PURL_TYPES = {
    "pypi": "pypi",
    "npm": "npm",
    "go": "golang",
    "cargo": "cargo",
    "rubygems": "gem",
    "packagist": "composer",
}
_PURL_TO_ECOSYSTEM = {purl_type: ecosystem for ecosystem, purl_type in _PURL_TYPES.items()}
_PEP503_RE = re.compile(r"[-_.]+")


def ecosystem_from_osv(value: str) -> str:
    """Map an OSV ecosystem (``PyPI``, ``crates.io``, ``Debian:12`` ...) to an R$F ecosystem id."""
    base = value.strip().lower().split(":", 1)[0]
    return _OSV_TO_ECOSYSTEM.get(base, base)


def normalize_name(ecosystem: str, name: str) -> str:
    """Canonical comparison form: PEP 503 for PyPI, lowercase elsewhere."""
    text = name.strip()
    if ecosystem == "pypi":
        return _PEP503_RE.sub("-", text).lower()
    return text.lower()


def package_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}/{name}@{version}"


def purl(ecosystem: str, name: str, version: str | None = None) -> str:
    """Package URL, e.g. ``pkg:pypi/raven-auth@1.2.0`` or ``pkg:npm/%40raven/ui@2.0.0``."""
    purl_type = _PURL_TYPES.get(ecosystem, ecosystem)
    segments = [quote(part, safe="") for part in name.split("/") if part]
    text = f"pkg:{purl_type}/" + "/".join(segments)
    if version:
        text += "@" + quote(version, safe="")
    return text


def parse_purl(text: str) -> tuple[str, str, str | None] | None:
    """``(ecosystem, normalized name, version)`` for a package URL, or None when it is not one."""
    if not text.startswith("pkg:"):
        return None
    rest = text[4:].split("#", 1)[0].split("?", 1)[0].lstrip("/")
    purl_type, _, path = rest.partition("/")
    if not purl_type or not path:
        return None
    version: str | None = None
    at = path.rfind("@")
    if at > 0:
        path, version = path[:at], unquote(path[at + 1 :]) or None
    segments = [unquote(part) for part in path.split("/") if part]
    if not segments:
        return None
    ecosystem = _PURL_TO_ECOSYSTEM.get(purl_type.lower(), purl_type.lower())
    return ecosystem, normalize_name(ecosystem, "/".join(segments)), version
