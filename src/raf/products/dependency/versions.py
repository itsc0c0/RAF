"""Version ordering per ecosystem.

* **PyPI** - a PEP 440 subset: epochs (``1!2.0``), release segments with
  trailing zeros ignored (``1.0 == 1.0.0``), pre-releases (``a``/``b``/``rc`` and
  the ``alpha``/``beta``/``c``/``pre``/``preview`` spellings), post releases
  (``.post1``, ``-1``, ``rev``/``r``) and dev releases (``.dev1``, which sort
  before pre-releases of the same release). Local versions (``+local``) are
  ignored.
* **npm, crates.io, Go** - Semantic Versioning 2.0: optional ``v``/``=``
  prefix, missing minor/patch read as 0, a pre-release sorts before its release,
  pre-release identifiers compare numerically (numbers) or lexically (text, which
  sorts after numbers), a shorter identifier list sorts first, build metadata
  (``+build``, ``+incompatible``) is ignored. Go pseudo-versions are pre-releases.
* **Everything else** (RubyGems, Packagist, unknown ecosystems) and versions the
  primary scheme cannot parse - a generic comparator over runs of digits and
  letters: missing components count as 0, known pre-release words sort before
  the release (dev/snapshot < alpha/a < beta/b < milestone/m < rc/pre/preview <
  unknown words), post-release words (post, patch, p, pl, rev, r, sp) sort after
  it, and release words (final, ga, release, stable) equal it.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable
from itertools import zip_longest
from typing import Any

from raf.core.errors import InvalidInputError

VersionKey = tuple[Any, ...]


class InvalidVersion(InvalidInputError):
    code = "raf.invalid_version"


def _invalid(text: str, scheme: str) -> InvalidVersion:
    return InvalidVersion(f"'{text[:64]}' is not a valid {scheme} version.")


# --------------------------------------------------------------------------- PEP 440

_PEP440_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


def pep440_key(text: str) -> VersionKey:
    match = _PEP440_RE.match(text)
    if match is None:
        raise _invalid(text, "PEP 440")
    release = [int(part) for part in match["release"].split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    if match["pre_l"]:
        pre: tuple[int, int, int] = (0, _PRE_RANK[match["pre_l"].lower()], int(match["pre_n"] or 0))
    elif match["dev_l"] and not match["post"]:
        pre = (-1, 0, 0)  # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (1, 0, 0)
    post = (0, int(match["post_n1"] or match["post_n2"] or 0)) if match["post"] else (-1, 0)
    dev = (0, int(match["dev_n"] or 0)) if match["dev_l"] else (1, 0)
    return (int(match["epoch"] or 0), tuple(release), pre, post, dev)


# --------------------------------------------------------------------------- SemVer

_SEMVER_RE = re.compile(
    r"^\s*[vV=]*\s*(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<pre>[0-9A-Za-z.\-]+))?(?:\+(?P<build>[0-9A-Za-z.\-+]*))?\s*$"
)


def semver_key(text: str) -> VersionKey:
    match = _SEMVER_RE.match(text)
    if match is None:
        raise _invalid(text, "semantic")
    if match["pre"]:
        identifiers = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in match["pre"].split("."))
        pre: tuple[Any, ...] = (0, identifiers)
    else:
        pre = (1, ())
    return (int(match["major"]), int(match["minor"] or 0), int(match["patch"] or 0), pre)


# --------------------------------------------------------------------------- generic

_TOKEN_RE = re.compile(r"\d+|[a-z]+")
_PRE_WORDS = {
    "dev": 0,
    "snapshot": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "milestone": 3,
    "m": 3,
    "rc": 4,
    "cr": 4,
    "c": 4,
    "pre": 4,
    "preview": 4,
}
_POST_WORDS = frozenset({"post", "patch", "p", "pl", "rev", "r", "sp"})
_RELEASE_WORDS = frozenset({"final", "ga", "release", "stable"})
_PAD = (2, 0, "")


def generic_tokens(text: str) -> list[tuple[int, float, str]]:
    value = text.strip().lower()
    while value[:1] in ("v", "="):
        value = value[1:]
    tokens = _TOKEN_RE.findall(value.split("+", 1)[0])
    if not tokens or not tokens[0].isdigit():
        raise _invalid(text, "generic")
    out: list[tuple[int, float, str]] = []
    for token in tokens:
        if token.isdigit():
            out.append((2, int(token), ""))
        elif token in _RELEASE_WORDS:
            out.append(_PAD)
        elif token in _POST_WORDS:
            out.append((2, 0.5, ""))  # after X.0, before X.1
        else:
            out.append((1, _PRE_WORDS.get(token, 9), token))
    return out


def generic_compare(a: str, b: str) -> int:
    for left, right in zip_longest(generic_tokens(a), generic_tokens(b), fillvalue=_PAD):
        if left != right:
            return -1 if left < right else 1
    return 0


# --------------------------------------------------------------------------- dispatch

_SCHEMES = {"pypi": "pep440", "npm": "semver", "cargo": "semver", "go": "semver", "semver": "semver"}


def scheme_for(ecosystem: str) -> str:
    return _SCHEMES.get(ecosystem, "generic")


def compare_versions(ecosystem: str, a: str, b: str) -> int:
    """-1, 0 or 1. Falls back to the generic comparator when the primary scheme cannot parse both versions."""
    scheme = scheme_for(ecosystem)
    if scheme != "generic":
        keyer = pep440_key if scheme == "pep440" else semver_key
        try:
            left, right = keyer(a), keyer(b)
        except InvalidVersion:
            pass
        else:
            return (left > right) - (left < right)
    return generic_compare(a, b)


def is_valid(ecosystem: str, version: str) -> bool:
    try:
        compare_versions(ecosystem, version, version)
    except InvalidVersion:
        return False
    return True


def sort_versions(ecosystem: str, versions: Iterable[str]) -> list[str]:
    def order(a: str, b: str) -> int:
        return compare_versions(ecosystem, a, b)

    return sorted(versions, key=functools.cmp_to_key(order))
