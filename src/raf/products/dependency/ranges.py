"""Version ranges as unions of intervals.

Two producers feed the same representation:

* dependency **constraints** as written in manifests (PEP 440 / Poetry, npm and
  Cargo SemVer ranges, RubyGems, Composer, exact Go versions);
* OSV **affected ranges** (``introduced`` / ``fixed`` / ``last_affected`` /
  ``limit`` events, evaluated in version order exactly like the OSV
  specification; ``introduced: "0"`` means "from the beginning").

Approximations (documented): ``!=`` exclusions and pre-release opt-in rules are
ignored, so a constraint's interval may be slightly larger than what a resolver
would accept. This only affects constraint-based (MEDIUM confidence) matches.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass

from raf.products.dependency.versions import InvalidVersion, compare_versions


@dataclass(frozen=True, slots=True)
class Bound:
    version: str
    inclusive: bool


@dataclass(frozen=True, slots=True)
class Interval:
    lo: Bound | None = None  # None: unbounded
    hi: Bound | None = None

    def describe(self) -> str:
        if self.lo is None and self.hi is None:
            return "*"
        parts = []
        if self.lo is not None:
            parts.append((">=" if self.lo.inclusive else ">") + self.lo.version)
        if self.hi is not None:
            parts.append(("<=" if self.hi.inclusive else "<") + self.hi.version)
        return ", ".join(parts)


ALL = Interval()


def contains(ecosystem: str, interval: Interval, version: str) -> bool:
    if interval.lo is not None:
        order = compare_versions(ecosystem, version, interval.lo.version)
        if order < 0 or (order == 0 and not interval.lo.inclusive):
            return False
    if interval.hi is not None:
        order = compare_versions(ecosystem, version, interval.hi.version)
        if order > 0 or (order == 0 and not interval.hi.inclusive):
            return False
    return True


def _max_lo(ecosystem: str, a: Bound | None, b: Bound | None) -> Bound | None:
    if a is None or b is None:
        return b if a is None else a
    order = compare_versions(ecosystem, a.version, b.version)
    if order == 0:
        return Bound(a.version, a.inclusive and b.inclusive)
    return a if order > 0 else b


def _min_hi(ecosystem: str, a: Bound | None, b: Bound | None) -> Bound | None:
    if a is None or b is None:
        return b if a is None else a
    order = compare_versions(ecosystem, a.version, b.version)
    if order == 0:
        return Bound(a.version, a.inclusive and b.inclusive)
    return a if order < 0 else b


def intersect(ecosystem: str, a: Interval, b: Interval) -> Interval:
    return Interval(_max_lo(ecosystem, a.lo, b.lo), _min_hi(ecosystem, a.hi, b.hi))


def is_empty(ecosystem: str, interval: Interval) -> bool:
    if interval.lo is None or interval.hi is None:
        return False
    order = compare_versions(ecosystem, interval.lo.version, interval.hi.version)
    return order > 0 or (order == 0 and not (interval.lo.inclusive and interval.hi.inclusive))


def overlaps(ecosystem: str, a: Sequence[Interval], b: Sequence[Interval]) -> bool:
    return any(not is_empty(ecosystem, intersect(ecosystem, x, y)) for x in a for y in b)


def in_any(ecosystem: str, intervals: Iterable[Interval], version: str) -> bool:
    return any(contains(ecosystem, interval, version) for interval in intervals)


# --------------------------------------------------------------------------- partial versions

_PARTIAL_RE = re.compile(r"^[vV]?(?P<parts>\d+(?:\.(?:\d+|[xX*]))*|[xX*])(?P<rest>[-+][0-9A-Za-z.+\-]*)?$")


@dataclass(frozen=True, slots=True)
class Partial:
    numbers: tuple[int, ...]  # numeric components before the first wildcard
    full: bool  # major.minor.patch present without wildcard
    text: str  # the version as written (keeps pre-release tags of full versions)


def parse_partial(text: str) -> Partial:
    value = text.strip()
    match = _PARTIAL_RE.match(value)
    if match is None:
        raise InvalidVersion(f"'{value[:64]}' is not a version or version prefix.")
    numbers: list[int] = []
    components = match["parts"].split(".")
    for component in components:
        if component in ("x", "X", "*"):
            break
        numbers.append(int(component))
    full = len(numbers) >= 3 and len(numbers) == len(components)
    return Partial(tuple(numbers), full, value.lstrip("vV") if full else _join(numbers))


def _join(numbers: Sequence[int]) -> str:
    padded = list(numbers) + [0] * (3 - len(numbers))
    return ".".join(str(n) for n in padded)


def _bump(numbers: Sequence[int], position: int) -> str:
    """Increment component ``position`` and drop everything after it (``1.2.3`` @1 -> ``1.3.0``)."""
    head = [*numbers[:position], numbers[position] + 1]
    return _join(head)


def _upper(p: Partial) -> Bound:
    """Upper bound of an x-range: ``1.2`` -> ``<1.3.0``."""
    return Bound(_bump(p.numbers, len(p.numbers) - 1), False)


def xrange(p: Partial) -> Interval:
    if not p.numbers:
        return ALL
    if p.full:
        return Interval(Bound(p.text, True), Bound(p.text, True))
    return Interval(Bound(_join(p.numbers), True), _upper(p))


def caret(p: Partial) -> Interval:
    n = p.numbers
    if not n:
        return ALL
    if n[0] != 0 or len(n) == 1:
        hi = _bump(n, 0)
    elif n[1] != 0 or len(n) == 2:
        hi = _bump(n, 1)
    else:
        hi = _bump(n, 2)
    return Interval(Bound(p.text, True), Bound(hi, False))


def tilde(p: Partial) -> Interval:
    """npm/Cargo/Poetry ``~``: ``~1.2.3`` -> ``>=1.2.3 <1.3.0``, ``~1`` -> ``>=1.0.0 <2.0.0``."""
    n = p.numbers
    if not n:
        return ALL
    return Interval(Bound(p.text, True), Bound(_bump(n, 0 if len(n) == 1 else 1), False))


def pessimistic(p: Partial) -> Interval:
    """``~=`` (PEP 440), ``~>`` (RubyGems), Composer ``~``: bump the second-to-last given component."""
    n = p.numbers
    if not n:
        return ALL
    return Interval(Bound(p.text, True), Bound(_bump(n, max(0, len(n) - 2)), False))


def _comparator(op: str, p: Partial, *, partial_semantics: bool) -> Interval:
    """``>``/``>=``/``<``/``<=`` with npm-style partial handling when ``partial_semantics`` is set."""
    if not p.numbers:
        return ALL
    loose = partial_semantics and not p.full
    if op == ">=":
        return Interval(Bound(p.text, True), None)
    if op == ">":
        return Interval(Bound(_upper(p).version, True), None) if loose else Interval(Bound(p.text, False), None)
    if op == "<":
        return Interval(None, Bound(p.text, False))
    if op == "<=":
        return Interval(None, _upper(p)) if loose else Interval(None, Bound(p.text, True))
    raise InvalidVersion(f"Unsupported operator {op!r}.")


# --------------------------------------------------------------------------- constraint syntaxes

_OP_SPACE_RE = re.compile(r"(<=|>=|~=|===|==|!=|~>|<|>|=|\^|~)\s+")
_CLAUSE_RE = re.compile(r"^(===|==|~=|!=|<=|>=|~>|<|>|=|\^|~)?\s*(.*)$")
_NON_SEMVER_RE = re.compile(r"^(?:file:|link:|git|https?:|github:|gitlab:|bitbucket:|workspace:|portal:|patch:)|/")


def _fold(ecosystem: str, clauses: Iterable[Interval]) -> Interval:
    return functools.reduce(lambda acc, item: intersect(ecosystem, acc, item), clauses, ALL)


def _split_clause(clause: str) -> tuple[str, str]:
    match = _CLAUSE_RE.match(clause.strip())
    assert match is not None  # the pattern accepts any text
    return match[1] or "", match[2].strip()


def _exact(version: str) -> Partial:
    """A version used verbatim (exact comparator semantics, no partial expansion)."""
    return Partial((0,), True, version)


def _pypi_clause(clause: str) -> Interval:
    op, version = _split_clause(clause)
    if op == "!=" or version in ("*", ""):
        return ALL
    if version.endswith(".*"):
        return xrange(parse_partial(version[:-2]))
    if op in ("", "==", "===", "="):
        return Interval(Bound(version, True), Bound(version, True))
    if op == "~=":
        return pessimistic(parse_partial(version))
    if op == "^":
        return caret(parse_partial(version))
    if op == "~":
        return tilde(parse_partial(version))
    return _comparator(op, _exact(version), partial_semantics=False)


def _semver_clause(clause: str, *, bare: Callable[[Partial], Interval]) -> Interval:
    op, version = _split_clause(clause)
    p = parse_partial(version)
    if op == "^":
        return caret(p)
    if op in ("~", "~>"):
        return tilde(p)
    if op in ("", "=", "=="):
        return bare(p) if op == "" else xrange(p)
    if op == "!=":
        return ALL
    return _comparator(op, p, partial_semantics=True)


def _hyphen(text: str) -> Interval | None:
    match = re.fullmatch(r"(\S+)\s+-\s+(\S+)", text)
    if match is None:
        return None
    low, high = parse_partial(match[1]), parse_partial(match[2])
    hi = Bound(high.text, True) if high.full else (_upper(high) if high.numbers else None)
    return Interval(Bound(low.text, True) if low.numbers else None, hi)


def _npm(text: str) -> list[Interval]:
    if _NON_SEMVER_RE.search(text) or not re.search(r"\d|^\s*[*xX]?\s*$", text):
        raise InvalidVersion(f"'{text[:64]}' is not a version range (tag, URL or path).")
    out = []
    for group in text.split("||"):
        group = group.strip()
        hyphen = _hyphen(group)
        if hyphen is not None:
            out.append(hyphen)
            continue
        clauses = _OP_SPACE_RE.sub(r"\1", group).split()
        out.append(_fold("npm", (_semver_clause(c, bare=xrange) for c in clauses)))
    return out


def _cargo(text: str) -> list[Interval]:
    clauses = [c.strip() for c in text.split(",") if c.strip()]
    return [_fold("cargo", (_semver_clause(_OP_SPACE_RE.sub(r"\1", c), bare=caret) for c in clauses))]


def _pypi(text: str) -> list[Interval]:
    out = []
    for group in re.split(r"\|\|?", text):
        clauses = [_OP_SPACE_RE.sub(r"\1", c.strip()) for c in group.split(",") if c.strip()]
        out.append(_fold("pypi", (_pypi_clause(c) for c in clauses)))
    return out


def _exact_or_comparators(ecosystem: str, text: str, *, tilde_fn: Callable[[Partial], Interval]) -> Interval:
    clauses = [c for c in re.split(r"[,\s]+", _OP_SPACE_RE.sub(r"\1", text)) if c]
    parts: list[Interval] = []
    for clause in clauses:
        op, version = _split_clause(clause)
        bare_version = version.lstrip("vV")
        if op == "!=":
            continue
        if "*" in version or version.lower().endswith(".x"):
            parts.append(xrange(parse_partial(version.rstrip("*xX").rstrip(".") or "*")))
        elif op in ("", "=", "=="):
            parts.append(Interval(Bound(bare_version, True), Bound(bare_version, True)))
        elif op in ("~>", "~"):
            parts.append(tilde_fn(parse_partial(version)))
        elif op == "^":
            parts.append(caret(parse_partial(version)))
        else:
            parts.append(_comparator(op, _exact(bare_version), partial_semantics=False))
    return _fold(ecosystem, parts)


def _rubygems(text: str) -> list[Interval]:
    return [_exact_or_comparators("rubygems", text, tilde_fn=pessimistic)]


def _composer(text: str) -> list[Interval]:
    cleaned = re.sub(r"@(?:dev|alpha|beta|RC|stable)\b", "", text, flags=re.IGNORECASE)
    if re.search(r"(?:^|\s|\|)dev-", cleaned):
        raise InvalidVersion(f"'{text[:64]}' targets a development branch.")
    out = []
    for group in re.split(r"\s*\|\|?\s*", cleaned):
        hyphen = _hyphen(group.strip())
        out.append(hyphen or _exact_or_comparators("packagist", group, tilde_fn=pessimistic))
    return out


def _go(text: str) -> list[Interval]:
    version = text.strip()
    if not re.match(r"^v?\d", version):
        raise InvalidVersion(f"'{version[:64]}' is not a Go module version.")
    return [Interval(Bound(version, True), Bound(version, True))]


_PARSERS: Mapping[str, Callable[[str], list[Interval]]] = {
    "pypi": _pypi,
    "npm": _npm,
    "cargo": _cargo,
    "rubygems": _rubygems,
    "packagist": _composer,
    "go": _go,
}


def constraint_intervals(ecosystem: str, constraint: str) -> list[Interval] | None:
    """Versions a constraint permits, or None when it cannot be interpreted (tag, URL, branch)."""
    text = constraint.strip()
    if text in ("", "*", "latest") and ecosystem != "go":
        return [ALL] if text != "latest" else None
    parser = _PARSERS.get(ecosystem, _rubygems)
    try:
        intervals = parser(text)
        for interval in intervals:  # validate every bound against the ecosystem's comparator
            for bound in (interval.lo, interval.hi):
                if bound is not None:
                    compare_versions(ecosystem, bound.version, bound.version)
    except (InvalidVersion, ValueError, IndexError):
        return None
    return intervals


# --------------------------------------------------------------------------- OSV ranges

_EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")


def _event_order(ecosystem: str, a: tuple[str, str], b: tuple[str, str]) -> int:
    a_zero = a == ("introduced", "0")
    b_zero = b == ("introduced", "0")
    if a_zero or b_zero:
        return 0 if a_zero and b_zero else (-1 if a_zero else 1)
    return compare_versions(ecosystem, a[1], b[1])


def osv_intervals(ecosystem: str, events: Sequence[Mapping[str, object]]) -> list[Interval]:
    """Affected intervals of one OSV range (raises InvalidVersion for unsortable events)."""
    flat = [(kind, str(event[kind])) for event in events for kind in _EVENT_KINDS if kind in event]

    def order(a: tuple[str, str], b: tuple[str, str]) -> int:
        return _event_order(ecosystem, a, b)

    ordered = sorted(flat, key=functools.cmp_to_key(order))
    intervals: list[Interval] = []
    start: Bound | None = None
    open_ = False
    for kind, version in ordered:
        if kind == "introduced":
            if not open_:
                start, open_ = (None if version == "0" else Bound(version, True)), True
        elif open_:
            intervals.append(Interval(start, Bound(version, kind == "last_affected")))
            open_ = False
    if open_:
        intervals.append(Interval(start, None))
    return intervals
