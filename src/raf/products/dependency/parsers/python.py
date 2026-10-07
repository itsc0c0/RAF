"""PyPI manifests: requirements*.txt, pyproject.toml (PEP 621, PEP 735, Poetry), poetry.lock, Pipfile.lock."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any

from raf.products.dependency.names import normalize_name
from raf.products.dependency.parsers.base import (
    Declared,
    Locked,
    ManifestResult,
    ParseError,
    PkgRef,
    exact_version,
    find_line,
)

ECO = "pypi"
_DEV_WORDS = re.compile(
    r"(?:^|[-_./])(?:dev|develop|test|tests|testing|lint|docs?|ci|typing)(?:[-_./]|$)", re.IGNORECASE
)
_REQ_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[(?P<extras>[^\]]*)\])?\s*(?P<rest>.*)$"
)
_SPEC_RE = re.compile(r"^[\s\w.*!=<>~,+\-^|]*$")
_MAX_INCLUDE_DEPTH = 10


def requirement_parts(text: str) -> tuple[str, str] | None:
    """``(name, constraint)`` of a PEP 508 requirement; markers and extras dropped. None if unparseable."""
    body = text.split(";", 1)[0].strip()
    match = _REQ_RE.match(body)
    if match is None:
        return None
    rest = match["rest"].strip()
    if rest.startswith("@"):
        return match["name"], ""  # direct URL reference: no resolvable version constraint
    if rest.startswith("(") and rest.endswith(")"):
        rest = rest[1:-1].strip()
    if rest and not _SPEC_RE.match(rest):
        return None
    return match["name"], rest


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Join backslash continuations and strip comments (a ``#`` at line start or after whitespace)."""
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        line = raw
        continued = line.rstrip().endswith("\\")
        if continued:
            line = line.rstrip()[:-1]
        buffer += line + " "
        if continued:
            continue
        cleaned = re.split(r"(?:^|\s)#", buffer, maxsplit=1)[0].strip()
        buffer = ""
        if cleaned:
            yield start, cleaned


def _scope_for(rel_path: str) -> str:
    return "dev" if _DEV_WORDS.search(PurePosixPath(rel_path).name.lower().replace("requirements", "")) else "runtime"


class RequirementsParser:
    """requirements*.txt with ``-r`` includes resolved only inside the scan root (no URLs, no symlinks)."""

    def __init__(self, root: Path, reader: Callable[[Path], str]) -> None:
        self.root = root
        self.reader = reader
        self.seen: set[Path] = set()

    def parse(self, path: Path, *, depth: int = 0) -> list[ManifestResult]:
        rel = path.relative_to(self.root).as_posix()
        self.seen.add(path)
        result = ManifestResult(path=rel, kind="requirements", ecosystem=ECO)
        results = [result]
        scope = _scope_for(rel)
        for line_no, line in _logical_lines(self.reader(path)):
            if line.startswith("-"):
                results.extend(self._option(result, path, line, depth))
                continue
            self._requirement(result, line_no, line, scope)
        return results

    def _option(self, result: ManifestResult, path: Path, line: str, depth: int) -> list[ManifestResult]:
        match = re.match(r"^(-r|--requirement|-c|--constraint|-e|--editable)(?:\s*=?\s*)(\S+)", line)
        if match is None:
            return []  # index URLs, --hash, --pre ... carry no dependency
        flag, target = match.groups()
        if flag in ("-e", "--editable"):
            result.warn(f"editable requirement {target[:80]} not resolved")
            return []
        if flag in ("-c", "--constraint"):
            return []
        return self._include(result, path, target, depth)

    def _include(self, result: ManifestResult, path: Path, target: str, depth: int) -> list[ManifestResult]:
        if "://" in target or depth >= _MAX_INCLUDE_DEPTH:
            result.warn(f"include {target[:80]} skipped (remote or too deep)")
            return []
        candidate = path.parent / target
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            result.warn(f"include {target[:80]} cannot be resolved")
            return []
        if not resolved.is_relative_to(self.root) or candidate.is_symlink():
            result.warn(f"include {target[:80]} is outside the scan root or a symlink; not followed")
            return []
        if resolved in self.seen:
            return []
        if not resolved.is_file():
            result.warn(f"include {target[:80]} does not exist")
            return []
        try:
            return self.parse(resolved, depth=depth + 1)
        except ParseError as exc:
            result.warn(f"include {target[:80]}: {exc.message}")
            return []

    @staticmethod
    def _requirement(result: ManifestResult, line_no: int, line: str, scope: str) -> None:
        requirement = re.split(r"\s+--?[A-Za-z]", line, maxsplit=1)[0]  # per-requirement options (--hash=...)
        parts = requirement_parts(requirement)
        if parts is None:
            result.warn(f"line {line_no}: unsupported requirement {requirement[:60]!r}")
            return
        name, constraint = parts
        result.declared.append(
            Declared(
                ecosystem=ECO,
                name=normalize_name(ECO, name),
                constraint=constraint.replace(" ", ""),
                scope=scope,
                manifest=result.path,
                line=line_no,
                exact=exact_version(ECO, constraint),
                raw_name=name,
            )
        )


# --------------------------------------------------------------------------- pyproject.toml


def _load_toml(text: str, rel: str) -> dict[str, Any]:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(f"{rel} is not valid TOML.", reason=str(exc)[:200]) from exc


def _pep508_list(
    result: ManifestResult, lines: list[str], items: Any, scope: str, group: str | None, *, origin: str
) -> None:
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, str):
            continue  # {include-group = ...} in PEP 735 groups
        parts = requirement_parts(item)
        if parts is None:
            result.warn(f"{origin}: unsupported requirement {item[:60]!r}")
            continue
        name, constraint = parts
        result.declared.append(
            Declared(
                ecosystem=ECO,
                name=normalize_name(ECO, name),
                constraint=constraint.replace(" ", ""),
                scope=scope,
                manifest=result.path,
                line=find_line(lines, ECO, name),
                group=group,
                exact=exact_version(ECO, constraint),
                raw_name=name,
            )
        )


def _poetry_constraint(spec: Any) -> tuple[str, bool, bool]:
    """``(constraint, optional, resolvable)`` of a Poetry dependency value."""
    if isinstance(spec, str):
        return spec.strip(), False, True
    if isinstance(spec, dict):
        if any(key in spec for key in ("git", "path", "url")) and "version" not in spec:
            return "", bool(spec.get("optional")), False
        return str(spec.get("version", "")).strip(), bool(spec.get("optional")), True
    if isinstance(spec, list):
        versions = [str(s.get("version", "")).strip() for s in spec if isinstance(s, dict) and s.get("version")]
        return " || ".join(versions), any(isinstance(s, dict) and s.get("optional") for s in spec), True
    return "", False, False


def _poetry_table(result: ManifestResult, lines: list[str], table: Any, scope: str, group: str | None) -> None:
    if not isinstance(table, dict):
        return
    for name, spec in table.items():
        if str(name).lower() == "python":
            continue
        constraint, optional, resolvable = _poetry_constraint(spec)
        if not resolvable:
            result.warn(f"{name}: git/path/url dependency not resolved")
        result.declared.append(
            Declared(
                ecosystem=ECO,
                name=normalize_name(ECO, str(name)),
                constraint="" if constraint == "*" else constraint,
                scope="optional" if optional and scope == "runtime" else scope,
                manifest=result.path,
                line=find_line(lines, ECO, str(name)),
                group=group,
                exact=exact_version(ECO, constraint, bare_is_exact=True),
                raw_name=str(name),
            )
        )


def parse_pyproject(rel: str, text: str) -> ManifestResult:
    data = _load_toml(text, rel)
    lines = text.splitlines()
    result = ManifestResult(path=rel, kind="pyproject", ecosystem=ECO)
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    assert isinstance(project, dict)
    _pep508_list(result, lines, project.get("dependencies"), "runtime", None, origin="project.dependencies")
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group, items in optional.items():
            _pep508_list(result, lines, items, "optional", str(group), origin=f"optional-dependencies.{group}")
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group, items in groups.items():
            _pep508_list(result, lines, items, "dev", str(group), origin=f"dependency-groups.{group}")
    poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        _poetry_table(result, lines, poetry.get("dependencies"), "runtime", None)
        _poetry_table(result, lines, poetry.get("dev-dependencies"), "dev", "dev")
        poetry_groups = poetry.get("group")
        if isinstance(poetry_groups, dict):
            for group, body in poetry_groups.items():
                if isinstance(body, dict):
                    scope = "runtime" if group == "main" else "dev"
                    _poetry_table(result, lines, body.get("dependencies"), scope, str(group))
    return result


# --------------------------------------------------------------------------- lockfiles


def _poetry_scope(package: dict[str, Any]) -> str:
    if package.get("optional"):
        return "optional"
    groups = package.get("groups")
    if isinstance(groups, list) and groups:
        return "runtime" if "main" in groups else "dev"
    return "dev" if package.get("category") == "dev" else "runtime"


def _name_lines(text: str, pattern: re.Pattern[str]) -> dict[str, int]:
    """First line of each package name, in one pass over the file."""
    found: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        match = pattern.match(line)
        if match is not None:
            found.setdefault(normalize_name(ECO, match.group(1)), number)
    return found


_POETRY_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"')
_PIPFILE_NAME_RE = re.compile(r'^\s{8}"([^"]+)"\s*:\s*\{')


def parse_poetry_lock(rel: str, text: str) -> ManifestResult:
    data = _load_toml(text, rel)
    result = ManifestResult(path=rel, kind="poetry.lock", ecosystem=ECO)
    packages = data.get("package") if isinstance(data.get("package"), list) else []
    assert isinstance(packages, list)
    positions = _name_lines(text, _POETRY_NAME_RE)
    by_name: dict[str, list[PkgRef]] = {}
    requirements: list[tuple[PkgRef, list[str]]] = []
    for package in packages:
        if not isinstance(package, dict) or not package.get("name") or not package.get("version"):
            continue
        name, version = normalize_name(ECO, str(package["name"])), str(package["version"])
        locked = Locked(ECO, name, version, rel, scope=_poetry_scope(package), line=positions.get(name))
        result.locked.append(locked)
        by_name.setdefault(name, []).append(locked.ref)
        deps = package.get("dependencies")
        if isinstance(deps, dict):
            requirements.append((locked.ref, [normalize_name(ECO, str(dep)) for dep in deps]))
    for parent, children in requirements:
        for child in children:
            result.edges.extend((parent, ref) for ref in by_name.get(child, []))
    return result


def parse_pipfile_lock(rel: str, text: str) -> ManifestResult:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ParseError(f"{rel} is not valid JSON.") from exc
    result = ManifestResult(path=rel, kind="Pipfile.lock", ecosystem=ECO)
    if not isinstance(data, dict):
        return result
    positions = _name_lines(text, _PIPFILE_NAME_RE)
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, info in entries.items():
            version = str(info.get("version", "")).lstrip("=").strip() if isinstance(info, dict) else ""
            if not version:
                result.warn(f"{name}: no version (VCS or editable entry)")
                continue
            norm = normalize_name(ECO, str(name))
            result.locked.append(Locked(ECO, norm, version, rel, scope=scope, line=positions.get(norm)))
    return result
