"""Go (go.mod), Rust (Cargo.toml, Cargo.lock), Ruby (Gemfile.lock) and PHP (composer.lock) manifests."""

from __future__ import annotations

import json
import re
import tomllib
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

# --------------------------------------------------------------------------- go.mod

_GO_REQUIRE_RE = re.compile(r"^(?:require\s+)?(?P<module>\"[^\"]+\"|\S+)\s+(?P<version>v\S+)")


def parse_go_mod(rel: str, text: str) -> ManifestResult:
    """``require`` lines and blocks; ``// indirect`` entries are transitive. replace/exclude are not applied."""
    result = ManifestResult(path=rel, kind="go.mod", ecosystem="go")
    in_block = False
    for number, raw in enumerate(text.splitlines(), start=1):
        code, _, comment = raw.partition("//")
        line = code.strip()
        if line.startswith(("replace", "exclude")) and not in_block:
            result.warn(f"line {number}: {line.split()[0]} directives are not applied")
            continue
        if line.startswith("require") and line.endswith("("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if not (in_block or line.startswith("require ")):
            continue
        match = _GO_REQUIRE_RE.match(line)
        if match is None:
            continue
        module, version = match["module"].strip('"'), match["version"]
        name = normalize_name("go", module)
        indirect = "indirect" in comment
        result.locked.append(Locked("go", name, version, rel, scope="runtime", direct=not indirect, line=number))
        if not indirect:
            result.declared.append(
                Declared("go", name, version, "runtime", rel, line=number, exact=version, raw_name=module)
            )
    return result


# --------------------------------------------------------------------------- Cargo


def _load_toml(rel: str, text: str) -> dict[str, Any]:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(f"{rel} is not valid TOML.", reason=str(exc)[:200]) from exc


def _cargo_tables(data: dict[str, Any]) -> list[tuple[Any, str]]:
    tables: list[tuple[Any, str]] = []
    sections = (("dependencies", "runtime"), ("dev-dependencies", "dev"), ("build-dependencies", "dev"))
    for key, scope in sections:
        tables.append((data.get(key), scope))
    targets = data.get("target")
    if isinstance(targets, dict):
        for body in targets.values():
            if isinstance(body, dict):
                tables.extend((body.get(key), scope) for key, scope in sections)
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        tables.append((workspace.get("dependencies"), "runtime"))
    return tables


def parse_cargo_toml(rel: str, text: str) -> ManifestResult:
    data = _load_toml(rel, text)
    result = ManifestResult(path=rel, kind="Cargo.toml", ecosystem="cargo")
    lines = text.splitlines()
    for table, scope in _cargo_tables(data):
        if not isinstance(table, dict):
            continue
        for key, spec in table.items():
            real, constraint, optional = str(key), "", False
            if isinstance(spec, str):
                constraint = spec.strip()
            elif isinstance(spec, dict):
                real = str(spec.get("package") or key)
                constraint = str(spec.get("version", "")).strip()
                optional = bool(spec.get("optional"))
                if not constraint and any(k in spec for k in ("path", "git")):
                    result.warn(f"{key}: path/git dependency not resolved")
            result.declared.append(
                Declared(
                    ecosystem="cargo",
                    name=normalize_name("cargo", real),
                    constraint=constraint,
                    scope="optional" if optional and scope == "runtime" else scope,
                    manifest=rel,
                    line=find_line(lines, "cargo", str(key)),
                    exact=exact_version("cargo", constraint),
                    raw_name=real,
                )
            )
    return result


def _cargo_dep(entry: str) -> tuple[str, str | None]:
    parts = entry.split()
    return normalize_name("cargo", parts[0]), parts[1] if len(parts) > 1 else None


def parse_cargo_lock(rel: str, text: str) -> ManifestResult:
    """Registry/git packages become packages; source-less entries (workspace members) define direct deps."""
    data = _load_toml(rel, text)
    result = ManifestResult(path=rel, kind="Cargo.lock", ecosystem="cargo")
    packages = [p for p in data.get("package", []) if isinstance(p, dict) and p.get("name") and p.get("version")]
    by_name: dict[str, list[PkgRef]] = {}
    for package in packages:
        if "source" not in package:
            continue
        locked = Locked("cargo", normalize_name("cargo", str(package["name"])), str(package["version"]), rel)
        result.locked.append(locked)
        by_name.setdefault(locked.name, []).append(locked.ref)

    def lookup(entry: str) -> list[PkgRef]:
        name, version = _cargo_dep(entry)
        refs = by_name.get(name, [])
        return [r for r in refs if version is None or r[2] == version] or ([] if version else refs)

    direct: set[PkgRef] = set()
    for package in packages:
        deps = [str(d) for d in package.get("dependencies", []) if isinstance(d, str)]
        if "source" not in package:
            direct.update(ref for dep in deps for ref in lookup(dep))
            continue
        parent = ("cargo", normalize_name("cargo", str(package["name"])), str(package["version"]))
        result.edges.extend((parent, ref) for dep in deps for ref in lookup(dep))
    for locked in result.locked:
        locked.direct = locked.ref in direct
    return result


# --------------------------------------------------------------------------- Gemfile.lock

_GEM_SPEC_RE = re.compile(r"^(?P<indent> {4}| {6})(?P<name>[^\s(!]+)(?: \((?P<version>[^)]*)\))?\s*$")
_GEM_DEP_RE = re.compile(r"^ {2}(?P<name>[^\s(!]+)(?P<bang>!)?(?: \((?P<constraint>[^)]*)\))?\s*$")


def parse_gemfile_lock(rel: str, text: str) -> ManifestResult:
    """``GEM`` specs (platform suffixes stripped) and the ``DEPENDENCIES`` section (direct gems)."""
    result = ManifestResult(path=rel, kind="Gemfile.lock", ecosystem="rubygems")
    section, in_specs = "", False
    current: Locked | None = None
    children: list[tuple[Locked, str]] = []
    seen: dict[str, Locked] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw and not raw.startswith(" "):
            section, in_specs, current = raw.strip(), False, None
            continue
        if section == "GEM" and raw.strip() == "specs:":
            in_specs = True
            continue
        if section == "GEM" and in_specs:
            current = _gem_spec(result, raw, number, current, children, seen)
        elif section == "DEPENDENCIES":
            _gem_dependency(result, raw, number)
    for parent, child in children:
        target = seen.get(child)
        if target is not None:
            result.edges.append((parent.ref, target.ref))
    direct = {d.name for d in result.declared}
    for locked in result.locked:
        locked.direct = locked.name in direct
    return result


def _gem_spec(
    result: ManifestResult,
    raw: str,
    number: int,
    current: Locked | None,
    children: list[tuple[Locked, str]],
    seen: dict[str, Locked],
) -> Locked | None:
    match = _GEM_SPEC_RE.match(raw)
    if match is None:
        return current
    name = normalize_name("rubygems", match["name"])
    if len(match["indent"]) == 6:
        if current is not None:
            children.append((current, name))
        return current
    version = (match["version"] or "").split("-", 1)[0].strip()  # drop platform (1.13.10-x86_64-linux)
    if not version:
        return current
    if name in seen:
        return seen[name]
    locked = Locked("rubygems", name, version, result.path, line=number)
    seen[name] = locked
    result.locked.append(locked)
    return locked


def _gem_dependency(result: ManifestResult, raw: str, number: int) -> None:
    match = _GEM_DEP_RE.match(raw)
    if match is None:
        return
    constraint = (match["constraint"] or "").strip()
    name = normalize_name("rubygems", match["name"])
    result.declared.append(
        Declared(
            "rubygems",
            name,
            constraint,
            "runtime",
            result.path,
            line=number,
            exact=exact_version("rubygems", constraint),
            raw_name=match["name"],
        )
    )


# --------------------------------------------------------------------------- composer.lock

_COMPOSER_NAME_RE = re.compile(r'^\s*"name"\s*:\s*"([^"]+/[^"]+)"')
_PLATFORM_RE = re.compile(r"^(?:php|hhvm|ext-.+|lib-.+|composer(?:-plugin-api|-runtime-api)?)$", re.IGNORECASE)


def parse_composer_lock(rel: str, text: str) -> ManifestResult:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ParseError(f"{rel} is not valid JSON.") from exc
    result = ManifestResult(path=rel, kind="composer.lock", ecosystem="packagist")
    if not isinstance(data, dict):
        return result
    positions: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        found = _COMPOSER_NAME_RE.match(line)
        if found is not None:
            positions.setdefault(normalize_name("packagist", found.group(1)), number)
    by_name: dict[str, Locked] = {}
    requires: list[tuple[Locked, list[str]]] = []
    for key, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        entries = data.get(key)
        for package in entries if isinstance(entries, list) else []:
            if not isinstance(package, dict) or not package.get("name") or not package.get("version"):
                continue
            name = normalize_name("packagist", str(package["name"]))
            version = str(package["version"])
            version = version[1:] if re.match(r"^v\d", version) else version
            locked = Locked("packagist", name, version, rel, scope=scope, line=positions.get(name))
            result.locked.append(locked)
            by_name[name] = locked
            require = package.get("require")
            if isinstance(require, dict):
                requires.append((locked, [normalize_name("packagist", str(d)) for d in require]))
    for parent, names in requires:
        for name in names:
            if not _PLATFORM_RE.match(name) and name in by_name:
                result.edges.append((parent.ref, by_name[name].ref))
    return result
