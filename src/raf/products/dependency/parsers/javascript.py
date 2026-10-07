"""npm manifests: package.json, package-lock.json / npm-shrinkwrap.json (v1, v2, v3) and yarn.lock (v1, Berry)."""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

from raf.products.dependency.names import normalize_name
from raf.products.dependency.parsers.base import (
    Declared,
    Locked,
    ManifestResult,
    ParseError,
    exact_version,
    find_line,
)

ECO = "npm"
_DECLARED_FIELDS = (("dependencies", "runtime"), ("devDependencies", "dev"), ("optionalDependencies", "optional"))
_EDGE_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+")


def _load_json(rel: str, text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ParseError(f"{rel} is not valid JSON.") from exc


def split_alias(name: str, spec: str) -> tuple[str, str]:
    """``("alias", "npm:real@^1")`` -> ``("real", "^1")``; other specs are returned unchanged."""
    if not spec.startswith("npm:"):
        return name, spec
    target = spec[4:]
    at = target.rfind("@")
    if at <= 0:
        return target, ""
    return target[:at], target[at + 1 :]


def parse_package_json(rel: str, text: str) -> ManifestResult:
    data = _load_json(rel, text)
    result = ManifestResult(path=rel, kind="package.json", ecosystem=ECO)
    if not isinstance(data, dict):
        return result
    lines = text.splitlines()
    for field, scope in _DECLARED_FIELDS:
        table = data.get(field)
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if not isinstance(spec, str):
                result.warn(f"{field}.{name}: unsupported value")
                continue
            real, constraint = split_alias(str(name), spec.strip())
            result.declared.append(
                Declared(
                    ecosystem=ECO,
                    name=normalize_name(ECO, real),
                    constraint=constraint,
                    scope=scope,
                    manifest=rel,
                    line=find_line(lines, ECO, str(name)),
                    exact=exact_version(ECO, constraint),
                    raw_name=str(name),
                )
            )
    return result


# --------------------------------------------------------------------------- package-lock.json


def _scope(info: dict[str, Any]) -> str:
    if info.get("dev") or info.get("devOptional"):
        return "dev"
    return "optional" if info.get("optional") else "runtime"


def _resolve_node(entries: dict[str, Locked], parent: str, name: str) -> str | None:
    """Node's module resolution: nearest ``node_modules/<name>`` walking up from ``parent``."""
    base = parent
    while True:
        candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if candidate in entries:
            return candidate
        if not base:
            return None
        cut = base.rfind("/node_modules/")
        base = base[:cut] if cut >= 0 else ""


_KEY_LINE_RE = re.compile(r'^\s*"(node_modules/[^"]+)"\s*:')


def _key_lines(lines: list[str]) -> dict[str, int]:
    """Line of each ``"node_modules/..."`` key, in one pass (lockfiles can be very large)."""
    found: dict[str, int] = {}
    for number, line in enumerate(lines, start=1):
        match = _KEY_LINE_RE.match(line)
        if match is not None:
            found.setdefault(match.group(1), number)
    return found


def _lock_entries_v2(result: ManifestResult, packages: dict[str, Any], lines: list[str]) -> dict[str, Locked]:
    root = packages.get("") if isinstance(packages.get(""), dict) else {}
    assert isinstance(root, dict)
    direct = {str(n) for field, _ in _DECLARED_FIELDS if isinstance(root.get(field), dict) for n in root[field]}
    positions = _key_lines(lines)
    entries: dict[str, Locked] = {}
    for path, info in packages.items():
        if not path or not isinstance(info, dict) or "node_modules/" not in path or info.get("link"):
            continue  # root, workspace sources and symlinked workspace packages are first-party code
        name = str(info.get("name") or path.rsplit("node_modules/", 1)[-1])
        version = str(info.get("version") or "")
        if not _VERSION_RE.match(version):
            result.warn(f"{path}: no registry version")
            continue
        top_level = path == f"node_modules/{path.rsplit('node_modules/', 1)[-1]}"
        is_direct = top_level and path.rsplit("node_modules/", 1)[-1] in direct
        entries[path] = Locked(
            ECO,
            normalize_name(ECO, name),
            version.lstrip("v"),
            result.path,
            scope=_scope(info),
            direct=is_direct,
            line=positions.get(path),
        )
    return entries


def _lock_entries_v1(result: ManifestResult, deps: dict[str, Any], prefix: str = "") -> dict[str, tuple[Locked, Any]]:
    entries: dict[str, tuple[Locked, Any]] = {}
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        path = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
        version = str(info.get("version") or "")
        if _VERSION_RE.match(version):
            locked = Locked(ECO, normalize_name(ECO, str(name)), version.lstrip("v"), result.path, scope=_scope(info))
            entries[path] = (locked, info.get("requires"))
        else:
            result.warn(f"{name}: no registry version")
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            entries.update(_lock_entries_v1(result, nested, path))
    return entries


def parse_package_lock(rel: str, text: str) -> ManifestResult:
    data = _load_json(rel, text)
    result = ManifestResult(path=rel, kind="package-lock.json", ecosystem=ECO)
    if not isinstance(data, dict):
        return result
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        entries = _lock_entries_v2(result, packages, text.splitlines())
        requires = {path: _requires(packages.get(path)) for path in entries}
    else:
        deps = data.get("dependencies") if isinstance(data.get("dependencies"), dict) else {}
        assert isinstance(deps, dict)
        v1 = _lock_entries_v1(result, deps)
        entries = {path: item[0] for path, item in v1.items()}
        requires = {path: list(item[1]) if isinstance(item[1], dict) else [] for path, item in v1.items()}
    result.locked.extend(entries.values())
    for path, names in requires.items():
        for name in names:
            child = _resolve_node(entries, path, name)
            if child is not None:
                result.edges.append((entries[path].ref, entries[child].ref))
    return result


def _requires(info: Any) -> list[str]:
    if not isinstance(info, dict):
        return []
    return [str(n) for field in _EDGE_FIELDS if isinstance(info.get(field), dict) for n in info[field]]


# --------------------------------------------------------------------------- yarn.lock


def _descriptor_name(descriptor: str) -> tuple[str, str]:
    """``@scope/pkg@^1.0`` -> ``("@scope/pkg", "^1.0")``."""
    at = descriptor.find("@", 1)
    if at <= 0:
        return descriptor, ""
    return descriptor[:at], descriptor[at + 1 :]


def _yarn_v1_blocks(text: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_deps = False
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0 and line.endswith(":"):
            descriptors = [d.strip().strip('"') for d in line[:-1].split(",") if d.strip()]
            current = {"descriptors": descriptors, "version": None, "deps": {}, "line": number}
            blocks.append(current)
            in_deps = False
        elif current is not None and indent <= 2:
            in_deps = line in ("dependencies:", "optionalDependencies:")
            if line.startswith("version "):
                current["version"] = line[len("version ") :].strip().strip('"')
        elif current is not None and in_deps:
            name, _, spec = line.partition(" ")
            current["deps"][name.strip('"')] = spec.strip().strip('"')
    return blocks


def _yarn_berry_blocks(rel: str, text: str) -> list[dict[str, Any]]:
    try:
        if any(isinstance(event, yaml.AliasEvent) for event in yaml.parse(text, Loader=yaml.SafeLoader)):
            raise ParseError(f"{rel} uses YAML aliases, which lockfiles never need; refusing to expand them.")
        data = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ParseError(f"{rel} is not valid YAML.") from exc
    blocks: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return blocks
    for key, info in data.items():
        if key == "__metadata" or not isinstance(info, dict):
            continue
        descriptors = [d.strip() for d in str(key).split(",") if d.strip()]
        deps = info.get("dependencies") if isinstance(info.get("dependencies"), dict) else {}
        assert isinstance(deps, dict)
        blocks.append({"descriptors": descriptors, "version": info.get("version"), "deps": deps, "line": None})
    return blocks


def parse_yarn_lock(rel: str, text: str) -> ManifestResult:
    result = ManifestResult(path=rel, kind="yarn.lock", ecosystem=ECO)
    berry = "__metadata:" in text
    blocks = _yarn_berry_blocks(rel, text) if berry else _yarn_v1_blocks(text)
    index: dict[str, Locked] = {}
    parsed: list[tuple[Locked, dict[str, Any]]] = []
    for block in blocks:
        version = str(block.get("version") or "")
        if not block["descriptors"] or not _VERSION_RE.match(version):
            continue
        name, _ = _descriptor_name(block["descriptors"][0])
        if "@workspace:" in block["descriptors"][0] or "@link:" in block["descriptors"][0]:
            continue
        locked = Locked(ECO, normalize_name(ECO, name), version, rel, line=block.get("line"))
        result.locked.append(locked)
        parsed.append((locked, block["deps"]))
        for descriptor in block["descriptors"]:
            index[descriptor] = locked
    for locked, deps in parsed:
        for name, spec in deps.items():
            spec_text = str(spec)
            child = index.get(f"{name}@{spec_text}") or index.get(f"{name}@npm:{spec_text}")
            if child is not None:
                result.edges.append((locked.ref, child.ref))
    return result
