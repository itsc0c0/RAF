"""SBOM import (CycloneDX JSON, SPDX 2.x JSON) and export (CycloneDX 1.5 JSON).

Import maps components/packages to Package objects (ecosystem, name and version
from the purl when present, else ``generic``), the dependency graph to
``DEPENDS_ON`` edges and the root component's direct dependencies to direct
packages. When an SBOM does not say what the root depends on, packages without
a parent are treated as direct.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

from raf.core.errors import InvalidInputError
from raf.core.timeutil import format_ts, utcnow
from raf.products.dependency.model import PackageInfo, ProjectModel
from raf.products.dependency.names import normalize_name, parse_purl, purl
from raf.products.dependency.parsers.base import PkgRef
from raf.version import RAF_VERSION

_CDX_SCOPE = {"required": "runtime", "optional": "optional", "excluded": "dev"}
_EXPORT_SCOPE = {"runtime": "required", "optional": "optional", "dev": "excluded"}
_SPDX_SCOPE = {"DEV": "dev", "TEST": "dev", "BUILD": "dev", "OPTIONAL": "optional", "RUNTIME": "runtime"}


def detect_format(document: Any) -> str:
    if isinstance(document, dict):
        if document.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if str(document.get("spdxVersion", "")).startswith("SPDX-"):
            return "spdx"
    raise InvalidInputError(
        "Not a CycloneDX or SPDX JSON document.",
        hint="Expected bomFormat=CycloneDX or spdxVersion=SPDX-2.x (SPDX 3 JSON-LD is not supported).",
    )


def _ref(purl_text: Any, name: Any, version: Any, group: Any = None) -> PkgRef | None:
    if isinstance(purl_text, str):
        parsed = parse_purl(purl_text)
        if parsed is not None:
            ecosystem, package, purl_version = parsed
            chosen = purl_version or (str(version) if version else None)
            return (ecosystem, package, chosen) if chosen else None
    if not name or not version:
        return None
    full = f"{group}/{name}" if group else str(name)
    return ("generic", normalize_name("generic", full), str(version))


def _components(items: Any) -> Iterator[dict[str, Any]]:
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            yield item
            yield from _components(item.get("components"))


def _finish(model: ProjectModel, roots_children: set[PkgRef], explicit_root: bool) -> ProjectModel:
    if explicit_root:
        for ref in roots_children:
            if ref in model.packages:
                model.packages[ref].direct = True
    else:
        has_parent = {child for _, child in model.edges}
        for ref, info in model.packages.items():
            info.direct = ref not in has_parent
    model.finalize()
    return model


def from_cyclonedx(document: dict[str, Any], key: str, name: str | None) -> ProjectModel:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    assert isinstance(metadata, dict)
    root = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    assert isinstance(root, dict)
    model = ProjectModel(key=key, name=name or str(root.get("name") or key), source="sbom")
    model.version = str(root["version"]) if root.get("version") else None
    refs: dict[str, PkgRef] = {}
    for component in _components(document.get("components")):
        ref = _ref(component.get("purl"), component.get("name"), component.get("version"), component.get("group"))
        if ref is None:
            model.warnings.append(f"component {str(component.get('name'))[:60]!r} has no version; skipped")
            continue
        scope = _CDX_SCOPE.get(str(component.get("scope", "")).lower())
        model.add_package(ref, scope=scope, direct=False, manifest="sbom")
        refs[str(component.get("bom-ref") or component.get("purl") or ref)] = ref
    root_ref = str(root.get("bom-ref") or "")
    direct: set[PkgRef] = set()
    explicit = False
    for entry in document.get("dependencies") or []:
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("ref") or "")
        targets = [refs[str(t)] for t in entry.get("dependsOn") or [] if str(t) in refs]
        if root_ref and source == root_ref:
            explicit = True
            direct.update(targets)
        elif source in refs:
            model.edges.update((refs[source], target) for target in targets)
    return _finish(model, direct, explicit)


def _spdx_purl(package: dict[str, Any]) -> str | None:
    for ref in package.get("externalRefs") or []:
        if isinstance(ref, dict) and str(ref.get("referenceType", "")).lower() == "purl":
            return str(ref.get("referenceLocator") or "") or None
    return None


def _spdx_edge(kind: str, a: str, b: str) -> tuple[str, str, str | None] | None:
    """(parent, child, scope) for a dependency relationship, None for anything else."""
    if kind == "DEPENDS_ON":
        return a, b, None
    if kind.endswith("DEPENDENCY_OF"):  # DEPENDENCY_OF, DEV_DEPENDENCY_OF, OPTIONAL_DEPENDENCY_OF, ...
        prefix = kind[: -len("DEPENDENCY_OF")].rstrip("_")
        return b, a, _SPDX_SCOPE.get(prefix)
    return None


def from_spdx(document: dict[str, Any], key: str, name: str | None) -> ProjectModel:
    relationships = [r for r in document.get("relationships") or [] if isinstance(r, dict)]
    roots = {str(x) for x in document.get("documentDescribes") or []}
    roots.update(
        str(r.get("relatedSpdxElement"))
        for r in relationships
        if str(r.get("relationshipType", "")).upper() == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT"
    )
    model = ProjectModel(key=key, name=name or str(document.get("name") or key), source="sbom")
    refs: dict[str, PkgRef] = {}
    for package in document.get("packages") or []:
        if not isinstance(package, dict):
            continue
        spdx_id = str(package.get("SPDXID") or "")
        if spdx_id in roots:
            model.name = name or str(package.get("name") or model.name)
            model.version = str(package["versionInfo"]) if package.get("versionInfo") else model.version
            continue
        ref = _ref(_spdx_purl(package), package.get("name"), package.get("versionInfo"))
        if ref is None:
            model.warnings.append(f"package {str(package.get('name'))[:60]!r} has no version; skipped")
            continue
        model.add_package(ref, scope=None, direct=False, manifest="sbom")
        refs[spdx_id] = ref
    direct: set[PkgRef] = set()
    explicit = False
    for rel in relationships:
        edge = _spdx_edge(
            str(rel.get("relationshipType", "")).upper(),
            str(rel.get("spdxElementId")),
            str(rel.get("relatedSpdxElement")),
        )
        if edge is None:
            continue
        parent, child, scope = edge
        if child not in refs:
            continue
        if scope:
            model.add_package(refs[child], scope=scope, direct=False, manifest=None)
        if parent in roots:
            explicit = True
            direct.add(refs[child])
        elif parent in refs:
            model.edges.add((refs[parent], refs[child]))
    return _finish(model, direct, explicit)


# --------------------------------------------------------------------------- export


def _component(info: PackageInfo) -> dict[str, Any]:
    ecosystem, name, version = info.ref
    group, _, short = name.rpartition("/")
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": purl(ecosystem, name, version),
        "name": short if group and ecosystem in ("npm", "packagist", "generic") else name,
        "version": version,
        "purl": purl(ecosystem, name, version),
        "scope": _EXPORT_SCOPE.get(info.scope or "runtime", "required"),
        "properties": [
            {"name": "raf:ecosystem", "value": ecosystem},
            {"name": "raf:direct", "value": str(info.direct)},
        ],
    }
    if group and ecosystem in ("npm", "packagist", "generic"):
        component["group"] = group
    return component


def to_cyclonedx(
    project: dict[str, Any], packages: list[PackageInfo], edges: set[tuple[PkgRef, PkgRef]]
) -> dict[str, Any]:
    """A CycloneDX 1.5 JSON document for one project."""
    root_ref = str(project["id"])
    ordered = sorted(packages, key=lambda p: p.ref)
    children: dict[PkgRef, list[str]] = {p.ref: [] for p in ordered}
    for parent, child in sorted(edges):
        if parent in children and child in children:
            children[parent].append(purl(*child))
    root_component: dict[str, Any] = {"type": "application", "bom-ref": root_ref, "name": str(project["name"])}
    if project.get("version"):
        root_component["version"] = str(project["version"])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": format_ts(utcnow()),
            "tools": {"components": [{"type": "application", "name": "R$F Dependency", "version": RAF_VERSION}]},
            "component": root_component,
        },
        "components": [_component(p) for p in ordered],
        "dependencies": [{"ref": root_ref, "dependsOn": [purl(*p.ref) for p in ordered if p.direct]}]
        + [{"ref": purl(*ref), "dependsOn": deps} for ref, deps in children.items()],
    }
