"""The dependency model of one project, built from parsed manifests or an SBOM.

* every declared constraint becomes a :class:`DependencyInfo` (one per
  ecosystem/name, keeping all declarations);
* a declared dependency *resolves to* the lockfile versions of the same name
  (preferring entries the lockfile marks as direct and versions that satisfy the
  constraint) and to the version of an exact pin;
* every resolved version is a :class:`PackageInfo` (direct when a declaration
  resolves to it or the lockfile says so);
* package-to-package edges come from lockfiles (or SBOM dependency graphs);
* packages without a scope inherit it from their parents (runtime wins over
  optional over dev); anything still unknown is treated as runtime.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from raf.products.dependency.parsers.base import (
    SCOPE_RANK,
    Declared,
    Locked,
    ManifestResult,
    PkgRef,
    stronger_scope,
)
from raf.products.dependency.ranges import constraint_intervals, in_any
from raf.products.dependency.versions import InvalidVersion


@dataclass(slots=True)
class PackageInfo:
    ref: PkgRef
    scope: str | None = None
    direct: bool = False
    manifests: set[str] = field(default_factory=set)

    @property
    def ecosystem(self) -> str:
        return self.ref[0]

    @property
    def name(self) -> str:
        return self.ref[1]

    @property
    def version(self) -> str:
        return self.ref[2]


@dataclass(slots=True)
class DependencyInfo:
    ecosystem: str
    name: str
    declarations: list[Declared] = field(default_factory=list)
    resolved: set[PkgRef] = field(default_factory=set)

    @property
    def primary(self) -> Declared:
        """The most significant declaration: strongest scope, then exact pins, then file order."""
        return min(
            self.declarations,
            key=lambda d: (SCOPE_RANK.get(d.scope, 0), d.exact is None, d.manifest, d.line or 0),
        )

    @property
    def scope(self) -> str:
        return self.primary.scope

    @property
    def constraint(self) -> str:
        return self.primary.constraint

    def permits(self, version: str) -> bool:
        """True when some declaration's constraint accepts ``version`` (unknown constraints accept)."""
        for declaration in self.declarations:
            intervals = constraint_intervals(self.ecosystem, declaration.constraint)
            try:
                if intervals is None or in_any(self.ecosystem, intervals, version):
                    return True
            except InvalidVersion:
                return True
        return False


@dataclass(slots=True)
class ProjectModel:
    key: str
    name: str
    path: str | None = None
    source: str = "scan"  # scan | sbom
    version: str | None = None
    manifests: list[dict[str, object]] = field(default_factory=list)
    dependencies: dict[tuple[str, str], DependencyInfo] = field(default_factory=dict)
    packages: dict[PkgRef, PackageInfo] = field(default_factory=dict)
    edges: set[tuple[PkgRef, PkgRef]] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)

    def add_package(self, ref: PkgRef, *, scope: str | None, direct: bool, manifest: str | None) -> PackageInfo:
        info = self.packages.setdefault(ref, PackageInfo(ref))
        info.scope = stronger_scope(info.scope, scope)
        info.direct = info.direct or direct
        if manifest:
            info.manifests.add(manifest)
        return info

    def ecosystems(self) -> list[str]:
        found = {d.ecosystem for d in self.dependencies.values()} | {p.ecosystem for p in self.packages.values()}
        return sorted(found)

    def finalize(self) -> None:
        """Propagate scopes along edges and default unknown scopes to runtime."""
        children: dict[PkgRef, set[PkgRef]] = defaultdict(set)
        for parent, child in self.edges:
            children[parent].add(child)
        for scope in ("runtime", "optional", "dev"):
            frontier = [ref for ref, info in self.packages.items() if info.scope == scope]
            while frontier:
                for child in children.get(frontier.pop(), ()):
                    info = self.packages.get(child)
                    if info is not None and info.scope is None:
                        info.scope = scope
                        frontier.append(child)
        for info in self.packages.values():
            info.scope = info.scope or "runtime"


def _resolve(model: ProjectModel, locks: dict[tuple[str, str], list[Locked]]) -> None:
    for key, dependency in model.dependencies.items():
        refs = {(key[0], key[1], d.exact) for d in dependency.declarations if d.exact}
        candidates = locks.get(key, [])
        if candidates:
            pool = [c for c in candidates if c.direct] or candidates
            chosen = [c for c in pool if dependency.permits(c.version)] or pool
            refs.update(c.ref for c in chosen)
        dependency.resolved = refs


def build_model(key: str, name: str, path: str | None, results: list[ManifestResult]) -> ProjectModel:
    model = ProjectModel(key=key, name=name, path=path)
    locks: dict[tuple[str, str], list[Locked]] = defaultdict(list)
    for result in results:
        model.manifests.append(
            {
                "path": result.path,
                "kind": result.kind,
                "ecosystem": result.ecosystem,
                "declared": len(result.declared),
                "locked": len(result.locked),
            }
        )
        model.warnings.extend(result.warnings)
        for declared in result.declared:
            info = model.dependencies.setdefault(
                (declared.ecosystem, declared.name), DependencyInfo(declared.ecosystem, declared.name)
            )
            info.declarations.append(declared)
        for locked in result.locked:
            locks[(locked.ecosystem, locked.name)].append(locked)
            model.add_package(locked.ref, scope=locked.scope, direct=bool(locked.direct), manifest=locked.manifest)
        model.edges.update(result.edges)
    _resolve(model, locks)
    for dependency in model.dependencies.values():
        for ref in dependency.resolved:
            model.add_package(ref, scope=dependency.scope, direct=True, manifest=dependency.primary.manifest)
    model.finalize()
    return model
