"""Persisting dependency models and advisory matches in the shared security model.

Objects: ``project``, ``dependency`` (declared constraint, key
``<project key>|<ecosystem>/<name>``), ``package`` (``<ecosystem>/<name>@<version>``)
and ``vulnerability`` (advisory id). Relationships: PROJECT DECLARES DEPENDENCY,
DEPENDENCY RESOLVES_TO PACKAGE, PACKAGE DEPENDS_ON PACKAGE (lockfile/SBOM graph;
``metadata.sources`` lists the projects that asserted the edge), PROJECT
DEPENDS_ON PACKAGE (``metadata.direct`` tells direct from transitive) and
VULNERABILITY AFFECTS PACKAGE (or DEPENDENCY for constraint-only matches).

Re-storing a project ends (``valid_to``) its DECLARES / DEPENDS_ON / RESOLVES_TO
relationships that the new model no longer contains, so history is kept and the
current graph stays exact. Package objects are shared between projects and are
never ended.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from raf.core.ids import object_id
from raf.core.objects.models import ObjectDraft, ProvenanceDraft, RelationshipDraft
from raf.core.storage.store import Store
from raf.core.timeutil import format_ts
from raf.products.dependency.model import DependencyInfo, PackageInfo, ProjectModel
from raf.products.dependency.names import package_key, purl
from raf.products.dependency.parsers.base import PkgRef

SOURCE = "dependency"


def package_id(ref: PkgRef) -> str:
    return object_id("package", package_key(*ref))


def dependency_id(project_key: str, ecosystem: str, name: str) -> str:
    return object_id("dependency", f"{project_key}|{ecosystem}/{name}")


def package_draft(info: PackageInfo, now: datetime) -> ObjectDraft:
    ecosystem, name, version = info.ref
    draft = ObjectDraft.make(
        "package",
        f"{name}@{version}",
        key=package_key(ecosystem, name, version),
        metadata={"ecosystem": ecosystem, "name": name, "version": version, "purl": purl(ecosystem, name, version)},
        tags={"dependency", ecosystem},
        source=SOURCE,
        confidence=0.95,
    )
    draft.observe(now)
    return draft


@dataclass(slots=True)
class StorePlan:
    objects: list[ObjectDraft] = field(default_factory=list)
    relationships: list[RelationshipDraft] = field(default_factory=list)
    provenance: list[ProvenanceDraft] = field(default_factory=list)
    ended_objects: list[ObjectDraft] = field(default_factory=list)
    ended_relationships: list[str] = field(default_factory=list)

    def rel(self, draft: RelationshipDraft, now: datetime, prov: ProvenanceDraft) -> None:
        draft.observe(now)
        self.relationships.append(draft)
        prov.subject_id, prov.subject_kind = draft.id, "relationship"
        self.provenance.append(prov)


def _prov(model: ProjectModel, manifest: str | None, line: int | None, now: datetime, kind: str) -> ProvenanceDraft:
    return ProvenanceDraft(
        subject_id="",
        subject_kind="object",
        source=f"{model.path or model.name}:{manifest or model.source}"[:512],
        parser=f"dependency/{kind}",
        record=(f"{manifest}:{line}" if line else manifest or model.source)[:128],
        observed_at=now,
    )


def _object(plan: StorePlan, draft: ObjectDraft, prov: ProvenanceDraft) -> None:
    plan.objects.append(draft)
    prov.subject_id = draft.id
    plan.provenance.append(prov)


def _dependency_draft(model: ProjectModel, project_id: str, dep: DependencyInfo, now: datetime) -> ObjectDraft:
    primary = dep.primary
    declarations = [
        {"manifest": d.manifest, "line": d.line, "constraint": d.constraint, "scope": d.scope, "group": d.group}
        for d in sorted(dep.declarations, key=lambda d: (d.manifest, d.line or 0))
    ]
    draft = ObjectDraft(
        type="dependency",
        name=f"{dep.name} {dep.constraint or '*'}"[:200],
        id=dependency_id(model.key, dep.ecosystem, dep.name),
        source=SOURCE,
        confidence=0.95,
        tags={"dependency", dep.ecosystem},
        metadata={
            "ecosystem": dep.ecosystem,
            "name": dep.name,
            "constraint": dep.constraint,
            "scope": dep.scope,
            "manifest": primary.manifest,
            "line": primary.line,
            "declarations": declarations[:50],
            "project": project_id,
            "resolved": sorted(ref[2] for ref in dep.resolved),
            "status": "declared",
        },
    )
    draft.observe(now)
    return draft


def plan_model(model: ProjectModel, now: datetime) -> tuple[str, StorePlan]:
    plan = StorePlan()
    project = ObjectDraft.make(
        "project",
        model.name,
        key=model.key,
        metadata={
            "path": model.path,
            "source": model.source,
            "version": model.version,
            "manifests": model.manifests[:200],
            "ecosystems": model.ecosystems(),
            "last_scan": format_ts(now),
        },
        tags={"dependency"},
        source=SOURCE,
        confidence=0.95,
    )
    project.observe(now)
    _object(plan, project, _prov(model, None, None, now, model.source))
    for dep in model.dependencies.values():
        draft = _dependency_draft(model, project.id, dep, now)
        primary = dep.primary
        _object(plan, draft, _prov(model, primary.manifest, primary.line, now, "manifest"))
        declares = RelationshipDraft.make(
            project.id, "DECLARES", draft.id, source=SOURCE, confidence=0.95, metadata={"scope": dep.scope}
        )
        plan.rel(declares, now, _prov(model, primary.manifest, primary.line, now, "manifest"))
        for ref in sorted(dep.resolved):
            via = "pin" if any(d.exact == ref[2] for d in dep.declarations) else "lockfile"
            resolves = RelationshipDraft.make(
                draft.id, "RESOLVES_TO", package_id(ref), source=SOURCE, confidence=0.9, metadata={"via": via}
            )
            plan.rel(resolves, now, _prov(model, primary.manifest, primary.line, now, "resolution"))
    for _ref, info in sorted(model.packages.items()):
        pkg = package_draft(info, now)
        manifest = sorted(info.manifests)[0] if info.manifests else None
        _object(plan, pkg, _prov(model, manifest, None, now, "lockfile"))
        uses = RelationshipDraft.make(
            project.id,
            "DEPENDS_ON",
            pkg.id,
            source=SOURCE,
            confidence=0.9 if info.direct else 0.8,
            metadata={"direct": info.direct, "scope": info.scope, "manifests": sorted(info.manifests)[:10]},
        )
        plan.rel(uses, now, _prov(model, manifest, None, now, "lockfile"))
    for parent, child in sorted(model.edges):
        if parent in model.packages and child in model.packages:
            edge = RelationshipDraft.make(
                package_id(parent),
                "DEPENDS_ON",
                package_id(child),
                source=SOURCE,
                confidence=0.85,
                metadata={"sources": [project.id]},
            )
            plan.rel(edge, now, _prov(model, None, None, now, "graph"))
    return project.id, plan


def plan_stale(store: Store, project_id: str, plan: StorePlan, now: datetime) -> None:
    """End the project's relationships (and dependencies) the new model no longer contains."""
    planned_rels = {r.id for r in plan.relationships}
    planned_objects = {o.id for o in plan.objects}
    current = store.relationships.edges([project_id], direction="out", types=["DECLARES", "DEPENDS_ON"])
    dependency_ids = [r.target_object for r in current if r.relationship_type == "DECLARES"]
    resolves = (
        store.relationships.edges(dependency_ids, direction="out", types=["RESOLVES_TO"]) if dependency_ids else []
    )
    plan.ended_relationships = [r.id for r in [*current, *resolves] if r.id not in planned_rels]
    for dep_id in dependency_ids:
        if dep_id not in planned_objects:
            plan.ended_objects.append(
                ObjectDraft(
                    type="dependency",
                    name=dep_id.split("|")[-1][:200],
                    id=dep_id,
                    valid_to=now,
                    source=SOURCE,
                    confidence=0.5,
                    observations=0,
                    metadata={"status": "removed", "removed_at": format_ts(now)},
                )
            )


def write_plan(store: Store, plan: StorePlan, now: datetime, job_id: str | None) -> dict[str, Any]:
    with store.transaction() as conn:
        objects = store.objects.upsert_drafts(plan.objects, conn=conn, now=now)
        relationships = store.relationships.upsert_drafts(plan.relationships, conn=conn, now=now)
        if plan.ended_objects:
            store.objects.upsert_drafts(plan.ended_objects, conn=conn, now=now)
        ended = store.relationships.end(plan.ended_relationships, now, conn=conn)
        store.provenance.add_many(plan.provenance, job_id=job_id, conn=conn)
    return {
        "objects_created": objects.created,
        "objects_updated": objects.updated,
        "relationships_created": relationships.created,
        "relationships_updated": relationships.updated,
        "relationships_ended": ended,
        "dependencies_removed": len(plan.ended_objects),
    }
