"""Matching a project's packages and declared constraints against imported advisories.

* A **package** (exact version from a lockfile, an exact pin or an SBOM) is
  affected when the OSV evaluation of an advisory's ranges/versions includes
  its version: rule ``vulnerable-package``, confidence HIGH (0.90).
* A **declared dependency without a resolved version** is flagged when its
  constraint permits at least one affected version: rule
  ``vulnerable-constraint``, confidence MEDIUM (0.55) - the installed version is
  unknown, it may or may not be affected.

Severity comes from the advisory (CVSS or database severity) and is independent
of confidence.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.ids import finding_id, object_id
from raf.core.objects.models import EvidenceRef, Finding, ProvenanceDraft, RafModel, RelationshipDraft, SecurityObject
from raf.core.objects.types import Severity
from raf.core.storage.store import Store
from raf.products.dependency.osv import Advisory, AffectedEntry, constraint_affected, version_affected
from raf.products.dependency.persist import SOURCE

PRODUCT = "dependency"
RULE_PACKAGE = "vulnerable-package"
RULE_CONSTRAINT = "vulnerable-constraint"
RULES = (RULE_PACKAGE, RULE_CONSTRAINT)

AdvisoryIndex = dict[tuple[str, str], list[tuple[Advisory, AffectedEntry]]]


class VulnerableItem(RafModel):
    advisory: str
    vulnerability_id: str
    summary: str
    severity: Severity
    cvss: float | None = None
    aliases: list[str] = Field(default_factory=list)
    ecosystem: str
    package: str
    version: str | None = None
    constraint: str | None = None
    basis: str  # exact | constraint
    confidence: float
    reason: str
    fixed: list[str] = Field(default_factory=list)
    direct: bool | None = None
    scope: str | None = None
    project_id: str
    project: str
    target_id: str
    finding_id: str


class CheckResult(RafModel):
    job_id: str | None = None
    advisories: int = 0
    projects: list[dict[str, Any]] = Field(default_factory=list)
    packages_checked: int = 0
    dependencies_checked: int = 0
    items: list[VulnerableItem] = Field(default_factory=list)
    by_severity: dict[str, int] = Field(default_factory=dict)
    findings: dict[str, int] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


@dataclass(slots=True)
class Hit:
    project: SecurityObject
    target: SecurityObject  # package (exact) or dependency (constraint)
    advisory: Advisory
    entry: AffectedEntry
    basis: str
    reason: str
    version: str | None = None
    constraint: str | None = None
    direct: bool | None = None
    scope: str | None = None

    @property
    def rule(self) -> str:
        return RULE_PACKAGE if self.basis == "exact" else RULE_CONSTRAINT

    @property
    def confidence(self) -> float:
        return 0.9 if self.basis == "exact" else 0.55

    @property
    def finding_id(self) -> str:
        if self.basis == "exact":
            return finding_id(PRODUCT, RULE_PACKAGE, f"{self.project.id}|{self.target.id}|{self.advisory.id}")
        return finding_id(PRODUCT, RULE_CONSTRAINT, f"{self.target.id}|{self.advisory.id}")

    @property
    def vulnerability_id(self) -> str:
        return object_id("vulnerability", self.advisory.id)


def index_advisories(advisories: list[Advisory]) -> AdvisoryIndex:
    index: AdvisoryIndex = defaultdict(list)
    for advisory in advisories:
        if advisory.withdrawn:
            continue
        for entry in advisory.affected:
            index[(entry.ecosystem, entry.name)].append((advisory, entry))
    return index


def _package_hits(
    project: SecurityObject, package: SecurityObject, meta: dict[str, Any], index: AdvisoryIndex
) -> list[Hit]:
    ecosystem, name, version = (str(package.metadata.get(k, "")) for k in ("ecosystem", "name", "version"))
    hits = []
    for advisory, entry in index.get((ecosystem, name), []):
        reason = version_affected(entry, version)
        if reason:
            hits.append(
                Hit(
                    project,
                    package,
                    advisory,
                    entry,
                    "exact",
                    reason,
                    version=version,
                    direct=meta.get("direct"),
                    scope=meta.get("scope"),
                )
            )
    return hits


def _constraint_hits(project: SecurityObject, dependency: SecurityObject, index: AdvisoryIndex) -> list[Hit]:
    meta = dependency.metadata
    ecosystem, name = str(meta.get("ecosystem", "")), str(meta.get("name", ""))
    constraints = list(
        dict.fromkeys(str(d.get("constraint") or "") for d in meta.get("declarations") or [] if isinstance(d, dict))
    ) or [str(meta.get("constraint") or "")]
    hits = []
    for advisory, entry in index.get((ecosystem, name), []):
        for constraint in constraints:
            reason = constraint_affected(entry, constraint)
            if reason:
                hits.append(
                    Hit(
                        project,
                        dependency,
                        advisory,
                        entry,
                        "constraint",
                        reason,
                        constraint=constraint,
                        scope=meta.get("scope"),
                        direct=True,
                    )
                )
                break
    return hits


def project_hits(store: Store, project: SecurityObject, index: AdvisoryIndex) -> tuple[list[Hit], set[str], int, int]:
    """Hits for one project, the checked target ids, and the package/dependency counts."""
    uses = store.relationships.edges([project.id], direction="out", types=["DEPENDS_ON"])
    edge_meta = {r.target_object: r.metadata for r in uses}
    packages = store.objects.get_many(edge_meta)
    hits: list[Hit] = []
    for package in sorted(packages.values(), key=lambda p: p.id):
        hits.extend(_package_hits(project, package, edge_meta[package.id], index))
    declares = store.relationships.edges([project.id], direction="out", types=["DECLARES"])
    dependency_ids = [r.target_object for r in declares]
    resolved = (
        {r.source_object for r in store.relationships.edges(dependency_ids, direction="out", types=["RESOLVES_TO"])}
        if dependency_ids
        else set()
    )
    dependencies = store.objects.get_many(dependency_ids)
    unresolved = [d for d in sorted(dependencies.values(), key=lambda d: d.id) if d.id not in resolved]
    for dependency in unresolved:
        hits.extend(_constraint_hits(project, dependency, index))
    targets = set(packages) | {d.id for d in unresolved}
    return hits, targets, len(packages), len(dependencies)


def affects_draft(hit: Hit, now: datetime) -> RelationshipDraft:
    draft = RelationshipDraft.make(
        hit.vulnerability_id,
        "AFFECTS",
        hit.target.id,
        source=SOURCE,
        confidence=0.9 if hit.basis == "exact" else 0.5,
        metadata={
            "basis": hit.basis,
            "advisory": hit.advisory.id,
            "reason": hit.reason,
            "version": hit.version,
            "constraint": hit.constraint,
            "fixed": hit.entry.fixed_versions(),
        },
    )
    draft.observe(now)
    return draft


def _recommendation(hit: Hit, fixed: list[str]) -> str:
    name = hit.entry.name
    if hit.basis == "constraint":
        if fixed:
            return f"Require {name}>={fixed[0]} (or pin a fixed version) and commit a lockfile so the version is known."
        return f"No fixed version of {name} is listed in {hit.advisory.id}; avoid the affected versions or replace it."
    if fixed:
        later = [v for v in fixed if v != fixed[0]]
        return f"Upgrade {name} from {hit.version} to {fixed[0]} or later" + (
            f" (also fixed in {', '.join(later)})." if later else "."
        )
    return (
        f"No fixed version of {name} is listed in {hit.advisory.id}; remove or replace the package, or apply the "
        "advisory's mitigations."
    )


def _explanation(hit: Hit) -> list[dict[str, Any]]:
    severity_note = f"severity {hit.advisory.severity.value} from {hit.advisory.severity_source}" + (
        f" (CVSS {hit.advisory.cvss})" if hit.advisory.cvss is not None else ""
    )
    if hit.basis == "exact":
        factors = [
            {"label": f"installed version: {hit.reason}", "sign": "+", "points": 60},
            {"label": "exact version known (lockfile, pin or SBOM)", "sign": "+", "points": 30},
        ]
    else:
        factors = [
            {"label": hit.reason, "sign": "+", "points": 40},
            {"label": "installed version unknown (no lockfile entry or exact pin)", "sign": "+", "points": 15},
        ]
    return [*factors, {"label": severity_note, "sign": "+", "points": 0}]


def build_finding(hit: Hit, now: datetime) -> Finding:
    advisory, name = hit.advisory, hit.entry.name
    fixed = hit.entry.fixed_versions()
    if hit.basis == "exact":
        title = f"{advisory.id}: {name} {hit.version} is affected"
        subject = f"{name} {hit.version} ({'direct' if hit.direct else 'transitive'}, {hit.scope or 'runtime'})"
    else:
        title = f"{advisory.id}: {name} constraint '{hit.constraint or '*'}' permits affected versions"
        subject = f"{name} declared as '{hit.constraint or '*'}' with no resolved version"
    description = (
        f"{advisory.summary or advisory.id}\n\nProject {hit.project.name} uses {subject}. {hit.reason}. "
        f"Affected: {hit.entry.describe()}. Fixed: {', '.join(fixed) or 'no fixed version listed'}."
    )
    return Finding(
        id=hit.finding_id,
        title=title[:500],
        description=description[:4000],
        severity=advisory.severity,
        confidence=hit.confidence,
        product=PRODUCT,
        rule_id=hit.rule,
        affected_objects=[hit.target.id, hit.project.id],
        evidence=[
            EvidenceRef(kind="object", id=hit.vulnerability_id, note="advisory"),
            EvidenceRef(kind="object", id=hit.target.id, note=hit.version or hit.constraint or "*"),
            EvidenceRef(kind="object", id=hit.project.id, note="project"),
        ],
        recommendation=_recommendation(hit, fixed),
        explanation=_explanation(hit),
        created_at=now,
        updated_at=now,
        tags=[PRODUCT, "advisory", hit.entry.ecosystem],
        metadata={
            "advisory": advisory.id,
            "aliases": advisory.aliases,
            "ecosystem": hit.entry.ecosystem,
            "package": name,
            "version": hit.version,
            "constraint": hit.constraint,
            "basis": hit.basis,
            "fixed": fixed,
            "cvss": advisory.cvss,
            "severity_source": advisory.severity_source,
            "project": hit.project.id,
            "project_name": hit.project.name,
            "direct": hit.direct,
            "scope": hit.scope,
        },
    )


def provenance(hit: Hit, subject: str, kind: str, now: datetime) -> ProvenanceDraft:
    return ProvenanceDraft(
        subject_id=subject,
        subject_kind=kind,
        source=f"osv:{hit.advisory.id}"[:512],
        parser="dependency/check",
        record=(hit.version or hit.constraint or "*")[:128],
        observed_at=now,
        note=hit.reason[:500],
    )


def item(hit: Hit) -> VulnerableItem:
    return VulnerableItem(
        advisory=hit.advisory.id,
        vulnerability_id=hit.vulnerability_id,
        summary=hit.advisory.summary,
        severity=hit.advisory.severity,
        cvss=hit.advisory.cvss,
        aliases=hit.advisory.aliases,
        ecosystem=hit.entry.ecosystem,
        package=hit.entry.name,
        version=hit.version,
        constraint=hit.constraint,
        basis=hit.basis,
        confidence=hit.confidence,
        reason=hit.reason,
        fixed=hit.entry.fixed_versions(),
        direct=hit.direct,
        scope=hit.scope,
        project_id=hit.project.id,
        project=hit.project.name,
        target_id=hit.target.id,
        finding_id=hit.finding_id,
    )
