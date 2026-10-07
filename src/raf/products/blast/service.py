"""R$F Blast: estimate the impact of a hypothetical compromise (defensive model).

Given an object assumed compromised, propagate over the shared graph using the
documented traversal semantics and report what could be controlled or reached,
how (explainable hops), and an explainable risk level. No exploitation is
performed - this is analysis of existing relationships.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.graph.propagation import Hop, Propagator, Reached
from raf.core.graph.source import GraphSource, load_propagation_source
from raf.core.objects.models import RafModel, SecurityObject
from raf.core.objects.semantics import CONTROL, REACH, TRUST, explain, is_privileged
from raf.core.objects.types import ASSET_TYPES, Criticality, ObjectType
from raf.core.risk.model import RiskAssessment, assess, factor

_CRIT_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


class BlastHop(RafModel):
    source: str
    source_name: str
    target: str
    target_name: str
    relationship_type: str
    relationship_id: str | None
    forward: bool
    mode: str
    confidence: float
    why: str


class BlastReach(RafModel):
    id: str
    name: str
    type: str
    depth: int
    confidence: float
    mode: str
    criticality: str | None = None
    privileged_path: bool = False
    via_vulnerability: str | None = None


class BlastResult(RafModel):
    target: dict[str, Any]
    reachable_assets: int
    controllable_assets: int
    critical_assets: int
    privileged_paths: int
    max_depth: int
    direct: list[BlastReach] = Field(default_factory=list)
    indirect: list[BlastReach] = Field(default_factory=list)
    identity_propagation: list[str] = Field(default_factory=list)
    network_propagation: list[str] = Field(default_factory=list)
    trust_propagation: list[str] = Field(default_factory=list)
    risk: RiskAssessment
    primary_path: list[BlastHop] = Field(default_factory=list)
    critical_paths: dict[str, list[BlastHop]] = Field(default_factory=dict)
    settings: dict[str, Any] = Field(default_factory=dict)
    at: datetime | None = None


def _crit(obj: SecurityObject | None) -> str | None:
    if obj is None:
        return None
    level = Criticality.of(obj.metadata, obj.tags)
    return level.value if level else None


def privileged_hop(hop: Hop, objects: dict[str, SecurityObject]) -> bool:
    rel = hop.relationship
    if rel is not None and rel.relationship_type == "ADMIN_OF":
        return True
    target = objects.get(hop.to)
    return bool(
        target
        and target.type in (ObjectType.ROLE, ObjectType.IDENTITY, ObjectType.GROUP)
        and is_privileged(target.type, target.metadata, target.tags)
    )


class BlastService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx

    def blast(
        self,
        object_id: str,
        *,
        max_depth: int | None = None,
        min_confidence: float | None = None,
        at: datetime | None = None,
        source: GraphSource | None = None,
    ) -> BlastResult:
        depth_limit = int(max_depth or self.ctx.settings.get("blast.max_depth"))
        threshold = float(
            min_confidence if min_confidence is not None else self.ctx.settings.get("blast.min_confidence")
        )
        graph = source or load_propagation_source(self.ctx.store, at)
        reached = Propagator(graph, max_depth=depth_limit, min_confidence=threshold).run([object_id])
        return self.summarize(object_id, reached, graph, depth_limit=depth_limit, threshold=threshold, at=at)

    def summarize(
        self,
        object_id: str,
        reached: dict[str, Reached],
        graph: GraphSource,
        *,
        depth_limit: int,
        threshold: float,
        at: datetime | None,
    ) -> BlastResult:
        ids = {object_id} | set(reached) | {hop.to for r in reached.values() for hop in r.path}
        objects = graph.nodes(ids)
        subject = objects.get(object_id)

        def name(i: str) -> str:
            obj = objects.get(i)
            return obj.name if obj else i.split(":", 1)[-1]

        reaches: list[BlastReach] = []
        for node, r in reached.items():
            otype = node.split(":", 1)[0]
            privileged = any(privileged_hop(h, objects) for h in r.path)
            reaches.append(
                BlastReach(
                    id=node,
                    name=name(node),
                    type=otype,
                    depth=r.depth,
                    confidence=round(r.confidence, 3),
                    mode=r.mode,
                    criticality=_crit(objects.get(node)),
                    privileged_path=privileged,
                    via_vulnerability=r.via_vulnerability,
                )
            )
        reaches.sort(key=lambda b: (-_CRIT_RANK.get(b.criticality or "", -1), b.depth, -b.confidence, b.id))
        assets = [b for b in reaches if b.type in ASSET_TYPES]
        controllable = [b for b in assets if b.mode in (CONTROL, TRUST)]
        critical = [b for b in assets if b.criticality in ("high", "critical")]
        critical_controllable = [b for b in critical if b.mode in (CONTROL, TRUST)]
        critical_reach_only = [b for b in critical if b.mode == REACH]
        privileged_targets = [b for b in critical_controllable if b.privileged_path]
        direct = [b for b in reaches if b.depth <= 1]
        indirect = [b for b in reaches if b.depth > 1]
        identities = [b.id for b in reaches if b.type in (ObjectType.USER, ObjectType.IDENTITY) and b.mode != REACH]
        network = [b.id for b in reaches if b.mode == REACH]
        trust = [b.id for b in reaches if any(h.mode == TRUST for h in reached[b.id].path)]

        def hops(r: Reached) -> list[BlastHop]:
            result = []
            for hop in r.path:
                rel = hop.relationship
                result.append(
                    BlastHop(
                        source=hop.frm,
                        source_name=name(hop.frm),
                        target=hop.to,
                        target_name=name(hop.to),
                        relationship_type=rel.relationship_type if rel else "EXPLOITABLE",
                        relationship_id=rel.id if rel else hop.vulnerability,
                        forward=hop.forward,
                        mode=hop.mode,
                        confidence=round(hop.factor, 3),
                        why=explain(hop.why, name(hop.frm), name(hop.to), rel.metadata if rel else None),
                    )
                )
            return result

        primary: list[BlastHop] = []
        target_for_primary = critical_controllable or controllable or critical or assets or reaches
        if target_for_primary:
            ranked = sorted(
                target_for_primary,
                key=lambda b: (-_CRIT_RANK.get(b.criticality or "", -1), -b.confidence, b.depth, b.id),
            )
            primary = hops(reached[ranked[0].id])
        critical_paths = {b.id: hops(reached[b.id]) for b in critical[:10]}
        risk = self._risk(
            object_id, subject, critical_controllable, critical_reach_only, privileged_targets, controllable, reaches
        )
        return BlastResult(
            target={"id": object_id, "name": name(object_id), "type": object_id.split(":", 1)[0]},
            reachable_assets=len(assets),
            controllable_assets=len(controllable),
            critical_assets=len(critical),
            privileged_paths=len(privileged_targets),
            max_depth=max((b.depth for b in reaches), default=0),
            direct=direct,
            indirect=indirect,
            identity_propagation=sorted(identities),
            network_propagation=sorted(network),
            trust_propagation=sorted(trust),
            risk=risk,
            primary_path=primary,
            critical_paths=critical_paths,
            settings={"max_depth": depth_limit, "min_confidence": threshold},
            at=at,
        )

    @staticmethod
    def _risk(
        object_id: str,
        subject: SecurityObject | None,
        critical: list[BlastReach],
        reach_only: list[BlastReach],
        privileged: list[BlastReach],
        controllable: list[BlastReach],
        reaches: list[BlastReach],
    ) -> RiskAssessment:
        factors = []
        crit = [b for b in critical if b.criticality == "critical"]
        high = [b for b in critical if b.criticality == "high"]
        if crit:
            factors.append(
                factor(
                    "blast.critical-control",
                    f"{len(crit)} critical asset(s) controllable",
                    min(50, 25 * len(crit)),
                    [b.id for b in crit],
                )
            )
        if high:
            factors.append(
                factor(
                    "blast.high-control",
                    f"{len(high)} high-criticality asset(s) controllable",
                    min(30, 10 * len(high)),
                    [b.id for b in high],
                )
            )
        if reach_only:
            factors.append(
                factor(
                    "blast.critical-reach",
                    f"{len(reach_only)} critical/high asset(s) network-reachable only (no control path)",
                    min(15, 5 * len(reach_only)),
                    [b.id for b in reach_only],
                )
            )
        if privileged:
            factors.append(
                factor(
                    "blast.privileged-paths",
                    f"{len(privileged)} path(s) through privileged roles, identities or admin rights",
                    min(20, 10 * len(privileged)),
                    [b.id for b in privileged],
                )
            )
        if controllable:
            factors.append(
                factor(
                    "blast.controllable",
                    f"{len(controllable)} asset(s) controllable",
                    min(20, len(controllable)),
                    [b.id for b in controllable[:20]],
                )
            )
        vulns = sorted({b.via_vulnerability for b in reaches if b.via_vulnerability})
        if vulns:
            factors.append(
                factor("blast.exploitable", "propagation relies on exploitable vulnerabilities", 5, list(vulns))
            )
        if subject is not None:
            if subject.metadata.get("mfa") is True:
                factors.append(factor("blast.mfa", "subject is protected by MFA", -10, [object_id]))
            if subject.metadata.get("disabled") is True:
                factors.append(factor("blast.disabled", "subject account is disabled", -30, [object_id]))
        return assess(object_id, factors)
