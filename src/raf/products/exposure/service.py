"""R$F Exposure: contextual, explainable asset exposure for the workspace (or any state)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.graph.source import MemoryGraphSource
from raf.core.ids import finding_id
from raf.core.objects.models import EvidenceRef, Finding, RafModel
from raf.core.objects.types import Severity
from raf.core.risk.exposure import AssetExposure, ExposureMetrics, ExposureModel
from raf.core.timeutil import utcnow

PRODUCT = "exposure"
RULE = "asset-exposure"
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class ExposureReport(RafModel):
    generated_at: datetime
    items: list[AssetExposure] = Field(default_factory=list)
    metrics: ExposureMetrics
    by_level: dict[str, int] = Field(default_factory=dict)
    findings: int = 0
    resolved: int = 0
    notes: list[str] = Field(default_factory=list)


def level_rank(level: str) -> int:
    return LEVELS.index(level) if level in LEVELS else -1


def parse_level(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    level = value.strip().upper()
    if level not in LEVELS:
        raise InvalidInputError(f"Unknown level '{value}'.", hint="Use low, medium, high or critical.")
    return level


class ExposureService:
    def __init__(self, ctx: RafContext, *, graph: MemoryGraphSource | None = None) -> None:
        self.ctx = ctx
        self._graph = graph
        self._model: ExposureModel | None = None

    def graph(self) -> MemoryGraphSource:
        if self._graph is None:
            store = self.ctx.store
            self._graph = MemoryGraphSource(store.objects.iter_all(), store.relationships.iter_all())
        return self._graph

    def model(self) -> ExposureModel:
        if self._model is None:
            depth = int(self.ctx.settings.get("blast.max_depth"))
            self._model = ExposureModel(self.graph(), max_depth=depth)
        return self._model

    def report(self, *, persist: bool = True) -> ExposureReport:
        model = self.model()
        items = model.assess_all()
        by_level: dict[str, int] = {}
        for item in items:
            by_level[item.level] = by_level.get(item.level, 0) + 1
        report = ExposureReport(
            generated_at=utcnow(), items=items, metrics=model.metrics(items), by_level=by_level, notes=list(model.notes)
        )
        if persist:
            findings = [self._finding(item) for item in items if item.level in ("HIGH", "CRITICAL")]
            self.ctx.store.findings.upsert(findings)
            report.findings = len(findings)
            report.resolved = self.ctx.store.findings.resolve_absent(PRODUCT, [RULE], [f.id for f in findings])
        return report

    def assess(self, object_id: str) -> AssetExposure:
        model = self.model()
        asset = model.objects.get(object_id)
        if asset is None:
            raise NotFoundError(f"'{object_id}' is not in this workspace.")
        if asset.type not in ("host", "service", "cloud_resource", "container"):
            raise InvalidInputError(
                f"Exposure is computed for hosts, services, cloud resources and containers, not {asset.type}.",
                suggestions=[f"raf blast {object_id}"],
            )
        return model.assess(asset)

    @staticmethod
    def _finding(item: AssetExposure) -> Finding:
        now = utcnow()
        oid = item.object["id"]
        positives = [f for f in item.factors if f.sign == "+"]
        top = "; ".join(f.label for f in positives[:4])
        return Finding(
            id=finding_id(PRODUCT, RULE, oid),
            title=f"{item.level.title()} exposure: {item.object['name']} ({item.score}/100)",
            description=f"{item.object['name']} scores {item.score}/100 ({item.level}) in the contextual exposure "
            f"model ({item.methodology}). Main factors: {top}.",
            severity=Severity(item.level),
            confidence=0.8,
            product=PRODUCT,
            rule_id=RULE,
            affected_objects=[
                oid,
                *[e.id for e in item.entry_points[:5]],
                *[v["id"] for v in item.vulnerabilities[:5]],
            ],
            evidence=[EvidenceRef(kind="object", id=ev, note=f.label) for f in positives[:6] for ev in f.evidence[:2]],
            recommendation=_recommendation(item),
            explanation=[
                {"factor": f.rule, "label": f.label, "sign": f.sign, "points": f.points} for f in item.factors
            ],
            created_at=now,
            updated_at=now,
            tags=["exposure"],
            metadata={"score": item.score},
        )


def _recommendation(item: AssetExposure) -> str:
    rules = {f.rule for f in item.factors if f.sign == "+"}
    steps = []
    if "exposure.vulnerability" in rules:
        steps.append("patch or mitigate " + item.vulnerabilities[0]["name"])
    if "exposure.internet-direct" in rules:
        steps.append("restrict Internet exposure to required ports and sources")
    if "exposure.privileged-credentials" in rules or "exposure.secrets" in rules:
        steps.append("move stored credentials into a secret manager and rotate them")
    if "exposure.controllers" in rules or "exposure.credential-path" in rules:
        steps.append("reduce who can obtain control (raf iam path <user> " + item.object["id"] + ")")
    if "exposure.stepping-stone" in rules:
        steps.append("break control paths to critical assets (segmentation, separate deploy credentials)")
    if not steps:
        steps.append("review the factors and segment the asset")
    return "; ".join(steps).capitalize() + "."


def to_api(item: AssetExposure) -> dict[str, Any]:
    data: dict[str, Any] = item.to_json_dict()
    return data
