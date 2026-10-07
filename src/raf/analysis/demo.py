"""``raf demo load``: the Raven Industries dataset, ready to explore.

The demo is assembled from steps. Each step names the product it needs, so the
demo grows with the platform and never claims what an unavailable product
would have produced.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raf.analysis.ingest import import_records
from raf.core.context.app import RafContext
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions
from raf.data import raven


@dataclass(slots=True)
class DemoStep:
    name: str
    product: str | None
    run: Callable[[RafContext, dict[str, Any]], dict[str, Any]]


@dataclass(slots=True)
class DemoResult:
    workspace: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"workspace": self.workspace, "steps": self.steps, "suggestions": self.suggestions}


def demo_files_dir(ctx: RafContext) -> Path:
    target = ctx.workspace.path / "demo"
    target.mkdir(parents=True, exist_ok=True)
    return target


def write_evidence_files(ctx: RafContext) -> Path:
    """Materialize the INC-001 evidence files inside the workspace (deterministic content)."""
    import json

    directory = demo_files_dir(ctx) / "evidence"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "auth.log").write_text(raven.evidence_auth_log(), encoding="utf-8")
    (directory / "edr-process-events.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in raven.evidence_edr_events()), encoding="utf-8"
    )
    (directory / "proxy.csv").write_text(raven.evidence_proxy_csv(), encoding="utf-8")
    (directory / "analyst-notes.txt").write_text(raven.EVIDENCE_NOTES, encoding="utf-8")
    try:
        raven_extra = importlib.import_module("raf.data.raven_extra")
    except ModuleNotFoundError:
        return directory
    raven_extra.write_extra_evidence(directory)
    return directory


def _step_core(ctx: RafContext, state: dict[str, Any]) -> dict[str, Any]:
    job, report = import_records(
        ctx,
        raven.raven_event_file_records(),
        source_name="raven-events.jsonl",
        title="Demo: Raven Industries inventory and events",
        options=IngestOptions(synthetic=True),
        label="raven-demo/1.0",
        kind="demo",
    )
    if report is None:
        raise RuntimeError(f"demo import failed ({job.id})")
    state["core_job"] = job.id
    return {
        "objects": report.objects_created + report.objects_updated,
        "events": report.events_created,
        "relationships": report.relationships_created + report.relationships_updated,
        "job": job.id,
    }


def _step_evidence_plain(ctx: RafContext, state: dict[str, Any]) -> dict[str, Any]:
    """Fallback when R$F Evidence is unavailable: import evidence files as plain data."""
    directory = write_evidence_files(ctx)
    pipeline = IngestionPipeline(ctx)
    report = pipeline.ingest_directory(directory, IngestOptions(incident=raven.INCIDENT, synthetic=True))
    return {"events": report.events_created, "files": len(report.files), "case": None}


#: Extended by products (evidence, policy, exposure ...) through ``register_demo_step``.
DEMO_STEPS: list[DemoStep] = [
    DemoStep("Raven inventory and events", None, _step_core),
]
_FALLBACK_EVIDENCE = DemoStep("INC-001 evidence (plain import)", None, _step_evidence_plain)


def register_demo_step(step: DemoStep, *, before: str | None = None) -> None:
    if any(s.name == step.name for s in DEMO_STEPS):
        return
    if before is not None:
        for index, existing in enumerate(DEMO_STEPS):
            if existing.name == before:
                DEMO_STEPS.insert(index, step)
                return
    DEMO_STEPS.append(step)


def _load_product_steps() -> None:
    import importlib

    for module in ("raf.analysis.demo_steps",):
        try:
            importlib.import_module(module)
        except ModuleNotFoundError as exc:
            if exc.name != module:
                raise


def load_demo(ctx: RafContext) -> DemoResult:
    _load_product_steps()
    result = DemoResult(workspace=ctx.workspace.name)
    state: dict[str, Any] = {}
    available = {p.name for p in ctx.registry.products() if p.available} if ctx.registry else set()
    steps = list(DEMO_STEPS)
    if not any(s.product == "evidence" for s in steps) or "evidence" not in available:
        steps.insert(1, _FALLBACK_EVIDENCE)
    for step in steps:
        if step.product is not None and step.product not in available:
            result.steps.append(
                {"name": step.name, "status": "skipped", "detail": f"R$F {step.product.title()} is not available"}
            )
            continue
        details = step.run(ctx, state)
        result.steps.append({"name": step.name, "status": "ok", "detail": details})
    ctx.audit.record("demo.load", affected=["incident:inc-001"], details={"steps": [s["name"] for s in result.steps]})
    ctx.refs.remember("incident", "incident:inc-001")
    ctx.refs.remember("object", "user:alice")
    result.suggestions = [
        "raf graph alice",
        "raf blast alice",
        "raf timeline alice",
        "raf replay INC-001",
        "raf trace bob",
        "raf findings",
        "raf tui",
    ]
    return result
