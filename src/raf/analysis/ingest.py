"""Application-level import service shared by the CLI, API and analyze pipelines."""

from __future__ import annotations

import importlib
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from raf.core.context.app import RafContext
from raf.core.errors import NotFoundError, RafError
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions, IngestReport
from raf.core.ingestion.registry import ParserRegistry
from raf.core.jobs.manager import Job, JobContext, ProgressCallback

log = logging.getLogger("raf.analysis.ingest")


def build_parser_registry(ctx: RafContext) -> ParserRegistry:
    """Core parsers plus parsers contributed by available products and trusted plugins."""
    registry = ParserRegistry.default()
    if ctx.registry is None:
        return registry
    for info in ctx.registry.products():
        if not info.available:
            continue
        for import_path in info.manifest.parsers:
            try:
                if info.source == "plugin":
                    parser = ctx.registry.load_plugin_attr(info.name, import_path)
                else:
                    module_name, attr = import_path.split(":", 1)
                    parser = getattr(importlib.import_module(module_name), attr)
            except (RafError, ImportError, AttributeError) as exc:
                log.warning("parser %s from %s unavailable: %s", import_path, info.name, exc)
                continue
            registry.register_parser(parser)
    return registry


def import_path(
    ctx: RafContext, path: Path, options: IngestOptions, *, on_progress: ProgressCallback | None = None
) -> tuple[Job, IngestReport | None]:
    """Run an import as a persisted job and audit it."""
    if not path.exists():
        raise NotFoundError(f"{path} does not exist.")

    def work(jc: JobContext) -> dict[str, Any]:
        pipeline = IngestionPipeline(ctx, build_parser_registry(ctx), jc)
        report = pipeline.ingest_path(path, options)
        return report.to_json_dict()

    params = {
        "path": str(path.resolve()),
        "format": options.format,
        "incident": options.incident,
        "host": options.default_host,
        "synthetic": options.synthetic,
    }
    job = ctx.jobs.run_inline("import", f"Import {path.name}", params, work, on_progress)
    report = IngestReport.model_validate(job.result) if job.result else None
    ctx.audit.record(
        "data.import",
        affected=[str(path.resolve())],
        result=job.status.value.lower(),
        details={
            "job": job.id,
            "accepted": report.accepted if report else 0,
            "rejected": report.rejected if report else 0,
            "sha256": report.sha256 if report else None,
        },
    )
    if report and report.incidents:
        ctx.refs.remember("incident", report.incidents[0])
    ctx.refs.remember("job", job.id)
    return job, report


def import_records(
    ctx: RafContext,
    records: Iterable[dict[str, Any]],
    *,
    source_name: str,
    title: str,
    options: IngestOptions | None = None,
    label: str = "generator/1.0",
    kind: str = "import",
) -> tuple[Job, IngestReport | None]:
    def work(jc: JobContext) -> dict[str, Any]:
        pipeline = IngestionPipeline(ctx, build_parser_registry(ctx), jc)
        return pipeline.ingest_records(records, source_name=source_name, options=options, label=label).to_json_dict()

    job = ctx.jobs.run_inline(kind, title, {"source": source_name}, work)
    report = IngestReport.model_validate(job.result) if job.result else None
    return job, report
