"""``raf analyze``: detect what an input is, run the matching pipeline, and record it as ``analysis-N``.

Pipelines (every executed step is reported, with its product, status, duration and numbers):

* **pcap** - Protocol decodes the capture into flows, DNS, HTTP and TLS events → Timeline → Graph →
  Detections → Exposure correlation → Findings.
* **events** (JSON Lines, JSON, CSV, syslog, access logs, mixed multi-source logs, text logs) and
  **directory** - Ingest (auto-detected parser) → Timeline → Graph → Incidents → Detections → IAM
  analysis → Exposure correlation → Findings.
* **policy** documents - Ingest → Policy analysis → Findings.
* **surface** inventories (``raf-surface/1``) - Ingest → Surface analysis (authorized scope only;
  the import never changes the scope) → Exposure correlation → Findings.
* **repository** (a directory with dependency manifests or ``.git``) - Dependency scan (+ advisory
  matching) → Vault secret scan → Graph → Findings. A single **manifest** file - Dependency scan.
* **sbom** (CycloneDX / SPDX JSON) - Dependency SBOM import (+ advisory matching) → Graph → Findings.
* **bundle** (``.raf``) - integrity verification → import → Timeline → Graph → Findings.

Workspace-wide correlation (IAM, Exposure) runs only when the input brought principals or assets
and can be skipped (``correlate=False``). Steps whose product is disabled are reported as skipped.
"""

from __future__ import annotations

import importlib
import re
import shlex
import time
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from raf.analysis.ingest import import_path
from raf.core.context.app import RafContext
from raf.core.errors import IngestionError, InvalidInputError, NotFoundError, RafError
from raf.core.ingestion.pipeline import IngestOptions, IngestReport
from raf.core.ingestion.products import build_parser_registry
from raf.core.objects.models import RafModel
from raf.core.objects.types import ASSET_TYPES, PRINCIPAL_TYPES
from raf.core.security.files import read_head, sha256_file
from raf.core.storage.repos.analyses import AnalysisRecord
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import format_ts, utcnow

PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
PARSER_LABELS = {
    "jsonl": "JSON Lines",
    "json": "JSON",
    "csv": "CSV",
    "syslog": "Syslog",
    "access-log": "Web access log",
    "text": "Text log",
    "multilog": "Multi-source log",
    "raf-policy": "Policy document",
    "raf-surface": "Surface inventory",
    "pcap": "PCAP",
}
KIND_LABELS = {
    "pcap": "PCAP",
    "sbom": "SBOM",
    "bundle": "R$F bundle",
    "repository": "Source repository",
    "manifest": "Dependency manifest",
    "directory": "Directory",
    "policy": "Policy document",
    "surface": "Surface inventory",
    "events": "Events",
}
_REPO_SCAN_LIMIT = 5000
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}


class AnalysisStep(RafModel):
    name: str
    product: str | None = None
    status: str = "ok"  # ok | skipped | failed
    detail: str = ""
    duration_ms: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(RafModel):
    id: str
    input: str
    input_name: str
    input_sha256: str | None = None
    detected_type: str
    detected_label: str
    detection: list[str] = Field(default_factory=list)
    status: str  # completed | partial | failed
    steps: list[AnalysisStep] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    suggestions: list[str] = Field(default_factory=list)
    job_id: str | None = None
    job_ids: list[str] = Field(default_factory=list)
    incidents: list[str] = Field(default_factory=list)
    created_at: datetime
    duration_ms: float = 0.0


@dataclass(slots=True)
class AnalyzeOptions:
    format: str | None = None  # force an ingestion parser
    incident: str | None = None
    source_name: str | None = None
    synthetic: bool = False
    correlate: bool = True
    on_step: Callable[[AnalysisStep], None] | None = None


@dataclass(slots=True)
class Detection:
    kind: str
    label: str
    parser: str | None = None
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- detection


def _product_available(ctx: RafContext, name: str) -> bool:
    return ctx.registry is None or ctx.registry.is_available(name)


def _dependency_kind(ctx: RafContext, name: str) -> str | None:
    if not _product_available(ctx, "dependency"):
        return None
    module = importlib.import_module("raf.products.dependency.parsers")
    kind: str | None = module.detect_kind(name)
    return kind


def _repository_markers(ctx: RafContext, root: Path) -> list[str]:
    markers: list[str] = []
    if (root / ".git").exists():
        markers.append(".git")
    seen = 0
    pending = [root]
    while pending and seen < _REPO_SCAN_LIMIT and len(markers) < 5:
        current = pending.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS and len(entry.relative_to(root).parts) < 4:
                    pending.append(entry)
            elif _dependency_kind(ctx, entry.relative_to(root).as_posix()):
                markers.append(entry.relative_to(root).as_posix())
    return markers


_PARSER_KINDS = {"pcap": "pcap", "raf-policy": "policy", "raf-surface": "surface"}


def _is_bundle(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            return "manifest.json" in archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return False


def detect_input(
    ctx: RafContext, path: Path, *, forced_format: str | None = None, name: str | None = None
) -> Detection:
    """What the input is (deterministic; based on content first, then names). ``name`` is the
    original file name when ``path`` is a stored upload."""
    if path.is_symlink():
        raise InvalidInputError(f"{path} is a symbolic link; pass the real path.")
    if not path.exists():
        raise NotFoundError(f"{path} does not exist.", hint="raf analyze <file or directory>")
    if path.is_dir():
        markers = _repository_markers(ctx, path)
        if markers:
            return Detection("repository", KIND_LABELS["repository"], None, [f"found {', '.join(markers[:5])}"])
        return Detection("directory", KIND_LABELS["directory"], None, ["a directory without dependency manifests"])
    if not path.is_file():
        raise InvalidInputError(f"{path} is neither a regular file nor a directory.")
    registry = build_parser_registry(ctx)
    if forced_format:
        parser = registry.get(forced_format)
        kind = _PARSER_KINDS.get(parser.name, "events")
        return Detection(kind, PARSER_LABELS.get(parser.name, parser.name), parser.name, [f"--format {parser.name}"])
    head = read_head(path, 65536)
    if head[:4] in PCAP_MAGIC:
        return Detection("pcap", "PCAP", "pcap", ["libpcap/pcapng magic number"])
    if head[:4] == b"PK\x03\x04" and _is_bundle(path):
        return Detection("bundle", KIND_LABELS["bundle"], None, ["ZIP archive with an R$F manifest.json"])
    file_name = name or path.name
    manifest_kind = _dependency_kind(ctx, file_name)
    if manifest_kind and file_name == path.name:
        return Detection("manifest", KIND_LABELS["manifest"], None, [f"{file_name} ({manifest_kind})"])
    if b'"bomFormat"' in head and b"CycloneDX" in head:
        return Detection("sbom", "SBOM (CycloneDX)", None, ['"bomFormat": "CycloneDX"'])
    if b'"spdxVersion"' in head:
        return Detection("sbom", "SBOM (SPDX)", None, ['"spdxVersion" field'])
    detected = registry.detect(path, head)
    if detected is None:
        raise IngestionError(
            f"R$F could not determine what {path.name} is.",
            hint="Force a parser with --format (" + ", ".join(sorted(p.name for p in registry.parsers())) + ").",
        )
    parser, score = detected
    kind = _PARSER_KINDS.get(parser.name, "events")
    reasons = [f"{parser.name} parser (score {score:.2f})"]
    describe = getattr(parser, "describe", None)
    if callable(describe):
        reasons.append(str(describe(head)))
    return Detection(kind, PARSER_LABELS.get(parser.name, parser.name), parser.name, reasons)


# --------------------------------------------------------------------------- running


class _Run:
    def __init__(self, ctx: RafContext, analysis_id: str, options: AnalyzeOptions) -> None:
        self.ctx = ctx
        self.id = analysis_id
        self.options = options
        self.steps: list[AnalysisStep] = []
        self.jobs: list[str] = []
        self.incidents: list[str] = []
        self.stats: dict[str, Any] = {}
        self.primary_failed = False

    def record(self, step: AnalysisStep) -> AnalysisStep:
        self.steps.append(step)
        if self.options.on_step is not None:
            self.options.on_step(step)
        return step

    def skip(self, name: str, product: str | None, reason: str) -> None:
        self.record(AnalysisStep(name=name, product=product, status="skipped", detail=reason))

    def run(
        self,
        name: str,
        product: str | None,
        fn: Callable[[], tuple[str, dict[str, Any]]],
        *,
        primary: bool = False,
    ) -> bool:
        if product and not _product_available(self.ctx, product):
            self.skip(name, product, f"product '{product}' is disabled or unavailable")
            if primary:
                self.primary_failed = True
            return False
        started = time.monotonic()
        try:
            detail, stats = fn()
        except RafError as exc:
            self.record(
                AnalysisStep(
                    name=name,
                    product=product,
                    status="failed",
                    detail=exc.message + (f" ({exc.reason})" if exc.reason else ""),
                    duration_ms=round((time.monotonic() - started) * 1000, 1),
                )
            )
            if primary:
                self.primary_failed = True
            return False
        self.record(
            AnalysisStep(
                name=name,
                product=product,
                detail=detail,
                stats=stats,
                duration_ms=round((time.monotonic() - started) * 1000, 1),
            )
        )
        return True

    def add_job(self, job_id: str | None) -> None:
        if job_id and job_id not in self.jobs:
            self.jobs.append(job_id)


def _scope_query(run: _Run) -> EventQuery:
    return EventQuery(job_ids=run.jobs or ["<none>"], source=run.stats.get("scope_source"))


def _capture_summary(run: _Run) -> tuple[str, dict[str, Any]]:
    counts = {str(k): v for k, v in run.ctx.store.events.group_counts(_scope_query(run), "event_type")}
    flows = int(counts.get("network.flow", 0))
    run.stats["flows"] = flows
    others = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()) if k != "network.flow")
    return f"; {flows:,} flows" + (f", {others}" if others else ""), {"flows": flows, "event_types": counts}


def _include_earlier_imports(run: _Run, report: IngestReport, *, single_file: bool) -> None:
    """Data imported before stays attributed to the job that first imported it. Jobs that imported
    only this input join the analysis scope; a job that also imported other sources joins it for a
    single-file input, with the scope narrowed to that source's name."""
    provenance = run.ctx.store.provenance
    digests = {d for d in [report.sha256 or ""] + [str(f.get("sha256") or "") for f in report.files] if d}
    events = run.ctx.store.events
    for earlier in report.earlier_jobs:  # jobs that stored the very events this import met again
        if earlier in run.jobs:
            continue
        run.add_job(earlier)
        if single_file and events.count(EventQuery(job_ids=[earlier])) != events.count(
            EventQuery(job_ids=[earlier], source=report.source)
        ):
            run.stats["scope_source"] = report.source
    for earlier in provenance.jobs_for_sources(digests):
        if earlier in run.jobs:
            continue
        if provenance.source_digests(earlier) <= digests:
            run.add_job(earlier)
        elif single_file and report.sha256:
            names = provenance.source_names(earlier, report.sha256)
            if len(names) == 1:
                run.add_job(earlier)
                run.stats["scope_source"] = next(iter(names))


def _ingest(run: _Run, path: Path, det: Detection, name: str, product: str | None) -> IngestReport | None:
    box: dict[str, IngestReport] = {}

    def step() -> tuple[str, dict[str, Any]]:
        options = IngestOptions(
            format=det.parser,
            incident=run.options.incident,
            source_name=run.options.source_name,
            synthetic=run.options.synthetic,
        )
        job, report = import_path(run.ctx, path, options)
        run.add_job(job.id)
        if report is None:
            error = job.error or {}
            raise IngestionError(
                str(error.get("message", "Import failed.")), reason=error.get("reason"), hint=error.get("hint")
            )
        box["report"] = report
        run.incidents += [i for i in report.incidents if i not in run.incidents]
        if report.events_duplicate or report.events_reparsed or report.objects_updated:
            _include_earlier_imports(run, report, single_file=path.is_file())
        if report.files:
            parsers = Counter(str(f.get("format")) for f in report.files)
            parser = ", ".join(f"{n} {fmt}" for fmt, n in sorted(parsers.items()))
        else:
            parser = f"{report.parser}" + (f" + {report.normalizer}" if report.normalizer else "")
        detail = f"{report.accepted:,} of {report.processed:,} records accepted ({parser})"
        if report.sources:
            ranked = sorted(report.sources.items(), key=lambda kv: (-kv[1], kv[0]))
            detail += f"; {len(ranked)} source(s): " + ", ".join(f"{name} {n:,}" for name, n in ranked[:8])
            if len(ranked) > 8:
                detail += f" and {len(ranked) - 8} more"
        if report.rejected:
            detail += f"; {report.rejected:,} rejected (raf import report {job.id})"
        if report.files or report.skipped_files:
            detail += f"; {len(report.files):,} file(s) imported"
            if report.skipped_files:
                detail += (
                    f", {len(report.skipped_files):,} skipped ("
                    + "; ".join(f"{Path(f['path']).name}: {f['reason']}" for f in report.skipped_files[:3])
                    + ")"
                )
        stats: dict[str, Any] = {
            "job": job.id,
            "processed": report.processed,
            "accepted": report.accepted,
            "rejected": report.rejected,
            "files": len(report.files),
            "skipped_files": len(report.skipped_files),
            "sources": dict(sorted(report.sources.items(), key=lambda kv: -kv[1])[:50]),
        }
        if det.kind == "pcap":
            extra, extra_stats = _capture_summary(run)
            detail += extra
            stats.update(extra_stats)
        return detail, stats

    run.run(name, product, step, primary=True)
    return box.get("report")


def _timeline_step(run: _Run, report: IngestReport) -> None:
    def step() -> tuple[str, dict[str, Any]]:
        query = _scope_query(run)
        first, last = run.ctx.store.events.bounds(query)
        window = f", {format_ts(first)} → {format_ts(last)}" if first and last else ""
        notes = []
        if report.events_reparsed:
            notes.append(f"{report.events_reparsed:,} re-read with the current parser")
        if report.events_duplicate:
            notes.append(f"{report.events_duplicate:,} already present")
        in_scope = run.ctx.store.events.count(query) if run.jobs else report.events_created
        run.stats["events"] = in_scope
        return (
            f"{report.events_created:,} events indexed" + (f" ({'; '.join(notes)})" if notes else "") + window,
            {
                "events": report.events_created,
                "duplicates": report.events_duplicate,
                "reparsed": report.events_reparsed,
                "in_scope": in_scope,
                "first": format_ts(first) if first else None,
                "last": format_ts(last) if last else None,
            },
        )

    run.run("Timeline", "timeline", step)


def _graph_step(run: _Run, created: int, updated: int, rels_created: int, rels_updated: int) -> None:
    def step() -> tuple[str, dict[str, Any]]:
        involved = len(_job_objects(run)) if run.jobs else created
        run.stats["objects"] = max(involved, run.stats.get("objects", 0) + created)
        run.stats["relationships"] = run.stats.get("relationships", 0) + rels_created + rels_updated
        detail = (
            f"{created:,} objects and {rels_created:,} relationships created; "
            f"{updated:,} objects and {rels_updated:,} relationships updated"
        )
        if involved > created:
            detail += f"; {involved:,} objects involved in this input"
        return (
            detail,
            {
                "objects_created": created,
                "objects_updated": updated,
                "relationships_created": rels_created,
                "relationships_updated": rels_updated,
                "objects_involved": involved,
            },
        )

    run.run("Graph", "graph", step)


def _job_objects(run: _Run) -> list[str]:
    if not run.jobs:
        return []
    source = run.stats.get("scope_source")
    ids = run.ctx.store.provenance.subjects_for_jobs(run.jobs, kind="object", source=source)
    ids.update(oid for oid, _n in run.ctx.store.events.object_counts(_scope_query(run), limit=5000))
    return sorted(ids)


def _involved_assets(run: _Run, object_ids: list[str]) -> list[str]:
    """Assets among the analyzed objects, plus hosts that own analyzed IP addresses."""
    assets = {oid for oid in object_ids if oid.split(":", 1)[0] in ASSET_TYPES}
    ips = [oid for oid in object_ids if oid.startswith("ip:")]
    if ips:
        for rel in run.ctx.store.relationships.edges(ips, direction="in", types=["HAS_ADDRESS"]):
            assets.add(rel.source_object)
    return sorted(assets)


def _correlate(run: _Run) -> None:
    objects = _job_objects(run)
    principals = [oid for oid in objects if oid.split(":", 1)[0] in PRINCIPAL_TYPES]
    assets = _involved_assets(run, objects)
    if not run.options.correlate:
        run.skip("IAM analysis", "iam", "correlation disabled (--no-correlate)")
        run.skip("Exposure correlation", "exposure", "correlation disabled (--no-correlate)")
        return
    if principals:

        def iam() -> tuple[str, dict[str, Any]]:
            module = importlib.import_module("raf.products.iam.service")
            report = module.IamService(run.ctx).analyze(persist=True)
            mine = [f for f in report.findings if set(f.affected_objects) & set(principals)]
            return (
                f"{len(principals)} principal(s) in the input; workspace re-analyzed: {len(report.findings)} IAM "
                f"finding(s), {len(mine)} involving them",
                {"principals": len(principals), "findings": len(report.findings), "involving_input": len(mine)},
            )

        run.run("IAM analysis", "iam", iam)
    else:
        run.skip("IAM analysis", "iam", "no users, identities, groups or roles in the input")
    if assets:

        def exposure() -> tuple[str, dict[str, Any]]:
            module = importlib.import_module("raf.products.exposure.service")
            report = module.ExposureService(run.ctx).report(persist=True)
            levels = {item.object["id"]: item.level for item in report.items}
            involved = Counter(levels[a] for a in assets if a in levels)
            high = sorted(a for a in assets if levels.get(a) in ("HIGH", "CRITICAL"))
            run.stats["exposed_assets"] = high[:20]
            parts = ", ".join(f"{n} {lvl.lower()}" for lvl, n in sorted(involved.items()))
            return (
                f"{len(assets)} asset(s) involved ({parts or 'not scored'}); "
                f"{report.findings} exposure finding(s) in the workspace",
                {"assets": len(assets), "levels": dict(involved), "high_or_critical": high[:20]},
            )

        run.run("Exposure correlation", "exposure", exposure)
    else:
        run.skip("Exposure correlation", "exposure", "no hosts, services or other assets in the input")


def _detections_step(run: _Run) -> None:
    """Timeline detections over the analysis scope; suspected incidents join the analysis."""

    def step() -> tuple[str, dict[str, Any]]:
        module = importlib.import_module("raf.products.timeline.detections")
        report = module.DetectionService(run.ctx).run(_scope_query(run), scope_label=run.id)
        findings = report.findings
        run.stats["detections"] = len(findings)
        run.stats["top_findings"] = [
            {"id": f.id, "severity": f.severity.value, "title": f.title, "rule": f.rule_id} for f in findings[:12]
        ]
        run.stats["explained"] = [{"title": e.title, "reason": e.reason} for e in report.explained[:12]]
        for incident in report.incidents:
            if incident.id not in run.incidents:
                run.incidents.insert(0, incident.id)
        counts = Counter(f.severity.value for f in findings)
        order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        detail = f"{len(findings)} detection(s)" + (
            " (" + ", ".join(f"{counts[s]} {s.lower()}" for s in order if counts.get(s)) + ")" if findings else ""
        )
        detail += f" over {report.events_examined:,} events"
        if report.explained:
            detail += f"; {len(report.explained)} explained (approved changes, tickets, scheduled jobs)"
        created = list(dict.fromkeys(i.name for i in report.incidents if not i.existing))
        matched = list(dict.fromkeys(i.name for i in report.incidents if i.existing))
        if created:
            detail += "; suspected incident " + ", ".join(created)
        if matched:
            detail += "; correlated detections match " + ", ".join(matched)
        if report.resolved:
            detail += f"; {report.resolved} earlier detection(s) resolved"
        return detail, {
            "findings": len(findings),
            "by_severity": dict(counts),
            "by_rule": report.by_rule,
            "explained": len(report.explained),
            "incidents": list(dict.fromkeys(i.name for i in report.incidents)),
            "events_examined": report.events_examined,
        }

    run.run("Detections", "timeline", step)


def _findings_step(run: _Run, before: dict[str, int]) -> None:
    def step() -> tuple[str, dict[str, Any]]:
        after = run.ctx.store.findings.count_by_severity()
        new = {sev: after.get(sev, 0) - before.get(sev, 0) for sev in after if after.get(sev, 0) > before.get(sev, 0)}
        total = sum(new.values())
        run.stats["findings"] = total
        objects = _job_objects(run)
        related = 0
        for oid in objects[:300]:
            related += run.ctx.store.findings.count(object_id=oid, statuses=["OPEN", "ACKNOWLEDGED"])
        detail = f"{total} new finding(s)" + (
            " (" + ", ".join(f"{n} {sev.lower()}" for sev, n in new.items()) + ")" if new else ""
        )
        return detail, {"new": total, "by_severity": new, "open_on_input_objects": related}

    run.run("Findings", None, step)


# --------------------------------------------------------------------------- pipelines


def _pipeline_ingested(run: _Run, path: Path, det: Detection) -> None:
    name = "Protocol" if det.kind == "pcap" else f"Ingest ({det.label})"
    product = "protocol" if det.kind == "pcap" else None
    report = _ingest(run, path, det, name, product)
    if report is None:
        return
    _timeline_step(run, report)
    _graph_step(
        run, report.objects_created, report.objects_updated, report.relationships_created, report.relationships_updated
    )
    if report.incidents:
        names = [i.split(":", 1)[1].upper() for i in report.incidents]
        run.record(AnalysisStep(name="Incidents", detail="events linked to " + ", ".join(names)))
    if det.kind in ("events", "pcap", "directory") and run.jobs:
        _detections_step(run)
    if det.kind == "policy":

        def policy() -> tuple[str, dict[str, Any]]:
            module = importlib.import_module("raf.products.policy.service")
            analysis = module.PolicyService(run.ctx).analyze()
            return f"{len(analysis.findings)} policy finding(s)", {"findings": len(analysis.findings)}

        run.run("Policy analysis", "policy", policy)
        return
    if det.kind == "surface":

        def surface() -> tuple[str, dict[str, Any]]:
            module = importlib.import_module("raf.products.surface.service")
            analysis = module.SurfaceService(run.ctx).analyze(via="analyze")
            if not analysis.scope_entries:
                return (
                    "no authorized scope configured: nothing evaluated (raf surface scope add, or "
                    "raf surface import FILE --apply-scope after review)",
                    {"scope_entries": 0},
                )
            return (
                f"{analysis.assets} asset(s), {analysis.in_scope} in scope, {analysis.out_of_scope} out of scope; "
                f"{len(analysis.findings)} surface finding(s)",
                {"assets": analysis.assets, "in_scope": analysis.in_scope, "findings": len(analysis.findings)},
            )

        run.run("Surface analysis", "surface", surface)
    _correlate(run)


def _pipeline_repository(run: _Run, path: Path, det: Detection) -> None:
    scanned: dict[str, Any] = {}
    store = run.ctx.store
    objects_before, rels_before = store.objects.count(), store.relationships.count()

    def dependency() -> tuple[str, dict[str, Any]]:
        module = importlib.import_module("raf.products.dependency.service")
        service = module.DependencyService(run.ctx)
        result = service.import_sbom(path) if det.kind == "sbom" else service.scan(path)
        run.add_job(result.job_id)
        scanned["dependency"] = result
        counts = result.counts
        vulnerable = len(result.check.items) if result.check else 0
        run.stats["packages"] = counts.get("packages", 0)
        run.stats["vulnerable_packages"] = vulnerable
        check = (
            f"; {vulnerable} vulnerable package(s) against {result.check.advisories} advisories"
            if result.check
            else "; no advisories imported (raf dependency advisories import <osv.json>)"
        )
        return (
            f"{len(result.manifests)} manifest(s), {counts.get('packages', 0)} package(s), "
            f"{counts.get('direct', 0)} direct{check}",
            {"manifests": len(result.manifests), **counts, "vulnerable": vulnerable},
        )

    name = "Dependency (SBOM import)" if det.kind == "sbom" else "Dependency scan"
    run.run(name, "dependency", dependency, primary=True)
    if det.kind == "repository":

        def vault() -> tuple[str, dict[str, Any]]:
            module = importlib.import_module("raf.products.vault.service")
            result = module.VaultService(run.ctx).scan(path)
            run.add_job(result.job_id)
            run.stats["secrets"] = len(result.results)
            return (
                f"{result.files_scanned:,} file(s) scanned, {len(result.results)} secret(s) found "
                f"(values redacted), {result.suppressed_count} suppressed",
                {"files": result.files_scanned, "secrets": len(result.results), "by_severity": result.by_severity},
            )

        run.run("Vault secret scan", "vault", vault)
    created = store.objects.count() - objects_before
    rels = store.relationships.count() - rels_before
    _graph_step(run, created, 0, rels, 0)


def _pipeline_bundle(run: _Run, path: Path, det: Detection) -> None:
    from raf.core.bundle.format import import_bundle, open_bundle

    def verify() -> tuple[str, dict[str, Any]]:
        reader = open_bundle(run.ctx, path)
        try:
            problems = reader.verify()
            manifest = reader.manifest
        finally:
            reader.close()
        if problems:
            raise IngestionError("Bundle integrity check failed; nothing was imported.", reason="; ".join(problems[:3]))
        return (
            f"{len(manifest.files)} members verified (SHA-256), workspace '{manifest.workspace}'",
            {"members": len(manifest.files), "counts": manifest.counts},
        )

    if not run.run("Bundle verification", None, verify, primary=True):
        return
    imported: dict[str, int] = {}

    def do_import() -> tuple[str, dict[str, Any]]:
        def work(_jc: Any) -> dict[str, Any]:
            return import_bundle(run.ctx, path, job_id=_jc.job_id)

        job = run.ctx.jobs.run_inline("import", f"Import bundle {path.name}", {"path": str(path.resolve())}, work)
        run.add_job(job.id)
        if job.result is None:
            error = job.error or {}
            raise IngestionError(str(error.get("message", "Bundle import failed.")), reason=error.get("reason"))
        imported.update(job.result.get("imported", {}))
        run.ctx.audit.record("bundle.import", affected=[str(path)], details=imported)
        return ", ".join(f"{v} {k}" for k, v in imported.items() if v) or "nothing new", dict(imported)

    if not run.run("Bundle import", None, do_import, primary=True):
        return
    report = IngestReport(source=path.name, events_created=imported.get("events", 0))
    _timeline_step(run, report)
    _graph_step(run, imported.get("objects", 0), 0, imported.get("relationships", 0), 0)


def _suggestions(run: _Run, det: Detection, path: Path) -> list[str]:
    # Paths and names come from the input: quoted, so a suggestion stays one safe command line.
    out = [f"raf lens {run.id}", f"raf graph {run.id}", f"raf timeline {run.id}"]
    if det.kind == "pcap":
        out.append(f"raf protocol inspect {shlex.quote(str(path))}")
    for incident in run.incidents[:1]:
        name = incident.split(":", 1)[1].upper()
        out.append(f"raf timeline {shlex.quote(name)}")
        question = f"Explain the most important security path in {name}"
        asked = f'"{question}"' if re.fullmatch(r"[\w.-]+", name) else shlex.quote(question)
        out += [f"raf replay {shlex.quote(name)}", f"raf oracle ask {asked}"]
    if det.kind in ("repository", "manifest", "sbom"):
        out += ["raf dependency vulnerable"]
    if det.kind == "repository":
        out.append("raf vault findings")
    if run.stats.get("exposed_assets"):
        out.append(f"raf exposure show {shlex.quote(str(run.stats['exposed_assets'][0]))}")
    if run.stats.get("findings") or run.stats.get("detections"):
        out.append("raf findings --severity high")
    return out


def analyze_path(ctx: RafContext, path: Path, options: AnalyzeOptions | None = None) -> AnalysisResult:
    options = options or AnalyzeOptions()
    started = time.monotonic()
    path = path.expanduser()
    det = detect_input(ctx, path, forced_format=options.format, name=options.source_name)
    if det.kind in ("repository", "manifest", "sbom") and options.format:
        raise InvalidInputError("--format applies to data files, not to repositories or SBOMs.")
    created_at = utcnow()
    analysis_id = ctx.store.next_id("analysis")
    digest = sha256_file(path) if path.is_file() else None
    record = AnalysisRecord(
        id=analysis_id,
        input=str(path.resolve()),
        input_sha256=digest,
        detected_type=det.kind,
        status="running",
        created_at=created_at,
    )
    ctx.store.analyses.save(record)
    run = _Run(ctx, analysis_id, options)
    run.record(AnalysisStep(name="Detect", detail=f"{det.label}: " + "; ".join(det.reasons)))
    findings_before = ctx.store.findings.count_by_severity()
    if det.kind in ("pcap", "events", "policy", "surface", "directory"):
        _pipeline_ingested(run, path, det)
    elif det.kind in ("repository", "manifest", "sbom"):
        _pipeline_repository(run, path, det)
    elif det.kind == "bundle":
        _pipeline_bundle(run, path, det)
    if not run.primary_failed:
        _findings_step(run, findings_before)
    failed = [s for s in run.steps if s.status == "failed"]
    status = "failed" if run.primary_failed else "partial" if failed else "completed"
    run.stats["job_ids"] = run.jobs
    run.stats["incidents"] = run.incidents
    suggestions = _suggestions(run, det, path) if not run.primary_failed else [f"raf job show {j}" for j in run.jobs]
    result = AnalysisResult(
        id=analysis_id,
        input=str(path.resolve()),
        input_name=options.source_name or path.name,
        input_sha256=digest,
        detected_type=det.kind,
        detected_label=det.label,
        detection=det.reasons,
        status=status,
        steps=run.steps,
        stats=run.stats,
        suggestions=suggestions,
        job_id=run.jobs[0] if run.jobs else None,
        job_ids=run.jobs,
        incidents=run.incidents,
        created_at=created_at,
        duration_ms=round((time.monotonic() - started) * 1000, 1),
    )
    record.status = status
    record.steps = [s.to_json_dict() for s in run.steps]
    record.stats = run.stats | {
        "detected_label": det.label,
        "input_name": result.input_name,
        "detection": det.reasons,
        "duration_ms": result.duration_ms,
    }
    record.suggestions = suggestions
    record.job_id = result.job_id
    ctx.store.analyses.save(record)
    ctx.audit.record(
        "analysis.run",
        affected=[analysis_id, str(path.resolve())],
        result=status,
        details={
            "detected": det.kind,
            "steps": [f"{s.name}:{s.status}" for s in run.steps],
            "jobs": run.jobs,
            "sha256": digest,
        },
    )
    ctx.refs.remember("analysis", analysis_id)
    return result


def get_analysis(ctx: RafContext, analysis_id: str) -> AnalysisRecord:
    record = ctx.store.analyses.get(analysis_id)
    if record is None:
        raise NotFoundError(f"Analysis '{analysis_id}' does not exist.", suggestions=["raf analyses"])
    return record
