"""R$F Surface service: authorized scope, inventory import, analysis and views.

Imports go through the core ingestion pipeline as an ``import`` job (provenance, rejection
quarantine, ``raf import report``), using R$F-native records built by
:mod:`raf.products.surface.convert`. Nothing here performs network I/O.
"""

from __future__ import annotations

import hashlib
import json
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import (
    ConflictError,
    IngestionError,
    InvalidInputError,
    NotFoundError,
    RafError,
    ResourceLimitExceeded,
)
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions, IngestReport, Rejection
from raf.core.jobs.manager import JobContext
from raf.core.objects.models import Finding, RafModel
from raf.core.objects.types import FindingStatus, Severity
from raf.core.timeutil import ensure_utc, utcnow
from raf.products.surface.convert import Conversion, build
from raf.products.surface.formats import FORMATS, SurfaceDocument, detect_format, parse_document
from raf.products.surface.graph import SurfaceModel
from raf.products.surface.model import (
    ASSET_KINDS,
    LABEL,
    MAX_DOCUMENT_BYTES,
    PRODUCT,
    safe_display,
)
from raf.products.surface.rules import DEFAULT_EXPIRING_DAYS, RULES, evaluate
from raf.products.surface.sample import raven_surface_json
from raf.products.surface.scope import ScopeEntry, ScopeStore
from raf.products.surface.views import SurfaceAsset, SurfaceSummary, SurfaceViews

MAX_REJECTIONS = 1000
_KIND_ALIASES = {
    "domain": "domain",
    "domains": "domain",
    "name": "domain",
    "dns": "domain",
    "ip": "ip",
    "ips": "ip",
    "address": "ip",
    "service": "service",
    "services": "service",
    "certificate": "certificate",
    "certificates": "certificate",
    "cert": "certificate",
    "cloud_asset": "cloud_asset",
    "cloud": "cloud_asset",
    "cloud_assets": "cloud_asset",
    "cloud_resource": "cloud_asset",
}


class ScopeChange(RafModel):
    target: str
    kind: str | None = None
    result: str  # added | replaced | unchanged | conflict | invalid
    detail: str | None = None


class SurfaceImportResult(RafModel):
    source: str
    path: str | None = None
    sha256: str
    size: int
    format: str
    organization: str | None = None
    as_of: datetime | None = None
    records: int = 0
    accepted: int = 0
    rejected: int = 0
    by_kind: dict[str, int] = Field(default_factory=dict)
    rejections: list[Rejection] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    scope_declared: int = 0
    scope_applied: bool = False
    scope_changes: list[ScopeChange] = Field(default_factory=list)
    job_id: str | None = None
    native_records: int = 0
    objects_created: int = 0
    objects_updated: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0


class SurfaceAnalysis(RafModel):
    generated_at: datetime
    reference_time: datetime
    reference_source: str
    expiring_days: int
    scope_entries: int
    assets: int
    in_scope: int
    out_of_scope: int
    findings: list[Finding] = Field(default_factory=list)
    by_rule: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    created: int = 0
    updated: int = 0
    resolved: int = 0
    persisted: bool = True
    notes: list[str] = Field(default_factory=list)


def parse_asset_kind(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    kind = _KIND_ALIASES.get(value.strip().lower().replace("-", "_"))
    if kind is None:
        raise InvalidInputError(f"Unknown asset kind {value[:40]!r}.", hint="Use " + ", ".join(ASSET_KINDS) + ".")
    return kind


def parse_scope_filter(value: str | None) -> str:
    text = (value or "all").strip().lower()
    if text not in ("in", "out", "all"):
        raise InvalidInputError(f"Unknown scope filter {text[:20]!r}.", hint="Use in, out or all.")
    return text


class SurfaceService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.scopes = ScopeStore(ctx.store.kv)

    # ------------------------------------------------------------------ scope
    def scope_entries(self) -> list[ScopeEntry]:
        return self.scopes.entries()

    def scope_entry(self, target: str) -> ScopeEntry:
        entry = self.scopes.get(self.scopes.resolve_key(target))
        if entry is None:
            raise NotFoundError(
                f"{target.strip()[:200]!r} is not in the authorized scope.", suggestions=["raf surface scope list"]
            )
        return entry

    def add_scope(
        self,
        target: Any,
        kind: str | None = None,
        owner: Any = None,
        authorization: Any = None,
        *,
        replace: bool = False,
        via: str = "cli",
    ) -> tuple[ScopeEntry, str]:
        entry, result = self.scopes.add(target, kind, owner, authorization, replace=replace)
        if result != "unchanged":
            self.ctx.audit.record(
                "surface.scope.add",
                affected=[f"surface.scope:{entry.target}"],
                details={
                    "result": result,
                    "kind": entry.kind,
                    "owner": entry.owner,
                    "authorization": entry.authorization,
                    "via": via,
                },
            )
        return entry, result

    def remove_scope(self, target: str, *, via: str = "cli") -> ScopeEntry:
        entry = self.scopes.remove(target)
        self.ctx.audit.record(
            "surface.scope.remove",
            affected=[f"surface.scope:{entry.target}"],
            details={"kind": entry.kind, "owner": entry.owner, "authorization": entry.authorization, "via": via},
        )
        return entry

    def _apply_scope(self, document: SurfaceDocument) -> list[ScopeChange]:
        changes: list[ScopeChange] = []
        for item in document.scope:
            data = item.data
            if not isinstance(data, dict):
                changes.append(ScopeChange(target=item.locator, result="invalid", detail="expected an object"))
                continue
            raw_kind = data.get("kind")
            label = safe_display(data.get("target") or item.locator, 120)
            if raw_kind is not None and not isinstance(raw_kind, str):
                changes.append(ScopeChange(target=label, result="invalid", detail="'kind' must be text"))
                continue
            try:
                entry, result = self.add_scope(
                    data.get("target"), raw_kind, data.get("owner"), data.get("authorization"), via="import"
                )
            except ConflictError as exc:
                detail = f"already in the scope with other details; the existing entry was kept ({exc.reason})"
                changes.append(ScopeChange(target=label, result="conflict", detail=detail))
            except RafError as exc:
                changes.append(ScopeChange(target=label, result="invalid", detail=exc.message))
            else:
                changes.append(ScopeChange(target=entry.target, kind=entry.kind, result=result))
        return changes

    # ------------------------------------------------------------------ import
    def import_file(
        self,
        path: Path,
        *,
        fmt: str | None = None,
        apply_scope: bool = False,
        source_name: str | None = None,
    ) -> SurfaceImportResult:
        path = path.expanduser()
        try:
            info = path.stat()
        except FileNotFoundError as exc:
            raise NotFoundError(f"{path} does not exist.") from exc
        except OSError as exc:
            raise InvalidInputError(f"Cannot read {path}.", reason=str(exc)) from exc
        if not stat.S_ISREG(info.st_mode):
            raise InvalidInputError(f"{path} is not a regular file.")
        if info.st_size > MAX_DOCUMENT_BYTES:
            raise ResourceLimitExceeded(
                f"{path.name} is {info.st_size / 1e6:.1f} MB; surface inventories are limited to "
                f"{MAX_DOCUMENT_BYTES // (1024 * 1024)} MB.",
                hint="Split the inventory into several files.",
            )
        with path.open("rb") as handle:
            data = handle.read(MAX_DOCUMENT_BYTES + 1)
        chosen = fmt or detect_format(path.name, data[:65536])
        return self._import(
            data,
            name=source_name or path.name,
            fmt=chosen,
            path=path.resolve(),
            apply_scope=apply_scope,
            via="cli",
        )

    def import_bytes(
        self,
        data: bytes,
        *,
        source_name: str = "api-request.json",
        fmt: str = "json",
        apply_scope: bool = False,
        via: str = "api",
    ) -> SurfaceImportResult:
        return self._import(data, name=source_name, fmt=fmt, path=None, apply_scope=apply_scope, via=via)

    def _import(
        self, data: bytes, *, name: str, fmt: str, path: Path | None, apply_scope: bool, via: str
    ) -> SurfaceImportResult:
        fmt = fmt.strip().lower()
        if fmt not in FORMATS:
            raise InvalidInputError(f"Unknown inventory format {fmt[:20]!r}.", hint="Use json, jsonl, yaml or csv.")
        source = safe_display(name, 200) or "inventory"
        document = parse_document(data, fmt)
        observed = document.as_of or utcnow()
        conversion = build(document, observed=observed)
        sha = hashlib.sha256(data).hexdigest()

        def work(jc: JobContext) -> dict[str, Any]:
            pipeline = IngestionPipeline(self.ctx, job=jc)
            report = pipeline.ingest_records(
                (native.data for native in conversion.natives),
                source_name=source,
                options=IngestOptions(),
                label=LABEL,
            )
            self._merge_rejections(report, conversion, jc.job_id)
            return report.to_json_dict()

        job = self.ctx.jobs.run_inline(
            "import",
            f"Surface inventory {source}",
            {
                "product": PRODUCT,
                "source": source,
                "path": str(path) if path else None,
                "format": fmt,
                "sha256": sha,
                "records": conversion.records,
            },
            work,
        )
        if job.result is None:
            error = job.error or {}
            raise IngestionError(
                str(error.get("message") or "The surface import failed."),
                reason=error.get("reason"),
                suggestions=[f"raf job show {job.id}"],
            )
        report = IngestReport.model_validate(job.result)
        changes = self._apply_scope(document) if apply_scope else []
        result = SurfaceImportResult(
            source=source,
            path=str(path) if path else None,
            sha256=sha,
            size=len(data),
            format=fmt,
            organization=document.organization,
            as_of=document.as_of,
            records=conversion.records,
            accepted=conversion.accepted,
            rejected=report.rejected,
            by_kind=conversion.by_kind,
            rejections=report.rejections[:200],
            warnings=conversion.warnings,
            scope_declared=len(document.scope),
            scope_applied=apply_scope,
            scope_changes=changes,
            job_id=job.id,
            native_records=len(conversion.natives),
            objects_created=report.objects_created,
            objects_updated=report.objects_updated,
            relationships_created=report.relationships_created,
            relationships_updated=report.relationships_updated,
        )
        self.ctx.audit.record(
            "surface.import",
            affected=[str(path) if path else source],
            details={
                "job": job.id,
                "sha256": sha,
                "records": result.records,
                "accepted": result.accepted,
                "rejected": result.rejected,
                "scope_added": [c.target for c in changes if c.result in ("added", "replaced")],
                "via": via,
            },
        )
        self.ctx.refs.remember("job", job.id)
        return result

    def _merge_rejections(self, report: IngestReport, conversion: Conversion, job_id: str) -> None:
        """Surface-level rejections (invalid records) join the pipeline's report and quarantine file."""
        if conversion.warnings:
            report.warnings += len(conversion.warnings)
            report.warning_samples = (conversion.warnings + report.warning_samples)[:50]
        if not conversion.rejected:
            return
        rejections = [Rejection(record=r.locator, reason=r.reason, source=report.source) for r in conversion.rejected]
        report.processed += len(rejections)
        report.rejected += len(rejections)
        report.rejections = (rejections + report.rejections)[:MAX_REJECTIONS]
        rejects = self.ctx.workspace.rejects_dir / f"{job_id}.jsonl"
        rejects.parent.mkdir(parents=True, exist_ok=True)
        with rejects.open("a", encoding="utf-8") as handle:
            for item in conversion.rejected[:MAX_REJECTIONS]:
                entry = {"record": item.locator, "reason": item.reason, "source": report.source, "raw": item.raw}
                handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
        report.rejects_file = str(rejects)

    # ------------------------------------------------------------------ analysis
    def reference_time(self, at: datetime | None = None) -> tuple[datetime, str]:
        """The time certificates are judged against: given, else the newest event, else now."""
        if at is not None:
            return ensure_utc(at), "given"
        newest = self.store.events.bounds()[1]
        if newest is not None:
            return newest, "newest event in the workspace"
        return utcnow(), "current time"

    def model(self) -> SurfaceModel:
        return SurfaceModel.load(self.store, self.scopes.scope())

    def analyze(
        self,
        *,
        at: datetime | None = None,
        expiring_days: int = DEFAULT_EXPIRING_DAYS,
        persist: bool = True,
        via: str = "cli",
    ) -> SurfaceAnalysis:
        if not 1 <= expiring_days <= 3650:
            raise InvalidInputError("The expiring window must be between 1 and 3650 days.")
        reference, source = self.reference_time(at)
        model = self.model()
        now = utcnow()
        findings = evaluate(model, reference=reference, expiring_days=expiring_days, now=now)
        created = updated = resolved = 0
        if persist:
            with self.store.transaction() as conn:
                stats = self.store.findings.upsert(findings, conn=conn)
                created, updated = stats.created, stats.updated
                resolved = self.store.findings.resolve_absent(PRODUCT, list(RULES), [f.id for f in findings], conn=conn)
            stored = {f.id: f for f in self.store.findings.list(product=PRODUCT, limit=100_000)}
            findings = [stored.get(f.id, f) for f in findings]
            self.ctx.audit.record(
                "surface.analyze",
                affected=[f.id for f in findings[:50]],
                details={
                    "findings": len(findings),
                    "created": created,
                    "resolved": resolved,
                    "reference_time": reference.isoformat(),
                    "via": via,
                },
            )
        assets = [oid for oid in model.surface_ids if model.kind(oid) in ASSET_KINDS and model.is_asset(oid)]
        notes: list[str] = []
        if not model.scope.configured:
            notes.append(
                "No authorized scope is configured, so nothing is treated as owned and no findings were produced. "
                "Add scope first: raf surface scope add <domain|cidr|ip|provider:account> --owner TEAM "
                "--authorization REF"
            )
        if not assets:
            notes.append("No surface inventory has been imported into this workspace yet (raf surface import FILE).")
        by_rule: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        return SurfaceAnalysis(
            generated_at=now,
            reference_time=reference,
            reference_source=source,
            expiring_days=expiring_days,
            scope_entries=len(model.scope.entries),
            assets=len(assets),
            in_scope=sum(1 for oid in assets if model.scope_match(oid).status == "in"),
            out_of_scope=sum(1 for oid in assets if model.scope_match(oid).status == "out"),
            findings=findings,
            by_rule=dict(sorted(by_rule.items())),
            by_severity=by_severity,
            created=created,
            updated=updated,
            resolved=resolved,
            persisted=persist,
            notes=notes,
        )

    # ------------------------------------------------------------------ views
    def _views(self, at: datetime | None, expiring_days: int) -> tuple[SurfaceViews, str]:
        reference, source = self.reference_time(at)
        findings = self.store.findings.list(product=PRODUCT, statuses=[FindingStatus.OPEN.value], limit=5000)
        views = SurfaceViews(self.model(), reference=reference, findings=findings, expiring_days=expiring_days)
        return views, source

    def summary(self, *, at: datetime | None = None, expiring_days: int = DEFAULT_EXPIRING_DAYS) -> SurfaceSummary:
        views, source = self._views(at, expiring_days)
        return views.summary(
            workspace=self.ctx.workspace.name, scope=views.model.scope.entries, reference_source=source
        )

    def assets(
        self,
        *,
        kind: str | None = None,
        scope: str | None = None,
        include_references: bool = False,
        limit: int = 1000,
        offset: int = 0,
    ) -> tuple[list[SurfaceAsset], int]:
        chosen_kind = parse_asset_kind(kind)
        chosen_scope = parse_scope_filter(scope)
        views, _source = self._views(None, DEFAULT_EXPIRING_DAYS)
        items = views.assets(kind=chosen_kind, scope=chosen_scope, include_references=include_references)
        return items[offset : offset + limit], len(items)

    def findings(
        self,
        *,
        rule: str | None = None,
        min_severity: str | None = None,
        status: str = "open",
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Finding], int]:
        if rule is not None and rule not in RULES:
            raise InvalidInputError(f"Unknown surface rule {rule[:60]!r}.", hint="Rules: " + ", ".join(RULES) + ".")
        severity = Severity.parse(min_severity) if min_severity else None
        text = status.strip().upper()
        if text == "ALL":
            statuses: list[str] | None = None
        elif text in FindingStatus.__members__:
            statuses = [text]
        else:
            raise InvalidInputError(
                f"Unknown finding status {status[:30]!r}.", hint="Use open, resolved, acknowledged ... or all."
            )
        everything = self.store.findings.list(
            product=PRODUCT, rule_id=rule, min_severity=severity, statuses=statuses, limit=100_000
        )
        return everything[offset : offset + limit], len(everything)

    # ------------------------------------------------------------------ sample
    @staticmethod
    def write_sample(path: Path) -> dict[str, Any]:
        text = raven_surface_json()
        path.expanduser().write_text(text, encoding="utf-8")
        return {"path": str(path.expanduser().resolve()), "bytes": len(text.encode("utf-8")), "format": "json"}
