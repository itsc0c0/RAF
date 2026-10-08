"""The ingestion pipeline.

RAW SOURCE -> PARSER -> NORMALIZER -> OBJECT/EVENT MODEL -> RELATIONSHIP BUILDER -> R$F DATA STORE

Guarantees:
* streaming with bounded memory (batched flushes);
* malformed records are rejected individually, quarantined with their reason
  and raw excerpt, and never abort the import;
* every object, relationship and event keeps provenance (source, content hash,
  record locator, parser, observation time, evidence ID);
* imports are idempotent: identical input produces identical IDs.
"""

from __future__ import annotations

import json
import logging
import zoneinfo
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import IO, Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import ConfigError, IngestionError, InvalidInputError, RafError
from raf.core.ids import object_id
from raf.core.ingestion import builder
from raf.core.ingestion.base import (
    IncidentDraft,
    NormalizedRecord,
    Normalizer,
    ParseContext,
    Parser,
    RawRecord,
    RecordRejected,
    SourceInfo,
)
from raf.core.ingestion.registry import ParserRegistry
from raf.core.ingestion.resolver import EntityResolver
from raf.core.jobs.manager import JobContext
from raf.core.logging import timed
from raf.core.objects.models import EventDraft, Finding, ObjectDraft, ProvenanceDraft, RafModel, RelationshipDraft
from raf.core.objects.types import ObjectType, Severity
from raf.core.security.files import check_input_file, iter_directory, read_head, sha256_file
from raf.core.timeutil import utcnow

log = logging.getLogger("raf.ingest")

_SAMPLE = 25
_MAX_SOURCES = 200  # distinct line sources counted per import report


@dataclass(slots=True)
class IngestOptions:
    format: str | None = None
    incident: str | None = None
    source_name: str | None = None
    default_host: str | None = None
    synthetic: bool = False
    evidence_id: str | None = None
    timezone: str | None = None
    reference_time: datetime | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Rejection(RafModel):
    record: str
    reason: str
    hint: str | None = None
    source: str | None = None


class IngestReport(RafModel):
    job_id: str | None = None
    source: str
    path: str | None = None
    sha256: str | None = None
    size: int | None = None
    format: str | None = None
    parser: str | None = None
    normalizer: str | None = None
    processed: int = 0
    accepted: int = 0
    rejected: int = 0
    warnings: int = 0
    warning_samples: list[str] = Field(default_factory=list)
    objects_created: int = 0
    objects_updated: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0
    events_created: int = 0
    events_duplicate: int = 0
    events_reparsed: int = 0
    findings_created: int = 0
    sources: dict[str, int] = Field(default_factory=dict)
    earlier_jobs: list[str] = Field(default_factory=list)  # jobs that first stored events this import met again
    incidents: list[str] = Field(default_factory=list)
    rejections: list[Rejection] = Field(default_factory=list)
    rejects_file: str | None = None
    files: list[dict[str, Any]] = Field(default_factory=list)
    skipped_files: list[dict[str, str]] = Field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: float | None = None

    def absorb(self, other: IngestReport) -> None:
        for key in (
            "processed",
            "accepted",
            "rejected",
            "warnings",
            "objects_created",
            "objects_updated",
            "relationships_created",
            "relationships_updated",
            "events_created",
            "events_duplicate",
            "events_reparsed",
            "findings_created",
        ):
            setattr(self, key, getattr(self, key) + getattr(other, key))
        for name, count in other.sources.items():
            if name in self.sources or len(self.sources) < _MAX_SOURCES:
                self.sources[name] = self.sources.get(name, 0) + count
        for job in other.earlier_jobs:
            if job not in self.earlier_jobs and len(self.earlier_jobs) < 50:
                self.earlier_jobs.append(job)
        self.incidents = sorted(set(self.incidents) | set(other.incidents))
        room = 1000 - len(self.rejections)
        if room > 0:
            self.rejections.extend(other.rejections[:room])
        self.warning_samples.extend(other.warning_samples[: max(0, 50 - len(self.warning_samples))])


@dataclass
class _Batch:
    objects: dict[str, ObjectDraft] = field(default_factory=dict)
    relationships: dict[str, RelationshipDraft] = field(default_factory=dict)
    events: list[EventDraft] = field(default_factory=list)
    incidents: dict[str, IncidentDraft] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    provenance: list[ProvenanceDraft] = field(default_factory=list)
    records: int = 0

    def add_object(self, draft: ObjectDraft) -> None:
        current = self.objects.get(draft.id)
        if current is None:
            self.objects[draft.id] = draft
        else:
            current.merge(draft)

    def add_relationship(self, draft: RelationshipDraft) -> None:
        current = self.relationships.get(draft.id)
        if current is None:
            self.relationships[draft.id] = draft
        else:
            current.merge(draft)


class IngestionPipeline:
    def __init__(self, ctx: RafContext, registry: ParserRegistry | None = None, job: JobContext | None = None) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.settings = ctx.settings
        self.registry = registry or ParserRegistry.default()
        self.job = job
        self.resolver = EntityResolver(ctx.store)
        self._normalizers = self.registry.normalizers(self.resolver.resolve)
        self._prov_counts: Counter[str] = Counter()
        self._types: dict[str, str] = {}

    # ------------------------------------------------------------------ helpers
    @property
    def job_id(self) -> str | None:
        return self.job.job_id if self.job else None

    def _tz(self, options: IngestOptions) -> tzinfo:
        name = options.timezone or str(self.settings.get("ingest.default_timezone"))
        if name.upper() == "UTC":
            return UTC
        try:
            return zoneinfo.ZoneInfo(name)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError) as exc:
            raise ConfigError(f"Unknown timezone '{name}'.", hint="Use an IANA name such as Europe/Istanbul.") from exc

    def _parse_context(self, source: SourceInfo, options: IngestOptions) -> ParseContext:
        return ParseContext(
            source=source,
            default_tz=self._tz(options),
            reference_time=options.reference_time,
            max_record_bytes=int(self.settings.get("ingest.max_record_kb")) * 1024,
            raw_max_bytes=int(self.settings.get("ingest.raw_max_bytes")),
            store_raw=bool(self.settings.get("ingest.store_raw")),
            user_strip_domain=bool(self.settings.get("ingest.user_strip_domain")),
            options={
                "max_json_document_bytes": int(self.settings.get("ingest.max_json_document_mb")) * 1024 * 1024,
                **options.extra,
            },
        )

    def _new_report(self, source: SourceInfo) -> IngestReport:
        return IngestReport(
            job_id=self.job_id,
            source=source.name,
            path=str(source.path) if source.path else None,
            sha256=source.sha256,
            size=source.size,
            started_at=utcnow(),
        )

    # ------------------------------------------------------------------ entry points
    def ingest_path(self, path: Path, options: IngestOptions | None = None) -> IngestReport:
        options = options or IngestOptions()
        path = path.expanduser()
        if path.is_dir():
            if options.format == "filesystem":
                from raf.core.ingestion.parsers.filesystem import ingest_filesystem

                return ingest_filesystem(self, path, options)
            return self.ingest_directory(path, options)
        return self.ingest_file(path, options)

    def ingest_file(self, path: Path, options: IngestOptions, parser_cls: type[Parser] | None = None) -> IngestReport:
        max_bytes = int(self.settings.get("ingest.max_file_mb")) * 1024 * 1024
        info = check_input_file(path, max_bytes)
        if parser_cls is None:
            if options.format:
                parser_cls = self.registry.get(options.format)
            else:
                detected = self.registry.detect(path, read_head(path))
                if detected is None:
                    raise IngestionError(
                        f"R$F could not determine the format of {path.name}.",
                        hint="Specify it with --format. Supported: "
                        + ", ".join(sorted(p.name for p in self.registry.parsers())),
                    )
                parser_cls = detected[0]
        source = SourceInfo(
            name=options.source_name or path.name,
            path=path.resolve(),
            sha256=sha256_file(path),
            size=info.st_size,
            evidence_id=options.evidence_id,
            synthetic=options.synthetic,
            incident=options.incident,
            default_host=options.default_host,
        )
        if options.reference_time is None:
            options.reference_time = datetime.fromtimestamp(info.st_mtime, UTC)
        parser = parser_cls()
        report = self._new_report(source)
        report.format = parser.name
        report.parser = parser.label
        with timed(log, "ingest.file", source=source.name), path.open("rb") as stream:
            parse_ctx = self._parse_context(source, options)
            records = parser.records(stream, parse_ctx)
            # one context for parser and normalizers, so parser warnings reach the report
            self._run(records, parser, source, options, report, stream=stream, total=info.st_size, ctx=parse_ctx)
        return report

    def ingest_records(
        self,
        records: Iterable[dict[str, Any]],
        *,
        source_name: str,
        options: IngestOptions | None = None,
        normalizer: str = "raf-native",
        label: str = "generator/1.0",
    ) -> IngestReport:
        """Ingest already-structured records (generators, plugins, APIs)."""
        options = options or IngestOptions()
        source = SourceInfo(
            name=source_name,
            synthetic=options.synthetic,
            incident=options.incident,
            evidence_id=options.evidence_id,
            default_host=options.default_host,
        )
        report = self._new_report(source)
        report.format = "records"
        report.parser = label

        def raw() -> Iterator[RawRecord]:
            for index, record in enumerate(records):
                yield RawRecord(record, f"record {index}", None, normalizer=normalizer, parser_label=label)

        with timed(log, "ingest.records", source=source_name):
            self._run(raw(), None, source, options, report)
        return report

    def ingest_directory(self, root: Path, options: IngestOptions) -> IngestReport:
        report = IngestReport(
            job_id=self.job_id, source=root.name, path=str(root.resolve()), format="directory", started_at=utcnow()
        )
        files = list(iter_directory(root, max_files=100_000))
        for index, file_path in enumerate(files):
            if self.job:
                self.job.check_cancelled()
                self.job.progress(index / max(len(files), 1), f"{file_path.name}")
            if file_path.is_symlink():
                report.skipped_files.append({"path": str(file_path), "reason": "symlink (not followed)"})
                continue
            try:
                detected = (
                    self.registry.detect(file_path, read_head(file_path))
                    if not options.format
                    else (self.registry.get(options.format), 1.0)
                )
            except OSError as exc:
                report.skipped_files.append({"path": str(file_path), "reason": f"unreadable: {exc}"})
                continue
            if detected is None:
                report.skipped_files.append({"path": str(file_path), "reason": "unknown format"})
                continue
            sub_options = replace(options, source_name=str(file_path.relative_to(root)), reference_time=None)
            try:
                sub = self.ingest_file(file_path, sub_options, detected[0])
            except RafError as exc:
                report.skipped_files.append({"path": str(file_path), "reason": exc.message})
                continue
            report.absorb(sub)
            report.files.append(
                {
                    "path": str(file_path.relative_to(root)),
                    "format": sub.format,
                    "accepted": sub.accepted,
                    "rejected": sub.rejected,
                    "sha256": sub.sha256,
                }
            )
        report.finished_at = utcnow()
        report.duration_ms = (
            round((report.finished_at - report.started_at).total_seconds() * 1000, 1) if report.started_at else None
        )
        return report

    # ------------------------------------------------------------------ core loop
    def _select_normalizer(self, sample: list[RawRecord], default: str) -> Normalizer:
        if default != "auto":
            return self._normalizers[default]
        scores: dict[str, float] = {}
        for record in sample:
            if record.error is not None or not isinstance(record.data, dict):
                continue
            for name, normalizer in self._normalizers.items():
                scores[name] = scores.get(name, 0.0) + type(normalizer).score(record.data)
        if not scores or max(scores.values()) <= 0.0:
            return self._normalizers["generic-json"]
        best = max(scores.items(), key=lambda kv: (kv[1], kv[0] == "raf-native"))[0]
        return self._normalizers[best]

    def _run(
        self,
        records: Iterator[RawRecord],
        parser: Parser | None,
        source: SourceInfo,
        options: IngestOptions,
        report: IngestReport,
        *,
        stream: IO[bytes] | None = None,
        total: int | None = None,
        ctx: ParseContext | None = None,
    ) -> None:
        ctx = ctx or self._parse_context(source, options)
        batch_size = int(self.settings.get("ingest.batch_size"))
        max_reported = int(self.settings.get("ingest.max_rejections_reported"))
        rejects_path = (
            self.ctx.workspace.rejects_dir / f"{self.job_id or 'import-' + utcnow().strftime('%Y%m%dT%H%M%S')}.jsonl"
        )
        rejects_handle: IO[str] | None = None
        sample: list[RawRecord] = []
        iterator = iter(records)
        for record in iterator:
            sample.append(record)
            if len(sample) >= _SAMPLE:
                break
        default_normalizer = parser.normalizer if parser is not None else "raf-native"
        normalizer = self._select_normalizer(sample, default_normalizer)
        report.normalizer = f"{normalizer.name}/{normalizer.version}"
        batch = _Batch()

        def all_records() -> Iterator[RawRecord]:
            yield from sample
            yield from iterator

        try:
            for record in all_records():
                report.processed += 1
                try:
                    if record.error is not None:
                        raise record.error
                    chosen = self._normalizers.get(record.normalizer, normalizer) if record.normalizer else normalizer
                    normalized = chosen.normalize(record, ctx)
                    label = record.parser_label or (parser.label if parser else "records/1.0")
                    if chosen.name != "raf-native":
                        label = f"{label}+{chosen.name}/{chosen.version}"
                    self._accept(normalized, record, label, source, batch)
                    report.accepted += 1
                    if record.origin is not None and (
                        record.origin in report.sources or len(report.sources) < _MAX_SOURCES
                    ):
                        report.sources[record.origin] = report.sources.get(record.origin, 0) + 1
                except (RafError, ValueError, TypeError, KeyError, OverflowError) as exc:
                    rejection = _rejection(record, exc, source)
                    report.rejected += 1
                    if len(report.rejections) < max_reported:
                        report.rejections.append(rejection)
                    if rejects_handle is None:
                        rejects_path.parent.mkdir(parents=True, exist_ok=True)
                        rejects_handle = rejects_path.open("a", encoding="utf-8")
                        report.rejects_file = str(rejects_path)
                    rejects_handle.write(
                        json.dumps({**rejection.to_json_dict(), "raw": (record.raw or "")[:4096]}, ensure_ascii=False)
                        + "\n"
                    )
                except Exception as exc:
                    log.error("internal error normalizing %s", record.locator, exc_info=True, extra={"file_only": True})
                    report.rejected += 1
                    if len(report.rejections) < max_reported:
                        report.rejections.append(
                            Rejection(
                                record=record.locator,
                                source=source.name,
                                reason=f"internal error while normalizing ({type(exc).__name__}); see raf.log",
                            )
                        )
                if batch.records >= batch_size:
                    self._flush(batch, report)
                    batch = _Batch()
                    if self.job:
                        self.job.check_cancelled()
                        if stream is not None and total:
                            self.job.progress(min(stream.tell() / total, 0.99), f"{report.processed:,} records")
                        else:
                            self.job.progress(0.5, f"{report.processed:,} records")
            self._flush(batch, report)
            if options.incident:
                incident_id = self.store.incidents.upsert(
                    options.incident, source=source.name, synthetic=options.synthetic
                )
                if incident_id not in report.incidents:
                    report.incidents.append(incident_id)
        finally:
            if rejects_handle is not None:
                rejects_handle.close()
        report.warnings += len(ctx.warnings)
        report.warning_samples.extend(ctx.warnings[:20])
        report.finished_at = utcnow()
        if report.started_at:
            report.duration_ms = round((report.finished_at - report.started_at).total_seconds() * 1000, 1)
        report.incidents = sorted(set(report.incidents))

    # ------------------------------------------------------------------ accept / flush
    def _accept(
        self, normalized: NormalizedRecord, record: RawRecord, label: str, source: SourceInfo, batch: _Batch
    ) -> None:
        batch.records += 1
        for draft in normalized.objects:
            self._types[draft.id] = draft.type
            self.resolver.register(draft)
            batch.add_object(draft)
            if not normalized.events:  # inventory record: provenance without an event
                self._provenance(batch, draft.id, "object", source, label, record.locator, None, draft.first_seen)
        for rel in normalized.relationships:
            batch.add_relationship(rel)
            self._provenance(batch, rel.id, "relationship", source, label, record.locator, None, rel.first_seen)
        for incident in normalized.incidents:
            existing = batch.incidents.get(incident.name)
            if existing is None or incident.title or incident.event_ids:
                batch.incidents[incident.name] = incident
        batch.findings.extend(normalized.findings)
        for ev in normalized.events:
            ev.parser = label[:128]
            result = builder.build(ev, self._types)
            for rel in result.relationships:
                batch.add_relationship(rel)
                ev.relationships.append(rel.id)
                self._provenance(batch, rel.id, "relationship", source, label, record.locator, ev.id, ev.timestamp)
            for patch in result.object_patches:
                batch.add_object(patch)
            for ref in ev.objects:
                self._provenance(batch, ref.object_id, "object", source, label, record.locator, ev.id, ev.timestamp)
            for rel in normalized.relationships:
                if rel.id not in ev.relationships:
                    ev.relationships.append(rel.id)
            batch.events.append(ev)

    def _provenance(
        self,
        batch: _Batch,
        subject: str,
        kind: str,
        source: SourceInfo,
        label: str,
        locator: str,
        event_id: str | None,
        observed: datetime | None,
    ) -> None:
        cap = int(self.settings.get("ingest.provenance_cap"))
        if self._prov_counts[subject] >= cap:
            return
        self._prov_counts[subject] += 1
        batch.provenance.append(
            ProvenanceDraft(
                subject_id=subject,
                subject_kind=kind,
                source=source.name,
                parser=label[:128],
                record=locator[:128],
                event_id=event_id,
                observed_at=observed,
                evidence_id=source.evidence_id,
                source_sha256=source.sha256,
            )
        )

    def _flush(self, batch: _Batch, report: IngestReport) -> None:
        if not (batch.objects or batch.relationships or batch.events or batch.incidents or batch.findings):
            return
        # Incident objects must exist before events reference them.
        for incident in batch.incidents.values():
            batch.add_object(
                ObjectDraft.make(
                    ObjectType.INCIDENT,
                    incident.name,
                    confidence=1.0,
                    metadata={
                        k: v
                        for k, v in {
                            "title": incident.title,
                            "status": incident.status,
                            "severity": Severity.parse(incident.severity).value if incident.severity else None,
                            "description": incident.description,
                            "start": incident.start.isoformat() if incident.start else None,
                            "end": incident.end.isoformat() if incident.end else None,
                        }.items()
                        if v is not None
                    },
                    tags=set(incident.tags),
                    source=report.source,
                )
            )
        with self.store.transaction() as conn:
            stats = self.store.objects.upsert_drafts(list(batch.objects.values()), conn=conn)
            report.objects_created += stats.created
            report.objects_updated += stats.updated
            rstats = self.store.relationships.upsert_drafts(list(batch.relationships.values()), conn=conn)
            report.relationships_created += rstats.created
            report.relationships_updated += rstats.updated
            estats = self.store.events.insert_drafts(batch.events, job_id=self.job_id, conn=conn, reparse=True)
            report.events_created += estats.created
            report.events_duplicate += estats.duplicates
            report.events_reparsed += estats.reparsed
            for earlier in sorted(estats.existing_jobs - {self.job_id or ""}):
                if earlier and earlier not in report.earlier_jobs and len(report.earlier_jobs) < 50:
                    report.earlier_jobs.append(earlier)
            self.store.provenance.add_many(batch.provenance, job_id=self.job_id, conn=conn)
            if batch.findings:
                fstats = self.store.findings.upsert(batch.findings, conn=conn)
                report.findings_created += fstats.created
        for incident in batch.incidents.values():
            incident_id = object_id(ObjectType.INCIDENT, incident.name)
            if incident_id not in report.incidents:
                report.incidents.append(incident_id)
            if incident.event_ids:
                self.store.events.link_incident(incident_id, incident.event_ids)


def _rejection(record: RawRecord, exc: Exception, source: SourceInfo) -> Rejection:
    if isinstance(exc, RafError):
        reason = exc.message + (f" ({exc.reason})" if exc.reason else "")
        return Rejection(record=record.locator, reason=reason, hint=exc.hint, source=source.name)
    if isinstance(exc, KeyError):
        return Rejection(record=record.locator, reason=f"Missing field {exc}", source=source.name)
    return Rejection(record=record.locator, reason=str(exc)[:500] or type(exc).__name__, source=source.name)


__all__ = ["IngestOptions", "IngestReport", "IngestionPipeline", "InvalidInputError", "RecordRejected", "Rejection"]
