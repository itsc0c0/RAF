"""R$F Evidence: DFIR case management with strict integrity.

* Cases group evidence and may be linked to an incident.
* Items are SHA-256 hashed, copied into a read-only content-addressed store (originals are never
  modified), recorded with source, import time, size, type, notes and a hash-chained chain of
  custody, and appear in the graph as ``evidence`` objects.
* Parsing happens on the *stored copy*; every derived event keeps ``evidence:<id>#<record>`` as its
  raw reference and derived objects/relationships keep the item in their provenance.
* Events are linked to the case's incident only when they fall inside the incident window.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import Field, computed_field

from raf.core.context.app import RafContext
from raf.core.errors import (
    ConflictError,
    IngestionError,
    InvalidInputError,
    NotFoundError,
    RafError,
    ResourceLimitExceeded,
)
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions, IngestReport
from raf.core.ingestion.products import build_parser_registry
from raf.core.jobs.manager import JobContext
from raf.core.objects.models import RafModel
from raf.core.security.files import read_head
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import utcnow
from raf.products.evidence.store import (
    CustodyEntry,
    EvidenceStore,
    actor_name,
    append_custody,
    item_too_large,
    verify_custody,
)

CASE_NS = "evidence.case"
ITEM_NS = "evidence.item"
_CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_FILES = 10_000
_MEDIA = {
    ".log": "text/plain",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".ndjson": "application/x-ndjson",
    ".pcap": "application/vnd.tcpdump.pcap",
    ".pcapng": "application/vnd.tcpdump.pcap",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".evtx": "application/octet-stream",
    ".xml": "application/xml",
}


class EvidenceCase(RafModel):
    name: str
    title: str = ""
    description: str = ""
    status: str = "open"
    incident: str | None = None
    created_at: datetime
    updated_at: datetime
    created_by: str = ""


class EvidenceItem(RafModel):
    id: str
    case: str
    name: str
    source: str
    sha256: str
    size: int
    type: str
    media_type: str
    stored: str
    imported_at: datetime
    notes: list[str] = Field(default_factory=list)
    derived_from: str | None = None
    job: str | None = None
    parser: str | None = None
    status: str = "stored"  # stored | parsed | unparsed
    events: int = 0
    rejected: int = 0
    custody: list[CustodyEntry] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def acquired_at(self) -> datetime:
        return self.imported_at

    @property
    def object_id(self) -> str:
        return f"evidence:{self.id}"


class ImportResult(RafModel):
    case: str
    items: list[EvidenceItem] = Field(default_factory=list)
    skipped: list[dict[str, str]] = Field(default_factory=list)
    linked_events: int = 0
    incident: str | None = None
    job: str | None = None


class VerifyResult(RafModel):
    verified: bool
    items: list[dict[str, Any]] = Field(default_factory=list)


def _fallback_type(path: Path) -> str:
    media = _MEDIA.get(path.suffix.lower(), "")
    return "text" if media.startswith("text/") else "binary"


def validate_case_name(name: str) -> str:
    text = name.strip()
    if not _CASE_RE.match(text):
        raise InvalidInputError(
            f"Invalid case name '{name}'.",
            hint="Use letters, digits, '.', '_' or '-' (up to 64 characters), e.g. INC-042.",
        )
    return text


class EvidenceService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.kv = ctx.store.kv
        self.store = EvidenceStore(ctx.workspace.evidence_dir)
        self.actor = actor_name(getattr(ctx, "interface", "cli"))

    # ------------------------------------------------------------------ cases
    def cases(self) -> list[EvidenceCase]:
        return sorted((EvidenceCase.model_validate(v) for v in self.kv.items(CASE_NS).values()), key=lambda c: c.name)

    def get_case(self, name: str) -> EvidenceCase:
        raw = self.kv.get(CASE_NS, name.strip().lower())
        if raw is None:
            raise NotFoundError(
                f"Evidence case '{name}' does not exist.",
                suggestions=["raf evidence case list", f"raf evidence case create {name}"],
            )
        return EvidenceCase.model_validate(raw)

    def create_case(
        self, name: str, *, title: str = "", description: str = "", incident: str | None = None
    ) -> EvidenceCase:
        name = validate_case_name(name)
        if self.kv.get(CASE_NS, name.lower()) is not None:
            raise ConflictError(
                f"Evidence case '{name}' already exists.", suggestions=[f"raf evidence list --case {name}"]
            )
        incident_id = None
        if incident:
            incident_id = self.ctx.resolve(incident, types=["incident"]).id
        else:
            candidate = f"incident:{name.lower()}"
            if self.ctx.store.incidents.get(candidate) is not None:
                incident_id = candidate
        now = utcnow()
        case = EvidenceCase(
            name=name,
            title=title[:200],
            description=description[:2000],
            incident=incident_id,
            created_at=now,
            updated_at=now,
            created_by=self.actor,
        )
        self.kv.set(CASE_NS, name.lower(), case.to_json_dict())
        self.ctx.audit.record(
            "evidence.case.create", affected=[f"case:{name}"], details={"incident": incident_id, "title": title[:200]}
        )
        return case

    # ------------------------------------------------------------------ items
    def items(self, case: str | None = None) -> list[EvidenceItem]:
        found = [EvidenceItem.model_validate(v) for v in self.kv.items(ITEM_NS).values()]
        if case is not None:
            wanted = self.get_case(case).name
            found = [i for i in found if i.case == wanted]
        return sorted(found, key=lambda i: i.id)

    def items_for_object(self, object_id: str, case: str | None = None) -> list[EvidenceItem]:
        """Evidence items whose parsed events involve ``object_id`` (via ``evidence:<id>#...`` references)."""
        ids: set[str] = set()
        for event in self.ctx.store.events.iter(EventQuery(object_ids=[object_id]), with_objects=False):
            ref = event.raw_reference or ""
            if ref.startswith("evidence:"):
                ids.add(ref.split(":", 1)[1].split("#", 1)[0])
            if len(ids) >= 1000:
                break
        found = [i for i in self.items(case) if i.id in ids]
        return found

    def get_item(self, item_id: str) -> EvidenceItem:
        key = item_id.strip().lower().removeprefix("evidence:")
        raw = self.kv.get(ITEM_NS, key)
        if raw is None:
            raise NotFoundError(f"Evidence item '{item_id}' does not exist.", suggestions=["raf evidence list"])
        return EvidenceItem.model_validate(raw)

    def _save(self, item: EvidenceItem) -> None:
        self.kv.set(ITEM_NS, item.id, item.to_json_dict())

    def _files(self, path: Path) -> tuple[list[Path], list[dict[str, str]]]:
        if path.is_symlink():
            return [], [{"path": str(path), "reason": "symbolic links are not followed"}]
        if path.is_file():
            return [path], []
        if not path.is_dir():
            raise NotFoundError(f"{path} does not exist.")
        files: list[Path] = []
        skipped: list[dict[str, str]] = []
        for candidate in sorted(path.rglob("*")):
            if len(files) >= MAX_FILES:
                skipped.append({"path": str(candidate), "reason": f"more than {MAX_FILES} files"})
                break
            if candidate.is_symlink():
                skipped.append({"path": str(candidate), "reason": "symbolic links are not followed"})
            elif candidate.is_file():
                files.append(candidate)
        return files, skipped

    def import_path(
        self,
        path: Path,
        case: str,
        *,
        parse: bool = True,
        note: str | None = None,
        derived_from: str | None = None,
        synthetic: bool = False,
    ) -> ImportResult:
        case_obj = self.get_case(case)
        parent = self.get_item(derived_from) if derived_from else None
        source = path.expanduser()
        files, skipped = self._files(source)
        if not files:
            raise InvalidInputError(f"No files to import from {path}.", details={"skipped": skipped})
        max_bytes = int(self.ctx.settings.get("evidence.max_item_mb")) * 1024 * 1024
        if files == [source] and source.stat().st_size > max_bytes:
            # One artifact was asked for: refuse it outright (from a directory, oversized files are skipped).
            raise item_too_large(source.name, source.stat().st_size, max_bytes)
        result = ImportResult(case=case_obj.name, skipped=skipped, incident=case_obj.incident)

        def work(jc: JobContext) -> dict[str, Any]:
            registry = build_parser_registry(self.ctx)
            records: list[dict[str, Any]] = []
            for index, file in enumerate(files):
                jc.progress(index / max(1, len(files)), file.name)
                try:
                    stored = self.store.put(file, max_bytes=max_bytes)
                except (InvalidInputError, ResourceLimitExceeded, OSError) as exc:
                    result.skipped.append({"path": str(file), "reason": getattr(exc, "message", str(exc))})
                    continue
                item_id = f"ev-{self.ctx.store.counters.next('evidence'):04d}"
                now = utcnow()
                detected = registry.detect(file, read_head(file))
                item = EvidenceItem(
                    id=item_id,
                    case=case_obj.name,
                    name=file.name,
                    source=str(file.resolve()),
                    sha256=stored.sha256,
                    size=stored.size,
                    type=detected[0].name if detected else _fallback_type(file),
                    media_type=_MEDIA.get(file.suffix.lower(), "application/octet-stream"),
                    stored=stored.relative,
                    imported_at=now,
                    notes=[note] if note else [],
                    derived_from=parent.id if parent else None,
                    job=jc.job_id,
                )
                mtime = datetime.fromtimestamp(file.stat().st_mtime, UTC)
                append_custody(
                    item.custody,
                    "acquired",
                    self.actor,
                    {
                        "source": item.source,
                        "sha256": stored.sha256,
                        "size": stored.size,
                        "source_mtime": mtime.isoformat(),
                    },
                    at=now,
                )
                append_custody(
                    item.custody,
                    "stored",
                    self.actor,
                    {"store": stored.relative, "read_only": True, "deduplicated": stored.deduplicated},
                    at=now,
                )
                if parent is not None:
                    append_custody(
                        item.custody, "derived", self.actor, {"from": parent.id, "sha256": parent.sha256}, at=now
                    )
                if parse:
                    self._parse(item, registry, mtime, synthetic, jc)
                self._save(item)
                result.items.append(item)
                records.append(
                    {
                        "kind": "object",
                        "type": "evidence",
                        "name": item.name,
                        "key": item.id,
                        "metadata": {
                            "case": item.case,
                            "sha256": item.sha256,
                            "size": item.size,
                            "type": item.type,
                            "media_type": item.media_type,
                            "stored": item.stored,
                            "source": item.source,
                            "imported_at": item.imported_at.isoformat(),
                            "derived_from": item.derived_from,
                            "job": item.job,
                        },
                    }
                )
                if case_obj.incident:
                    records.append(
                        {
                            "kind": "relationship",
                            "source": item.object_id,
                            "type": "RELATED_TO",
                            "target": case_obj.incident,
                            "confidence": 1.0,
                        }
                    )
                if parent is not None:
                    records.append(
                        {
                            "kind": "relationship",
                            "source": item.object_id,
                            "type": "DERIVED_FROM",
                            "target": parent.object_id,
                            "confidence": 1.0,
                        }
                    )
            if records:
                IngestionPipeline(self.ctx, job=jc).ingest_records(
                    records,
                    source_name=f"evidence-case:{case_obj.name}",
                    options=IngestOptions(synthetic=synthetic),
                    label="raf-evidence/1.0",
                )
            return {"items": [i.id for i in result.items], "skipped": len(result.skipped)}

        job = self.ctx.jobs.run_inline(
            "evidence",
            f"Evidence import into {case_obj.name}",
            {"case": case_obj.name, "path": str(path), "files": len(files)},
            work,
        )
        result.job = job.id
        if case_obj.incident:
            result.linked_events = self._link_incident(case_obj.incident, [i for i in result.items if i.job])
        self.ctx.audit.record(
            "evidence.import",
            affected=[i.object_id for i in result.items],
            details={
                "case": case_obj.name,
                "job": job.id,
                "items": len(result.items),
                "skipped": len(result.skipped),
                "linked_events": result.linked_events,
                "sha256": [i.sha256 for i in result.items][:20],
            },
        )
        self.ctx.refs.remember("case", case_obj.name)
        if result.items:
            self.ctx.refs.remember("object", result.items[-1].object_id)
        return result

    def _parse(self, item: EvidenceItem, registry: Any, mtime: datetime, synthetic: bool, jc: JobContext) -> None:
        stored_path = self.store.path_for(item.stored)
        options = IngestOptions(source_name=item.name, evidence_id=item.id, synthetic=synthetic, reference_time=mtime)
        try:
            report: IngestReport = IngestionPipeline(self.ctx, registry, jc).ingest_file(stored_path, options)
        except IngestionError as exc:
            item.status = "unparsed"
            append_custody(item.custody, "parsed", self.actor, {"result": "not parsed", "reason": exc.message})
            return
        except RafError as exc:
            item.status = "unparsed"
            append_custody(item.custody, "parsed", self.actor, {"result": "failed", "reason": exc.message})
            return
        item.status = "parsed"
        item.parser = report.parser
        item.events = report.events_created
        item.rejected = report.rejected
        append_custody(
            item.custody,
            "parsed",
            self.actor,
            {
                "parser": report.parser,
                "job": jc.job_id,
                "accepted": report.accepted,
                "rejected": report.rejected,
                "events": report.events_created,
                "note": "parsed from the stored read-only copy",
            },
        )

    def _link_incident(self, incident_id: str, items: list[EvidenceItem]) -> int:
        incident = self.ctx.store.incidents.get(incident_id)
        jobs = sorted({i.job for i in items if i.job and i.status == "parsed"})
        if incident is None or not jobs:
            return 0
        query = EventQuery(job_ids=jobs, start=incident.start, end=incident.end)
        event_ids = [
            e.id
            for e in self.ctx.store.events.iter(query, with_objects=False)
            if e.raw_reference and e.raw_reference.startswith("evidence:")
        ]
        linked = self.ctx.store.events.link_incident(incident_id, event_ids)
        window = (
            f"{incident.start.isoformat() if incident.start else '-'} → "
            f"{incident.end.isoformat() if incident.end else '-'}"
        )
        for item in items:
            if item.status != "parsed":
                continue
            append_custody(item.custody, "linked", self.actor, {"incident": incident_id, "window": window})
            self._save(item)
        return linked

    # ------------------------------------------------------------------ verification and custody
    def verify(self, *, case: str | None = None, item_ids: list[str] | None = None) -> VerifyResult:
        targets = [self.get_item(i) for i in item_ids] if item_ids else self.items(case)
        if not targets:
            raise NotFoundError("No evidence items to verify.", suggestions=["raf evidence list"])
        results = []
        for item in targets:
            check = self.store.check(item.stored, item.sha256)
            custody_ok, custody_reason = verify_custody(item.custody)
            ok = bool(check["ok"]) and custody_ok
            results.append(
                {
                    "id": item.id,
                    "name": item.name,
                    "ok": ok,
                    "expected": item.sha256,
                    "actual": check["actual"],
                    "reason": check["reason"] or custody_reason,
                    "custody_ok": custody_ok,
                }
            )
            append_custody(
                item.custody,
                "verified",
                self.actor,
                {
                    "ok": ok,
                    "sha256": check["actual"],
                    "custody_chain": "intact" if custody_ok else "broken",
                    "reason": check["reason"] or custody_reason,
                },
            )
            self._save(item)
        verified = all(r["ok"] for r in results)
        self.ctx.audit.record(
            "evidence.verify",
            affected=[f"evidence:{r['id']}" for r in results],
            result="success" if verified else "failure",
            details={"items": len(results), "failed": [r["id"] for r in results if not r["ok"]]},
        )
        return VerifyResult(verified=verified, items=results)

    def note(self, item_id: str, text: str) -> EvidenceItem:
        item = self.get_item(item_id)
        clean = text.strip()
        if not clean or len(clean) > 4000:
            raise InvalidInputError("A note needs 1-4000 characters.")
        item.notes.append(clean)
        append_custody(item.custody, "note", self.actor, {"note": clean})
        self._save(item)
        return item

    def export(self, item_id: str, destination: Path) -> tuple[EvidenceItem, Path]:
        item = self.get_item(item_id)
        check = self.store.check(item.stored, item.sha256)
        if not check["ok"]:
            raise InvalidInputError(f"{item.id} failed verification ({check['reason']}); not exporting.")
        target = self.store.export(item.stored, destination)
        append_custody(item.custody, "exported", self.actor, {"to": str(target.resolve()), "sha256": item.sha256})
        self._save(item)
        self.ctx.audit.record("evidence.export", affected=[item.object_id], details={"to": str(target.resolve())})
        return item, target
