"""The R$F bundle format (``.raf``).

A bundle is a ZIP archive::

    manifest.json          format id + version, counts, SHA-256 of every member
    objects.jsonl          full-fidelity objects
    relationships.jsonl
    events.jsonl
    findings.json
    provenance.jsonl
    cases.jsonl, evidence.jsonl, custody.jsonl   (DFIR metadata, optional)
    evidence/<sha256>      original evidence bytes (optional)
    snapshots.jsonl, snapshot_items.jsonl, blobs.jsonl, audit.jsonl (workspace backups)

Imports are defensive: every member path is validated (no absolute paths,
traversal, drive letters, symlinks or duplicates), total and per-member sizes
and compression ratios are limited, and every member hash is verified against
the manifest before anything is written to the workspace.
"""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import Field, ValidationError
from sqlalchemy import select

from raf.core.context.app import RafContext
from raf.core.errors import IntegrityError, InvalidInputError, ResourceLimitExceeded, SecurityViolation
from raf.core.objects.models import (
    Event,
    EventDraft,
    EventObjectRef,
    Finding,
    ObjectDraft,
    ProvenanceDraft,
    RafModel,
    Relationship,
    RelationshipDraft,
    SecurityObject,
)
from raf.core.objects.types import Severity
from raf.core.security.files import safe_member_path
from raf.core.storage import schema as s
from raf.core.storage.database import upsert
from raf.core.timeutil import parse_timestamp, utcnow
from raf.version import BUNDLE_FORMAT, BUNDLE_FORMAT_VERSION, RAF_VERSION

SUPPORTED_VERSIONS = {"1.0"}
_JSONL_MEMBERS = (
    "objects.jsonl",
    "relationships.jsonl",
    "events.jsonl",
    "provenance.jsonl",
    "cases.jsonl",
    "evidence.jsonl",
    "custody.jsonl",
    "snapshots.jsonl",
    "snapshot_items.jsonl",
    "blobs.jsonl",
    "audit.jsonl",
)


class BundleManifest(RafModel):
    format: str = BUNDLE_FORMAT
    format_version: str = BUNDLE_FORMAT_VERSION
    raf_version: str = RAF_VERSION
    created_at: datetime
    workspace: str
    description: str = ""
    scope: dict[str, Any] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)
    files: dict[str, dict[str, Any]] = Field(default_factory=dict)


class _Writer:
    def __init__(self, archive: zipfile.ZipFile) -> None:
        self.archive = archive
        self.files: dict[str, dict[str, Any]] = {}

    def write_bytes(self, name: str, data: bytes) -> None:
        safe_member_path(name)
        self.archive.writestr(name, data)
        self.files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    def write_jsonl(self, name: str, rows: Iterable[dict[str, Any]]) -> int:
        buffer = io.StringIO()
        count = 0
        for row in rows:
            buffer.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n")
            count += 1
        if count:
            self.write_bytes(name, buffer.getvalue().encode("utf-8"))
        return count


def export_bundle(
    ctx: RafContext,
    path: Path,
    *,
    objects: Iterable[SecurityObject] = (),
    relationships: Iterable[Relationship] = (),
    events: Iterable[Event] = (),
    findings: Iterable[Finding] = (),
    provenance: Iterable[dict[str, Any]] = (),
    extra_tables: dict[str, Iterable[dict[str, Any]]] | None = None,
    evidence_files: dict[str, Path] | None = None,
    scope: dict[str, Any] | None = None,
    description: str = "",
) -> BundleManifest:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    counts: dict[str, int] = {}
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        writer = _Writer(archive)
        counts["objects"] = writer.write_jsonl("objects.jsonl", (o.to_json_dict() for o in objects))
        counts["relationships"] = writer.write_jsonl("relationships.jsonl", (r.to_json_dict() for r in relationships))
        counts["events"] = writer.write_jsonl("events.jsonl", (e.to_json_dict() for e in events))
        finding_rows = [f.to_json_dict() for f in findings]
        if finding_rows:
            writer.write_bytes("findings.json", json.dumps(finding_rows, ensure_ascii=False, default=str).encode())
        counts["findings"] = len(finding_rows)
        counts["provenance"] = writer.write_jsonl("provenance.jsonl", provenance)
        for name, rows in (extra_tables or {}).items():
            counts[name] = writer.write_jsonl(f"{name}.jsonl", rows)
        for digest, source in sorted((evidence_files or {}).items()):
            writer.write_bytes(f"evidence/{digest}", source.read_bytes())
        counts["evidence_files"] = len(evidence_files or {})
        manifest = BundleManifest(
            created_at=utcnow(),
            workspace=ctx.workspace.name,
            description=description,
            scope=scope or {},
            counts=counts,
            files=writer.files,
        )
        archive.writestr("manifest.json", json.dumps(manifest.to_json_dict(), indent=2, ensure_ascii=False))
    tmp.replace(path)
    return manifest


# --------------------------------------------------------------------------- reading


class BundleReader:
    """Validated, read-only access to a bundle's members."""

    def __init__(self, path: Path, *, max_total_bytes: int, max_members: int, max_ratio: int) -> None:
        self.path = path
        try:
            self.archive = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise InvalidInputError(f"{path.name} is not a valid R$F bundle (not a ZIP archive).") from exc
        infos = self.archive.infolist()
        if len(infos) > max_members:
            raise ResourceLimitExceeded(f"Bundle has {len(infos)} members (limit {max_members}).")
        seen: set[str] = set()
        total = 0
        for info in infos:
            safe_member_path(info.filename.rstrip("/") or info.filename)
            if info.filename in seen:
                raise SecurityViolation(f"Duplicate archive member {info.filename!r}.")
            seen.add(info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise SecurityViolation(f"Symlink member rejected: {info.filename!r}")
            if info.flag_bits & 0x1:
                raise SecurityViolation("Encrypted archive members are not supported.")
            total += info.file_size
            if total > max_total_bytes:
                raise ResourceLimitExceeded("Bundle expands beyond the configured size limit (possible archive bomb).")
            if info.compress_size and info.file_size / max(info.compress_size, 1) > max_ratio and info.file_size > 1e6:
                raise ResourceLimitExceeded(f"Member {info.filename!r} has a suspicious compression ratio.")
        if "manifest.json" not in seen:
            raise InvalidInputError(f"{path.name} has no manifest.json; it is not an R$F bundle.")
        try:
            raw = json.loads(self._read_raw("manifest.json"))
            self.manifest = BundleManifest.model_validate(raw)
        except (ValueError, ValidationError) as exc:
            raise InvalidInputError("Bundle manifest is invalid.", reason=str(exc)[:300]) from exc
        if self.manifest.format != BUNDLE_FORMAT:
            raise InvalidInputError(f"Unsupported bundle format '{self.manifest.format}'.")
        if self.manifest.format_version not in SUPPORTED_VERSIONS:
            raise InvalidInputError(
                f"Unsupported bundle version {self.manifest.format_version}.",
                hint=f"This R$F reads versions {', '.join(sorted(SUPPORTED_VERSIONS))}.",
            )
        undeclared = seen - set(self.manifest.files) - {"manifest.json"}
        if undeclared:
            raise IntegrityError(
                "Bundle contains members not listed in its manifest.", details={"members": sorted(undeclared)[:20]}
            )

    def _read_raw(self, name: str) -> bytes:
        with self.archive.open(name) as handle:
            return handle.read()

    def verify(self) -> list[str]:
        problems = []
        for name, meta in self.manifest.files.items():
            try:
                data = self._read_raw(name)
            except KeyError:
                problems.append(f"{name}: missing")
                continue
            if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
                problems.append(f"{name}: SHA-256 mismatch")
            if len(data) != meta.get("size"):
                problems.append(f"{name}: size mismatch")
        return problems

    def read(self, name: str) -> bytes:
        meta = self.manifest.files.get(name)
        if meta is None:
            return b""
        data = self._read_raw(name)
        if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
            raise IntegrityError(f"Bundle member {name} failed its integrity check.")
        return data

    def rows(self, name: str) -> Iterator[dict[str, Any]]:
        data = self.read(name)
        for line in data.decode("utf-8").splitlines():
            if line.strip():
                yield json.loads(line)

    def close(self) -> None:
        self.archive.close()


def open_bundle(ctx: RafContext, path: Path) -> BundleReader:
    settings = ctx.settings
    return BundleReader(
        path,
        max_total_bytes=int(settings.get("ingest.max_archive_mb")) * 1024 * 1024,
        max_members=int(settings.get("ingest.max_archive_members")),
        max_ratio=int(settings.get("ingest.max_compression_ratio")),
    )


def _time(value: Any) -> datetime | None:
    return parse_timestamp(value) if value else None


def import_bundle(ctx: RafContext, path: Path, *, restore_tables: bool = False) -> dict[str, Any]:
    """Merge a bundle into the workspace (``restore_tables`` also restores snapshots/audit/DFIR tables)."""
    reader = open_bundle(ctx, path)
    try:
        problems = reader.verify()
        if problems:
            raise IntegrityError(
                "Bundle integrity check failed; nothing was imported.", details={"problems": problems[:20]}
            )
        store = ctx.store
        counts: dict[str, int] = {}
        objects = [
            ObjectDraft(
                type=r["type"],
                name=r["name"],
                id=r["id"],
                first_seen=_time(r.get("first_seen")),
                last_seen=_time(r.get("last_seen")),
                valid_from=_time(r.get("valid_from")),
                valid_to=_time(r.get("valid_to")),
                source=r.get("source", "bundle"),
                confidence=float(r.get("confidence", 0.8)),
                tags=set(r.get("tags") or []),
                metadata=dict(r.get("metadata") or {}),
                observations=int(r.get("observations", 1)),
                synthetic=bool(r.get("synthetic", False)),
            )
            for r in reader.rows("objects.jsonl")
        ]
        relationships = [
            RelationshipDraft(
                type=r["relationship_type"],
                source_id=r["source_object"],
                target_id=r["target_object"],
                id=r["id"],
                first_seen=_time(r.get("first_seen")),
                last_seen=_time(r.get("last_seen")),
                valid_from=_time(r.get("valid_from")),
                valid_to=_time(r.get("valid_to")),
                source=r.get("source", "bundle"),
                confidence=float(r.get("confidence", 0.8)),
                metadata=dict(r.get("metadata") or {}),
                observations=int(r.get("observations", 1)),
                synthetic=bool(r.get("synthetic", False)),
            )
            for r in reader.rows("relationships.jsonl")
        ]
        events = []
        for r in reader.rows("events.jsonl"):
            events.append(
                EventDraft(
                    id=r["id"],
                    timestamp=parse_timestamp(r["timestamp"]),
                    event_type=r["event_type"],
                    category=r["category"],
                    action=r["action"],
                    source=r["source"],
                    parser=r["parser"],
                    outcome=r.get("outcome"),
                    actor=r.get("actor"),
                    target=r.get("target"),
                    objects=[EventObjectRef(o["object_id"], o["role"]) for o in r.get("objects") or []],
                    record=r.get("record"),
                    raw_reference=r.get("raw_reference"),
                    raw=r.get("raw"),
                    severity=Severity.parse(r.get("severity", "INFO")),
                    confidence=float(r.get("confidence", 0.8)),
                    attributes=dict(r.get("attributes") or {}),
                    relationships=list(r.get("relationships") or []),
                    message=r.get("message"),
                    synthetic=bool(r.get("synthetic", False)),
                    incidents=list(r.get("incidents") or []),
                )
            )
        findings_data = reader.read("findings.json")
        findings = [Finding.model_validate(f) for f in json.loads(findings_data)] if findings_data else []
        provenance = [
            ProvenanceDraft(
                subject_id=r["subject_id"],
                subject_kind=r["subject_kind"],
                source=r["source"],
                parser=r.get("parser"),
                record=r.get("record"),
                event_id=r.get("event_id"),
                observed_at=_time(r.get("observed_at")),
                evidence_id=r.get("evidence_id"),
                source_sha256=r.get("source_sha256"),
                note=r.get("note"),
            )
            for r in reader.rows("provenance.jsonl")
        ]
        with store.transaction() as conn:
            counts["objects"] = store.objects.upsert_drafts(objects, conn=conn).created
            counts["relationships"] = store.relationships.upsert_drafts(relationships, conn=conn).created
            counts["events"] = store.events.insert_drafts(events, job_id=None, conn=conn).created
            counts["findings"] = store.findings.upsert(findings, conn=conn).created
            counts["provenance"] = store.provenance.add_many(provenance, conn=conn)
            for name, table, keys in (("cases", s.cases, ["id"]), ("evidence", s.evidence_items, ["id"])):
                rows = [_table_row(table, r) for r in reader.rows(f"{name}.jsonl")]
                upsert(conn, table, rows, keys, update=False)
                counts[name] = len(rows)
            custody = [_table_row(s.custody_events, r, drop=("id",)) for r in reader.rows("custody.jsonl")]
            if custody:
                existing = {r[0] for r in conn.execute(select(s.custody_events.c.entry_hash))}
                fresh = [r for r in custody if r["entry_hash"] not in existing]
                if fresh:
                    conn.execute(s.custody_events.insert(), fresh)
                counts["custody"] = len(fresh)
            if restore_tables:
                for name, table, keys in (
                    ("snapshots", s.snapshots, ["id"]),
                    ("snapshot_items", s.snapshot_items, ["snapshot_id", "kind", "item_id"]),
                    ("blobs", s.blobs, ["hash"]),
                ):
                    rows = [_table_row(table, r) for r in reader.rows(f"{name}.jsonl")]
                    upsert(conn, table, rows, keys, update=False)
                    counts[name] = len(rows)
                audit_rows = [_table_row(s.audit_log, r, drop=("id",)) for r in reader.rows("audit.jsonl")]
                if audit_rows and conn.execute(select(s.audit_log.c.id).limit(1)).first() is None:
                    conn.execute(s.audit_log.insert(), audit_rows)
                    counts["audit"] = len(audit_rows)
        evidence_restored = 0
        for name in reader.manifest.files:
            if name.startswith("evidence/"):
                digest = name.split("/", 1)[1]
                target = ctx.workspace.evidence_dir / digest[:2] / digest
                if not target.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    data = reader.read(name)
                    if hashlib.sha256(data).hexdigest() != digest:
                        raise IntegrityError(f"Evidence member {name} does not match its content hash.")
                    target.write_bytes(data)
                    target.chmod(0o444)
                    evidence_restored += 1
        counts["evidence_files"] = evidence_restored
        return {"manifest": reader.manifest.to_json_dict(), "imported": counts}
    finally:
        reader.close()


def _table_row(table: Any, row: dict[str, Any], drop: tuple[str, ...] = ()) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for column in table.columns:
        if column.key in drop:
            continue
        key = "metadata" if column.key == "meta" else column.key
        value = row.get(key, row.get(column.key))
        if value is not None and column.type.__class__.__name__ == "UTCDateTime":
            value = parse_timestamp(value)
        result[column.key] = value
    return result


def table_rows(ctx: RafContext, table: Any) -> Iterator[dict[str, Any]]:
    """Dump a core table as JSON-able rows (used for workspace backups)."""
    with ctx.store.engine.connect() as conn:
        for row in conn.execute(select(table)).yield_per(2000):
            data = {}
            for column in table.columns:
                key = "metadata" if column.key == "meta" else column.key
                value = row._mapping[column.key]
                data[key] = value.isoformat() if isinstance(value, datetime) else value
            yield data
