"""Relational schema of an R$F workspace.

Design notes
------------
* Objects, relationships and events are the shared security model. Products
  never create private copies of these; they read and write through the store.
* Relationship endpoints are *universal IDs* (``<type>:<key>``) and may point to
  objects, events, findings or evidence; hence no foreign keys on them.
* ``event_objects`` indexes every object involved in an event (with its role and
  timestamp) so per-object timelines are a single indexed range scan.
* Snapshots use content-addressed ``blobs`` shared across snapshots (structural
  sharing): unchanged items cost one ``snapshot_items`` row, not a copy.
* Custody and audit logs are hash chained (``prev_hash`` -> ``entry_hash``).
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
)

from raf.core.storage.types import JSONType, UTCDateTime

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)

ID = 512  # universal id length

objects = Table(
    "objects",
    metadata,
    Column("id", String(ID), primary_key=True),
    Column("type", String(64), nullable=False),
    Column("name", String(1024), nullable=False),
    Column("name_lc", String(1024), nullable=False),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("updated_at", UTCDateTime(), nullable=False),
    Column("first_seen", UTCDateTime()),
    Column("last_seen", UTCDateTime()),
    Column("valid_from", UTCDateTime()),
    Column("valid_to", UTCDateTime()),
    Column("source", String(512), nullable=False),
    Column("confidence", Float, nullable=False),
    Column("tags", JSONType, nullable=False),
    Column("metadata", JSONType, nullable=False, key="meta"),
    Column("observations", Integer, nullable=False, default=1),
    Column("synthetic", Boolean, nullable=False, default=False),
    Index("ix_objects_type_name_lc", "type", "name_lc"),
    Index("ix_objects_name_lc", "name_lc"),
)

object_aliases = Table(
    "object_aliases",
    metadata,
    Column("alias_lc", String(1024), primary_key=True),
    Column("object_id", String(ID), primary_key=True),
    Index("ix_object_aliases_object_id", "object_id"),
)

relationships = Table(
    "relationships",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("type", String(64), nullable=False),
    Column("source_id", String(ID), nullable=False),
    Column("target_id", String(ID), nullable=False),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("updated_at", UTCDateTime(), nullable=False),
    Column("first_seen", UTCDateTime()),
    Column("last_seen", UTCDateTime()),
    Column("valid_from", UTCDateTime()),
    Column("valid_to", UTCDateTime()),
    Column("source", String(512), nullable=False),
    Column("confidence", Float, nullable=False),
    Column("metadata", JSONType, nullable=False, key="meta"),
    Column("observations", Integer, nullable=False, default=1),
    Column("synthetic", Boolean, nullable=False, default=False),
    Index("ix_relationships_source_type", "source_id", "type"),
    Index("ix_relationships_target_type", "target_id", "type"),
    Index("ix_relationships_type", "type"),
)

events = Table(
    "events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("ts", UTCDateTime(), nullable=False),
    Column("event_type", String(128), nullable=False),
    Column("category", String(32), nullable=False),
    Column("action", String(128), nullable=False),
    Column("outcome", String(32)),
    Column("actor_id", String(ID)),
    Column("target_id", String(ID)),
    Column("severity", String(16), nullable=False),
    Column("confidence", Float, nullable=False),
    Column("source", String(512), nullable=False),
    Column("parser", String(128), nullable=False),
    Column("record", String(128)),
    Column("raw_ref", String(512)),
    Column("raw", Text),
    Column("attributes", JSONType, nullable=False),
    Column("rel_ids", JSONType, nullable=False),
    Column("message", Text),
    Column("synthetic", Boolean, nullable=False, default=False),
    Column("job_id", String(64)),
    Column("ingested_at", UTCDateTime(), nullable=False),
    Index("ix_events_ts_id", "ts", "id"),
    Index("ix_events_type_ts", "event_type", "ts"),
    Index("ix_events_category_ts", "category", "ts"),
    Index("ix_events_actor_ts", "actor_id", "ts"),
    Index("ix_events_target_ts", "target_id", "ts"),
    Index("ix_events_job_id", "job_id"),
)

event_objects = Table(
    "event_objects",
    metadata,
    Column("event_id", String(64), primary_key=True),
    Column("object_id", String(ID), primary_key=True),
    Column("role", String(32), primary_key=True),
    Column("ts", UTCDateTime(), nullable=False),
    Index("ix_event_objects_object_ts", "object_id", "ts"),
)

incident_events = Table(
    "incident_events",
    metadata,
    Column("incident_id", String(ID), primary_key=True),
    Column("event_id", String(64), primary_key=True),
    Column("ts", UTCDateTime(), nullable=False),
    Index("ix_incident_events_incident_ts", "incident_id", "ts"),
    Index("ix_incident_events_event_id", "event_id"),
)

provenance = Table(
    "provenance",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("subject_id", String(ID), nullable=False),
    Column("subject_kind", String(16), nullable=False),
    Column("event_id", String(64)),
    Column("source", String(512), nullable=False),
    Column("source_sha256", String(64)),
    Column("record", String(128)),
    Column("parser", String(128)),
    Column("observed_at", UTCDateTime()),
    Column("job_id", String(64)),
    Column("evidence_id", String(128)),
    Column("note", Text),
    Column("recorded_at", UTCDateTime(), nullable=False),
    Index("ix_provenance_subject", "subject_id"),
    Index("ix_provenance_job", "job_id"),
)

findings = Table(
    "findings",
    metadata,
    Column("id", String(256), primary_key=True),
    Column("product", String(64), nullable=False),
    Column("rule_id", String(128), nullable=False),
    Column("title", String(512), nullable=False),
    Column("description", Text, nullable=False),
    Column("severity", String(16), nullable=False),
    Column("severity_rank", Integer, nullable=False),
    Column("confidence", Float, nullable=False),
    Column("status", String(32), nullable=False),
    Column("recommendation", Text, nullable=False),
    Column("affected", JSONType, nullable=False),
    Column("evidence", JSONType, nullable=False),
    Column("explanation", JSONType, nullable=False),
    Column("tags", JSONType, nullable=False),
    Column("metadata", JSONType, nullable=False, key="meta"),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("updated_at", UTCDateTime(), nullable=False),
    Index("ix_findings_product", "product"),
    Index("ix_findings_severity", "severity_rank"),
    Index("ix_findings_status", "status"),
)

finding_objects = Table(
    "finding_objects",
    metadata,
    Column("finding_id", String(256), primary_key=True),
    Column("object_id", String(ID), primary_key=True),
    Index("ix_finding_objects_object_id", "object_id"),
)

blobs = Table(
    "blobs",
    metadata,
    Column("hash", String(64), primary_key=True),
    Column("body", Text, nullable=False),
)

snapshots = Table(
    "snapshots",
    metadata,
    Column("id", String(160), primary_key=True),
    Column("name", String(128), nullable=False, unique=True),
    Column("source", String(256), nullable=False),
    Column("description", Text, nullable=False, default=""),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("stats", JSONType, nullable=False),
    Column("content_hash", String(64), nullable=False),
)

snapshot_items = Table(
    "snapshot_items",
    metadata,
    Column("snapshot_id", String(160), primary_key=True),
    Column("kind", String(16), primary_key=True),
    Column("item_id", String(ID), primary_key=True),
    Column("content_hash", String(64), nullable=False),
)

jobs = Table(
    "jobs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("kind", String(64), nullable=False),
    Column("title", String(512), nullable=False),
    Column("status", String(16), nullable=False),
    Column("progress", Float, nullable=False, default=0.0),
    Column("message", Text),
    Column("params", JSONType, nullable=False),
    Column("result", JSONType),
    Column("error", JSONType),
    Column("actor", String(256), nullable=False),
    Column("cancel_requested", Boolean, nullable=False, default=False),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("started_at", UTCDateTime()),
    Column("finished_at", UTCDateTime()),
    Index("ix_jobs_status", "status"),
    Index("ix_jobs_created_at", "created_at"),
)

counters = Table(
    "counters",
    metadata,
    Column("name", String(64), primary_key=True),
    Column("value", Integer, nullable=False),
)

analyses = Table(
    "analyses",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("input", Text, nullable=False),
    Column("input_sha256", String(64)),
    Column("detected_type", String(64), nullable=False),
    Column("status", String(16), nullable=False),
    Column("steps", JSONType, nullable=False),
    Column("stats", JSONType, nullable=False),
    Column("suggestions", JSONType, nullable=False),
    Column("job_id", String(64)),
    Column("created_at", UTCDateTime(), nullable=False),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", UTCDateTime(), nullable=False),
    Column("actor", String(256), nullable=False),
    Column("interface", String(16), nullable=False),
    Column("command", Text, nullable=False),
    Column("workspace", String(128), nullable=False),
    Column("operation", String(128), nullable=False),
    Column("affected", JSONType, nullable=False),
    Column("result", String(32), nullable=False),
    Column("details", JSONType, nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("entry_hash", String(64), nullable=False),
    Index("ix_audit_log_ts", "ts"),
    Index("ix_audit_log_operation", "operation"),
)

cases = Table(
    "cases",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("name", String(128), nullable=False, unique=True),
    Column("title", String(512), nullable=False),
    Column("status", String(32), nullable=False),
    Column("description", Text, nullable=False),
    Column("incident_id", String(ID)),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("updated_at", UTCDateTime(), nullable=False),
)

evidence_items = Table(
    "evidence_items",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("case_id", String(128), nullable=False),
    Column("original_name", String(1024), nullable=False),
    Column("source_path", Text, nullable=False),
    Column("relative_path", Text, nullable=False),
    Column("stored_path", Text, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("size", Integer, nullable=False),
    Column("media_type", String(128), nullable=False),
    Column("kind", String(16), nullable=False),  # original | derived
    Column("derived_from", String(128)),
    Column("notes", Text, nullable=False, default=""),
    Column("metadata", JSONType, nullable=False, key="meta"),
    Column("imported_at", UTCDateTime(), nullable=False),
    Column("ingest_job_id", String(64)),
    Index("ix_evidence_items_case", "case_id"),
    Index("ix_evidence_items_sha256", "sha256"),
)

custody_events = Table(
    "custody_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("evidence_id", String(128), nullable=False),
    Column("case_id", String(128), nullable=False),
    Column("ts", UTCDateTime(), nullable=False),
    Column("action", String(64), nullable=False),
    Column("actor", String(256), nullable=False),
    Column("details", JSONType, nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("entry_hash", String(64), nullable=False),
    Index("ix_custody_events_evidence", "evidence_id"),
    Index("ix_custody_events_case", "case_id"),
)

kv = Table(
    "kv",
    metadata,
    Column("namespace", String(64), primary_key=True),
    Column("key", String(256), primary_key=True),
    Column("value", JSONType, nullable=False),
    Column("updated_at", UTCDateTime(), nullable=False),
)
