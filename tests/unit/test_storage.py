from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from raf.core.context.app import RafContext
from raf.core.errors import AmbiguousReferenceError, NotFoundError
from raf.core.ids import event_id
from raf.core.objects.models import EventDraft, Finding, ObjectDraft, RelationshipDraft
from raf.core.objects.types import FindingStatus, Severity
from raf.core.storage.database import SCHEMA_HEAD, alembic_head
from raf.core.storage.repos.events import EventQuery

T0 = datetime(2026, 10, 7, 9, 0, tzinfo=UTC)


def _event(n: int, actor: str = "user:alice", target: str = "host:ws-01", etype: str = "auth.login") -> EventDraft:
    ev = EventDraft(
        id=event_id("test", n),
        timestamp=T0 + timedelta(minutes=n),
        event_type=etype,
        category=etype.split(".")[0],
        action="login",
        source="test",
        parser="test/1",
        actor=actor,
        target=target,
        record=str(n),
    )
    ev.involve(actor, "actor")
    ev.involve(target, "target")
    return ev


def test_schema_head_matches_migrations() -> None:
    assert alembic_head() == SCHEMA_HEAD


def test_migrated_database_matches_the_schema(tmp_path: Path) -> None:
    """The tables, columns and indexes the migrations create are exactly what schema.py declares."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from raf.core.storage.database import create_db_engine, migrate, sqlite_url
    from raf.core.storage.schema import metadata

    engine = create_db_engine(sqlite_url(tmp_path / "check.db"))
    migrate(engine)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), metadata)
    assert diff == []


def test_object_upsert_is_idempotent_and_merges(ctx: RafContext) -> None:
    store = ctx.store
    stats = store.objects.upsert_drafts([ObjectDraft.make("host", "WS-01"), ObjectDraft.make("host", "ws-01")])
    assert (stats.created, stats.updated) == (1, 0)
    stats = store.objects.upsert_drafts([ObjectDraft.make("host", "WS-01", metadata={"os": "linux"})])
    assert (stats.created, stats.updated) == (0, 1)
    obj = store.objects.require("host:ws-01")
    assert obj.metadata["os"] == "linux"
    assert obj.observations == 3


def test_relationship_temporal_queries(ctx: RafContext) -> None:
    store = ctx.store
    rel = RelationshipDraft.make("user:alice", "HAS_ROLE", "role:admin", first_seen=T0)
    store.relationships.upsert_drafts([rel])
    assert len(store.relationships.edges(["user:alice"])) == 1
    store.relationships.end([rel.id], T0 + timedelta(hours=1))
    assert store.relationships.edges(["user:alice"]) == []
    assert len(store.relationships.edges(["user:alice"], at=T0 + timedelta(minutes=30))) == 1
    assert store.relationships.edges(["user:alice"], at=T0 - timedelta(minutes=1)) == []


def test_events_insert_dedup_query_and_pagination(ctx: RafContext) -> None:
    store = ctx.store
    drafts = [_event(i) for i in range(25)]
    drafts[3].incidents.append("incident:inc-001")
    stats = store.events.insert_drafts(drafts)
    assert stats.created == 25
    again = store.events.insert_drafts([_event(i) for i in range(5)])
    assert again.created == 0 and again.duplicates == 5
    page = store.events.query(EventQuery(object_ids=["host:ws-01"]), limit=10)
    assert len(page.items) == 10 and page.next_cursor
    page2 = store.events.query(EventQuery(object_ids=["host:ws-01"]), limit=10, cursor=page.next_cursor)
    assert page2.items[0].timestamp > page.items[-1].timestamp
    assert store.events.count(EventQuery(event_types=["auth.*"])) == 25
    assert store.events.count(EventQuery(event_types=["auth"])) == 25
    assert store.events.count(EventQuery(incident_id="incident:inc-001")) == 1
    hist = store.events.histogram(EventQuery(), buckets=5)
    assert sum(b["count"] for b in hist) == 25
    groups = store.events.group_counts(EventQuery(), "actor")
    assert groups == [("user:alice", 25)]
    ev = store.events.get(drafts[0].id)
    assert ev is not None and {o.role for o in ev.objects} == {"actor", "target"}


def test_findings_preserve_analyst_decisions(ctx: RafContext) -> None:
    store = ctx.store
    now = datetime.now(UTC)
    f = Finding(
        id="finding:test:rule:1",
        title="t",
        description="d",
        severity=Severity.HIGH,
        confidence=0.3,
        product="test",
        rule_id="rule",
        affected_objects=["host:ws-01"],
        created_at=now,
        updated_at=now,
    )
    store.findings.upsert([f])
    store.findings.set_status(f.id, FindingStatus.FALSE_POSITIVE, "known scanner")
    store.findings.upsert([f])  # analyzer re-run
    stored = store.findings.require(f.id)
    assert stored.status is FindingStatus.FALSE_POSITIVE
    assert stored.severity is Severity.HIGH and stored.confidence == 0.3  # independent axes
    assert store.findings.list(object_id="host:ws-01")[0].id == f.id
    assert store.findings.resolve_absent("test", ["rule"], []) == 0  # sticky status untouched


def test_resolver(ctx: RafContext) -> None:
    ctx.store.objects.upsert_drafts(
        [
            ObjectDraft.make("user", "alice"),
            ObjectDraft.make("identity", "alice"),
            ObjectDraft.make("network", "PROD", metadata={"aliases": ["production"]}),
            ObjectDraft.make("host", "dup", key="dup-1", metadata={}),
            ObjectDraft.make("host", "dup", key="dup-2"),
        ]
    )
    resolved = ctx.resolve("alice")
    assert resolved.id == "user:alice" and resolved.notes  # documented priority + note
    assert ctx.resolve("identity:alice").id == "identity:alice"
    assert ctx.resolve("production").id == "network:prod"
    assert ctx.resolve("alice", types=["identity"]).id == "identity:alice"
    with pytest.raises(AmbiguousReferenceError):
        ctx.resolve("dup")
    with pytest.raises(NotFoundError):
        ctx.resolve("nobody")


def test_context_refs(ctx: RafContext) -> None:
    ctx.store.objects.upsert_drafts([ObjectDraft.make("user", "bob")])
    ctx.refs.remember("object", "user:bob")
    assert ctx.resolve("@last").id == "user:bob"
    ctx.refs.remember("lab", "demo-lab")  # not a graph object: @last for objects skips it
    assert ctx.resolve("@last").id == "user:bob"
    assert ctx.refs.resolve("@last") == ("lab", "demo-lab")
    assert ctx.refs.resolve("@workspace") == ("workspace", "default")
    with pytest.raises(NotFoundError):
        ctx.refs.resolve("@snapshot")


def test_audit_chain_detects_tampering(ctx: RafContext) -> None:
    from sqlalchemy import update

    from raf.core.storage import schema as s

    for i in range(3):
        ctx.audit.record("op", affected=[str(i)])
    assert ctx.audit.verify()["valid"]
    with ctx.store.engine.begin() as conn:
        conn.execute(update(s.audit_log).where(s.audit_log.c.id == 2).values(operation="forged"))
    result = ctx.audit.verify()
    assert not result["valid"] and result["broken_at"] == 2


def test_jobs_lifecycle(ctx: RafContext) -> None:
    from raf.core.errors import InvalidInputError
    from raf.core.jobs.manager import JobStatus

    ok = ctx.jobs.run_inline("test", "ok", {"x": 1}, lambda jc: {"value": 42})
    assert ok.status is JobStatus.COMPLETED and ok.result == {"value": 42}

    def failing(_jc: object) -> dict[str, object]:
        raise InvalidInputError("bad input", reason="because")

    failed = ctx.jobs.run_inline("test", "fail", None, failing)
    assert failed.status is JobStatus.FAILED and failed.error and failed.error["reason"] == "because"

    def cancelled(jc: object) -> dict[str, object]:
        from raf.core.jobs.manager import JobContext

        assert isinstance(jc, JobContext)
        jc.request_cancel()
        jc.check_cancelled()
        return {}

    assert ctx.jobs.run_inline("test", "cancel", None, cancelled).status is JobStatus.CANCELLED
    assert [j.id for j in ctx.jobs.list(limit=3)] == ["job-3", "job-2", "job-1"]
