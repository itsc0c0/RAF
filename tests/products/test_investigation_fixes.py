"""Investigation fixes: Diff, relationship builder, Trace, Replay, Timeline, Graph and finding history."""

from __future__ import annotations

import csv
import io
import json
import re
import tempfile
import warnings
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError
from raf.core.graph.algorithms import GraphEdge, GraphNode, Subgraph
from raf.core.graph.export import export_subgraph
from raf.core.ingestion.pipeline import IngestionPipeline
from raf.core.objects.models import Finding, ObjectDraft
from raf.core.objects.types import FindingStatus, Severity
from raf.core.query.scope import resolve_scope
from raf.core.snapshots.service import StateView
from raf.core.storage.repos.events import EventQuery
from raf.core.storage.repos.findings import RESOLVED_ABSENT_NOTE
from raf.products.diff.service import CATEGORIES, DiffService
from raf.products.replay.service import ReplayService, _State, apply_step
from raf.products.timeline.service import CSV_COLUMNS, EXPORT_FORMATS, TimelineService
from raf.products.trace.service import TraceLink, TraceService, _corroborate

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

_CANONICAL_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?Z$")
T0 = datetime(2026, 10, 6, 8, 0, tzinfo=UTC)


@pytest.fixture
def api(raven_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)})) as client:
        yield client


def _ingest(ctx: RafContext, path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    report = IngestionPipeline(ctx).ingest_path(path)
    assert report.rejected == 0


def _ts(minutes: float) -> str:
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- 26: Diff


def _objects(ctx: RafContext, *drafts: ObjectDraft) -> list[Any]:
    ctx.store.objects.upsert_drafts(list(drafts))
    return list(ctx.store.objects.get_many([d.id for d in drafts]).values())


def _finding(**changes: Any) -> Finding:
    data: dict[str, Any] = {
        "id": "finding:test:rule:1",
        "title": "Exposed service",
        "description": "d",
        "severity": Severity.MEDIUM,
        "confidence": 0.6,
        "product": "test",
        "rule_id": "rule",
        "affected_objects": ["host:a"],
        "created_at": T0,
        "updated_at": T0,
    }
    return Finding(**(data | changes))


class TestDiff:
    def test_package_version_change_is_reported_once(self, ctx: RafContext) -> None:
        pkg = [
            ObjectDraft.make("package", name)
            for name in (
                "pypi/requests@2.9.0",
                "pypi/requests@2.31.0",
                "pypi/urllib3@1.26.0",
                "pypi/requests@2.32.3",
                "pypi/urllib3@2.2.0",
                "pypi/flask@3.0.0",
            )
        ]
        objects = {o.id: o for o in _objects(ctx, *pkg)}
        a = StateView.from_items("a", [objects[d.id] for d in pkg[:3]], [])
        b = StateView.from_items("b", [objects[d.id] for d in pkg[3:]], [])
        result = DiffService(ctx).compare(a, b)
        packages = [c for c in result.changes if c.category == "packages"]
        changed = {c.label: c for c in packages if c.change == "changed"}
        # the newest removed version pairs with the newest added one (2.31.0 > 2.9.0: compared number by number)
        assert changed["requests (pypi)"].details == {
            "from": "2.31.0",
            "to": "2.32.3",
            "previous_id": "package:pypi/requests@2.31.0",
        }
        assert changed["urllib3 (pypi)"].reason == "package version changed 1.26.0 -> 2.2.0"
        assert sorted((c.change, c.item_id) for c in packages if c.change != "changed") == [
            ("added", "package:pypi/flask@3.0.0"),
            ("removed", "package:pypi/requests@2.9.0"),
        ]
        assert len(packages) == 4 and result.summary["packages"] == {"added": 1, "removed": 1, "changed": 2}

    def test_finding_changes_other_than_status(self, ctx: RafContext) -> None:
        def diff(before: Finding, after: Finding) -> Any:
            changes = (
                DiffService(ctx)
                .compare(StateView.from_items("a", [], [], [before]), StateView.from_items("b", [], [], [after]))
                .changes
            )
            assert len(changes) == 1 and changes[0].category == "findings" and changes[0].change == "changed"
            return changes[0]

        base = _finding()
        raised = diff(base, _finding(severity=Severity.CRITICAL))
        assert (raised.importance, raised.reason) == ("HIGH", "severity MEDIUM -> CRITICAL")
        assert raised.details["fields"]["severity"] == {"from": "MEDIUM", "to": "CRITICAL"}
        assert diff(base, _finding(severity=Severity.HIGH, affected_objects=["host:a", "host:b"])).importance == "HIGH"
        lowered = diff(base, _finding(severity=Severity.LOW))
        assert lowered.importance == "LOW" and "risk reduced" in lowered.reason
        spread = diff(base, _finding(affected_objects=["host:a", "host:b", "host:c"]))
        assert (spread.importance, spread.reason) == ("MEDIUM", "affects 2 more object(s)")
        assert spread.details["fields"]["affected_objects"] == {"added": ["host:b", "host:c"], "removed": []}
        assert diff(base, _finding(affected_objects=[])).importance == "LOW"
        surer = diff(base, _finding(confidence=0.9))
        assert surer.importance == "MEDIUM" and surer.reason == "confidence 0.60 -> 0.90 (MEDIUM -> HIGH)"
        assert diff(base, _finding(confidence=0.7)).importance == "LOW"  # same confidence level
        combined = diff(base, _finding(status=FindingStatus.RESOLVED, confidence=0.3))
        assert combined.importance == "LOW"
        assert combined.reason == "confidence 0.60 -> 0.30; status OPEN -> RESOLVED"

    def test_unknown_category_is_rejected(self, cli: Any, raven_home: Path, api: Any) -> None:
        cli("snapshot", "create", "base")
        result = cli("diff", "base", "current", "--only", "bogus")
        assert result.exit_code == 4
        assert "Unknown change category 'bogus'" in result.stderr and "privileges" in result.stderr
        assert cli("diff", "base", "current", "--only", "Privileges").exit_code == 0
        response = api.get("/api/v1/diff", params={"a": "base", "b": "current", "category": "bogus"})
        assert response.status_code == 422
        assert response.json()["error"]["details"]["valid_categories"] == list(CATEGORIES)
        ok = api.get("/api/v1/diff", params={"a": "base", "b": "current", "category": "exposure"})
        assert ok.status_code == 200 and ok.json()["changes"] == []


# --------------------------------------------------------------------------- 27: relationship builder


class TestFailedEvents:
    def test_failed_access_changes_neither_grant_nor_end(self, ctx: RafContext, tmp_path: Path) -> None:
        def event(minutes: float, event_type: str, outcome: str, **attributes: Any) -> dict[str, Any]:
            return {
                "timestamp": _ts(minutes),
                "event_type": event_type,
                "actor": "admin",
                "target": "bob",
                "outcome": outcome,
                "attributes": attributes,
            }

        _ingest(
            ctx,
            tmp_path / "iam.jsonl",
            [
                event(0, "iam.role.assign", "failure", role="db-admin"),
                event(1, "iam.group.add", "denied", group="admins"),
                event(2, "iam.role.assign", "success", role="developer"),
                event(3, "iam.group.add", "success", group="vpn-users"),
                event(4, "iam.role.remove", "failure", role="developer"),
                event(5, "iam.group.remove", "failure", group="vpn-users"),
                {
                    "timestamp": _ts(6),
                    "event_type": "policy.change",
                    "actor": "admin",
                    "target": {"type": "policy", "name": "fw-main"},
                    "outcome": "failure",
                },
                {
                    "timestamp": _ts(7),
                    "event_type": "process.start",
                    "actor": "bob",
                    "host": "ws-9",
                    "outcome": "blocked",
                    "attributes": {"pid": 4242, "image": "/tmp/dropper", "command_line": "/tmp/dropper"},
                },
            ],
        )
        rels = {(r.relationship_type, r.target_object): r for r in ctx.store.relationships.iter_all()}
        assert ("HAS_ROLE", "role:db-admin") not in rels and ("MEMBER_OF", "group:admins") not in rels
        # the failed removals did not end the successful grants
        assert rels[("HAS_ROLE", "role:developer")].valid_to is None
        assert rels[("MEMBER_OF", "group:vpn-users")].valid_to is None
        assert not [key for key in rels if key[0] in ("MODIFIED", "SPAWNED", "STARTED", "EXECUTED", "RUNS")]


# --------------------------------------------------------------------------- 28: Trace


def _link(source: str, event_id: str, confidence: float = 0.8) -> TraceLink:
    return TraceLink(
        cause="user:a",
        effect="host:h",
        relation="LOGGED_INTO",
        kind="observed",
        confidence=confidence,
        timestamp=T0,
        event_id=event_id,
        explanation="",
        provenance={"source": source},
        direction="backward",
    )


def _acyclic(subject: str, chain: list[TraceLink]) -> bool:
    causes = [lk.cause for lk in chain]
    return len(set(causes)) == len(causes) and subject not in causes


class TestTrace:
    def test_each_source_is_counted_once(self, raven: RafContext) -> None:
        links = [_link("a", "e1", 0.5), _link("b", "e2", 0.5), _link("b", "e3", 0.5), _link("b", "e2", 0.5)]
        merged = _corroborate(links)
        assert len(merged) == 1
        assert [c["event_id"] for c in merged[0].corroborated_by] == ["e2"]
        assert merged[0].confidence == 0.75  # 1 - (1 - 0.5)(1 - 0.5): source b counts once
        result = TraceService(raven).trace("identity:svc-deploy", direction="back")
        session = next(lk for lk in result.backward if lk.relation == "SESSION_CONTEXT")
        assert [c["source"] for c in session.corroborated_by] == ["raven-events.jsonl"]

    def test_reads_the_events_nearest_to_the_traced_point(self, ctx: RafContext, tmp_path: Path) -> None:
        # 600 logins: the first 550 from one address, the last 50 from another (more than one read holds)
        records = [
            {
                "timestamp": _ts(i),
                "event_type": "auth.login",
                "actor": "u1",
                "target": "srv",
                "outcome": "success",
                "attributes": {"src_ip": "10.0.0.1" if i < 550 else "10.0.0.2"},
            }
            for i in range(600)
        ]
        _ingest(ctx, tmp_path / "logins.jsonl", records)
        result = TraceService(ctx).trace("user:u1", depth=1)
        assert {lk.cause for lk in result.backward} == {"ip:10.0.0.2"}
        assert max(lk.timestamp for lk in result.backward) == T0 + timedelta(minutes=599)
        assert max(lk.timestamp for lk in result.forward) == T0 + timedelta(minutes=599)
        # from a point in time: the latest causes before it, the earliest effects after it
        srv = TraceService(ctx).trace("host:srv", direction="back", depth=2)
        nested = [lk for lk in srv.backward if lk.parent_step is not None]
        assert nested and all(lk.timestamp <= srv.backward[lk.parent_step].timestamp for lk in nested)

    def test_chains_never_revisit_an_object(self, raven: RafContext) -> None:
        service = TraceService(raven)
        for subject in ("user:alice", "identity:svc-deploy", "host:dev-01", "incident:inc-001"):
            result = service.trace(subject, direction="back", depth=6)
            assert result.chain and _acyclic(subject, result.chain), subject
            assert result.chain[-1].effect == subject
            assert all(b.effect == a.cause for a, b in zip(result.chain[1:], result.chain, strict=False))
            assert all(a.timestamp <= b.timestamp for a, b in zip(result.chain, result.chain[1:], strict=False))
        chain = service.trace("identity:svc-deploy", direction="back", depth=4).chain
        assert [lk.cause for lk in chain] == ["host:ws-02", "user:bob", "host:dev-01"]

    def test_incident_is_traced_from_its_most_significant_event(self, raven: RafContext) -> None:
        result = TraceService(raven).trace("incident:inc-001", depth=6)
        anchor = result.anchor
        assert anchor is not None and anchor.severity is Severity.HIGH and anchor.event_type == "alert"
        assert anchor.object == "host:app-01" and anchor.timestamp == datetime(2026, 10, 6, 23, 20, tzinfo=UTC)
        assert any(anchor.event_id in note and "most significant event" in note for note in result.notes)
        first = result.backward[0]
        assert (first.cause, first.effect, first.relation, first.event_id) == (
            "host:app-01",
            "incident:inc-001",
            "ALERT",
            anchor.event_id,
        )
        assert all(lk.timestamp <= anchor.timestamp for lk in result.backward)
        assert all(lk.timestamp >= anchor.timestamp for lk in result.forward)
        assert [lk.cause for lk in result.chain] == [
            "host:ws-02",
            "user:bob",
            "host:dev-01",
            "identity:svc-deploy",
            "host:app-01",
        ]

    def test_key_event_is_highest_severity_then_latest(self, ctx: RafContext, tmp_path: Path) -> None:
        def event(minutes: float, severity: str, target: str) -> dict[str, Any]:
            return {
                "timestamp": _ts(minutes),
                "event_type": "alert",
                "target": {"type": "host", "name": target},
                "severity": severity,
                "incident": "INC-9",
                "message": target,
            }

        _ingest(
            ctx,
            tmp_path / "inc.jsonl",
            [event(0, "critical", "early"), event(5, "critical", "later"), event(9, "high", "latest")],
        )
        result = TraceService(ctx).trace("incident:inc-9")
        assert result.anchor is not None and result.anchor.object == "host:later"
        assert result.subject.type == "incident" and result.subject.name == "INC-9"

    def test_correlation_window_bounds_credential_exposure(self, raven: RafContext) -> None:
        def exposures() -> list[TraceLink]:
            result = TraceService(raven).trace("identity:svc-deploy", direction="back", depth=1)
            return [lk for lk in result.backward if lk.relation == "CREDENTIAL_EXPOSURE"]

        assert exposures()  # .env read 2m54s before svc-deploy logged in, within the default 720 minutes
        raven.settings = raven.settings.with_overrides({"trace.correlation_window_minutes": 2})
        assert not exposures()

    def test_events_and_other_references(self, raven: RafContext) -> None:
        read = raven.store.events.query(EventQuery(event_types=["file.read"], incident_id="incident:inc-001")).items[0]
        result = TraceService(raven).trace(read.id, direction="back")
        assert result.subject.type == "event" and result.anchor is not None
        assert result.anchor.object == read.target and result.chain[-1].effect == read.id
        assert "user:bob" in [lk.cause for lk in result.chain]
        finding = raven.store.findings.list(limit=1)[0]
        with pytest.raises(InvalidInputError):
            TraceService(raven).trace(finding.id)

    def test_cli_and_api_for_incidents(self, cli: Any, raven_home: Path, api: Any) -> None:
        out = cli("trace", "INC-001")
        assert out.exit_code == 0 and "most significant event" in out.stdout
        assert "raf replay INC-001" in out.stdout and "raf trace host:app-01" in out.stdout
        assert "raf blast" not in out.stdout and "No events reference" not in out.stdout
        quoted = cli("trace", "cat [20903]", "--direction", "back").stdout
        assert "raf timeline 'process:dev-01|20903|2026-10-06T23:01:47Z'" in quoted
        data = api.get("/api/v1/trace/INC-001", params={"depth": 2}).json()
        assert data["anchor"]["object"] == "host:app-01" and data["backward"][0]["effect"] == "incident:inc-001"


# --------------------------------------------------------------------------- 29: Replay


def test_replay_checkpoints_are_state_hashes(raven: RafContext) -> None:
    raven.settings = raven.settings.with_overrides({"replay.checkpoint_interval": 10})
    timeline = ReplayService(raven).build(resolve_scope(raven, ["INC-001"]))
    assert timeline.checkpoints and all(set(cp) == {"index", "state_hash"} for cp in timeline.checkpoints)
    for checkpoint in timeline.checkpoints:
        state = _State(objects=set(timeline.initial_objects), relationships=set(timeline.initial_relationships))
        for step in timeline.steps[: checkpoint["index"] + 1]:
            apply_step(state, step)
        assert state.digest() == checkpoint["state_hash"]


# --------------------------------------------------------------------------- 30: Timeline


class TestTimelineExport:
    def test_api_export_leaves_no_temporary_files(
        self, api: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        temp = tmp_path / "temp"
        temp.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(temp))
        bad = api.get("/api/v1/timeline/export", params={"ref": "INC-001", "format": "xlsx"})
        assert bad.status_code == 422 and "csv" in bad.json()["error"]["hint"]
        assert list(temp.iterdir()) == []
        good = api.get("/api/v1/timeline/export", params={"ref": "INC-001", "format": "JSONL"})
        assert good.status_code == 200 and good.headers["content-type"].startswith("application/x-ndjson")
        assert list(temp.iterdir()) == []

        def fail(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise InvalidInputError("export failed")

        monkeypatch.setattr(TimelineService, "export", fail)
        assert api.get("/api/v1/timeline/export", params={"ref": "INC-001"}).status_code == 422
        assert list(temp.iterdir()) == []

    def test_csv_neutralizes_every_text_column(self, ctx: RafContext, tmp_path: Path) -> None:
        _ingest(
            ctx,
            tmp_path / "evil.jsonl",
            [
                {
                    "timestamp": _ts(0),
                    "event_type": "auth.login",
                    "action": "@SUM(1+1)",
                    "outcome": "-2+3",
                    "actor": {"type": "user", "name": '=HYPERLINK("http://x")'},
                    "target": {"type": "host", "name": "+cmd"},
                    "source": "@source",
                    "message": "=1+2",
                }
            ],
        )
        service = TimelineService(ctx)
        scope = resolve_scope(ctx, [])
        query, _ = service.query(scope)
        service.export(scope, query, "csv", tmp_path / "out.csv")
        rows = list(csv.DictReader((tmp_path / "out.csv").open(encoding="utf-8")))
        assert len(rows) == 1 and tuple(rows[0]) == CSV_COLUMNS
        row = rows[0]
        for column in ("action", "outcome", "actor_name", "target_name", "source", "message"):
            assert row[column].startswith("'") and row[column][1] in "=+-@", column
        assert row["timestamp"] == _ts(0) and row["event_id"].startswith("event:")

    def test_media_types_cover_every_format(self) -> None:
        from raf.products.timeline.api import _MEDIA

        assert set(_MEDIA) == set(EXPORT_FORMATS)


# --------------------------------------------------------------------------- 31: Graph


class TestGraph:
    def test_views_without_layers_show_every_root(self, cli: Any, raven_home: Path) -> None:
        overview = cli("graph").stdout
        assert "without a tree parent" not in overview
        for name in ("DB-01", "alice", "production", "LAB-01", "JUMP-01"):
            assert name in overview
        job = cli("graph", "job-1").stdout
        tree = job.split("Depth   0", 1)[1]
        assert len([line for line in tree.splitlines() if line.strip()]) > 70
        assert "output limited to 80 lines" in job and "more root(s) not shown" in job

    def test_spanning_forest(self) -> None:
        from raf.products.graph.cli import _spanning_forest

        def edge(source: str, target: str) -> GraphEdge:
            return GraphEdge(id=f"rel:{source}{target}", type="LINKS", source=source, target=target, confidence=1.0)

        graph = Subgraph(
            roots=[],
            nodes=[GraphNode(id=i, type="host", name=i) for i in ("host:a", "host:b", "host:c", "host:d", "host:e")],
            edges=[edge("host:a", "host:b"), edge("host:b", "host:c"), edge("host:e", "host:d")],
        )
        roots, parents = _spanning_forest(graph)
        assert roots == ["host:b", "host:d"]
        assert parents == {
            "host:a": ("host:b", "LINKS", False),
            "host:c": ("host:b", "LINKS", True),
            "host:e": ("host:d", "LINKS", False),
        }

    def test_api_validates_type_filters(self, api: Any) -> None:
        for path, params in (
            ("/api/v1/graph/view", {"ref": "alice", "rel": "not a type!"}),
            ("/api/v1/graph/view", {"ref": "alice", "type": "spaceship"}),
            ("/api/v1/graph/neighbors", {"ref": "alice", "rel": "??"}),
            ("/api/v1/graph/path", {"source": "alice", "target": "DB-01", "rel": "-"}),
        ):
            assert api.get(path, params=params).status_code == 422, params
        view = api.get("/api/v1/graph/view", params={"ref": "alice", "depth": 1, "rel": "member_of", "type": "Group"})
        data = view.json()
        assert view.status_code == 200 and data["edges"]
        assert {e["type"] for e in data["edges"]} == {"MEMBER_OF"} and {n["type"] for n in data["nodes"]} == {
            "user",
            "group",
        }

    def test_csv_export_uses_canonical_timestamps(self, raven: RafContext) -> None:
        from raf.products.graph.service import GraphService

        text = export_subgraph(GraphService(raven).view(resolve_scope(raven, ["INC-001"])), "csv")
        rows = list(csv.DictReader(io.StringIO(text)))
        stamps = [row[k] for row in rows for k in ("first_seen", "last_seen", "valid_to") if row[k]]
        assert stamps and all(_CANONICAL_TS.match(s) for s in stamps)
        evil = Subgraph(
            roots=[],
            nodes=[],
            edges=[GraphEdge(id="rel:1", type="LINKS", source="=cmd|' /C calc'!A0", target="@x", confidence=1.0)],
        )
        row = next(csv.DictReader(io.StringIO(export_subgraph(evil, "csv"))))
        assert row["source"] == "'=cmd|' /C calc'!A0" and row["target"] == "'@x"


# --------------------------------------------------------------------------- 32: finding status history


class TestFindingHistory:
    def test_automatic_transitions_are_recorded(self, ctx: RafContext) -> None:
        store = ctx.store
        old = {"from": "ACKNOWLEDGED", "to": "OPEN", "note": None, "at": "2026-10-01T10:00:00+00:00"}
        store.findings.upsert([_finding(metadata={"status_history": [old]})])
        store.findings.upsert([_finding(id="finding:test:rule:2")])
        resolved = store.findings.resolve_absent("test", ["rule"], [], candidates=["finding:test:rule:1"])
        assert resolved == 1
        first = store.findings.require("finding:test:rule:1")
        assert first.status is FindingStatus.RESOLVED
        history = first.metadata["status_history"]
        assert history[0] == old  # older entries are kept as written
        entry = history[-1]
        assert {k: entry[k] for k in ("from", "to", "note", "automatic")} == {
            "from": "OPEN",
            "to": "RESOLVED",
            "note": RESOLVED_ABSENT_NOTE,
            "automatic": True,
        }
        assert _CANONICAL_TS.match(entry["at"])
        untouched = store.findings.require("finding:test:rule:2")  # outside the candidates
        assert untouched.status is FindingStatus.OPEN and "status_history" not in untouched.metadata
        # it reappears: reopened automatically, with the history carried forward
        store.findings.upsert([_finding()])
        reopened = store.findings.require("finding:test:rule:1")
        assert reopened.status is FindingStatus.OPEN
        last = reopened.metadata["status_history"][-1]
        assert last["automatic"] is True and last["to"] == "OPEN" and _CANONICAL_TS.match(last["at"])
        assert len(reopened.metadata["status_history"]) == 3
        # analyst decisions: canonical time, no automatic flag
        acked = store.findings.set_status("finding:test:rule:1", FindingStatus.ACKNOWLEDGED, "triaged")
        manual = acked.metadata["status_history"][-1]
        assert _CANONICAL_TS.match(manual["at"]) and "automatic" not in manual and manual["note"] == "triaged"
