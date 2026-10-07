"""Graph, Timeline, Trace, Snapshot/Diff and Replay over the shared Raven model."""

from __future__ import annotations

import csv
import json
import random
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select, update

from raf.core.context.app import RafContext
from raf.core.errors import ConflictError, IntegrityError, InvalidInputError, ResourceLimitExceeded, SecurityViolation
from raf.core.graph.source import MemoryGraphSource, StoreGraphSource
from raf.core.ingestion.pipeline import IngestionPipeline
from raf.core.objects.content import content_hash
from raf.core.objects.models import ObjectDraft, RelationshipDraft
from raf.core.query.language import parse_filter
from raf.core.query.scope import resolve_scope
from raf.core.snapshots.service import (
    SnapshotService,
    StateView,
    object_content,
    relationship_content,
    resolve_state,
)
from raf.core.storage import schema as s
from raf.core.storage.store import Store
from raf.products.diff.service import DiffService
from raf.products.graph.service import GraphService
from raf.products.replay.service import ReplayService
from raf.products.timeline.service import TimelineService
from raf.products.trace.service import TraceService
from tests.conftest import FIXTURES


class TestGraph:
    def test_neighborhood_and_types(self, raven: RafContext) -> None:
        graph = GraphService(raven).view(resolve_scope(raven, ["alice"]), depth=1)
        ids = {n.id for n in graph.nodes}
        assert {"user:alice", "group:engineering", "host:ws-01", "host:dev-01"} <= ids
        assert all(n.depth <= 1 for n in graph.nodes)
        only_groups = GraphService(raven).view(resolve_scope(raven, ["alice"]), depth=1, node_types=["group"])
        assert {n.type for n in only_groups.nodes} == {"user", "group"}

    def test_paths_directed_and_undirected(self, raven: RafContext) -> None:
        service = GraphService(raven)
        undirected = service.path("user:bob", "host:db-01")
        assert undirected.found and undirected.hops[-1].target == "host:db-01"
        directed = service.path("identity:svc-deploy", "cloud_resource:production", directed=True)
        assert directed.found
        assert [h.relationship.type for h in directed.hops][-1] == "DEPLOYS_TO"
        assert all(h.forward for h in directed.hops)

    def test_temporal_view(self, raven: RafContext) -> None:
        before = StoreGraphSource(raven.store, at=datetime(2026, 10, 6, 23, 26, tzinfo=UTC))
        after = StoreGraphSource(raven.store, at=datetime(2026, 10, 6, 23, 28, tzinfo=UTC))
        groups_before = {r.target_object for r in before.edges(["user:bob"], "out", ["MEMBER_OF"])}
        groups_after = {r.target_object for r in after.edges(["user:bob"], "out", ["MEMBER_OF"])}
        assert "group:vpn-users" in groups_before and "group:vpn-users" not in groups_after

    def test_incident_view_has_virtual_involves_edges(self, raven: RafContext) -> None:
        graph = GraphService(raven).view(resolve_scope(raven, ["INC-001"]))
        assert graph.roots == ["incident:inc-001"]
        assert any(e.type == "INVOLVES" and e.metadata.get("virtual") for e in graph.edges)

    def test_memory_source_matches_store(self, raven: RafContext) -> None:
        objects = list(raven.store.objects.iter_all())
        rels = list(raven.store.relationships.iter_all())
        memory = MemoryGraphSource(objects, rels)
        store = StoreGraphSource(raven.store)
        assert {r.id for r in memory.edges(["user:alice"], "both")} == {
            r.id for r in store.edges(["user:alice"], "both")
        }


class TestSnapshotsAndDiff:
    def test_structural_sharing_and_identity(self, raven: RafContext) -> None:
        service = SnapshotService(raven.store)
        a = service.create("a")
        b = service.create("b")
        assert a.content_hash == b.content_hash  # identical state -> identical hash
        assert b.stats["new_blobs"] == 0 and b.stats["shared_blobs"] > 1000
        with pytest.raises(ConflictError):
            service.create("a")
        with pytest.raises(InvalidInputError):
            service.create("current")

    def test_diff_classifies_and_explains(self, raven: RafContext) -> None:
        SnapshotService(raven.store).create("before")
        raven.store.relationships.upsert_drafts(
            [
                RelationshipDraft.make("user:bob", "HAS_ROLE", "role:db-admin"),
                RelationshipDraft.make("network:internet", "CAN_REACH", "host:db-01"),
            ]
        )
        raven.store.objects.upsert_drafts([ObjectDraft.make("host", "NEW-01")])
        raven.store.relationships.end(
            [RelationshipDraft.make("host:dev-01", "USES", "identity:svc-deploy").id], datetime(2026, 10, 7, tzinfo=UTC)
        )
        result = DiffService(raven).diff("before", "current")
        by_label = {c.label: c for c in result.changes}
        grant = by_label["bob -HAS_ROLE-> db-admin"]
        assert grant.importance == "HIGH" and grant.category == "privileges"
        exposure = by_label["INTERNET -CAN_REACH-> DB-01"]
        assert exposure.importance == "HIGH" and exposure.category == "exposure"
        ended = by_label["DEV-01 -USES-> svc-deploy"]
        assert ended.change == "removed" and ended.importance == "LOW"
        assert result.summary["hosts"]["added"] == 1
        assert all(c.reason for c in result.changes)

    def test_snapshot_materialize_roundtrip(self, raven: RafContext) -> None:
        service = SnapshotService(raven.store)
        service.create("base")
        objects, rels = service.materialize("base")
        assert len(objects) == raven.store.objects.count()
        assert len(rels) == raven.store.relationships.count()
        stored_objects = {o.id: o for o in raven.store.objects.iter_all()}
        stored_rels = {r.id: r for r in raven.store.relationships.iter_all()}
        for obj in objects:
            original = stored_objects[obj.id]
            assert (obj.type, obj.name, sorted(obj.tags), obj.synthetic) == (
                original.type,
                original.name,
                sorted(original.tags),
                original.synthetic,
            )
        assert all(stored_rels[r.id].source_object == r.source_object for r in rels)
        deleted = service.delete("base")
        assert deleted["items"] > 0

    def test_table_contents_hash_like_models(self, raven: RafContext) -> None:
        """Snapshots and "current" read content straight from the tables; it must hash exactly like
        the content of the corresponding models (Ghost states and older snapshots use those)."""
        raven.store.relationships.end(
            [RelationshipDraft.make("host:dev-01", "USES", "identity:svc-deploy").id], datetime(2026, 10, 7, tzinfo=UTC)
        )
        current = SnapshotService(raven.store).current_state()
        from_models = StateView.from_items(
            "models",
            raven.store.objects.iter_all(),
            raven.store.relationships.iter_all(),
            raven.store.findings.list(limit=1_000_000),
        )
        assert current.hashes == from_models.hashes
        assert any(not body["active"] for body in current.bodies.values() if "source" in body)
        snapshot = SnapshotService(raven.store).create("tables")
        assert (
            snapshot.content_hash
            == SnapshotService(raven.store).create_from_state("models", from_models, source="t").content_hash
        )

    def test_rows_carry_their_content_hash(self, raven: RafContext) -> None:
        """Every write stores the hash of the row's content with the row; relationships ended in bulk
        lose theirs until the next snapshot computes it again."""
        store = raven.store
        assert set(_hash_mismatches(store).values()) <= {None}  # the demo load: only ended relationships
        store.objects.upsert_drafts(
            [ObjectDraft.make("host", "NEW-01", metadata={"ports": (22, 443), "by_port": {22: "ssh"}})]
        )
        store.objects.upsert_drafts([ObjectDraft.make("host", "NEW-01", metadata={"criticality": "high"})])
        store.objects.update_metadata("host:new-01", {"owner": "ops", "scanned_at": "2026-10-07"})
        store.relationships.upsert_drafts(
            [RelationshipDraft.make("user:bob", "HAS_ROLE", "role:db-admin", metadata={"via": "x", "ttl": 5})]
        )
        ended = RelationshipDraft.make("host:dev-01", "USES", "identity:svc-deploy").id
        store.relationships.end([ended], datetime(2026, 10, 7, tzinfo=UTC))
        mismatches = _hash_mismatches(store)
        assert ended in mismatches and set(mismatches.values()) == {None}
        SnapshotService(store).create("s")
        assert _hash_mismatches(store) == {}

    def test_snapshots_compute_missing_hashes_and_repair_stale_ones(self, raven: RafContext) -> None:
        service = SnapshotService(raven.store)
        reference = service.create("reference")
        some_rel = next(iter(raven.store.relationships.ids()))
        with raven.store.transaction() as conn:
            conn.execute(update(s.objects).values(content_hash=None))  # rows written before hashes were kept
            conn.execute(update(s.relationships).where(s.relationships.c.id == some_rel).values(content_hash="0" * 64))
        again = service.create("again")
        assert again.content_hash == reference.content_hash
        assert again.stats["new_blobs"] == 0 and again.stats["objects"] == reference.stats["objects"]
        assert _hash_mismatches(raven.store) == {}
        assert service.current_state().hashes == service.snapshot_state("again").hashes

    def test_current_state_bodies_match_the_models(self, raven: RafContext) -> None:
        current = SnapshotService(raven.store).current_state()
        assert not current.bodies.keys() - set(current.hashes["finding"].values())  # rows: bodies on demand
        sample = {o.id: o for o in raven.store.objects.iter_all(types=["host", "user"])}
        bodies = current.body([current.hashes["object"][i] for i in sample])
        assert len(bodies) == len(sample)
        for oid, obj in sample.items():
            assert bodies[current.hashes["object"][oid]] == object_content(obj)

    def test_delete_removes_only_the_blobs_no_other_snapshot_holds(self, raven: RafContext) -> None:
        service = SnapshotService(raven.store)
        service.create("one")
        raven.store.objects.upsert_drafts([ObjectDraft.make("host", "ONLY-IN-TWO")])
        two = service.create("two")
        assert two.stats["new_blobs"] == 1
        assert service.delete("two")["blobs_removed"] == 1
        objects, _rels = service.materialize("one")
        assert len(objects) == raven.store.objects.count() - 1
        assert service.delete("one")["blobs_removed"] > 1000
        with raven.store.engine.connect() as conn:
            assert conn.execute(select(func.count()).select_from(s.blobs)).scalar_one() == 0

    def test_diff_reads_only_the_bodies_of_changes(self, raven: RafContext) -> None:
        SnapshotService(raven.store).create("before")
        raven.store.relationships.upsert_drafts([RelationshipDraft.make("user:bob", "HAS_ROLE", "role:db-admin")])
        a, b = resolve_state(raven, "before"), resolve_state(raven, "current")
        requested: list[str] = []
        for view in (a, b):
            loader = view.loader
            assert loader is not None

            def counting(hashes: list[str], loader: Any = loader) -> dict[str, dict[str, Any]]:
                requested.extend(hashes)
                result: dict[str, dict[str, Any]] = loader(hashes)
                return result

            view.loader = counting
        result = DiffService(raven).compare(a, b)
        assert [c.label for c in result.changes] == ["bob -HAS_ROLE-> db-admin"]
        object_hashes = set(a.hashes["object"].values()) | set(b.hashes["object"].values())
        assert len(object_hashes & set(requested)) <= 2  # the endpoints, not every object


def _hash_mismatches(store: Store) -> dict[str, str | None]:
    """Rows whose stored content hash is not the hash of their content (as the models compute it)."""
    stored: dict[str, str | None] = {}
    with store.engine.connect() as conn:
        for table in (s.objects, s.relationships):
            stored.update((row.id, row.content_hash) for row in conn.execute(select(table.c.id, table.c.content_hash)))
    expected = {o.id: content_hash(object_content(o)) for o in store.objects.iter_all()}
    expected |= {r.id: content_hash(relationship_content(r)) for r in store.relationships.iter_all()}
    assert stored.keys() == expected.keys()
    return {item_id: stored[item_id] for item_id, digest in expected.items() if stored[item_id] != digest}


class TestTimeline:
    def test_scopes_filters_groups(self, raven: RafContext) -> None:
        service = TimelineService(raven)
        scope = resolve_scope(raven, ["user", "alice"])
        query, terms = service.query(scope, filter_text="type:auth.* outcome:success")
        result = service.timeline(scope, query, terms, limit=10)
        assert result.total > 0 and all(e.event_type.startswith("auth.") for e in result.items)
        assert result.groups and result.histogram
        page2 = service.timeline(
            scope, query, terms, limit=2, cursor=service.timeline(scope, query, terms, limit=2).next_cursor
        )
        assert page2.items

    def test_histogram_buckets_are_exact(self, raven: RafContext, monkeypatch: pytest.MonkeyPatch) -> None:
        """An event on a bucket boundary falls into the later bucket, in SQL and in the portable
        fallback alike (whole microseconds, no floating-point day fractions)."""
        from datetime import timedelta

        from raf.core.storage.repos import events as repo

        query = resolve_scope(raven, ["INC-001"]).event_query()
        in_sql = raven.store.events.histogram(query, buckets=48)
        monkeypatch.setattr(repo, "_epoch_micros", lambda dialect: None)
        in_python = raven.store.events.histogram(query, buckets=48)
        assert in_sql == in_python
        events = raven.store.events.query(query, limit=1000).items
        assert sum(b["count"] for b in in_sql) == len(events)
        first, width = in_sql[0]["start"], in_sql[1]["start"] - in_sql[0]["start"]
        offsets = [e.timestamp - first for e in events]
        on_boundary = [o for o in offsets if o > timedelta(0) and o % width == timedelta(0)]
        assert on_boundary  # whole-minute demo timestamps land on 50 s boundaries
        for offset in on_boundary:
            assert in_sql[offset // width]["start"] == first + offset and in_sql[offset // width]["count"] >= 1

    def test_filter_language_rejects_unknown_keys(self, raven: RafContext) -> None:
        with pytest.raises(InvalidInputError):
            parse_filter("colour:blue", resolver=raven.resolver)
        parsed = parse_filter('severity>=high "export"', resolver=raven.resolver)
        assert parsed.query.min_severity is not None and parsed.query.texts == ["export"]

    def test_exports_csv_json_raf(self, raven: RafContext, tmp_path: Path) -> None:
        service = TimelineService(raven)
        scope = resolve_scope(raven, ["INC-001"])
        query, _ = service.query(scope)
        info = service.export(scope, query, "csv", tmp_path / "t.csv")
        rows = list(csv.DictReader((tmp_path / "t.csv").open()))
        assert len(rows) == info["events"] > 20
        assert rows[0]["event_id"].startswith("event:")
        service.export(scope, query, "json", tmp_path / "t.json")
        assert len(json.loads((tmp_path / "t.json").read_text())) == info["events"]
        bundle = service.export(scope, query, "raf", tmp_path / "t.raf")
        assert bundle["events"] == info["events"]
        with zipfile.ZipFile(tmp_path / "t.raf") as archive:
            assert {"manifest.json", "events.jsonl", "objects.jsonl"} <= set(archive.namelist())

    def test_csv_export_neutralizes_formulas(self, ctx: RafContext, tmp_path: Path) -> None:
        path = tmp_path / "f.jsonl"
        path.write_text(
            json.dumps(
                {
                    "timestamp": "2026-10-06T10:00:00Z",
                    "event_type": "log.message",
                    "host": "h1",
                    "message": '=HYPERLINK("http://x")',
                }
            )
            + "\n"
        )
        IngestionPipeline(ctx).ingest_path(path)
        service = TimelineService(ctx)
        scope = resolve_scope(ctx, [])
        query, _ = service.query(scope)
        service.export(scope, query, "csv", tmp_path / "out.csv")
        row = next(csv.DictReader((tmp_path / "out.csv").open()))
        assert row["message"].startswith("'=")


class TestTrace:
    def test_incident_chain_with_labeled_correlation(self, raven: RafContext) -> None:
        result = TraceService(raven).trace("identity:svc-deploy", direction="back", depth=4)
        exposure = [lk for lk in result.backward if lk.relation == "CREDENTIAL_EXPOSURE"]
        assert exposure and all(lk.kind == "correlated" and lk.confidence <= 0.65 for lk in exposure)
        assert exposure[0].cause.startswith("process:dev-01|20903")
        assert any("not proven causation" in n for n in result.notes)
        chain_nodes = [lk.cause for lk in result.chain]
        assert "user:bob" in chain_nodes and "host:dev-01" in chain_nodes

    def test_process_chain_reaches_external_ip(self, raven: RafContext) -> None:
        process = raven.resolve("cat [20903]").id
        result = TraceService(raven).trace(process, direction="back", depth=6)
        # The backward links reach the attacker's address; the chain itself never revisits an object, so it
        # stops at bob's SSH session from WS-02 instead of alternating bob -> host -> bob back to the VPN login.
        assert any(lk.cause == "ip:203.0.113.45" for lk in result.backward)
        assert [lk.cause for lk in result.chain] == ["host:ws-02", "user:bob"]
        assert all(a.timestamp <= b.timestamp for a, b in zip(result.chain, result.chain[1:], strict=False))


class TestReplay:
    def test_deterministic_and_order_independent(self, ctx: RafContext, tmp_path: Path, raf_home: Path) -> None:
        from raf.core.context.app import open_context

        IngestionPipeline(ctx).ingest_path(FIXTURES / "raven-events.jsonl")
        first = ReplayService(ctx).build(resolve_scope(ctx, ["INC-001"]))
        second = ReplayService(ctx).build(resolve_scope(ctx, ["INC-001"]))
        assert first.final_state_hash == second.final_state_hash
        assert [s.event_id for s in first.steps] == [s.event_id for s in second.steps]
        # The same events imported in a shuffled order (different file, different record IDs)
        # reconstruct to the identical state.
        lines = (FIXTURES / "raven-events.jsonl").read_text().splitlines()
        inventory = [ln for ln in lines if '"kind"' in ln]
        events = [ln for ln in lines if '"kind"' not in ln]
        random.Random(5).shuffle(events)
        shuffled = tmp_path / "shuffled.jsonl"
        shuffled.write_text("\n".join(inventory + events) + "\n")
        ctx.workspaces.create("shuffled")
        other = open_context(workspace="shuffled", env={"RAF_HOME": str(raf_home)})
        try:
            IngestionPipeline(other).ingest_path(shuffled)
            replayed = ReplayService(other).build(resolve_scope(other, ["INC-001"]))
        finally:
            other.close()
        assert len(replayed.steps) == len(first.steps)
        assert replayed.final_state_hash == first.final_state_hash

    def test_state_at_and_window(self, raven: RafContext) -> None:
        service = ReplayService(raven)
        timeline = service.build(resolve_scope(raven, ["INC-001"]))
        state = service.state_at(timeline, datetime(2026, 10, 6, 23, 5, tzinfo=UTC))
        sessions = {(s["user"], s["host"]) for s in state.sessions}
        assert ("user:bob", "host:dev-01") in sessions and ("identity:svc-deploy", "host:ci-01") in sessions
        later = service.state_at(timeline, datetime(2026, 10, 6, 23, 13, 30, tzinfo=UTC))
        assert ("user:bob", "host:dev-01") not in {(s["user"], s["host"]) for s in later.sessions}
        window = service.changes(
            timeline, datetime(2026, 10, 6, 23, 0, tzinfo=UTC), datetime(2026, 10, 6, 23, 10, tzinfo=UTC)
        )
        assert window["files"] and window["files"][0]["operation"] == "read"
        assert timeline.excluded_events >= 0 and timeline.initial_relationships

    def test_removal_ends_relationship_in_replay(self, raven: RafContext) -> None:
        timeline = ReplayService(raven).build(resolve_scope(raven, ["INC-001"]))
        removal = next(s for s in timeline.steps if s.event_type == "iam.group.remove")
        assert removal.removed_relationships


class TestBundleSecurity:
    def _bundle(self, tmp_path: Path, members: dict[str, bytes], manifest: dict[str, Any] | None = None) -> Path:
        path = tmp_path / "evil.raf"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)
            if manifest is not None:
                archive.writestr("manifest.json", json.dumps(manifest))
        return path

    def _manifest(self, files: dict[str, bytes]) -> dict[str, Any]:
        import hashlib

        return {
            "format": "raf-bundle",
            "format_version": "1.0",
            "created_at": "2026-10-07T00:00:00Z",
            "workspace": "x",
            "files": {n: {"sha256": hashlib.sha256(d).hexdigest(), "size": len(d)} for n, d in files.items()},
        }

    def test_rejects_traversal_and_absolute_paths(self, ctx: RafContext, tmp_path: Path) -> None:
        from raf.core.bundle.format import open_bundle

        for bad in ("../escape.txt", "/etc/passwd", "a/../../b", "C:\\windows\\x"):
            files = {bad: b"x"}
            with pytest.raises(SecurityViolation):
                open_bundle(ctx, self._bundle(tmp_path, files, self._manifest(files)))

    def test_rejects_symlink_members(self, ctx: RafContext, tmp_path: Path) -> None:
        from raf.core.bundle.format import open_bundle

        path = tmp_path / "link.raf"
        with zipfile.ZipFile(path, "w") as archive:
            info = zipfile.ZipInfo("objects.jsonl")
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "/etc/passwd")
            archive.writestr("manifest.json", json.dumps(self._manifest({"objects.jsonl": b"/etc/passwd"})))
        with pytest.raises(SecurityViolation):
            open_bundle(ctx, path)

    def test_rejects_compression_bomb(self, ctx: RafContext, tmp_path: Path) -> None:
        from raf.core.bundle.format import open_bundle

        payload = b"0" * 30_000_000
        path = tmp_path / "bomb.raf"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("events.jsonl", payload)
            archive.writestr("manifest.json", json.dumps(self._manifest({"events.jsonl": payload})))
        with pytest.raises(ResourceLimitExceeded):
            open_bundle(ctx, path)

    def test_tampered_member_is_rejected_before_import(self, ctx: RafContext, tmp_path: Path) -> None:
        from raf.core.bundle.format import import_bundle

        good = json.dumps({"id": "host:x", "type": "host", "name": "x"}).encode() + b"\n"
        manifest = self._manifest({"objects.jsonl": good})
        path = self._bundle(tmp_path, {"objects.jsonl": good.replace(b'"x"', b'"y"')}, manifest)
        with pytest.raises(IntegrityError):
            import_bundle(ctx, path)
        assert ctx.store.objects.count() == 0

    def test_not_a_bundle(self, ctx: RafContext, tmp_path: Path) -> None:
        from raf.core.bundle.format import open_bundle

        with pytest.raises(InvalidInputError):
            open_bundle(ctx, self._bundle(tmp_path, {"x.txt": b"x"}))
        junk = tmp_path / "junk.raf"
        junk.write_bytes(b"not a zip")
        with pytest.raises(InvalidInputError):
            open_bundle(ctx, junk)


def test_workspace_backup_restore_roundtrip(raven: RafContext, tmp_path: Path, raven_home: Path) -> None:
    from raf.analysis.backup import export_workspace, restore_workspace

    SnapshotService(raven.store).create("baseline")
    manifest = export_workspace(raven, tmp_path / "backup.raf")
    assert manifest.counts["events"] > 500 and manifest.counts["snapshots"] == 1
    result = restore_workspace(tmp_path / "backup.raf", "restored")
    assert result["imported"]["events"] == manifest.counts["events"]
    from raf.core.context.app import open_context

    restored = open_context(workspace="restored", env={"RAF_HOME": str(raven_home)})
    try:
        assert restored.store.events.count() == raven.store.events.count()
        assert SnapshotService(restored.store).get("baseline") is not None
        assert restored.audit.verify()["valid"]
    finally:
        restored.close()
