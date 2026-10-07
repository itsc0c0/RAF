"""Security-state snapshots with structural sharing.

A snapshot records, for every object, relationship and finding, the hash of
its *canonical content* (:mod:`raf.core.objects.content`: bookkeeping such as
``updated_at``/``last_seen``/observation counts is excluded so re-observing the
same state does not look like change). Bodies live once in the content-addressed
``blobs`` table and are shared by every snapshot that contains the same content;
an unchanged item costs one index row, not a copy.

Objects and relationships carry their content hash in the ``content_hash``
column (written with the row), so a snapshot of the workspace copies hashes with
``INSERT ... SELECT`` and only computes bodies for content no snapshot holds yet
and hashes of rows that lack one.

States can come from the workspace ("current"), a stored snapshot, or a
registered provider (Ghost registers ``ghost:<model>``).
"""

from __future__ import annotations

import builtins
import hashlib
import json
import re
from collections.abc import Callable, Collection, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from typing import Any

from pydantic import Field
from sqlalchemy import ColumnElement, Connection, Table, bindparam, delete, func, literal, select, update

from raf.core.context.app import RafContext
from raf.core.errors import ConflictError, InvalidInputError, NotFoundError
from raf.core.objects.content import content_hash, finding_body, json_value, object_body, relationship_body
from raf.core.objects.models import RafModel, Relationship, SecurityObject, build_object, build_relationship
from raf.core.objects.semantics import NON_PROPAGATING_TYPES, PROPAGATION_RELATIONSHIPS
from raf.core.storage import schema as s
from raf.core.storage.database import chunks, upsert
from raf.core.storage.store import Store
from raf.core.timeutil import utcnow

KINDS = ("object", "relationship", "finding")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def object_content(obj: SecurityObject) -> dict[str, Any]:
    return object_body(obj.type, obj.name, obj.tags, json_value(obj.metadata), obj.valid_to is None, obj.synthetic)


def relationship_content(rel: Relationship) -> dict[str, Any]:
    return relationship_body(
        rel.relationship_type, rel.source_object, rel.target_object, json_value(rel.metadata), rel.valid_to is None
    )


def finding_content(finding: Any) -> dict[str, Any]:
    return finding_body(finding)


def item_content(kind: str, item: Any) -> dict[str, Any]:
    if kind == "object":
        return object_content(item)
    if kind == "relationship":
        return relationship_content(item)
    return finding_content(item)


def _item_contents(kind: str, items: Iterable[Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for item in items:
        yield item.id, item_content(kind, item)


@dataclass(frozen=True)
class _ContentTable:
    """How to read the canonical content of a stored object or relationship straight from its table:
    no model objects and no timestamp conversions (large workspaces stay fast)."""

    table: Table
    columns: Callable[[], list[ColumnElement[Any]]]
    body: Callable[[Any], dict[str, Any]]


def _object_columns() -> list[ColumnElement[Any]]:
    c = s.objects.c
    return [c.id, c.type, c.name, c.tags, c.meta, c.valid_to.is_(None).label("active"), c.synthetic, c.content_hash]


def _relationship_columns() -> list[ColumnElement[Any]]:
    c = s.relationships.c
    return [c.id, c.type, c.source_id, c.target_id, c.meta, c.valid_to.is_(None).label("active"), c.content_hash]


_CONTENT_TABLES = {
    "object": _ContentTable(
        s.objects,
        _object_columns,
        lambda row: object_body(
            row.type, row.name, row.tags or [], dict(row.meta or {}), bool(row.active), bool(row.synthetic)
        ),
    ),
    "relationship": _ContentTable(
        s.relationships,
        _relationship_columns,
        lambda row: relationship_body(row.type, row.source_id, row.target_id, dict(row.meta or {}), bool(row.active)),
    ),
}


def _row_contents(
    conn: Connection, kind: str, where: ColumnElement[bool], *, joined: Any = None
) -> Iterator[tuple[str, str | None, dict[str, Any]]]:
    """``(id, stored content hash, canonical content)`` of the rows of ``kind`` matching ``where``."""
    spec = _CONTENT_TABLES[kind]
    stmt = select(*spec.columns())
    if joined is not None:
        stmt = stmt.select_from(joined)
    for row in conn.execute(stmt.where(where)).yield_per(5000):
        yield row.id, row.content_hash, spec.body(row)


class Snapshot(RafModel):
    id: str
    name: str
    source: str
    description: str = ""
    created_at: datetime
    stats: dict[str, Any] = Field(default_factory=dict)
    content_hash: str


@dataclass
class StateView:
    """A comparable security state: per kind, item id -> content hash (+ bodies)."""

    label: str
    hashes: dict[str, dict[str, str]]
    bodies: dict[str, dict[str, Any]] = field(default_factory=dict)
    loader: Callable[[list[str]], dict[str, dict[str, Any]]] | None = None

    def body(self, hashes: Iterable[str]) -> dict[str, dict[str, Any]]:
        hashes = list(hashes)
        wanted = [h for h in set(hashes) if h not in self.bodies]
        if wanted and self.loader is not None:
            self.bodies.update(self.loader(wanted))
        return {h: self.bodies[h] for h in hashes if h in self.bodies}

    @classmethod
    def from_items(
        cls,
        label: str,
        objects: Iterable[SecurityObject],
        relationships: Iterable[Relationship],
        findings: Iterable[Any] = (),
    ) -> StateView:
        view = cls(label=label, hashes={k: {} for k in KINDS})
        for kind, items in (("object", objects), ("relationship", relationships), ("finding", findings)):
            for item in items:
                body = item_content(kind, item)
                digest = content_hash(body)
                view.hashes[kind][item.id] = digest
                view.bodies[digest] = body
        return view


StateProvider = Callable[[RafContext, str], StateView]
#: Prefix providers (e.g. "ghost") registered by products through the application layer.
STATE_PROVIDERS: dict[str, StateProvider] = {}


def validate_snapshot_name(name: str) -> str:
    if not _NAME_RE.match(name) or name.lower() == "current" or ":" in name:
        raise InvalidInputError(
            f"Invalid snapshot name '{name}'.", hint="Use letters, digits, '.', '_' or '-' (not 'current')."
        )
    return name


class SnapshotService:
    def __init__(self, store: Store) -> None:
        self.store = store

    # ------------------------------------------------------------------ create
    def create(
        self,
        name: str,
        *,
        source: str = "workspace",
        description: str = "",
        objects: Iterable[SecurityObject] | None = None,
        relationships: Iterable[Relationship] | None = None,
        findings: Iterable[Any] | None = None,
    ) -> Snapshot:
        """Snapshot the workspace (or the given items in place of its objects, relationships or findings)."""
        snapshot_id = self._new_id(name)
        given = {"object": objects, "relationship": relationships}
        finding_items = findings if findings is not None else self.store.findings.list(limit=1_000_000)
        with self.store.transaction() as conn:
            new_blobs = 0
            for kind, items in given.items():
                if items is None:
                    new_blobs += self._copy_table(conn, snapshot_id, kind)
                else:
                    new_blobs += self._insert_items(conn, snapshot_id, kind, _item_contents(kind, items))
            new_blobs += self._insert_items(conn, snapshot_id, "finding", _item_contents("finding", finding_items))
            self._finish(conn, name, snapshot_id, new_blobs, source, description)
        return self._created(name)

    def create_from_state(self, name: str, state: StateView, *, source: str, description: str = "") -> Snapshot:
        """Persist an in-memory state (e.g. a Ghost model) as a snapshot."""
        snapshot_id = self._new_id(name)
        rows = [(kind, item_id, digest) for kind in KINDS for item_id, digest in state.hashes.get(kind, {}).items()]
        bodies = state.body([digest for _k, _i, digest in rows])
        missing = {digest for _k, _i, digest in rows} - set(bodies)
        if missing:
            raise InvalidInputError(f"State '{state.label}' is missing {len(missing)} item bodies.")
        with self.store.transaction() as conn:
            new_blobs = self._add_blobs(conn, bodies)
            item_rows = [{"snapshot_id": snapshot_id, "kind": k, "item_id": i, "content_hash": h} for k, i, h in rows]
            for start in range(0, len(item_rows), 2000):
                conn.execute(s.snapshot_items.insert(), item_rows[start : start + 2000])
            self._finish(conn, name, snapshot_id, new_blobs, source, description)
        return self._created(name)

    def _new_id(self, name: str) -> str:
        validate_snapshot_name(name)
        if self.get(name) is not None:
            raise ConflictError(f"Snapshot '{name}' already exists.", suggestions=[f"raf snapshot delete {name}"])
        return f"snapshot:{name.lower()}"

    def _created(self, name: str) -> Snapshot:
        snapshot = self.get(name)
        assert snapshot is not None
        return snapshot

    def _insert_items(
        self, conn: Connection, snapshot_id: str, kind: str, contents: Iterable[tuple[str, dict[str, Any]]]
    ) -> int:
        """Store items whose content was computed in memory; returns the number of new blobs."""
        rows: list[dict[str, str]] = []
        bodies: dict[str, dict[str, Any]] = {}
        for item_id, body in contents:
            digest = content_hash(body)
            rows.append({"snapshot_id": snapshot_id, "kind": kind, "item_id": item_id, "content_hash": digest})
            bodies[digest] = body
        new_blobs = self._add_blobs(conn, bodies)
        for start in range(0, len(rows), 2000):
            conn.execute(s.snapshot_items.insert(), rows[start : start + 2000])
        return new_blobs

    def _copy_table(self, conn: Connection, snapshot_id: str, kind: str) -> int:
        """Store every row of the objects or relationships table; returns the number of new blobs.

        Rows without a content hash (written before hashes were kept, or ended in bulk) get one
        first. Bodies are computed only for content that no snapshot holds yet; an item costs one
        row copied by the database."""
        table = _CONTENT_TABLES[kind].table
        computed: list[tuple[str, str]] = []
        bodies: dict[str, dict[str, Any]] = {}
        for item_id, _h, body in _row_contents(conn, kind, table.c.content_hash.is_(None)):
            digest = content_hash(body)
            computed.append((item_id, digest))
            bodies[digest] = body
        self._store_hashes(conn, table, computed)
        new_blobs = self._add_blobs(conn, bodies)
        bodies, stale = {}, []
        unseen = table.outerjoin(s.blobs, s.blobs.c.hash == table.c.content_hash)
        for item_id, stored, body in _row_contents(conn, kind, s.blobs.c.hash.is_(None), joined=unseen):
            digest = content_hash(body)
            bodies[digest] = body
            if digest != stored:  # a hash that no longer matches its row: repair it
                stale.append((item_id, digest))
        self._store_hashes(conn, table, stale)
        new_blobs += self._add_blobs(conn, bodies)
        columns = ["snapshot_id", "kind", "item_id", "content_hash"]
        # in key order: the primary key index of snapshot_items grows at its end
        rows = select(literal(snapshot_id), literal(kind), table.c.id, table.c.content_hash).order_by(table.c.id)
        conn.execute(s.snapshot_items.insert().from_select(columns, rows))
        return new_blobs

    @staticmethod
    def _store_hashes(conn: Connection, table: Table, hashes: list[tuple[str, str]]) -> None:
        stmt = update(table).where(table.c.id == bindparam("item_id")).values(content_hash=bindparam("digest"))
        for start in range(0, len(hashes), 2000):
            conn.execute(stmt, [{"item_id": i, "digest": h} for i, h in hashes[start : start + 2000]])

    @staticmethod
    def _add_blobs(conn: Connection, bodies: dict[str, dict[str, Any]]) -> int:
        """Store the bodies no snapshot holds yet; returns how many were new."""
        hashes = sorted(bodies)
        existing: set[str] = set()
        for batch in chunks(hashes, 500):
            existing.update(r[0] for r in conn.execute(select(s.blobs.c.hash).where(s.blobs.c.hash.in_(batch))))
        blob_rows = [
            {"hash": h, "body": json.dumps(bodies[h], sort_keys=True, default=str)} for h in hashes if h not in existing
        ]
        upsert(conn, s.blobs, blob_rows, ["hash"], update=False)
        return len(blob_rows)

    def _finish(
        self, conn: Connection, name: str, snapshot_id: str, new_blobs: int, source: str, description: str
    ) -> None:
        """Record the snapshot: counts and the manifest hash over its sorted (kind, item, content) rows."""
        c = s.snapshot_items.c
        stmt = select(c.kind, c.item_id, c.content_hash).where(c.snapshot_id == snapshot_id)
        rows = [tuple(row) for row in conn.execute(stmt.order_by(c.kind, c.item_id)).all()]
        rows.sort()  # the order of Python strings, whatever the database's collation (already sorted: cheap)
        manifest = hashlib.sha256()
        counts = dict.fromkeys(KINDS, 0)
        for kind, item_id, digest in rows:
            manifest.update(f"{kind}\x1f{item_id}\x1f{digest}\n".encode())
            counts[kind] += 1
        distinct = len({digest for _k, _i, digest in rows})
        stats = {
            "objects": counts["object"],
            "relationships": counts["relationship"],
            "findings": counts["finding"],
            "new_blobs": new_blobs,
            "shared_blobs": distinct - new_blobs,
        }
        conn.execute(
            s.snapshots.insert().values(
                id=snapshot_id,
                name=name,
                source=source,
                description=description,
                created_at=utcnow(),
                stats=stats,
                content_hash=manifest.hexdigest(),
            )
        )

    # ------------------------------------------------------------------ read
    def get(self, name: str) -> Snapshot | None:
        key = name.split(":", 1)[1] if name.startswith("snapshot:") else name
        with self.store.engine.connect() as conn:
            row = conn.execute(select(s.snapshots).where(func.lower(s.snapshots.c.name) == key.lower())).first()
        if row is None:
            return None
        m = row._mapping
        return Snapshot(
            id=m["id"],
            name=m["name"],
            source=m["source"],
            description=m["description"],
            created_at=m["created_at"],
            stats=dict(m["stats"] or {}),
            content_hash=m["content_hash"],
        )

    def require(self, name: str) -> Snapshot:
        snapshot = self.get(name)
        if snapshot is None:
            raise NotFoundError(
                f"Snapshot '{name}' does not exist.", suggestions=["raf snapshot list", f"raf snapshot create {name}"]
            )
        return snapshot

    def list(self) -> list[Snapshot]:
        with self.store.engine.connect() as conn:
            rows = conn.execute(select(s.snapshots).order_by(s.snapshots.c.created_at)).all()
        return [
            Snapshot(
                id=r.id,
                name=r.name,
                source=r.source,
                description=r.description,
                created_at=r.created_at,
                stats=dict(r.stats or {}),
                content_hash=r.content_hash,
            )
            for r in rows
        ]

    def delete(self, name: str) -> dict[str, int]:
        """Delete a snapshot and the blobs that only it referenced."""
        snapshot = self.require(name)
        items_c = s.snapshot_items.c
        held = select(items_c.content_hash).where(items_c.snapshot_id == snapshot.id)
        elsewhere = select(items_c.content_hash).where(items_c.snapshot_id != snapshot.id)
        with self.store.transaction() as conn:
            orphaned = conn.execute(delete(s.blobs).where(s.blobs.c.hash.in_(held.except_(elsewhere)))).rowcount
            items = conn.execute(delete(s.snapshot_items).where(items_c.snapshot_id == snapshot.id)).rowcount
            conn.execute(delete(s.snapshots).where(s.snapshots.c.id == snapshot.id))
        return {"items": int(items or 0), "blobs_removed": int(orphaned or 0)}

    def item_hashes(self, snapshot_id: str) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {k: {} for k in KINDS}
        with self.store.engine.connect() as conn:
            stmt = select(s.snapshot_items.c.kind, s.snapshot_items.c.item_id, s.snapshot_items.c.content_hash).where(
                s.snapshot_items.c.snapshot_id == snapshot_id
            )
            for kind, item_id, digest in conn.execute(stmt).all():
                result.setdefault(kind, {})[item_id] = digest
        return result

    def load_bodies(self, hashes: builtins.list[str]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        with self.store.engine.connect() as conn:
            for batch in chunks(sorted(set(hashes)), 500):
                for digest, body in conn.execute(
                    select(s.blobs.c.hash, s.blobs.c.body).where(s.blobs.c.hash.in_(batch))
                ):
                    result[digest] = json.loads(body)
        return result

    # ------------------------------------------------------------------ states
    def current_state(self) -> StateView:
        """The workspace as a comparable state: stored content hashes; bodies computed from the rows when
        asked for (a row that changes in between is described as it is then)."""
        view = StateView(label="current", hashes={k: {} for k in KINDS})
        with self.store.engine.connect() as conn:
            for kind, spec in _CONTENT_TABLES.items():
                hashes = view.hashes[kind]
                for item_id, digest in conn.execute(select(spec.table.c.id, spec.table.c.content_hash)):
                    if digest is not None:
                        hashes[item_id] = digest
                for item_id, _h, body in _row_contents(conn, kind, spec.table.c.content_hash.is_(None)):
                    digest = content_hash(body)
                    hashes[item_id] = digest
                    view.bodies[digest] = body
        for item_id, body in _item_contents("finding", self.store.findings.list(limit=1_000_000)):
            digest = content_hash(body)
            view.hashes["finding"][item_id] = digest
            view.bodies[digest] = body
        view.loader = partial(self._current_bodies, view)
        return view

    def _current_bodies(self, view: StateView, wanted: builtins.list[str]) -> dict[str, dict[str, Any]]:
        """Bodies of current rows by the content hash ``view`` recorded for them."""
        remaining = set(wanted)
        result: dict[str, dict[str, Any]] = {}
        with self.store.engine.connect() as conn:
            for kind, spec in _CONTENT_TABLES.items():
                hashes = view.hashes[kind]
                ids: builtins.list[str] = []
                for item_id, digest in hashes.items():
                    if digest in remaining:
                        ids.append(item_id)
                        remaining.discard(digest)
                for batch in chunks(ids, 500):
                    for item_id, _h, body in _row_contents(conn, kind, spec.table.c.id.in_(batch)):
                        result[hashes[item_id]] = body
        return result

    def snapshot_state(self, name: str) -> StateView:
        snapshot = self.require(name)
        return StateView(label=snapshot.name, hashes=self.item_hashes(snapshot.id), loader=self.load_bodies)

    def materialize(
        self, name: str, *, propagation_only: bool = False, with_types: Collection[str] = ()
    ) -> tuple[builtins.list[SecurityObject], builtins.list[Relationship]]:
        """Rebuild objects and relationships of a snapshot (for graph algorithms over past states).

        ``propagation_only`` keeps what propagation uses (like
        :func:`~raf.core.graph.source.propagation_source`) and decodes only those bodies: a
        relationship ID determines its type and endpoints, so IDs that still exist in the workspace
        are classified there and only relationships that have since disappeared are decoded.
        ``with_types`` adds every relationship of those types whatever its endpoints, and the
        objects at their ends (an operation that edits such relationships sees all of them)."""
        snapshot = self.require(name)
        hashes = self.item_hashes(snapshot.id)
        object_hashes, rel_hashes = hashes["object"], hashes["relationship"]
        extra = frozenset(with_types)
        if propagation_only:
            excluded = sorted(NON_PROPAGATING_TYPES)
            all_objects = object_hashes
            object_hashes = {i: h for i, h in all_objects.items() if i.split(":", 1)[0] not in NON_PROPAGATING_TYPES}
            relevant = self.store.relationships.ids(
                types=sorted(PROPAGATION_RELATIONSHIPS), exclude_endpoint_types=excluded
            )
            if extra:
                relevant |= self.store.relationships.ids(types=sorted(extra))
            existing = self.store.relationships.ids()
            rel_hashes = {i: h for i, h in rel_hashes.items() if i in relevant or i not in existing}
        rel_bodies = self.load_bodies(builtins.list(rel_hashes.values()))
        kept = {
            item_id: rel_bodies[digest]
            for item_id, digest in rel_hashes.items()
            if not propagation_only or rel_bodies[digest]["type"] in extra or _propagates(rel_bodies[digest])
        }
        if propagation_only:
            for body in kept.values():
                for end in (body["source"], body["target"]) if body["type"] in extra else ():
                    if end in all_objects:
                        object_hashes.setdefault(end, all_objects[end])
        bodies = self.load_bodies(builtins.list(object_hashes.values()))
        when = snapshot.created_at
        # bodies were written by R$F from validated models: construct without re-validating
        objects = []
        for item_id, digest in object_hashes.items():
            body = bodies[digest]
            objects.append(
                build_object(
                    id=item_id,
                    type=body["type"],
                    name=body["name"],
                    created_at=when,
                    updated_at=when,
                    tags=body["tags"],
                    metadata=body["metadata"],
                    synthetic=body.get("synthetic", False),
                    valid_to=None if body.get("active", True) else when,
                )
            )
        relationships = [
            build_relationship(
                id=item_id,
                relationship_type=body["type"],
                source_object=body["source"],
                target_object=body["target"],
                metadata=body["metadata"],
                created_at=when,
                updated_at=when,
                valid_to=None if body.get("active", True) else when,
            )
            for item_id, body in kept.items()
        ]
        return objects, relationships

    def item_ids(self, name: str, kind: str = "relationship") -> set[str]:
        """IDs of one kind of item in a snapshot, without loading anything else."""
        snapshot = self.require(name)
        with self.store.engine.connect() as conn:
            stmt = select(s.snapshot_items.c.item_id).where(
                s.snapshot_items.c.snapshot_id == snapshot.id, s.snapshot_items.c.kind == kind
            )
            return {row[0] for row in conn.execute(stmt)}


def _propagates(body: dict[str, Any]) -> bool:
    """Whether propagation can use a relationship (its type, and no endpoint it never enters)."""
    return (
        body["type"] in PROPAGATION_RELATIONSHIPS
        and body["source"].split(":", 1)[0] not in NON_PROPAGATING_TYPES
        and body["target"].split(":", 1)[0] not in NON_PROPAGATING_TYPES
    )


def resolve_state(ctx: RafContext, ref: str) -> StateView:
    """``current``, a snapshot name, or ``<provider>:<name>`` (e.g. ``ghost:hardened``)."""
    service = SnapshotService(ctx.store)
    if ref.lower() in ("current", "now", "@workspace"):
        return service.current_state()
    if ":" in ref and not ref.startswith("snapshot:"):
        prefix, name = ref.split(":", 1)
        provider = STATE_PROVIDERS.get(prefix)
        if provider is None:
            raise InvalidInputError(
                f"Unknown state provider '{prefix}'.", hint="Use 'current', a snapshot name, or ghost:<model>."
            )
        return provider(ctx, name)
    if ctx.refs is not None and ref.startswith("@"):
        _kind, stored = ctx.refs.resolve(ref, accept=("snapshot",))
        ref = stored
    return service.snapshot_state(ref)
