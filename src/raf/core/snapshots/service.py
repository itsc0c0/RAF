"""Security-state snapshots with structural sharing.

A snapshot records, for every object, relationship and finding, the hash of
its *canonical content* (bookkeeping such as ``updated_at``/``last_seen``/
observation counts is excluded so re-observing the same state does not look
like change). Bodies live once in the content-addressed ``blobs`` table and are
shared by every snapshot that contains the same content; an unchanged item
costs one index row, not a copy.

States can come from the workspace ("current"), a stored snapshot, or a
registered provider (Ghost registers ``ghost:<model>``).
"""

from __future__ import annotations

import builtins
import hashlib
import json
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import Field
from sqlalchemy import delete, func, select

from raf.core.context.app import RafContext
from raf.core.errors import ConflictError, InvalidInputError, NotFoundError
from raf.core.objects.models import RafModel, Relationship, SecurityObject, build_object, build_relationship
from raf.core.objects.semantics import NON_PROPAGATING_TYPES, PROPAGATION_RELATIONSHIPS
from raf.core.storage import schema as s
from raf.core.storage.database import chunks, upsert
from raf.core.storage.store import Store
from raf.core.timeutil import utcnow

KINDS = ("object", "relationship", "finding")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_VOLATILE_META = {"state_changed_at", "status_history", "last_scan", "scanned_at"}


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in sorted(value.items()) if k not in _VOLATILE_META}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value


def object_content(obj: SecurityObject) -> dict[str, Any]:
    return {
        "type": obj.type,
        "name": obj.name,
        "tags": sorted(obj.tags),
        "metadata": _canonical(obj.metadata),
        "active": obj.valid_to is None,
        "synthetic": obj.synthetic,
    }


def relationship_content(rel: Relationship) -> dict[str, Any]:
    meta = {k: v for k, v in rel.metadata.items() if k not in ("via",)}
    return {
        "type": rel.relationship_type,
        "source": rel.source_object,
        "target": rel.target_object,
        "metadata": _canonical(meta),
        "active": rel.valid_to is None,
    }


def finding_content(finding: Any) -> dict[str, Any]:
    return {
        "title": finding.title,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "product": finding.product,
        "rule_id": finding.rule_id,
        "affected": sorted(finding.affected_objects),
        "confidence": round(float(finding.confidence), 2),
    }


def item_content(kind: str, item: Any) -> dict[str, Any]:
    if kind == "object":
        return object_content(item)
    if kind == "relationship":
        return relationship_content(item)
    return finding_content(item)


def _item_contents(kind: str, items: Iterable[Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for item in items:
        yield item.id, item_content(kind, item)


def _object_contents(store: Store) -> Iterator[tuple[str, dict[str, Any]]]:
    """``(id, object_content)`` for every stored object, read straight from the table: no model
    objects and no timestamp conversions (snapshots of large workspaces stay fast)."""
    c = s.objects.c
    stmt = select(c.id, c.type, c.name, c.tags, c.meta, c.valid_to.is_(None).label("active"), c.synthetic)
    with store.engine.connect() as conn:
        for row in conn.execute(stmt.order_by(c.id)).yield_per(5000):
            yield (
                row.id,
                {
                    "type": row.type,
                    "name": row.name,
                    "tags": sorted(row.tags or []),
                    "metadata": _canonical(dict(row.meta or {})),
                    "active": bool(row.active),
                    "synthetic": bool(row.synthetic),
                },
            )


def _relationship_contents(store: Store) -> Iterator[tuple[str, dict[str, Any]]]:
    """``(id, relationship_content)`` for every stored relationship (see :func:`_object_contents`)."""
    c = s.relationships.c
    stmt = select(c.id, c.type, c.source_id, c.target_id, c.meta, c.valid_to.is_(None).label("active"))
    with store.engine.connect() as conn:
        for row in conn.execute(stmt.order_by(c.id)).yield_per(5000):
            meta = {k: v for k, v in (row.meta or {}).items() if k not in ("via",)}
            yield (
                row.id,
                {
                    "type": row.type,
                    "source": row.source_id,
                    "target": row.target_id,
                    "metadata": _canonical(meta),
                    "active": bool(row.active),
                },
            )


def content_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


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
        validate_snapshot_name(name)
        snapshot_id = f"snapshot:{name.lower()}"
        if self.get(name) is not None:
            raise ConflictError(f"Snapshot '{name}' already exists.", suggestions=[f"raf snapshot delete {name}"])
        sources = {
            "object": _item_contents("object", objects) if objects is not None else _object_contents(self.store),
            "relationship": _item_contents("relationship", relationships)
            if relationships is not None
            else _relationship_contents(self.store),
            "finding": _item_contents(
                "finding", findings if findings is not None else self.store.findings.list(limit=1_000_000)
            ),
        }
        counts = {"object": 0, "relationship": 0, "finding": 0}
        pending: dict[str, dict[str, Any]] = {}
        rows: list[tuple[str, str, str]] = []
        for kind, contents in sources.items():
            for item_id, body in contents:
                digest = content_hash(body)
                rows.append((kind, item_id, digest))
                counts[kind] += 1
                pending[digest] = body
        return self._store(name, snapshot_id, rows, pending, counts, source, description)

    def create_from_state(self, name: str, state: StateView, *, source: str, description: str = "") -> Snapshot:
        """Persist an in-memory state (e.g. a Ghost model) as a snapshot."""
        validate_snapshot_name(name)
        snapshot_id = f"snapshot:{name.lower()}"
        if self.get(name) is not None:
            raise ConflictError(f"Snapshot '{name}' already exists.", suggestions=[f"raf snapshot delete {name}"])
        rows = [(kind, item_id, digest) for kind in KINDS for item_id, digest in state.hashes.get(kind, {}).items()]
        pending = state.body([digest for _k, _i, digest in rows])
        missing = {digest for _k, _i, digest in rows} - set(pending)
        if missing:
            raise InvalidInputError(f"State '{state.label}' is missing {len(missing)} item bodies.")
        counts = {kind: len(state.hashes.get(kind, {})) for kind in KINDS}
        return self._store(name, snapshot_id, rows, pending, counts, source, description)

    def _store(
        self,
        name: str,
        snapshot_id: str,
        rows: list[tuple[str, str, str]],
        pending: dict[str, dict[str, Any]],
        counts: dict[str, int],
        source: str,
        description: str,
    ) -> Snapshot:
        manifest = hashlib.sha256()
        rows.sort()
        for kind, item_id, digest in rows:
            manifest.update(f"{kind}\x1f{item_id}\x1f{digest}\n".encode())
        with self.store.transaction() as conn:
            hashes = sorted(pending)
            existing: set[str] = set()
            for batch in chunks(hashes, 500):
                existing.update(r[0] for r in conn.execute(select(s.blobs.c.hash).where(s.blobs.c.hash.in_(batch))))
            blob_rows = [
                {"hash": h, "body": json.dumps(pending[h], sort_keys=True, default=str)}
                for h in hashes
                if h not in existing
            ]
            upsert(conn, s.blobs, blob_rows, ["hash"], update=False)
            item_rows = [{"snapshot_id": snapshot_id, "kind": k, "item_id": i, "content_hash": h} for k, i, h in rows]
            for start in range(0, len(item_rows), 2000):
                conn.execute(s.snapshot_items.insert(), item_rows[start : start + 2000])
            stats = {
                "objects": counts.get("object", 0),
                "relationships": counts.get("relationship", 0),
                "findings": counts.get("finding", 0),
                "new_blobs": len(blob_rows),
                "shared_blobs": len(hashes) - len(blob_rows),
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
        snapshot = self.get(name)
        assert snapshot is not None
        return snapshot

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
        snapshot = self.require(name)
        with self.store.transaction() as conn:
            items = conn.execute(delete(s.snapshot_items).where(s.snapshot_items.c.snapshot_id == snapshot.id)).rowcount
            conn.execute(delete(s.snapshots).where(s.snapshots.c.id == snapshot.id))
            referenced = select(s.snapshot_items.c.content_hash).distinct()
            orphaned = conn.execute(delete(s.blobs).where(s.blobs.c.hash.not_in(referenced))).rowcount
        return {"items": int(items or 0), "blobs_removed": int(orphaned or 0)}

    def item_hashes(self, snapshot_id: str) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {k: {} for k in KINDS}
        with self.store.engine.connect() as conn:
            stmt = select(s.snapshot_items.c.kind, s.snapshot_items.c.item_id, s.snapshot_items.c.content_hash).where(
                s.snapshot_items.c.snapshot_id == snapshot_id
            )
            for kind, item_id, digest in conn.execute(stmt).yield_per(5000):
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
        view = StateView(label="current", hashes={k: {} for k in KINDS})
        for kind, contents in (
            ("object", _object_contents(self.store)),
            ("relationship", _relationship_contents(self.store)),
            ("finding", _item_contents("finding", self.store.findings.list(limit=1_000_000))),
        ):
            for item_id, body in contents:
                digest = content_hash(body)
                view.hashes[kind][item_id] = digest
                view.bodies[digest] = body
        return view

    def snapshot_state(self, name: str) -> StateView:
        snapshot = self.require(name)
        return StateView(label=snapshot.name, hashes=self.item_hashes(snapshot.id), loader=self.load_bodies)

    def materialize(
        self, name: str, *, propagation_only: bool = False
    ) -> tuple[builtins.list[SecurityObject], builtins.list[Relationship]]:
        """Rebuild objects and relationships of a snapshot (for graph algorithms over past states).

        ``propagation_only`` keeps what propagation uses (like
        :func:`~raf.core.graph.source.propagation_source`) and decodes only those bodies: a
        relationship ID determines its type and endpoints, so IDs that still exist in the workspace
        are classified there and only relationships that have since disappeared are decoded."""
        snapshot = self.require(name)
        hashes = self.item_hashes(snapshot.id)
        object_hashes, rel_hashes = hashes["object"], hashes["relationship"]
        if propagation_only:
            excluded = sorted(NON_PROPAGATING_TYPES)
            object_hashes = {i: h for i, h in object_hashes.items() if i.split(":", 1)[0] not in NON_PROPAGATING_TYPES}
            relevant = self.store.relationships.ids(
                types=sorted(PROPAGATION_RELATIONSHIPS), exclude_endpoint_types=excluded
            )
            existing = self.store.relationships.ids()
            rel_hashes = {i: h for i, h in rel_hashes.items() if i in relevant or i not in existing}
        bodies = self.load_bodies([*object_hashes.values(), *rel_hashes.values()])
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
        relationships = []
        for item_id, digest in rel_hashes.items():
            body = bodies[digest]
            if propagation_only and not (
                body["type"] in PROPAGATION_RELATIONSHIPS
                and body["source"].split(":", 1)[0] not in NON_PROPAGATING_TYPES
                and body["target"].split(":", 1)[0] not in NON_PROPAGATING_TYPES
            ):
                continue
            relationships.append(
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
            )
        return objects, relationships

    def item_ids(self, name: str, kind: str = "relationship") -> set[str]:
        """IDs of one kind of item in a snapshot, without loading anything else."""
        snapshot = self.require(name)
        with self.store.engine.connect() as conn:
            stmt = select(s.snapshot_items.c.item_id).where(
                s.snapshot_items.c.snapshot_id == snapshot.id, s.snapshot_items.c.kind == kind
            )
            return {row[0] for row in conn.execute(stmt)}


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
