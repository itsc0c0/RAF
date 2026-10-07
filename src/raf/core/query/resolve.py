"""Resolution of user-supplied references to canonical entities.

Accepted forms: full IDs (``host:ws-04``), type-qualified names (via the
``types`` argument), bare names or aliases (``alice``, ``WS-04``,
``production``), human IDs (``analysis-3``, ``job-12``), and context tokens
(``@last``). When a bare name matches several objects of different types, a
documented type priority decides and the caller receives a note naming the
alternatives; same-type ambiguity is an error listing the candidates.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import select

from raf.core.context.refs import ContextRefs
from raf.core.errors import AmbiguousReferenceError, InvalidInputError, NotFoundError
from raf.core.ids import normalize_key, try_split_id
from raf.core.objects.models import SecurityObject
from raf.core.objects.types import ObjectType
from raf.core.storage import schema as s
from raf.core.storage.store import Store

TYPE_PRIORITY: tuple[str, ...] = (
    "incident",
    "user",
    "host",
    "identity",
    "service",
    "group",
    "role",
    "network",
    "cloud_resource",
    "container",
    "domain",
    "ip",
    "project",
    "package",
    "vulnerability",
    "policy",
    "organization",
    "permission",
    "process",
    "file",
    "directory",
    "url",
    "certificate",
    "secret",
    "session",
    "connection",
    "port",
    "dependency",
    "alert",
    "evidence",
)
_HUMAN_ID_RE = re.compile(r"^(analysis|job)-\d+$")


@dataclass(slots=True)
class Resolved:
    kind: str  # object | event | finding | snapshot | analysis | job
    id: str
    obj: SecurityObject | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.obj.name if self.obj is not None else self.id


class Resolver:
    def __init__(self, store: Store, refs: ContextRefs | None = None) -> None:
        self.store = store
        self.refs = refs

    def resolve(self, ref: str, *, types: Sequence[str] | None = None, accept: Sequence[str] = ("object",)) -> Resolved:
        text = ref.strip()
        if not text:
            raise InvalidInputError("Empty reference.")
        if self.refs is not None and ContextRefs.is_reference(text):
            context_kinds = {
                "object": ("object",),
                "incident": ("incident",),
                "analysis": ("analysis",),
                "snapshot": ("snapshot",),
                "job": ("job",),
            }
            allowed: list[str] = []
            for kind in accept:
                allowed.extend(context_kinds.get(kind, (kind,)))
            if "object" in accept:
                allowed.extend(["incident", "case", "range", "lab", "ghost"])
            kind, stored = self.refs.resolve(text, accept=allowed)
            resolved = self.resolve(stored, types=types if kind == "object" else None, accept=accept)
            resolved.notes.append(f"{text} -> {stored}")
            return resolved

        if _HUMAN_ID_RE.match(text):
            kind = text.split("-", 1)[0]
            if kind in accept:
                return Resolved(kind=kind, id=text)
            raise InvalidInputError(f"'{text}' is a {kind} ID, which this command does not accept.")

        split = try_split_id(text)
        if split is not None:
            otype, key = split
            if otype == ObjectType.EVENT:
                event = self.store.events.get(text)
                if event is None:
                    raise NotFoundError(f"Event '{text}' does not exist.")
                return Resolved(kind="event", id=event.id)
            if otype == ObjectType.FINDING:
                self.store.findings.require(text)
                return Resolved(kind="finding", id=text)
            if otype == ObjectType.SNAPSHOT:
                return Resolved(kind="snapshot", id=text)
            if types and otype not in types:
                raise InvalidInputError(f"'{text}' is a {otype}, expected {', '.join(types)}.")
            obj = self.store.objects.get(text)
            if obj is None:
                normalized = f"{otype}:{normalize_key(otype, key)}"
                obj = self.store.objects.get(normalized)
            if obj is not None:
                return Resolved(kind="object", id=obj.id, obj=obj)
            # fall through: maybe a name containing ':' (e.g. "svc:deploy")

        candidates = self.store.objects.find_by_name(text, types)
        if not candidates and types:
            for otype in types:
                try:
                    obj = self.store.objects.get(f"{otype}:{normalize_key(otype, text)}")
                except InvalidInputError:
                    continue
                if obj is not None:
                    candidates.append(obj)
        if not candidates and (types is None or ObjectType.INCIDENT in types):
            candidates = self._case_incident(text)
        if not candidates:
            similar = self.store.objects.search(text, types=types, limit=5)
            suggestion = [f"raf show {o.id}" for o in similar]
            raise NotFoundError(
                f"No object named '{text}'"
                + (f" of type {', '.join(types)}" if types else "")
                + " exists in this workspace.",
                hint=("Similar: " + ", ".join(o.id for o in similar))
                if similar
                else "Import data first (raf analyze <file>) or load the demo (raf demo load).",
                suggestions=suggestion or ["raf search " + text],
            )
        if len(candidates) == 1:
            return Resolved(kind="object", id=candidates[0].id, obj=candidates[0])
        return self._disambiguate(text, candidates)

    def _case_incident(self, text: str) -> list[SecurityObject]:
        with self.store.engine.connect() as c:
            row = c.execute(select(s.cases.c.incident_id).where(s.cases.c.name == text.upper())).first()
        if row and row[0]:
            obj = self.store.objects.get(row[0])
            return [obj] if obj else []
        return []

    def _disambiguate(self, text: str, candidates: list[SecurityObject]) -> Resolved:
        by_type: dict[str, list[SecurityObject]] = {}
        for obj in candidates:
            by_type.setdefault(obj.type, []).append(obj)
        ordered = sorted(by_type, key=lambda t: TYPE_PRIORITY.index(t) if t in TYPE_PRIORITY else len(TYPE_PRIORITY))
        best = by_type[ordered[0]]
        if len(best) > 1:
            raise AmbiguousReferenceError(text, [o.id for o in candidates])
        others = [o.id for o in candidates if o.id != best[0].id]
        note = f"'{text}' also matches {', '.join(others)}; using {best[0].id} (use a full ID to choose)."
        return Resolved(kind="object", id=best[0].id, obj=best[0], notes=[note])
