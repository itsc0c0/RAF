"""R$F Trace: how did this object become involved, and what did it do?

Links are built from events (and supporting inventory relationships):

* **observed** links come straight from a single event's fields (a parent
  process id, the actor of a login, the process that wrote a file). Their
  confidence is the event's confidence.
* **correlated** links connect facts that are consistent in time and
  structure (a credential file was read shortly before that credential was
  used; a session was open on the host an identity authenticated from).
  They are labeled as correlation, never as proven causation, and carry
  lower confidence.

Backward traversal only follows causes that precede their effect; forward
traversal only follows effects after their cause.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.objects.models import Event, RafModel, SecurityObject
from raf.core.objects.types import ObjectType
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import format_ts

_PER_RULE = 25
_RECENT = 5
_MAX_LINKS = 400
_SESSION_WINDOW = timedelta(hours=2)


class TraceLink(RafModel):
    cause: str
    effect: str
    relation: str
    kind: str  # observed | correlated
    confidence: float
    timestamp: datetime
    event_id: str | None = None
    explanation: str
    provenance: dict[str, Any] = Field(default_factory=dict)
    direction: str  # backward | forward
    step: int = 0
    parent_step: int | None = None
    corroborated_by: list[dict[str, Any]] = Field(default_factory=list)


class TraceNode(RafModel):
    id: str
    name: str
    type: str
    depth: int
    direction: str


class TraceResult(RafModel):
    subject: TraceNode
    nodes: list[TraceNode]
    backward: list[TraceLink]
    forward: list[TraceLink]
    chain: list[TraceLink] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


@dataclass(slots=True)
class _Frontier:
    object_id: str
    depth: int
    bound: datetime | None  # backward: causes must be <= bound; forward: effects >= bound


def _prov(ev: Event) -> dict[str, Any]:
    return {"source": ev.source, "record": ev.record, "parser": ev.parser, "raw_reference": ev.raw_reference}


class TraceService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.window = timedelta(minutes=int(ctx.settings.get("trace.correlation_window_minutes")))
        self._objects: dict[str, SecurityObject] = {}
        self._ip_host: dict[str, str | None] = {}

    # ------------------------------------------------------------------ helpers
    def _obj(self, object_id: str) -> SecurityObject | None:
        if object_id not in self._objects:
            found = self.store.objects.get(object_id)
            if found is not None:
                self._objects[object_id] = found
        return self._objects.get(object_id)

    def _name(self, object_id: str) -> str:
        obj = self._obj(object_id)
        return obj.name if obj else object_id.split(":", 1)[-1]

    def _type(self, object_id: str) -> str:
        return object_id.split(":", 1)[0]

    def _host_of_ip(self, ip_id: str) -> str | None:
        if ip_id not in self._ip_host:
            rels = self.store.relationships.list(target=ip_id, types=["HAS_ADDRESS"], limit=5)
            hosts = sorted(r.source_object for r in rels if r.source_object.startswith("host:"))
            self._ip_host[ip_id] = hosts[0] if hosts else None
        return self._ip_host[ip_id]

    def _events(
        self,
        object_id: str,
        *,
        before: datetime | None = None,
        after: datetime | None = None,
        types: list[str] | None = None,
        limit: int = 500,
    ) -> list[Event]:
        query = EventQuery(object_ids=[object_id], event_types=types, end=before, start=after)
        return self.store.events.query(query, limit=limit, descending=before is not None).items

    @staticmethod
    def _role(ev: Event, role: str) -> str | None:
        for ref in ev.objects:
            if ref.role == role:
                return ref.object_id
        return None

    # ------------------------------------------------------------------ backward rules
    def _causes(self, node: _Frontier) -> list[TraceLink]:
        x = node.object_id
        xtype = self._type(x)
        links: list[TraceLink] = []
        events = self._events(x, before=node.bound)

        def link(
            cause: str | None,
            relation: str,
            ev: Event,
            explanation: str,
            kind: str = "observed",
            confidence: float | None = None,
        ) -> None:
            if not cause or cause == x:
                return
            links.append(
                TraceLink(
                    cause=cause,
                    effect=x,
                    relation=relation,
                    kind=kind,
                    confidence=round(confidence if confidence is not None else ev.confidence, 3),
                    timestamp=ev.timestamp,
                    event_id=ev.id,
                    explanation=explanation,
                    provenance=_prov(ev),
                    direction="backward",
                )
            )

        for ev in events:
            if len(links) >= _PER_RULE * 3:
                break
            et = ev.event_type
            if xtype == ObjectType.PROCESS and ev.target == x and et == "process.start":
                link(self._role(ev, "parent"), "SPAWNED", ev, f"{self._name(x)} was spawned by its parent process")
                if ev.actor and self._type(ev.actor) in (ObjectType.USER, ObjectType.IDENTITY):
                    link(ev.actor, "STARTED", ev, f"{self._name(ev.actor)} started {self._name(x)}")
            elif xtype == ObjectType.FILE and ev.target == x and et.startswith("file."):
                actor = self._role(ev, "process") or ev.actor
                link(
                    actor, et.split(".")[1].upper(), ev, f"{self._name(actor or '')} performed {et} on {self._name(x)}"
                )
            elif (
                xtype in (ObjectType.USER, ObjectType.IDENTITY)
                and ev.actor == x
                and et.startswith("auth.")
                and ev.outcome != "failure"
            ):
                src = self._role(ev, "src_ip")
                if src:
                    host = self._host_of_ip(src)
                    origin = host or src
                    detail = f"{self._name(src)}" + (f" ({self._name(host)}'s address)" if host else "")
                    link(
                        origin,
                        "AUTHENTICATED_FROM",
                        ev,
                        f"{self._name(x)} authenticated to {self._name(ev.target or '')} from {detail}",
                        confidence=ev.confidence * 0.95,
                    )
            elif (
                xtype in (ObjectType.USER, ObjectType.IDENTITY)
                and ev.target == x
                and et.startswith("iam.")
                and not et.endswith((".remove", ".revoke", ".disable"))
            ):
                link(ev.actor, "CHANGED_ACCESS", ev, f"{self._name(ev.actor or '')} ran {et} on {self._name(x)}")
            elif (
                xtype == ObjectType.HOST
                and ev.target == x
                and et in ("auth.login", "auth.privilege")
                and ev.outcome != "failure"
            ):
                link(
                    ev.actor,
                    "LOGGED_INTO" if et == "auth.login" else "ELEVATED_ON",
                    ev,
                    f"{self._name(ev.actor or '')} accessed {self._name(x)}",
                )
            elif (
                xtype in (ObjectType.IP, ObjectType.HOST)
                and ev.target == x
                and et.startswith("network.")
                and ev.outcome != "failure"
            ):
                link(ev.actor, "CONNECTED_TO", ev, f"{self._name(ev.actor or '')} connected to {self._name(x)}")
            elif xtype == ObjectType.DOMAIN and ev.target == x and et == "dns.query":
                link(ev.actor, "QUERIED", ev, f"{self._name(ev.actor or '')} resolved {self._name(x)}")
            elif xtype == ObjectType.IP and et == "dns.query" and self._role(ev, "answer") == x:
                link(ev.target, "RESOLVED_TO", ev, f"{self._name(ev.target or '')} resolved to {self._name(x)}")
            elif xtype == ObjectType.URL and ev.target == x and et == "http.request":
                link(ev.actor, "REQUESTED", ev, f"{self._name(ev.actor or '')} requested {self._name(x)}")
        links.extend(self._correlations(node, events))
        links = _corroborate(links)
        per_relation: dict[str, int] = {}
        focused: list[TraceLink] = []
        for lk in sorted(links, key=lambda lk: lk.timestamp, reverse=True):
            count = per_relation.get(lk.relation, 0)
            if count < _RECENT:
                per_relation[lk.relation] = count + 1
                focused.append(lk)
        return focused

    def _correlations(self, node: _Frontier, events: list[Event]) -> list[TraceLink]:
        x = node.object_id
        xtype = self._type(x)
        links: list[TraceLink] = []
        if xtype in (ObjectType.IDENTITY, ObjectType.USER):
            uses = [e for e in events if e.actor == x and e.event_type == "auth.login" and e.outcome != "failure"]
            if not uses:
                return links
            # 1) credential exposure: a file holding a secret that authenticates as X was read before X was used
            for secret_rel in self.store.relationships.list(target=x, types=["AUTHENTICATES_AS"], limit=20):
                for holder in self.store.relationships.list(
                    target=secret_rel.source_object, types=["CONTAINS_SECRET"], limit=20
                ):
                    if self._type(holder.source_object) != ObjectType.FILE:
                        continue
                    for read in self._events(holder.source_object, before=node.bound, types=["file.read"], limit=20):
                        later = [u for u in uses if u.timestamp >= read.timestamp]
                        if not later:
                            continue
                        use = min(later, key=lambda e: e.timestamp)
                        gap = use.timestamp - read.timestamp
                        reader = self._role(read, "process") or read.actor
                        if gap > self.window or not reader:
                            continue
                        links.append(
                            TraceLink(
                                cause=reader,
                                effect=x,
                                relation="CREDENTIAL_EXPOSURE",
                                kind="correlated",
                                confidence=round(min(0.65, read.confidence * 0.7), 3),
                                timestamp=read.timestamp,
                                event_id=read.id,
                                direction="backward",
                                explanation=(
                                    f"{self._name(holder.source_object)} holds a credential that authenticates "
                                    f"as {self._name(x)}; it was read by {self._name(reader)} "
                                    f"{_duration(gap)} before {self._name(x)} authenticated to "
                                    f"{self._name(use.target or '')}. Correlation, not proof."
                                ),
                                provenance=_prov(read),
                            )
                        )
            # 2) session context: another principal had an open session on the host X authenticated from
            for use in uses[:5]:
                src = self._role(use, "src_ip")
                host = self._host_of_ip(src) if src else None
                if not host:
                    continue
                recent = self._events(
                    host,
                    before=use.timestamp,
                    after=use.timestamp - _SESSION_WINDOW,
                    types=["auth.login", "auth.logout"],
                    limit=50,
                )
                for login in recent:
                    if (
                        login.event_type != "auth.login"
                        or login.target != host
                        or not login.actor
                        or login.actor == x
                        or login.outcome == "failure"
                    ):
                        continue
                    closed = any(
                        e.event_type == "auth.logout"
                        and e.actor == login.actor
                        and login.timestamp <= e.timestamp <= use.timestamp
                        for e in recent
                    )
                    if closed:
                        continue
                    links.append(
                        TraceLink(
                            cause=login.actor,
                            effect=x,
                            relation="SESSION_CONTEXT",
                            kind="correlated",
                            confidence=0.4,
                            timestamp=login.timestamp,
                            event_id=login.id,
                            direction="backward",
                            explanation=(
                                f"{self._name(login.actor)} had an open session on {self._name(host)} "
                                f"({_duration(use.timestamp - login.timestamp)} before {self._name(x)} "
                                f"authenticated from that host). Correlation, not proof."
                            ),
                            provenance=_prov(login),
                        )
                    )
        if xtype == ObjectType.IP:
            for ev in events:
                if ev.target != x or not ev.event_type.startswith("network."):
                    continue
                for dns in self._events(
                    x, before=ev.timestamp, after=ev.timestamp - self.window, types=["dns.query"], limit=10
                ):
                    if dns.actor == ev.actor and dns.target:
                        links.append(
                            TraceLink(
                                cause=dns.target,
                                effect=x,
                                relation="RESOLUTION_BEFORE_CONNECTION",
                                kind="correlated",
                                confidence=0.7,
                                timestamp=dns.timestamp,
                                event_id=dns.id,
                                direction="backward",
                                explanation=(
                                    f"{self._name(ev.actor or '')} resolved {self._name(dns.target)} to "
                                    f"{self._name(x)} before connecting to it."
                                ),
                                provenance=_prov(dns),
                            )
                        )
                        break
        return links[:_PER_RULE]

    # ------------------------------------------------------------------ forward rules
    def _effects(self, node: _Frontier) -> list[TraceLink]:
        x = node.object_id
        links: list[TraceLink] = []
        for ev in self._events(x, after=node.bound, limit=400):
            if len(links) >= _PER_RULE * 3:
                break
            et = ev.event_type
            effect: str | None = None
            relation = et.upper().replace(".", "_")
            if ev.actor == x and ev.target and ev.outcome != "failure":
                effect = ev.target
                relation = {
                    "auth.login": "LOGGED_INTO",
                    "process.start": "STARTED",
                    "dns.query": "QUERIED",
                    "http.request": "REQUESTED",
                    "network.connection": "CONNECTED_TO",
                }.get(et, relation)
            elif self._role(ev, "parent") == x and et == "process.start":
                effect, relation = ev.target, "SPAWNED"
            elif self._role(ev, "process") == x and et.startswith("file."):
                effect, relation = ev.target, et.split(".")[1].upper()
            elif self._role(ev, "host") == x and et == "process.start":
                effect, relation = ev.target, "RAN"
            if not effect or effect == x:
                continue
            links.append(
                TraceLink(
                    cause=x,
                    effect=effect,
                    relation=relation,
                    kind="observed",
                    confidence=round(ev.confidence, 3),
                    timestamp=ev.timestamp,
                    event_id=ev.id,
                    explanation=f"{self._name(x)} → {relation} → {self._name(effect)} ({et})",
                    provenance=_prov(ev),
                    direction="forward",
                )
            )
        return _corroborate(links)

    # ------------------------------------------------------------------ driver
    def trace(self, subject_id: str, *, direction: str = "both", depth: int = 3) -> TraceResult:
        subject = self._obj(subject_id)
        subject_node = TraceNode(
            id=subject_id, name=self._name(subject_id), type=self._type(subject_id), depth=0, direction="subject"
        )
        nodes: dict[str, TraceNode] = {subject_id: subject_node}
        backward: list[TraceLink] = []
        forward: list[TraceLink] = []
        notes: list[str] = []
        if subject is None:
            notes.append("Subject is not stored as an object; only event references are traced.")
        if direction in ("both", "back", "backward"):
            backward = self._walk(subject_id, depth, nodes, backward=True)
        if direction in ("both", "forward", "fwd"):
            forward = self._walk(subject_id, depth, nodes, backward=False)
        chain = self._best_chain(subject_id, backward)
        if any(link.kind == "correlated" for link in backward):
            notes.append("Correlated links are consistent in time and structure but are not proven causation.")
        return TraceResult(
            subject=subject_node,
            nodes=list(nodes.values()),
            backward=backward,
            forward=forward,
            chain=chain,
            notes=notes,
        )

    def _walk(self, start: str, depth: int, nodes: dict[str, TraceNode], *, backward: bool) -> list[TraceLink]:
        frontier: list[tuple[_Frontier, int | None]] = [(_Frontier(start, 0, None), None)]
        links: list[TraceLink] = []
        seen_links: set[tuple[str, str, str, str | None]] = set()
        visited: set[tuple[str, datetime | None]] = {(start, None)}
        while frontier and len(links) < _MAX_LINKS:
            current, parent_step = frontier.pop(0)
            if current.depth >= depth:
                continue
            found = self._causes(current) if backward else self._effects(current)
            for link in sorted(found, key=lambda lk: (lk.timestamp, lk.cause, lk.effect), reverse=backward):
                key = (link.cause, link.effect, link.relation, link.event_id)
                if key in seen_links:
                    continue
                seen_links.add(key)
                link.step = len(links)
                link.parent_step = parent_step
                links.append(link)
                nxt = link.cause if backward else link.effect
                if nxt not in nodes:
                    nodes[nxt] = TraceNode(
                        id=nxt,
                        name=self._name(nxt),
                        type=self._type(nxt),
                        depth=current.depth + 1,
                        direction="backward" if backward else "forward",
                    )
                state = (nxt, link.timestamp)
                if state not in visited and len(visited) < 300:
                    visited.add(state)
                    frontier.append((_Frontier(nxt, current.depth + 1, link.timestamp), link.step))
        return links

    def _best_chain(self, subject: str, links: Iterable[TraceLink]) -> list[TraceLink]:
        """Greedy, proximity-weighted backward chain: from the subject's most recent strong cause, repeatedly
        follow the cause that is both confident and closest in time to its effect."""
        by_effect: dict[str, list[TraceLink]] = {}
        for link in links:
            by_effect.setdefault(link.effect, []).append(link)
        chain: list[TraceLink] = []
        node, bound = subject, None
        used: set[tuple[str, str | None]] = set()
        for _ in range(12):
            candidates = [
                lk
                for lk in by_effect.get(node, [])
                if (bound is None or lk.timestamp <= bound)
                and (lk.cause, lk.event_id) not in used
                and lk.confidence >= 0.3
            ]
            if not candidates:
                break
            if bound is None:
                observed = [lk for lk in candidates if lk.kind == "observed"] or candidates
                pick = max(observed, key=lambda lk: (lk.timestamp, lk.confidence))
            else:
                def score(lk: TraceLink, ref: datetime = bound) -> float:
                    gap_minutes = abs((ref - lk.timestamp).total_seconds()) / 60
                    return lk.confidence / (1 + gap_minutes / 15)

                pick = max(candidates, key=lambda lk: (score(lk), lk.timestamp))
            used.add((pick.cause, pick.event_id))
            chain.append(pick)
            node, bound = pick.cause, pick.timestamp
        return list(reversed(chain))


def _corroborate(links: list[TraceLink]) -> list[TraceLink]:
    """Merge links describing the same fact from different sources; independent sources raise confidence."""
    merged: dict[tuple[str, str, str, datetime], TraceLink] = {}
    for link in links:
        key = (link.cause, link.effect, link.relation, link.timestamp)
        existing = merged.get(key)
        if existing is None:
            merged[key] = link
            continue
        if link.provenance.get("source") == existing.provenance.get("source"):
            continue
        existing.corroborated_by.append({**link.provenance, "event_id": link.event_id})
        cap = 0.95 if existing.kind == "observed" else 0.6  # correlation stays correlation
        existing.confidence = round(min(cap, 1 - (1 - existing.confidence) * (1 - link.confidence)), 3)
    return list(merged.values())


def _duration(delta: timedelta) -> str:
    seconds = int(abs(delta.total_seconds()))
    if seconds < 120:
        return f"{seconds}s"
    if seconds < 7200:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def describe(link: TraceLink) -> str:
    return f"{format_ts(link.timestamp)} {link.relation} ({link.kind}, {link.confidence:.2f})"
