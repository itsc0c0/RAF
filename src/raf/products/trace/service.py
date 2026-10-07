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
traversal only follows effects after their cause. Every step reads the events
nearest to the point being traced: the latest ones before it backward, the
earliest ones after it forward (an object traced without a point in time reads
its latest events in both directions).

Incidents are not referenced by their events as objects: an incident is traced
from its most significant event (highest severity, then latest), an event
reference from that event.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.objects.models import Event, RafModel, SecurityObject
from raf.core.objects.types import ObjectType, Severity
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import format_ts

_PER_RULE = 25
_RECENT = 5
_MAX_LINKS = 400
_BACKWARD_EVENTS = 500  # events of an object read when looking for its causes
_FORWARD_EVENTS = 400  # events of an object read when looking for its effects
_SESSION_USES = 5  # most recent logins of an identity examined for session context
_SESSION_WINDOW = timedelta(hours=2)
_CHAIN_LINKS = 12
_CHAIN_MIN_CONFIDENCE = 0.3
_CHAIN_MIN_SUPPORT = 0.1  # e.g. a 0.8 cause more than 105 minutes before the link it would explain is not chained
_CHAIN_BRANCHES = 3  # best candidate links tried at each step of the chain search
_CHAIN_BUDGET = 2000  # candidate links tried in total by the chain search


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


class TraceAnchor(RafModel):
    """The event an incident or event reference is traced from, and the object it is traced through."""

    event_id: str
    event_type: str
    timestamp: datetime
    severity: Severity
    object: str


class TraceResult(RafModel):
    subject: TraceNode
    nodes: list[TraceNode]
    backward: list[TraceLink]
    forward: list[TraceLink]
    chain: list[TraceLink] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    anchor: TraceAnchor | None = None


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
        limit: int = _BACKWARD_EVENTS,
        latest: bool = True,
    ) -> list[Event]:
        """At most ``limit`` events of ``object_id`` within [after, before] nearest to the point being traced:
        the latest ones, newest first (``latest``), or the earliest ones, oldest first."""
        query = EventQuery(object_ids=[object_id], event_types=types, end=before, start=after)
        return self.store.events.query(query, limit=limit, descending=latest).items

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
            # (``uses`` is newest first: the logins closest to the point being traced)
            for use in uses[:_SESSION_USES]:
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
            connections = [ev for ev in events if ev.target == x and ev.event_type.startswith("network.")]
            for ev in connections[:_PER_RULE]:  # newest first: the connections closest to the point being traced
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
        # From a point in time: the earliest effects after it; without one (the subject): its latest events.
        for ev in self._events(x, after=node.bound, limit=_FORWARD_EVENTS, latest=node.bound is None):
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
        subject_type = self._type(subject_id)
        if subject_type in (ObjectType.FINDING, ObjectType.SNAPSHOT):
            raise InvalidInputError(
                f"'{subject_id}' is a {subject_type}; trace follows objects, incidents and events.",
                hint="Trace one of the objects it refers to instead.",
            )
        notes: list[str] = []
        anchor_event: Event | None = None
        if subject_type == ObjectType.EVENT:
            anchor_event = self.store.events.get(subject_id)
            if anchor_event is None:
                raise NotFoundError(f"Event '{subject_id}' does not exist.")
            label = f"{anchor_event.event_type} {format_ts(anchor_event.timestamp)}"
        else:
            label = self._name(subject_id)
            if subject_type == ObjectType.INCIDENT:
                anchor_event = self._key_event(subject_id)
                if anchor_event is None:
                    notes.append(f"No events are linked to {label}; there is nothing to trace.")
            elif self._obj(subject_id) is None:
                notes.append("Subject is not stored as an object; only event references are traced.")
        subject_node = TraceNode(id=subject_id, name=label, type=subject_type, depth=0, direction="subject")
        nodes: dict[str, TraceNode] = {subject_id: subject_node}
        anchor: TraceAnchor | None = None
        if anchor_event is not None:
            origin = _event_object(anchor_event)
            what = f"{anchor_event.severity.value} {anchor_event.event_type} at {format_ts(anchor_event.timestamp)}"
            if origin is None:
                notes.append(f"Event {anchor_event.id} ({what}) references no objects; there is nothing to trace.")
            else:
                anchor = TraceAnchor(
                    event_id=anchor_event.id,
                    event_type=anchor_event.event_type,
                    timestamp=anchor_event.timestamp,
                    severity=anchor_event.severity,
                    object=origin,
                )
                if subject_type == ObjectType.INCIDENT:
                    notes.append(
                        f"{label} is traced from its most significant event (highest severity, then latest): "
                        f"{what} involving {self._name(origin)} ({anchor_event.id})."
                    )
                else:
                    notes.append(f"The event is traced through {self._name(origin)} ({origin}).")
        backward: list[TraceLink] = []
        forward: list[TraceLink] = []
        traceable = anchor is not None or subject_type not in (ObjectType.INCIDENT, ObjectType.EVENT)
        if traceable and direction in ("both", "back", "backward"):
            seed = self._anchor_link(subject_id, label, anchor_event, anchor, backward=True)
            backward = self._walk(subject_id, depth, nodes, backward=True, anchor=seed)
        if traceable and direction in ("both", "forward", "fwd"):
            seed = self._anchor_link(subject_id, label, anchor_event, anchor, backward=False)
            forward = self._walk(subject_id, depth, nodes, backward=False, anchor=seed)
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
            anchor=anchor,
        )

    def _key_event(self, incident_id: str) -> Event | None:
        """The incident's most significant event: highest severity, then latest (then highest event ID)."""
        linked = EventQuery(incident_id=incident_id)
        for severity in sorted(Severity, key=lambda sev: sev.rank, reverse=True):
            # No event is more severe than ``severity`` here, so the minimum selects exactly this level.
            page = self.store.events.query(linked.with_(min_severity=severity), limit=1, descending=True)
            if page.items:
                return page.items[0]
        return None

    def _anchor_link(
        self, subject_id: str, label: str, event: Event | None, anchor: TraceAnchor | None, *, backward: bool
    ) -> TraceLink | None:
        """The first link of a trace from an event: between the subject and the object the event is traced through."""
        if event is None or anchor is None:
            return None
        origin = anchor.object
        what = f"{event.severity.value} {event.event_type} involving {self._name(origin)}"
        if event.message:
            what += f": {event.message[:160]}"
        own = event.id == subject_id
        return TraceLink(
            cause=origin if backward else subject_id,
            effect=subject_id if backward else origin,
            relation=event.event_type.upper().replace(".", "_"),
            kind="observed",
            confidence=round(event.confidence, 3),
            timestamp=event.timestamp,
            event_id=event.id,
            explanation=f"The traced event: {what}" if own else f"{label}'s most significant event: {what}",
            provenance=_prov(event),
            direction="backward" if backward else "forward",
        )

    def _walk(
        self,
        start: str,
        depth: int,
        nodes: dict[str, TraceNode],
        *,
        backward: bool,
        anchor: TraceLink | None = None,
    ) -> list[TraceLink]:
        """Breadth-first walk from ``start``, or, given an anchor link (a trace from an event), from the object
        at its other end, bounded by the event's time."""
        frontier: list[tuple[_Frontier, int | None]] = []
        links: list[TraceLink] = []
        seen_links: set[tuple[str, str, str, str | None]] = set()
        visited: set[tuple[str, datetime | None]] = {(start, None)}
        if anchor is None:
            frontier.append((_Frontier(start, 0, None), None))
        else:
            anchor.step, anchor.parent_step = 0, None
            links.append(anchor)
            seen_links.add((anchor.cause, anchor.effect, anchor.relation, anchor.event_id))
            origin = anchor.cause if backward else anchor.effect
            nodes.setdefault(
                origin,
                TraceNode(
                    id=origin,
                    name=self._name(origin),
                    type=self._type(origin),
                    depth=1,
                    direction="backward" if backward else "forward",
                ),
            )
            visited.add((origin, anchor.timestamp))
            frontier.append((_Frontier(origin, 1, anchor.timestamp), anchor.step))
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
        """The most supported causal chain into the subject, earliest cause first.

        A chain is a sequence of backward links, each into the cause of the one after it and not later than
        it, that never visits an object twice (the subject included). Its support is the sum of the support of
        its links (:func:`_support`); a link whose support is below ``_CHAIN_MIN_SUPPORT`` (a weak cause, or
        one long before the link it would explain) does not extend a chain, and the first link is an observed
        one when the subject has one. The search is depth-first over the best ``_CHAIN_BRANCHES`` links at each
        step, bounded by ``_CHAIN_LINKS`` links and ``_CHAIN_BUDGET`` tried links, so it is deterministic and
        its first chain is the greedy one."""
        by_effect: dict[str, list[TraceLink]] = {}
        for link in links:
            if link.confidence >= _CHAIN_MIN_CONFIDENCE:
                by_effect.setdefault(link.effect, []).append(link)
        chain: list[TraceLink] = []
        on_chain = {subject}
        best: list[TraceLink] = []
        best_support = 0.0
        budget = _CHAIN_BUDGET

        def candidates(node: str, bound: datetime | None) -> list[tuple[float, TraceLink]]:
            found = [
                lk
                for lk in by_effect.get(node, [])
                if lk.cause not in on_chain and (bound is None or lk.timestamp <= bound)
            ]
            if bound is None:
                found = [lk for lk in found if lk.kind == "observed"] or found
            scored = [(support, lk) for lk in found if (support := _support(lk, bound)) >= _CHAIN_MIN_SUPPORT]
            scored.sort(
                key=lambda item: (item[0], item[1].timestamp, item[1].cause, item[1].event_id or ""), reverse=True
            )
            return scored[:_CHAIN_BRANCHES]

        def search(node: str, bound: datetime | None, support: float) -> None:
            nonlocal best, best_support, budget
            if support > best_support:
                best, best_support = list(chain), support
            if len(chain) >= _CHAIN_LINKS:
                return
            for link_support, link in candidates(node, bound):
                if budget <= 0:
                    return
                budget -= 1
                chain.append(link)
                on_chain.add(link.cause)
                search(link.cause, link.timestamp, support + link_support)
                chain.pop()
                on_chain.discard(link.cause)

        search(subject, None, 0.0)
        return list(reversed(best))


def _event_object(ev: Event) -> str | None:
    """The object a trace from ``ev`` goes through: its target, else its actor, else the first object it names."""
    return ev.target or ev.actor or next((ref.object_id for ref in ev.objects), None)


def _support(link: TraceLink, bound: datetime | None) -> float:
    """How well ``link`` explains the link after it in a chain (at ``bound``): its confidence, discounted by the
    time between the two (a cause 15 minutes earlier counts half); the confidence for the link into the subject."""
    if bound is None:
        return link.confidence
    gap_minutes = abs((bound - link.timestamp).total_seconds()) / 60
    return link.confidence / (1 + gap_minutes / 15)


def _corroborate(links: list[TraceLink]) -> list[TraceLink]:
    """Merge links describing the same fact (cause, effect, relation and time) from different sources.

    Each independent source counts once and raises the confidence; further records from a source already
    counted (or the same event found twice) add nothing."""
    merged: dict[tuple[str, str, str, datetime], TraceLink] = {}
    counted: dict[tuple[str, str, str, datetime], set[Any]] = {}
    for link in links:
        key = (link.cause, link.effect, link.relation, link.timestamp)
        source = link.provenance.get("source")
        existing = merged.get(key)
        if existing is None:
            merged[key] = link
            counted[key] = {source}
            continue
        if source in counted[key]:
            continue
        counted[key].add(source)
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
