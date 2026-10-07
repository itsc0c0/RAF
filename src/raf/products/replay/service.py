"""R$F Replay: deterministic temporal reconstruction.

EVENT STREAM -> STATE RECONSTRUCTOR -> TIME INDEX -> GRAPH SNAPSHOT

Events are ordered by (timestamp, event id), giving a total order; every step's
effects are derived only from the event and stored relationships, and all
state collections are serialized sorted. Identical events therefore always
produce identical states and identical state hashes, regardless of import
order. Every ``replay.checkpoint_interval`` steps a checkpoint records the
*hash* of the state reached (not the state itself), so a client can verify its
own reconstruction; nothing is stored between requests, and the state at a time
is rebuilt by applying the steps from the start of the window.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError
from raf.core.objects.models import Event, RafModel, Relationship
from raf.core.objects.types import Criticality, Severity
from raf.core.query.scope import Scope
from raf.core.timeutil import format_ts, parse_timestamp

_REMOVAL_TYPES = ("iam.role.remove", "iam.group.remove", "iam.permission.revoke", "process.end", "file.delete")
FLOW_WINDOW = timedelta(minutes=10)


class ReplayStep(RafModel):
    index: int
    timestamp: datetime
    event_id: str
    event_type: str
    severity: Severity
    summary: str
    actor: str | None = None
    target: str | None = None
    added_objects: list[str] = Field(default_factory=list)
    added_relationships: list[str] = Field(default_factory=list)
    removed_relationships: list[str] = Field(default_factory=list)
    sessions_opened: list[dict[str, Any]] = Field(default_factory=list)
    sessions_closed: list[dict[str, Any]] = Field(default_factory=list)
    processes_started: list[dict[str, Any]] = Field(default_factory=list)
    processes_ended: list[str] = Field(default_factory=list)
    flows: list[dict[str, Any]] = Field(default_factory=list)
    files: list[dict[str, Any]] = Field(default_factory=list)
    identity_changes: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)


class ReplayTimeline(RafModel):
    scope: dict[str, Any]
    title: str
    start: datetime
    end: datetime
    objects: dict[str, dict[str, Any]]
    relationships: dict[str, dict[str, Any]]
    initial_objects: list[str]
    initial_relationships: list[str]
    steps: list[ReplayStep]
    checkpoints: list[dict[str, Any]]
    final_state_hash: str
    excluded_events: int = 0
    notes: list[str] = Field(default_factory=list)


class ReplayState(RafModel):
    at: datetime
    step_index: int
    objects: list[str]
    relationships: list[str]
    sessions: list[dict[str, Any]]
    processes: list[dict[str, Any]]
    recent_flows: list[dict[str, Any]]
    files: list[dict[str, Any]]
    identity_changes: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    state_hash: str


@dataclass
class _State:
    objects: set[str] = field(default_factory=set)
    relationships: set[str] = field(default_factory=set)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    processes: dict[str, dict[str, Any]] = field(default_factory=dict)
    flows: list[dict[str, Any]] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)
    identity_changes: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)

    def canonical(self) -> dict[str, Any]:
        """Content-based and order-independent: no event IDs, lists sorted by content."""

        def ordered(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
            cleaned = [{k: v for k, v in item.items() if k != "event_id"} for item in items]
            return sorted(cleaned, key=lambda i: json.dumps(i, sort_keys=True, default=str))

        return {
            "objects": sorted(self.objects),
            "relationships": sorted(self.relationships),
            "sessions": [self.sessions[k] for k in sorted(self.sessions)],
            "processes": [self.processes[k] for k in sorted(self.processes)],
            "flows": ordered(self.flows),
            "files": ordered(self.files),
            "identity_changes": ordered(self.identity_changes),
            "alerts": ordered(self.alerts),
        }

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.canonical(), sort_keys=True, default=str).encode()).hexdigest()


def _session_key(user: str, host: str) -> str:
    return f"{user}@{host}"


def apply_step(state: _State, step: ReplayStep) -> None:
    state.objects.update(step.added_objects)
    state.relationships.update(step.added_relationships)
    state.relationships.difference_update(step.removed_relationships)
    for session in step.sessions_opened:
        state.sessions[_session_key(session["user"], session["host"])] = session
    for session in step.sessions_closed:
        state.sessions.pop(_session_key(session["user"], session["host"]), None)
    for process in step.processes_started:
        state.processes[process["process"]] = process
    for process_id in step.processes_ended:
        state.processes.pop(process_id, None)
    state.flows.extend(step.flows)
    state.files.extend(step.files)
    state.identity_changes.extend(step.identity_changes)
    state.alerts.extend(step.alerts)


class ReplayService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.interval = int(ctx.settings.get("replay.checkpoint_interval"))

    # ------------------------------------------------------------------ build
    def window_for(self, scope: Scope) -> tuple[datetime | None, datetime | None]:
        if scope.kind == "incident" and scope.obj is not None:
            meta = scope.obj.metadata
            start = parse_timestamp(meta["start"]) if meta.get("start") else None
            end = parse_timestamp(meta["end"]) if meta.get("end") else None
            if start and end:
                return start, end
        return self.store.events.bounds(scope.event_query())

    def build(
        self,
        scope: Scope,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        include_context: bool = True,
        max_events: int = 50_000,
    ) -> ReplayTimeline:
        win_start, win_end = self.window_for(scope)
        start = start or win_start
        end = end or win_end
        if start is None or end is None:
            raise InvalidInputError(
                f"{scope.label} has no events to replay.", suggestions=[f"raf timeline {scope.label}"]
            )
        if end < start:
            raise InvalidInputError("Replay window ends before it starts.")
        base = scope.event_query()
        total_linked = self.store.events.count(base)
        query = base.with_(start=start, end=end)
        events = list(self.store.events.iter(query))
        if len(events) > max_events:
            raise InvalidInputError(
                f"The replay window contains {len(events):,} events (limit {max_events:,}).",
                hint="Narrow it with --from/--to.",
            )
        events.sort(key=lambda e: (e.timestamp, e.id))
        involved = sorted({ref.object_id for ev in events for ref in ev.objects})
        objects = self.store.objects.get_many(involved)
        rel_ids = sorted({rid for ev in events for rid in ev.relationships})
        rels = self.store.relationships.get_many(rel_ids)
        initial_rels: dict[str, Relationship] = {}
        if include_context and involved:
            involved_set = set(involved)
            for rel in self.store.relationships.edges(involved, direction="out", at=start):
                if rel.target_object in involved_set:
                    initial_rels[rel.id] = rel
        object_index = {
            i: {
                "name": objects[i].name if i in objects else i.split(":", 1)[-1],
                "type": i.split(":", 1)[0],
                "criticality": (c.value if (c := Criticality.of(objects[i].metadata, objects[i].tags)) else None)
                if i in objects
                else None,
            }
            for i in involved
        }
        rel_index = {
            r.id: {"type": r.relationship_type, "source": r.source_object, "target": r.target_object}
            for r in [*rels.values(), *initial_rels.values()]
        }
        for entry in rel_index.values():
            for endpoint in (entry["source"], entry["target"]):
                object_index.setdefault(
                    endpoint,
                    {"name": endpoint.split(":", 1)[-1], "type": endpoint.split(":", 1)[0], "criticality": None},
                )
        initial_objects = sorted(
            {r.source_object for r in initial_rels.values()} | {r.target_object for r in initial_rels.values()}
        )
        state = _State(objects=set(initial_objects), relationships=set(initial_rels))
        steps: list[ReplayStep] = []
        checkpoints: list[dict[str, Any]] = []
        for index, ev in enumerate(events):
            step = self._step(index, ev, state, rels, object_index)
            apply_step(state, step)
            steps.append(step)
            if (index + 1) % self.interval == 0:
                checkpoints.append({"index": index, "state_hash": state.digest()})
        notes = []
        excluded = total_linked - len(events) if scope.kind == "incident" else 0
        if excluded > 0:
            notes.append(
                f"{excluded} event(s) linked to {scope.label} fall outside the replay window "
                f"({format_ts(start)} .. {format_ts(end)}) and were not replayed."
            )
        title = scope.label
        if scope.obj is not None and scope.obj.metadata.get("title"):
            title = f"{scope.label}  {scope.obj.metadata['title']}"
        return ReplayTimeline(
            scope=scope.to_dict(),
            title=title,
            start=start,
            end=end,
            objects=object_index,
            relationships=rel_index,
            initial_objects=initial_objects,
            initial_relationships=sorted(initial_rels),
            steps=steps,
            checkpoints=checkpoints,
            final_state_hash=state.digest(),
            excluded_events=max(excluded, 0),
            notes=notes,
        )

    def _name(self, object_id: str | None, index: dict[str, dict[str, Any]]) -> str:
        if not object_id:
            return "-"
        return str(index.get(object_id, {}).get("name") or object_id.split(":", 1)[-1])

    def _step(
        self, index: int, ev: Event, state: _State, rels: dict[str, Relationship], objects: dict[str, dict[str, Any]]
    ) -> ReplayStep:
        step = ReplayStep(
            index=index,
            timestamp=ev.timestamp,
            event_id=ev.id,
            event_type=ev.event_type,
            severity=ev.severity,
            summary="",
            actor=ev.actor,
            target=ev.target,
        )
        step.added_objects = sorted({ref.object_id for ref in ev.objects} - state.objects)
        removal = ev.event_type in _REMOVAL_TYPES
        for rid in sorted(set(ev.relationships)):
            rel = rels.get(rid)
            if rel is None:
                continue
            if removal and rel.valid_to is not None and rel.valid_to <= ev.timestamp:
                if rid in state.relationships:
                    step.removed_relationships.append(rid)
            elif rid not in state.relationships:
                step.added_relationships.append(rid)
        a, t = self._name(ev.actor, objects), self._name(ev.target, objects)
        attrs = ev.attributes
        src = next((ref.object_id for ref in ev.objects if ref.role == "src_ip"), None)
        et = ev.event_type
        ts = format_ts(ev.timestamp)
        if et == "auth.login" and ev.outcome != "failure" and ev.actor and ev.target:
            step.sessions_opened.append(
                {"user": ev.actor, "host": ev.target, "since": ts, "source": src, "method": attrs.get("method")}
            )
            step.summary = f"{a} logged into {t}" + (f" from {self._name(src, objects)}" if src else "")
        elif et == "auth.logout" and ev.actor and ev.target:
            if _session_key(ev.actor, ev.target) in state.sessions:
                step.sessions_closed.append({"user": ev.actor, "host": ev.target})
            step.summary = f"{a} logged out of {t}"
        elif et == "auth.failure":
            step.summary = f"failed login for {a} on {t}" + (f" from {self._name(src, objects)}" if src else "")
        elif et == "auth.privilege":
            step.summary = f"{a} elevated privileges on {t} ({attrs.get('as_user', '?')})"
        elif et == "process.start" and ev.target:
            host = next((ref.object_id for ref in ev.objects if ref.role == "host"), None)
            step.processes_started.append(
                {
                    "process": ev.target,
                    "host": host,
                    "user": ev.actor,
                    "since": ts,
                    "command_line": attrs.get("command_line"),
                }
            )
            step.summary = (
                f"{a} started {t}"
                + (f" on {self._name(host, objects)}" if host else "")
                + (f": {attrs['command_line']}" if attrs.get("command_line") else "")
            )
        elif et == "process.end" and ev.target:
            step.processes_ended.append(ev.target)
            step.summary = f"{t} exited"
        elif et.startswith(("network.", "tls.")):
            if ev.outcome != "failure":
                step.flows.append(
                    {
                        "at": ts,
                        "source": ev.actor,
                        "destination": ev.target,
                        "port": attrs.get("dst_port"),
                        "bytes_out": attrs.get("bytes_out"),
                        "protocol": attrs.get("protocol"),
                    }
                )
            size = f" ({int(attrs['bytes_out']) / 1e6:.1f} MB out)" if attrs.get("bytes_out") else ""
            step.summary = (
                f"{a} → {t}"
                + (f":{attrs['dst_port']}" if attrs.get("dst_port") else "")
                + size
                + (" [blocked]" if ev.outcome == "failure" else "")
            )
        elif et.startswith("file."):
            actor = next((ref.object_id for ref in ev.objects if ref.role == "process"), ev.actor)
            step.files.append({"at": ts, "operation": et.split(".", 1)[1], "file": ev.target, "actor": actor})
            step.summary = f"{self._name(actor, objects)} {et.split('.', 1)[1]} {t}"
        elif et.startswith("iam."):
            step.identity_changes.append(
                {
                    "at": ts,
                    "change": et,
                    "actor": ev.actor,
                    "target": ev.target,
                    "detail": {k: attrs[k] for k in ("role", "group", "resource") if k in attrs},
                }
            )
            step.summary = f"{a}: {et} on {t}"
        elif et.startswith("alert"):
            step.alerts.append(
                {
                    "at": ts,
                    "event_id": ev.id,
                    "severity": ev.severity.value,
                    "message": ev.message or et,
                    "target": ev.target,
                }
            )
            step.summary = f"ALERT {ev.message or et}"
        elif et == "dns.query":
            answers = attrs.get("answers") or []
            step.summary = f"{a} resolved {t}" + (f" → {', '.join(map(str, answers))}" if answers else "")
        elif et == "http.request":
            step.summary = f"{a} {attrs.get('method', 'requested')} {t}"
        else:
            step.summary = ev.message or f"{et} {a} → {t}"
        return step

    # ------------------------------------------------------------------ query
    def state_at(self, timeline: ReplayTimeline, at: datetime) -> ReplayState:
        state = _State(objects=set(timeline.initial_objects), relationships=set(timeline.initial_relationships))
        last = -1
        for step in timeline.steps:
            if step.timestamp > at:
                break
            apply_step(state, step)
            last = step.index
        recent = [f for f in state.flows if parse_timestamp(f["at"]) >= at - FLOW_WINDOW]
        return ReplayState(
            at=at,
            step_index=last,
            objects=sorted(state.objects),
            relationships=sorted(state.relationships),
            sessions=[state.sessions[k] for k in sorted(state.sessions)],
            processes=[state.processes[k] for k in sorted(state.processes)],
            recent_flows=recent,
            files=state.files,
            identity_changes=state.identity_changes,
            alerts=state.alerts,
            state_hash=state.digest(),
        )

    def changes(self, timeline: ReplayTimeline, start: datetime, end: datetime) -> dict[str, Any]:
        selected = [s for s in timeline.steps if start <= s.timestamp <= end]
        before = self.state_at(timeline, start - timedelta(microseconds=1))
        result: dict[str, Any] = {
            "from": format_ts(start),
            "to": format_ts(end),
            "events": len(selected),
            "new_objects": [],
            "added_relationships": [],
            "removed_relationships": [],
            "sessions_opened": [],
            "sessions_closed": [],
            "processes": [],
            "flows": [],
            "files": [],
            "identity_changes": [],
            "alerts": [],
        }
        seen_objects = set(before.objects)
        for step in selected:
            for oid in step.added_objects:
                if oid not in seen_objects:
                    seen_objects.add(oid)
                    result["new_objects"].append(oid)
            result["added_relationships"] += step.added_relationships
            result["removed_relationships"] += step.removed_relationships
            result["sessions_opened"] += step.sessions_opened
            result["sessions_closed"] += step.sessions_closed
            result["processes"] += step.processes_started
            result["flows"] += step.flows
            result["files"] += step.files
            result["identity_changes"] += step.identity_changes
            result["alerts"] += step.alerts
        return result


def group_steps(steps: Sequence[ReplayStep]) -> list[tuple[ReplayStep, int]]:
    """Collapse consecutive identical steps (same type, actor, target) for display."""
    grouped: list[tuple[ReplayStep, int]] = []
    for step in steps:
        if grouped:
            last, count = grouped[-1]
            if (last.event_type, last.actor, last.target) == (step.event_type, step.actor, step.target):
                grouped[-1] = (last, count + 1)
                continue
        grouped.append((step, 1))
    return grouped


def clone_state(state: ReplayState) -> ReplayState:
    return copy.deepcopy(state)
