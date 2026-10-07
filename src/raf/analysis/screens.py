"""R$F OS screens: what each page of the terminal control panel (``raf tui``) shows.

A screen is a JSON document of typed blocks; the ``raf-os`` terminal UI (``tui/``, Rust + Ratatui)
lays the blocks out and styles them. Every name and number comes from the R$F services the CLI and
the API use; nothing here is invented or decorative. The block protocol is documented in
``docs/tui.md``.

Pages share a *focus* (an incident, the identity at the center of it, and the most critical asset
it can reach), derived from the same reasoning Oracle uses, so that Timeline, Trace, IAM, Blast,
Ghost, Graph and Oracle tell one consistent story by default. Every page also accepts its own
parameter (any R$F reference).
"""

from __future__ import annotations

import ipaddress
import itertools
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.objects.models import Event, SecurityObject
from raf.core.objects.semantics import CONTROL, NON_PROPAGATING_TYPES, TRUST, is_privileged
from raf.core.objects.types import ASSET_TYPES, PRINCIPAL_TYPES, Severity, confidence_level
from raf.core.query.scope import Scope, resolve_scope
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import format_ts, utcnow
from raf.version import RAF_VERSION

Block = dict[str, Any]
SEVERITY_STYLE = {"CRITICAL": "danger", "HIGH": "danger", "MEDIUM": "warn", "LOW": "info", "INFO": "dim"}
LEVEL_STYLE = {**SEVERITY_STYLE, "NONE": "dim"}
_CATEGORY = {
    "auth": "AUTH",
    "network": "NETWORK",
    "dns": "DNS",
    "http": "HTTP",
    "tls": "TLS",
    "file": "FILE",
    "process": "PROCESS",
    "iam": "IAM",
    "alert": "ALERT",
    "log": "LOG",
    "cloud": "CLOUD",
}
_REL_WORDS = {
    "LOGGED_INTO": "logged into",
    "MEMBER_OF": "member of",
    "HAS_ROLE": "holds role",
    "CAN_ACCESS": "can access",
    "ADMIN_OF": "administers",
    "CONTAINS": "contains",
    "CONTAINS_SECRET": "contains secret",
    "AUTHENTICATES_AS": "authenticates as",
    "USES": "holds credentials of",
    "DEPLOYS_TO": "deploys to",
    "RUNS": "runs",
    "OWNS": "owns",
    "HAS_IDENTITY": "controls account",
    "CAN_ASSUME": "can assume",
    "TRUSTS": "trusted by",
    "CAN_REACH": "can reach",
    "CONNECTED_TO": "connected to",
    "HAS_ADDRESS": "has address",
    "EXPLOITABLE": "exploitable",
}


# --------------------------------------------------------------------------- block helpers


def section(text: str) -> Block:
    return {"t": "section", "text": text}


def text(*lines: str, style: str = "normal") -> Block:
    return {"t": "text", "lines": list(lines), "style": style}


def kv(rows: Iterable[tuple[Any, ...]]) -> Block:
    """Label/value rows: ``(label, value[, style[, ref]])``."""
    out = []
    for row in rows:
        label, value = row[0], row[1]
        style = row[2] if len(row) > 2 else None
        ref = row[3] if len(row) > 3 else None
        out.append({"k": label, "v": str(value), "style": style, "ref": ref})
    return {"t": "kv", "rows": out}


def table(columns: list[str], rows: list[dict[str, Any]], align: list[str] | None = None) -> Block:
    return {"t": "table", "columns": columns, "align": align or ["l"] * len(columns), "rows": rows}


def spacer() -> Block:
    return {"t": "spacer"}


def _kind(ref: str | None) -> str | None:
    return ref.split(":", 1)[0] if ref else None


def chain_node(label: str, ref: str | None, note: str | None = None) -> dict[str, Any]:
    return {"label": label, "type": _kind(ref) or "", "ref": ref, "note": note}


def chain_edge(label: str, kind: str, note: str | None = None) -> dict[str, Any]:
    """``kind``: observed (backed by an event), modeled (from the security model) or correlated."""
    return {"label": label, "kind": kind, "note": note}


def tree_node(
    label: str,
    ref: str | None = None,
    note: str | None = None,
    children: list[dict[str, Any]] | None = None,
    style: str | None = None,
) -> dict[str, Any]:
    return {"label": label, "type": _kind(ref), "ref": ref, "note": note, "style": style, "children": children or []}


def rel_words(rel_type: str) -> str:
    return _REL_WORDS.get(rel_type, rel_type.lower().replace("_", " "))


def duration(delta: timedelta) -> str:
    seconds = abs(delta.total_seconds())
    if seconds < 60:
        return f"{seconds:.1f}s" if seconds < 10 else f"{seconds:.0f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes:02d}m"
    return f"{hours // 24}d {hours % 24:02d}h"


def clock(ts: datetime) -> str:
    return ts.strftime("%H:%M:%S.") + f"{ts.microsecond // 1000:03d}"


@dataclass(slots=True)
class Screen:
    page: str
    title: str
    blocks: list[Block]
    subtitle: str | None = None
    param: str | None = None
    notes: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "page": self.page,
            "title": self.title,
            "subtitle": self.subtitle,
            "param": self.param,
            "blocks": self.blocks,
            "notes": self.notes or [],
        }


# --------------------------------------------------------------------------- focus


@dataclass(slots=True)
class Focus:
    incident: SecurityObject | None = None
    subject: SecurityObject | None = None
    target: SecurityObject | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident": self.incident.name if self.incident else None,
            "subject": self.subject.name if self.subject else None,
            "subject_id": self.subject.id if self.subject else None,
            "target": self.target.name if self.target else None,
            "target_id": self.target.id if self.target else None,
        }


def _story(ctx: RafContext, incident: SecurityObject) -> Any:
    """Oracle's retrieval for the incident's most important path (FoundPath, events, ...)."""
    from raf.products.oracle.retrieval import Retriever

    return Retriever(ctx).retrieve(f"Explain the most important security path in {incident.name}")


def focus(ctx: RafContext) -> Focus:
    """Default focus: the most severe incident, its most important path's identity and target."""
    store = ctx.store
    incidents = sorted(store.incidents.list(limit=50), key=lambda i: (-i.severity.rank, -(i.event_count or 0), i.name))
    result = Focus()
    if incidents:
        result.incident = store.objects.get(incidents[0].id)
    if result.incident is not None and _available(ctx, "oracle"):
        retrieval = _story(ctx, result.incident)
        if retrieval.paths:
            path = retrieval.paths[0]
            result.subject = store.objects.get(path.subject)
            result.target = store.objects.get(path.target)
    if result.subject is None:
        users = list(store.objects.iter_all(types=["user"]))
        result.subject = users[0] if users else None
    return result


def _available(ctx: RafContext, product: str) -> bool:
    return ctx.registry is None or ctx.registry.is_available(product)


def _resolve(ctx: RafContext, ref: str | None, fallback: SecurityObject | None, what: str) -> SecurityObject:
    if ref:
        resolved = ctx.resolve(ref)
        obj = resolved.obj or ctx.store.objects.get(resolved.id)
        if obj is None:
            raise NotFoundError(f"'{ref}' is not an object.", hint=f"Give the {what} as a name or ID (e.g. bob).")
        return obj
    if fallback is None:
        raise NotFoundError(f"No default {what} in this workspace.", hint="raf demo load, or type a reference with /")
    return fallback


def _names(ctx: RafContext, ids: list[str]) -> dict[str, str]:
    found = ctx.store.objects.get_many(ids)
    return {i: (found[i].name if i in found else i.split(":", 1)[-1]) for i in ids}


# --------------------------------------------------------------------------- pages


def pages_index(ctx: RafContext) -> dict[str, Any]:
    store = ctx.store
    products = ctx.registry.products() if ctx.registry is not None else []
    current = focus(ctx)
    incident = current.incident.name if current.incident else None
    subject = current.subject.name if current.subject else None
    target = current.target.name if current.target else None
    question = f"Explain the most important security path in {incident}" if incident else "What should I look at first?"
    params: dict[str, dict[str, Any] | None] = {
        "home": None,
        "timeline": {"name": "ref", "label": "incident or object", "default": incident or "workspace"},
        "trace": {"name": "ref", "label": "incident or object", "default": incident or subject},
        "iam": {"name": "ref", "label": "identity", "default": subject},
        "blast": {"name": "ref", "label": "assumed compromised", "default": subject},
        "exposure": {"name": "ref", "label": "asset (optional)", "default": ""},
        "policy": None,
        "ghost": {
            "name": "ref",
            "label": "subject → target",
            "default": f"{subject} → {target}" if subject and target else (subject or ""),
        },
        "graph": {"name": "ref", "label": "object", "default": subject},
        "oracle": {"name": "question", "label": "question", "default": question},
        "findings": {"name": "ref", "label": "product or minimum severity (optional)", "default": ""},
        "evidence": {"name": "ref", "label": "case", "default": incident or ""},
    }
    return {
        "system": {
            "version": RAF_VERSION,
            "workspace": ctx.workspace.name,
            "products": len(products),
            "available": sum(1 for p in products if p.available),
            "oracle": str(ctx.settings.get("oracle.provider")),
        },
        "stats": {
            "objects": store.objects.count(),
            "relationships": store.relationships.count(),
            "events": store.events.count(),
            "findings_open": store.findings.count(statuses=["OPEN"]),
            "incidents": len(store.incidents.list(limit=1000)),
        },
        "focus": current.to_dict(),
        "pages": [{"id": page, "title": PAGE_TITLES[page], "param": params[page]} for page in PAGE_TITLES],
    }


def home(ctx: RafContext, _ref: str | None) -> Screen:
    store = ctx.store
    products = ctx.registry.products() if ctx.registry is not None else []
    stats = store.stats()
    jobs = ctx.jobs.list(limit=1000)
    sources = {e.source for e in store.events.query(EventQuery(), limit=2000, with_objects=False).items}
    by_severity = store.findings.count_by_severity(statuses=["OPEN"])
    current = focus(ctx)
    blocks: list[Block] = [
        kv(
            [
                ("Version", RAF_VERSION),
                ("Workspace", ctx.workspace.name),
                ("Products", f"{sum(1 for p in products if p.available)} of {len(products)} online", "ok"),
                ("Oracle", str(ctx.settings.get("oracle.provider"))),
            ]
        ),
        section("SECURITY WORLD MODEL"),
        diagram_pipeline(ctx, stats, len(sources), len(jobs)),
    ]
    if products:
        blocks += [
            section("PRODUCTS"),
            {
                "t": "grid",
                "columns": 4,
                "items": [
                    {
                        "label": p.manifest.display_name,
                        "status": p.manifest.status.value if p.available else "UNAVAILABLE",
                        "style": "ok" if p.available else "dim",
                    }
                    for p in products
                ],
            },
        ]
    total = sum(by_severity.values())
    blocks += [section(f"OPEN FINDINGS  {total}")]
    peak = max(by_severity.values(), default=0) or 1
    blocks.append(
        {
            "t": "bars",
            "rows": [
                {"label": sev, "value": by_severity.get(sev, 0), "max": peak, "style": SEVERITY_STYLE[sev]}
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            ],
        }
    )
    incidents = store.incidents.list(limit=20)
    if incidents:
        blocks += [
            section("INCIDENTS"),
            table(
                ["INCIDENT", "SEVERITY", "STATUS", "EVENTS", "TITLE"],
                [
                    {
                        "cells": [i.name, i.severity.value, i.status, str(i.event_count), i.title],
                        "style": SEVERITY_STYLE.get(i.severity.value),
                        "ref": i.id,
                    }
                    for i in incidents
                ],
                ["l", "l", "l", "r", "l"],
            ),
        ]
    if current.incident or current.subject:
        rows: list[Any] = []
        if current.incident:
            rows.append(("Incident", current.incident.name, "accent", current.incident.id))
        if current.subject:
            rows.append(("Identity", current.subject.name, "accent", current.subject.id))
        if current.target:
            rows.append(("Critical target", current.target.name, "danger", current.target.id))
        blocks += [
            section("FOCUS"),
            text("Pages open on this story by default; press / on a page to choose another subject.", style="dim"),
            kv(rows),
        ]
    if not stats["objects"]:
        blocks += [section("EMPTY WORKSPACE"), text("raf demo load", "raf analyze <file>", "raf range create demo")]
    return Screen("home", "R$F OS", blocks, subtitle="Every security capability. One command away.")


def diagram_pipeline(ctx: RafContext, stats: dict[str, Any], sources: int, jobs: int) -> Block:
    names = ["Graph", "Timeline", "Trace", "IAM", "Policy", "Blast", "Exposure", "Replay", "Evidence"]
    names += ["Ghost", "Diff", "Lens", "Range", "Forge", "Lab", "Protocol", "Vault", "Dependency", "Surface"]
    width = 12
    rows = [names[i : i + 3] for i in range(0, len(names), 3)]
    inner = width * 3 + 2
    box = ["┌" + "─" * inner + "┐"]
    for row in rows:
        box.append("│ " + "".join(f"{n:<{width}}" for n in row).ljust(inner - 1) + "│")
    box.append("└" + "─" * inner + "┘")
    provider = str(ctx.settings.get("oracle.provider"))
    lines = [
        f"RAW LOGS ············· {sources} telemetry source(s)",
        "   ↓",
        f"INGEST ··············· {jobs} job(s), provenance on every fact",
        "   ↓",
        f"SECURITY WORLD MODEL · {stats['objects']:,} objects · {stats['relationships']:,} relationships "
        f"· {stats['events']:,} events",
        "   ↓",
        *box,
        "   ↓",
        f"ORACLE ··············· {provider} reasoner, cited answers",
    ]
    return {"t": "diagram", "lines": lines, "style": "accent"}


def _incident_scope(ctx: RafContext, ref: str | None) -> Scope:
    if not ref:
        current = focus(ctx)
        if current.incident is None:
            return resolve_scope(ctx, [])
        ref = current.incident.name
    return resolve_scope(ctx, [ref])


_MIN_GAP = timedelta(seconds=1)  # shorter gaps are not drawn: same-second events read as one moment


def timeline(ctx: RafContext, ref: str | None) -> Screen:
    from raf.products.replay.service import ReplayService, group_steps

    scope = _incident_scope(ctx, ref)
    blocks: list[Block] = []
    if scope.kind == "incident":
        replay = ReplayService(ctx).build(scope, include_context=False)
        steps = replay.steps
        events = list(ctx.store.events.iter(scope.event_query()))
        title_detail = f"{format_ts(replay.start)} → {format_ts(replay.end)}"
    else:
        page = ctx.store.events.query(scope.event_query(), limit=300, descending=True)
        events = list(reversed(page.items))
        steps = []
        title_detail = f"latest {len(events)} events"
    by_id = {e.id: e for e in events}
    previous: datetime | None = None
    if steps:
        for step, count in group_steps(steps):
            if previous is not None and step.timestamp - previous >= _MIN_GAP:
                blocks.append({"t": "gap", "text": "+" + duration(step.timestamp - previous)})
            event = by_id.get(step.event_id)
            lines = [("" if count == 1 else f"{count}x ") + step.summary]
            if event is not None and event.outcome:
                lines.append(f"result={event.outcome.upper()}")
            blocks.append(_event_block(step.timestamp, step.event_type, lines, step.severity.value, step.event_id))
            previous = step.timestamp
    else:
        for event in events:
            if previous is not None and event.timestamp - previous >= _MIN_GAP:
                blocks.append({"t": "gap", "text": "+" + duration(event.timestamp - previous)})
            lines = [_describe(ctx, event)]
            if event.outcome:
                lines.append(f"result={event.outcome.upper()}")
            blocks.append(_event_block(event.timestamp, event.event_type, lines, event.severity.value, event.id))
            previous = event.timestamp
    if not events:
        blocks.append(text("No events in this scope.", style="dim"))
    else:
        principals_assets = {
            oid
            for e in events
            for oid in (e.actor, e.target)
            if oid and oid.split(":", 1)[0] in (PRINCIPAL_TYPES | ASSET_TYPES)
        }
        window = events[-1].timestamp - events[0].timestamp
        blocks += [
            section("SUMMARY"),
            kv(
                [
                    ("Events", f"{len(events):,}"),
                    ("Telemetry sources", len({e.source for e in events})),
                    ("Identities/assets correlated", len(principals_assets)),
                    ("Window", duration(window)),
                    ("First", format_ts(events[0].timestamp)),
                ]
            ),
        ]
    return Screen("timeline", f"R$F TIMELINE — {scope.label}", blocks, subtitle=title_detail, param=scope.label)


def _event_block(ts: datetime, event_type: str, lines: list[str], severity: str, ref: str) -> Block:
    category = _CATEGORY.get(event_type.split(".", 1)[0], event_type.split(".", 1)[0].upper())
    return {
        "t": "event",
        "time": clock(ts),
        "date": ts.strftime("%Y-%m-%d"),
        "category": category,
        "lines": lines,
        "severity": severity,
        "ref": ref,
    }


def _describe(ctx: RafContext, event: Event) -> str:
    names = _names(ctx, [i for i in (event.actor, event.target) if i])
    actor = names.get(event.actor or "", "")
    target = names.get(event.target or "", "")
    action = event.event_type.split(".", 1)[-1].replace("_", " ")
    core = " ".join(part for part in (actor, action, "→" if target else "", target) if part)
    return core if not event.message else f"{core} · {event.message[:120]}"


# ------------------------------------------------------------------ trace


def trace(ctx: RafContext, ref: str | None) -> Screen:
    current = focus(ctx)
    target_ref = ref or (current.incident.name if current.incident else None)
    if target_ref is None:
        raise NotFoundError("Nothing to trace yet.", hint="raf demo load, or type a reference with /")
    resolved = ctx.resolve(target_ref)
    obj = resolved.obj or ctx.store.objects.get(resolved.id)
    if obj is not None and obj.type == "incident" and _available(ctx, "oracle"):
        return _incident_trace(ctx, obj)
    from raf.products.trace.service import TraceService

    subject = _resolve(ctx, target_ref, None, "object")
    result = TraceService(ctx).trace(subject.id)
    links = result.chain
    blocks: list[Block] = []
    if links:
        names = _names(ctx, [links[0].cause, *[link.effect for link in links]])
        nodes = [chain_node(names[links[0].cause], links[0].cause)]
        edges = []
        for link in links:
            nodes.append(chain_node(names[link.effect], link.effect))
            edges.append(
                chain_edge(
                    rel_words(link.relation),
                    "observed" if link.kind == "observed" else "correlated",
                    f"{format_ts(link.timestamp)} · {link.confidence:.2f}",
                )
            )
        blocks.append({"t": "chain", "nodes": nodes, "edges": edges})
        observed = sum(1 for link in links if link.kind == "observed")
        blocks += [
            section("CORROBORATION"),
            kv(
                [
                    ("Observed edges", observed, "ok"),
                    ("Correlated edges", len(links) - observed, "warn" if observed < len(links) else None),
                    ("Overall confidence", confidence_level(min(link.confidence for link in links)).value),
                ]
            ),
            section("EVIDENCE"),
            *[
                kv(
                    [
                        (
                            link.event_id or "-",
                            f"{format_ts(link.timestamp)}  {link.explanation[:90]}",
                            None,
                            link.event_id,
                        )
                    ]
                )
                for link in links
                if link.event_id
            ],
        ]
    else:
        blocks.append(text("No causal chain leads to this object.", style="dim"))
    for note in result.notes:
        blocks.append(text(note, style="note"))
    return Screen("trace", f"R$F TRACE — {subject.name}", blocks, subtitle="how did we get here?", param=subject.name)


def _incident_trace(ctx: RafContext, incident: SecurityObject) -> Screen:
    retrieval = _story(ctx, incident)
    if not retrieval.paths:
        raise NotFoundError(f"No security path was found for {incident.name}.")
    path = retrieval.paths[0]
    events = list(ctx.store.events.iter(EventQuery(incident_id=incident.id)))
    by_id = {e.id: e for e in events}
    entry = _entry_point(path.subject, events)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    evidence: list[tuple[str, str]] = []
    if entry is not None:
        ip, gateway, event = entry
        names = _names(ctx, [ip, gateway])
        nodes += [chain_node(names[ip], ip), chain_node(names[gateway], gateway)]
        when = f"{clock(event.timestamp)} {event.event_type}"
        edges += [chain_edge("network observation", "observed", when), chain_edge("authenticated as", "observed", when)]
        evidence.append((event.id, _observed_note(event, None) or ""))
    nodes.append(chain_node(_names(ctx, [path.subject])[path.subject], path.subject))
    for hop in path.hops:
        if hop.target == hop.source:
            continue
        observed = hop.observed_event is not None
        nodes.append(chain_node(hop.target_name, hop.target))
        edges.append(
            chain_edge(
                rel_words(hop.relationship_type),
                "observed" if observed else "modeled",
                _observed_note(by_id.get(hop.observed_event or ""), hop.observed) if observed else None,
            )
        )
        if observed and hop.observed_event:
            evidence.append((hop.observed_event, _observed_note(by_id.get(hop.observed_event), hop.observed) or ""))
    observed_edges = sum(1 for e in edges if e["kind"] == "observed")
    level = confidence_level(path.confidence).value
    blocks: list[Block] = [
        {"t": "chain", "nodes": nodes, "edges": edges},
        section("CORROBORATION"),
        kv(
            [
                ("Observed edges", observed_edges, "ok"),
                ("Modeled edges", len(edges) - observed_edges, "dim"),
                ("Path confidence", f"{path.confidence:.2f}  ({level})"),
                ("Target criticality", (path.criticality or "-").upper(), "danger"),
            ]
        ),
        text(
            "Observed edges are backed by incident events; modeled edges come from the security model "
            "(credentials, memberships, roles) and are possible, not proven.",
            style="note",
        ),
        section("EVIDENCE"),
        kv([(event_id, detail, None, event_id) for event_id, detail in dict(evidence).items()]),
    ]
    return Screen(
        "trace",
        f"R$F TRACE — {incident.name}",
        blocks,
        subtitle=f"entry → {path.target_name}",
        param=incident.name,
    )


_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10")
)


def _external(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Outside the organization: not RFC 1918/4193, loopback or link-local (documentation ranges
    such as 203.0.113.0/24 model the Internet in synthetic data)."""
    return not any(address in net for net in _INTERNAL_NETS)


def _observed_note(event: Event | None, fallback: str | None) -> str | None:
    if event is None:
        return fallback
    return f"{clock(event.timestamp)} {event.event_type}"


def _entry_point(subject: str, events: list[Event]) -> tuple[str, str, Event] | None:
    """The subject's first successful login in the incident that came from an outside address."""
    for event in sorted(events, key=lambda e: e.timestamp):
        if event.actor != subject or event.event_type != "auth.login" or event.outcome not in (None, "success"):
            continue
        src = event.attributes.get("src_ip")
        if not isinstance(src, str) or not event.target:
            continue
        try:
            address = ipaddress.ip_address(src)
        except ValueError:
            continue
        if _external(address):
            return f"ip:{src}", event.target, event
    return None


# ------------------------------------------------------------------ IAM


def _trie(paths: list[list[tuple[str, str | None, str | None]]]) -> list[dict[str, Any]]:
    """Merge paths [(label, ref, note), ...] into tree nodes."""
    roots: list[dict[str, Any]] = []
    for path in paths:
        level = roots
        for label, ref, note in path:
            node = next((n for n in level if n["label"] == label), None)
            if node is None:
                node = tree_node(label, ref, note)
                level.append(node)
            level = node["children"]
    return roots


def iam(ctx: RafContext, ref: str | None) -> Screen:
    from raf.products.blast.service import BlastService
    from raf.products.iam.service import IamService

    current = focus(ctx)
    subject = _resolve(ctx, ref, current.subject, "identity")
    service = IamService(ctx)
    access = service.effective_access(subject.id, findings=True)
    meta = subject.metadata
    rows: list[Any] = [("Identity", subject.name, "accent", subject.id), ("Type", subject.type)]
    for key in ("full_name", "department", "title", "kind", "owner"):
        if meta.get(key):
            rows.append((key.replace("_", " ").capitalize(), meta[key]))
    rows.append(("Privileged", "yes" if access.privileged else "no", "danger" if access.privileged else "ok"))
    if meta.get("disabled"):
        rows.append(("State", "DISABLED", "warn"))
    if access.last_activity:
        rows.append(("Last activity", format_ts(access.last_activity)))
    blocks: list[Block] = [kv(rows)]
    direct = [g for g in access.groups if len(g["chain"]) == 2]
    nested = [g for g in access.groups if len(g["chain"]) > 2]
    blocks += [section("DIRECT MEMBERSHIPS")]
    blocks.append(text(*[f"  {g['name']}" for g in direct]) if direct else text("  none", style="dim"))
    if nested:
        blocks += [section("NESTED MEMBERSHIPS"), text(*[f"  {' → '.join(g['chain'])}" for g in nested])]
    if access.roles:
        blocks += [
            section("ROLES"),
            table(
                ["ROLE", "VIA", "PRIVILEGED"],
                [
                    {
                        "cells": [r["name"], " → ".join(r["chain"]), "yes" if r.get("privileged") else "no"],
                        "style": "danger" if r.get("privileged") else None,
                        "ref": r.get("id"),
                    }
                    for r in access.roles
                ],
            ),
        ]
    granted = [r for r in access.resources if r.get("via")]
    if granted:
        known = {subject.name: subject.id} | {g["name"]: g["id"] for g in access.groups}
        known |= {r["name"]: r["id"] for r in access.roles} | {i["name"]: i["id"] for i in access.identities}
        paths = []
        for resource in granted[:30]:
            parts = [p.strip() for p in str(resource["via"]).split("→")]
            steps: list[tuple[str, str | None, str | None]] = [(p, known.get(p), None) for p in parts]
            steps[-1] = (parts[-1], resource["id"], (resource.get("criticality") or "") or None)
            paths.append(steps)
        trie = _trie(paths)
        root = trie[0] if len(trie) == 1 else tree_node(subject.name, subject.id, children=trie)
        blocks += [section("INHERITED ACCESS"), {"t": "tree", "root": root, "arrows": False}]
    blast = BlastService(ctx).blast(subject.id) if _available(ctx, "blast") else None
    derived = _credential_path(blast, current.target.id if current.target and subject == current.subject else None)
    if derived is not None:
        hops, rest = derived
        steps = [(subject.name, subject.id, None)] + [
            (h.target_name, h.target, rel_words(h.relationship_type)) for h in hops if h.target != h.source
        ]
        blocks += [section("CREDENTIAL-DERIVED PATH"), {"t": "tree", "root": _nest(steps), "arrows": False}]
        if rest:
            blocks.append(
                text(
                    f"{hops[-1].target_name} then leads to " + " → ".join(h.target_name for h in rest),
                    style="dim",
                )
            )
    findings = list(access.findings)
    if blast is not None:
        involved = {subject.id} | {h.target for hops in blast.critical_paths.values() for h in hops}
        for oid in sorted(involved)[:60]:
            for finding in ctx.store.findings.list(
                object_id=oid, product="iam", statuses=["OPEN", "ACKNOWLEDGED"], limit=5
            ):
                if all(f.id != finding.id for f in findings):
                    findings.append(finding)
    findings.sort(key=lambda f: (-f.severity.rank, f.title))
    blocks.append(section("FINDINGS"))
    if findings:
        blocks.append(
            table(
                ["SEVERITY", "FINDING"],
                [
                    {"cells": [f.severity.value, f.title], "style": SEVERITY_STYLE[f.severity.value], "ref": f.id}
                    for f in findings[:15]
                ],
            )
        )
    else:
        blocks.append(text("No open IAM findings involve this identity.", style="dim"))
    if blast is not None and blast.critical_paths:
        target_id, hops = min(blast.critical_paths.items(), key=lambda item: (len(item[1]), item[0]))
        name = _names(ctx, [target_id])[target_id]
        blocks.append(
            kv(
                [
                    (
                        "Shortest critical path",
                        f"{len(hops)} hop{'s' if len(hops) != 1 else ''} → {name}",
                        "warn",
                        target_id,
                    )
                ]
            )
        )
    return Screen(
        "iam",
        f"R$F IAM — {subject.name}",
        blocks,
        subtitle="effective access and how it is obtained",
        param=subject.name,
    )


_SECRET_HOPS = ("CONTAINS_SECRET", "AUTHENTICATES_AS", "USES")


def _credential_path(blast: Any, preferred: str | None) -> tuple[list[Any], list[Any]] | None:
    """The blast path that goes through obtained credentials, cut after the identity it yields.

    Prefers the path to ``preferred`` (the focus target), then paths through a discovered secret,
    then the shortest. Returns (hops up to the derived identity, the remaining hops).
    """
    if blast is None:
        return None
    candidates = []
    for target, hops in blast.critical_paths.items():
        kinds = [h.relationship_type for h in hops]
        if not any(k in _SECRET_HOPS for k in kinds):
            continue
        cut = max(i for i, k in enumerate(kinds) if k in _SECRET_HOPS) + 1
        candidates.append(((target != preferred, "CONTAINS_SECRET" not in kinds, len(hops), target), hops, cut))
    if not candidates:
        return None
    _, hops, cut = min(candidates, key=lambda c: c[0])
    return hops[:cut], hops[cut:]


def _nest(steps: list[tuple[str, str | None, str | None]]) -> dict[str, Any]:
    """A single chain as nested tree nodes (each step the only child of the previous)."""
    root: dict[str, Any] | None = None
    parent: dict[str, Any] | None = None
    for label, ref, note in steps:
        node = tree_node(label, ref, note)
        if parent is None:
            root = node
        else:
            parent["children"].append(node)
        parent = node
    assert root is not None
    return root


# ------------------------------------------------------------------ blast


def blast(ctx: RafContext, ref: str | None) -> Screen:
    from raf.products.blast.service import BlastService

    current = focus(ctx)
    subject = _resolve(ctx, ref, current.subject, "subject")
    result = BlastService(ctx).blast(subject.id)
    reached = result.direct + result.indirect
    hosts = [r for r in reached if r.type == "host"]
    identities = [r for r in reached if r.type in ("user", "identity")]
    blocks: list[Block] = [
        text("Starting assumption:", style="dim"),
        text(f"  {subject.type.capitalize()} {subject.name} is controlled.", style="accent"),
        section("REACHABILITY"),
        kv(
            [
                ("Reachable objects", len(reached)),
                ("Reachable assets", result.reachable_assets),
                ("Controllable assets", result.controllable_assets, "warn"),
                ("Reachable hosts", len(hosts)),
                ("Controllable hosts", sum(1 for h in hosts if h.mode in (CONTROL, TRUST)), "warn"),
                ("Reachable identities", len(identities)),
                ("Critical/high assets", result.critical_assets, "danger"),
                ("Privileged paths", result.privileged_paths, "danger" if result.privileged_paths else None),
            ]
        ),
    ]
    target_id = current.target.id if current.target else None
    chosen = None
    if (
        target_id
        and target_id in result.critical_paths
        and subject.id == (current.subject.id if current.subject else None)
    ):
        chosen = (target_id, result.critical_paths[target_id])
    elif result.primary_path:
        chosen = (result.primary_path[-1].target, result.primary_path)
    if chosen is not None:
        hops = chosen[1]
        steps: list[tuple[str, str | None, str | None]] = [(subject.name, subject.id, None)] + [
            (h.target_name, h.target, rel_words(h.relationship_type)) for h in hops if h.target != h.source
        ]
        blocks += [section("CRITICAL PATH"), {"t": "tree", "root": _nest(steps), "arrows": True}]
        others = [t for t in result.critical_paths if t != chosen[0]]
        if others:
            names = _names(ctx, others[:8])
            blocks.append(text("Also controllable: " + ", ".join(names[t] for t in others[:8]), style="dim"))
    risk = result.risk
    blocks += [
        section("BLAST ASSESSMENT"),
        kv(
            [
                ("Severity", risk.level, LEVEL_STYLE.get(risk.level)),
                ("Score", f"{risk.score} / 100", LEVEL_STYLE.get(risk.level)),
                ("Methodology", risk.methodology, "dim"),
            ]
        ),
        section("WHY"),
        *[kv([(f"{f.sign}{f.points}", f.label, "danger" if f.sign == "+" else "ok")]) for f in risk.factors[:8]],
    ]
    if chosen is not None:
        target_name = _names(ctx, [chosen[0]])[chosen[0]]
        blocks += [
            text(""),
            text("Primary reason:", style="dim"),
            text(
                f"A compromise beginning at {subject.name} has a modeled control path to {target_name}.",
                style="accent",
            ),
        ]
    blocks += [
        section("IMPORTANT"),
        text("This is modeled reachability, not evidence that every step actually occurred.", style="warn"),
    ]
    return Screen(
        "blast",
        f"R$F BLAST — {subject.name}",
        blocks,
        subtitle="impact of a hypothetical compromise",
        param=subject.name,
    )


# ------------------------------------------------------------------ exposure


def exposure(ctx: RafContext, ref: str | None) -> Screen:
    from raf.products.exposure.service import ExposureService

    service = ExposureService(ctx)
    if ref:
        asset = _resolve(ctx, ref, None, "asset")
        item = service.assess(asset.id)
        return Screen(
            "exposure",
            f"R$F EXPOSURE — {asset.name}",
            _exposure_detail(item),
            param=asset.name,
            subtitle=f"{item.level} · {item.score}/100 · {item.methodology}",
        )
    report = service.report(persist=False)
    items = sorted(report.items, key=lambda i: (-i.score, i.object["name"]))
    rows = []
    for item in items:
        factors = [f.label for f in item.factors if f.sign == "+"][:2]
        rows.append(
            {
                "cells": [item.object["name"], str(item.score), item.level, "; ".join(factors) or "-"],
                "style": LEVEL_STYLE.get(item.level),
                "ref": item.object["id"],
            }
        )
    metrics = report.metrics
    blocks: list[Block] = [
        kv(
            [
                ("Assets scored", len(items)),
                ("Entry points", metrics.entry_points),
                ("Attack paths", metrics.attack_paths, "warn"),
                ("Critical paths", metrics.critical_paths, "danger"),
                ("Exposed critical assets", metrics.exposed_critical_assets, "danger"),
            ]
        ),
        section("ASSETS"),
        table(["ASSET", "SCORE", "LEVEL", "PRIMARY FACTORS"], rows, ["l", "r", "l", "l"]),
    ]
    interesting = _interesting(items)
    if interesting is not None:
        item, cvss = interesting
        reasons = [f.label for f in item.factors if f.sign == "-"]
        if item.internet == "none" and not item.entry_points:
            reasons.append("no modeled route from an entry point (Internet zones, workstations)")
        if not any(c.via_credentials for c in item.controllers):
            reasons.append("no credential path to it")
        blocks += [
            section("INTERESTING"),
            kv(
                [
                    (item.object["name"], "", "accent", item.object["id"]),
                    ("  CVSS maximum", f"{cvss:.1f}", "danger"),
                    ("  Exposure score", f"{item.score} ({item.level})", LEVEL_STYLE.get(item.level)),
                ]
            ),
            text("Reason:", style="dim"),
            text(*[f"  {r}" for r in reasons] or ["  no exposure factors raise it"]),
        ]
    return Screen("exposure", "R$F EXPOSURE", blocks, subtitle="explainable exposure of every asset (raf-risk/1.0)")


def _interesting(items: list[Any]) -> tuple[Any, float] | None:
    """The asset whose vulnerability score is highest while its exposure stays low."""
    best: tuple[Any, float] | None = None
    for item in items:
        if item.level not in ("LOW", "NONE", "MEDIUM"):
            continue
        cvss = max((float(v.get("cvss") or 0) for v in item.vulnerabilities), default=0.0)
        if cvss >= 7 and (best is None or cvss > best[1] or (cvss == best[1] and item.score < best[0].score)):
            best = (item, cvss)
    return best


def _exposure_detail(item: Any) -> list[Block]:
    blocks: list[Block] = [
        kv(
            [
                ("Level", item.level, LEVEL_STYLE.get(item.level)),
                ("Score", f"{item.score} / 100"),
                ("Internet", item.internet),
            ]
        ),
        section("FACTORS"),
        *[kv([(f"{f.sign}{f.points}", f.label, "danger" if f.sign == "+" else "ok")]) for f in item.factors],
    ]
    if item.controllers:
        blocks += [
            section("WHO CAN OBTAIN CONTROL"),
            table(
                ["PRINCIPAL", "TYPE", "CONFIDENCE", "VIA CREDENTIALS"],
                [
                    {
                        "cells": [c.name, c.type, f"{c.confidence:.2f}", "yes" if c.via_credentials else "no"],
                        "style": "danger" if c.privileged else None,
                        "ref": c.id,
                    }
                    for c in item.controllers[:20]
                ],
            ),
        ]
    if item.entry_points:
        blocks += [
            section("ENTRY POINTS"),
            text(
                *[
                    f"  {e.name} ({e.kind}, {e.hops} network hop(s)): {' → '.join(e.path)}"
                    for e in item.entry_points[:8]
                ]
            ),
        ]
    return blocks


# ------------------------------------------------------------------ policy


def policy(ctx: RafContext, _ref: str | None) -> Screen:
    from raf.products.policy.service import PolicyService

    service = PolicyService(ctx)
    policies = service.require_stored()
    analysis = service.analyze(persist=False)
    rules = {(p.id, r.id): r for p in policies for r in p.rules}
    counts = Counter(f.severity.value for f in analysis.findings)
    blocks: list[Block] = [
        kv(
            [
                ("Policies", ", ".join(p.id for p in policies)),
                ("Rules analyzed", sum(len(p.rules) for p in policies)),
            ]
        ),
        section("FINDINGS"),
        kv([(sev, counts.get(sev, 0), SEVERITY_STYLE[sev]) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]),
        spacer(),
    ]
    for finding in sorted(analysis.findings, key=lambda f: (-f.severity.rank, f.title)):
        policy_id = str(finding.metadata.get("policy"))
        rule_ids = [str(r) for r in finding.metadata.get("rules") or []]
        lines: list[str] = []
        for rule_id in rule_ids[:3]:
            rule = rules.get((policy_id, rule_id))
            if rule is None:
                continue
            lines += [
                f"{rule.effect.upper()}  ({rule.id})",
                f"  source       {', '.join(rule.sources) or '-'}",
                f"  destination  {', '.join(rule.destinations) or '-'}",
                f"  port         {', '.join(rule.ports) or '-'}",
            ]
            if rule.actions and rule.actions != ["*"] and policy_id != "raven-fw":
                lines.append(f"  actions      {', '.join(rule.actions)}")
        lines += ["", "Reason:", finding.description]
        if finding.recommendation:
            lines += ["", f"Recommendation: {finding.recommendation}"]
        blocks.append(
            {
                "t": "finding",
                "severity": finding.severity.value,
                "title": finding.title,
                "id": rule_ids[0] if rule_ids else finding.rule_id,
                "lines": lines,
                "ref": finding.id,
            }
        )
    return Screen("policy", "R$F POLICY", blocks, subtitle="firewall and access policy analysis")


# ------------------------------------------------------------------ ghost


def _ghost_refs(ctx: RafContext, ref: str | None) -> tuple[SecurityObject, SecurityObject]:
    current = focus(ctx)
    if ref and ("→" in ref or "->" in ref or " to " in ref):
        left, right = [p.strip() for p in ref.replace("->", "→").replace(" to ", "→").split("→", 1)]
        return _resolve(ctx, left, None, "subject"), _resolve(ctx, right, None, "target")
    subject = _resolve(ctx, ref, current.subject, "subject")
    if current.target is None:
        raise InvalidInputError("Give the experiment as 'subject → target', for example: bob → production.")
    return subject, current.target


def ghost(ctx: RafContext, ref: str | None) -> Screen:
    from raf.core.graph.propagation import Propagator
    from raf.core.risk.exposure import ExposureModel
    from raf.products.blast.service import BlastService
    from raf.products.ghost.ops import run_operation
    from raf.products.ghost.service import GhostService

    subject, target = _ghost_refs(ctx, ref)
    # propagation-only states: same verdicts, metrics and cut as the full workspace, without
    # loading activity records (see GhostService.propagation_state)
    before = GhostService(ctx).propagation_state()
    after = before.copy("containment-test")

    def controls(state: Any, *, vulnerabilities: bool = False) -> bool:
        reached = Propagator(
            state.graph(), max_depth=12, min_confidence=0.0, upgrade_vulnerabilities=vulnerabilities
        ).run([subject.id])
        found = reached.get(target.id)
        return found is not None and found.mode in (CONTROL, TRUST)

    was = controls(before)
    removed: list[str] = []
    result = None
    if was:
        result = run_operation(after, "remove-access", f"{subject.id}:{target.id}", "containment-test")
        after.apply(result.effects, model="containment-test", when=utcnow())
        removed = list(result.effects.removed_relationships)

    blast_service = BlastService(ctx)
    blast_before = blast_service.blast(subject.id, source=before.graph())
    blast_after = blast_service.blast(subject.id, source=after.graph())
    exposure_before, exposure_after = ExposureModel(before.graph()), ExposureModel(after.graph())
    metrics_before, metrics_after = exposure_before.metrics(), exposure_after.metrics()
    pairs_before, pairs_after = exposure_before.attack_pairs()[0], exposure_after.attack_pairs()[0]
    broken, opened = len(pairs_before - pairs_after), len(pairs_after - pairs_before)

    def privileged(blast_result: Any) -> int:
        nodes = before.objects
        count = 0
        for reach in blast_result.direct + blast_result.indirect:
            obj = nodes.get(reach.id)
            if obj is not None and obj.type in ("user", "identity") and is_privileged(obj.type, obj.metadata, obj.tags):
                count += 1
        return count

    now = controls(after)
    vuln_before, vuln_after = controls(before, vulnerabilities=True), controls(after, vulnerabilities=True)
    blocks: list[Block] = [
        text("Objective:", style="dim"),
        text(f"  Remove modeled path {subject.name} → {target.name}", style="accent"),
        spacer(),
    ]
    if result is None:
        blocks.append(text(f"{subject.name} has no access path to {target.name}; nothing to cut.", style="ok"))
    else:
        blocks.append(text(f"Minimum cut found: {result.summary}.", style="ok"))
        blocks += [
            section("PROPOSED CHANGES"),
            text(*[f"{n}. {line}" for n, line in enumerate(result.explanation, 1)]),
        ]
    blocks += [
        text(""),
        text("No production changes have been made: this ran in an unsaved Ghost model.", style="warn"),
        section("BEFORE / AFTER"),
        {
            "t": "compare",
            "left": "BEFORE",
            "right": "AFTER",
            "rows": [
                {
                    "label": f"{subject.name} → {target.name}",
                    "before": "REACHABLE" if was else "BLOCKED",
                    "after": "REACHABLE" if now else "BLOCKED",
                    "verdict": "better" if was and not now else ("same" if was == now else "worse"),
                },
                {
                    "label": "  incl. exploitable vulnerabilities",
                    "before": "REACHABLE" if vuln_before else "BLOCKED",
                    "after": "REACHABLE" if vuln_after else "BLOCKED",
                    "verdict": "better"
                    if vuln_before and not vuln_after
                    else ("same" if vuln_before == vuln_after else "worse"),
                },
                _compare_row("Blast score", blast_before.risk.score, blast_after.risk.score),
                _compare_row(
                    "Critical/high assets controllable", blast_before.critical_assets, blast_after.critical_assets
                ),
                _compare_row("Reachable privileged identities", privileged(blast_before), privileged(blast_after)),
                _compare_row("Attack paths (workspace)", metrics_before.attack_paths, metrics_after.attack_paths),
                _compare_row("Critical paths (workspace)", metrics_before.critical_paths, metrics_after.critical_paths),
                {
                    "label": "Attack paths broken",
                    "before": "",
                    "after": str(broken),
                    "verdict": "better" if broken else "same",
                },
                {
                    "label": "New attack paths",
                    "before": "",
                    "after": str(opened),
                    "verdict": "worse" if opened else "same",
                },
                {
                    "label": "Operational impact",
                    "before": "",
                    "after": f"{len(removed)} modeled relationship(s) removed",
                    "verdict": "info",
                },
            ],
        },
        *(
            [
                text(
                    f"{subject.name} can still reach {target.name} through network access combined with an "
                    "exploitable vulnerability: access changes alone do not close it (try the patch-vuln operation).",
                    style="warn",
                )
            ]
            if vuln_after
            else []
        ),
        section("SAVE THIS EXPERIMENT"),
        text(
            "raf ghost create containment-test",
            f"raf ghost modify containment-test --remove-access {subject.name}:{target.name}",
            "raf ghost compare current containment-test",
            style="info",
        ),
    ]
    return Screen(
        "ghost",
        "R$F GHOST — containment-test",
        blocks,
        subtitle="what-if model of the current workspace (not saved)",
        param=f"{subject.name} → {target.name}",
    )


def _compare_row(label: str, before: int, after: int) -> dict[str, Any]:
    verdict = "same" if before == after else ("better" if after < before else "worse")
    return {"label": label, "before": str(before), "after": str(after), "verdict": verdict}


# ------------------------------------------------------------------ graph


def graph(ctx: RafContext, ref: str | None) -> Screen:
    from raf.products.graph.service import GraphService

    current = focus(ctx)
    subject = _resolve(ctx, ref, current.subject, "object")
    scope = resolve_scope(ctx, [subject.id])
    # process records (activity: every program a host ran) would crowd out the security structure;
    # propagation never enters them either, so they are only drawn when one is the subject
    present = ctx.store.objects.count_by_type()
    hidden = sorted(t for t in present if t in NON_PROPAGATING_TYPES and t != subject.type)
    node_types = [t for t in present if t not in hidden] if hidden else None
    sub = GraphService(ctx).view(scope, depth=2, max_nodes=60, node_types=node_types)
    index = sub.node_index()
    path_nodes: list[str] = []
    story_path: Any = None
    if current.subject is not None and subject.id == current.subject.id and current.incident is not None:
        retrieval = _story(ctx, current.incident)
        if retrieval.paths:
            story_path = retrieval.paths[0]
            path_nodes = [story_path.subject] + [h.target for h in story_path.hops if h.target != h.source]
    adjacency: dict[str, list[tuple[str, str, str]]] = {}
    for edge in sub.edges:
        adjacency.setdefault(edge.source, []).append((edge.target, edge.type, "out"))
        adjacency.setdefault(edge.target, []).append((edge.source, edge.type, "in"))
    # spanning tree: the story path first, then breadth-first by relationship priority
    parent: dict[str, tuple[str, str, str] | None] = {subject.id: None}
    order = [subject.id]
    # the whole story path is drawn, also beyond the 2-hop neighborhood (its hops say how)
    hop_types = {h.target: h.relationship_type for h in story_path.hops} if story_path is not None else {}
    for prev, node in itertools.pairwise(path_nodes):
        if node in parent or prev not in parent:
            continue
        rel = next(((t, d) for n, t, d in adjacency.get(prev, []) if n == node), None)
        if rel is None:
            if node not in hop_types:
                break
            rel = (hop_types[node], "out")
        parent[node] = (prev, rel[0], rel[1])
        order.append(node)
    queue = list(order)
    priority = {"LOGGED_INTO": 0, "MEMBER_OF": 1, "HAS_ROLE": 2, "CAN_ACCESS": 3, "ADMIN_OF": 3, "USES": 4}
    while queue:
        node = queue.pop(0)
        neighbours = sorted(adjacency.get(node, []), key=lambda x: (priority.get(x[1], 9), x[0]))
        for other, rel_type, direction in neighbours:
            if other in parent or other not in index or len(parent) >= 40:
                continue
            parent[other] = (node, rel_type, direction)
            order.append(other)
            queue.append(other)
    outside = ctx.store.objects.get_many([n for n in order if n not in index])
    nodes = []
    for node_id in order:
        gnode = index.get(node_id)
        stored = outside.get(node_id)
        obj_name = gnode.name if gnode else (stored.name if stored else node_id.split(":", 1)[-1])
        criticality = gnode.criticality if gnode else (stored.metadata.get("criticality") if stored else None)
        link = parent[node_id]
        nodes.append(
            {
                "id": node_id,
                "label": obj_name,
                "type": gnode.type if gnode else node_id.split(":", 1)[0],
                "criticality": str(criticality) if criticality else None,
                "highlight": node_id in path_nodes,
                "parent": link[0] if link else None,
                "edge": link[1] if link else None,
                "dir": link[2] if link else None,
            }
        )
    tree_pairs = {(p[0], n) for n, p in parent.items() if p} | {(n, p[0]) for n, p in parent.items() if p}
    links = [
        {"source": e.source, "target": e.target, "label": e.type}
        for e in sub.edges
        if (e.source, e.target) not in tree_pairs and e.source in parent and e.target in parent
    ]
    blocks: list[Block] = [{"t": "graph", "root": subject.id, "nodes": nodes, "links": links[:40]}]
    if story_path is not None:
        names = _names(ctx, path_nodes)
        steps = [(names[path_nodes[0]], path_nodes[0], None)]
        hops = [h for h in story_path.hops if h.target != h.source]
        steps += [(names.get(h.target, h.target_name), h.target, h.relationship_type) for h in hops]
        blocks += [
            section("CRITICAL PATH"),
            {
                "t": "chain",
                "nodes": [chain_node(label, r) for label, r, _ in steps],
                "edges": [
                    chain_edge(
                        label or "",
                        "observed" if h.observed_event else "modeled",
                        _observed_note(ctx.store.events.get(h.observed_event), h.observed)
                        if h.observed_event
                        else None,
                    )
                    for (_, _, label), h in zip(steps[1:], hops, strict=False)
                ],
            },
        ]
    notes = [f"{len(sub.nodes)} objects within 2 hops; {len(nodes)} drawn"]
    if hidden:
        notes.append(f"{', '.join(hidden)} records are not drawn (raf graph {subject.name} shows everything)")
    if sub.truncated:
        notes.append("the neighborhood was truncated (graph.max_nodes)")
    return Screen(
        "graph",
        f"R$F GRAPH — {subject.name}",
        blocks,
        subtitle=f"{subject.type} · {subject.id}",
        param=subject.name,
        notes=notes,
    )


# ------------------------------------------------------------------ oracle


def oracle(ctx: RafContext, question: str | None) -> Screen:
    from raf.products.oracle.service import OracleService

    current = focus(ctx)
    asked = question or (
        f"Explain the most important security path in {current.incident.name}"
        if current.incident
        else "What should I look at first?"
    )
    answer = OracleService(ctx).ask(asked)
    blocks: list[Block] = [
        text(f"Q: {answer.question}", style="accent"),
        text(f"{answer.mode} · intent {answer.intent} · {len(answer.facts)} fact(s) retrieved", style="dim"),
        spacer(),
        text(*answer.answer.splitlines()),
    ]
    if answer.citations:
        blocks += [
            section("CITATIONS"),
            {"t": "citations", "items": [c.model_dump() for c in answer.citations]},
        ]
    if answer.warnings:
        blocks += [section("WARNINGS"), text(*answer.warnings, style="warn")]
    if answer.suggestions:
        blocks += [section("NEXT (never executed by Oracle)"), text(*answer.suggestions, style="info")]
    blocks.append(text(answer.notice, style="note"))
    return Screen("oracle", "R$F ORACLE", blocks, subtitle="grounded answers with validated citations", param=asked)


# ------------------------------------------------------------------ findings and evidence


def findings(ctx: RafContext, ref: str | None) -> Screen:
    product = None
    minimum = None
    if ref:
        try:
            minimum = Severity.parse(ref)
        except Exception:  # noqa: BLE001 - anything else is a product name
            product = ref.strip().lower()
    items = ctx.store.findings.list(statuses=["OPEN", "ACKNOWLEDGED"], product=product, min_severity=minimum, limit=300)
    counts = Counter(f.severity.value for f in items)
    rows = [
        {
            "cells": [f.severity.value, confidence_level(f.confidence).value, f.product, f.title],
            "style": SEVERITY_STYLE[f.severity.value],
            "ref": f.id,
        }
        for f in items
    ]
    blocks: list[Block] = [
        kv([(sev, counts.get(sev, 0), SEVERITY_STYLE[sev]) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]),
        section(f"OPEN FINDINGS  {len(items)}"),
        table(["SEVERITY", "CONFIDENCE", "PRODUCT", "FINDING"], rows),
        text(
            "Severity and confidence are independent: a HIGH finding can rest on LOW-confidence evidence.", style="note"
        ),
    ]
    label = f" — {ref}" if ref else ""
    return Screen("findings", f"R$F FINDINGS{label}", blocks, subtitle="all products", param=ref or "")


def evidence(ctx: RafContext, ref: str | None) -> Screen:
    from raf.products.evidence.service import EvidenceService

    service = EvidenceService(ctx)
    cases = service.cases()
    if not cases:
        return Screen(
            "evidence",
            "R$F EVIDENCE",
            [text("No evidence cases yet.", "raf evidence case create INC-001", style="dim")],
        )
    case = next((c for c in cases if ref and c.name.lower() == ref.lower()), cases[0])
    items = service.items(case.name)
    check = service.verify(case=case.name) if items else None
    status = {str(i.get("id")): bool(i.get("ok")) for i in (check.items if check else [])}
    rows = []
    for item in items:
        ok = status.get(item.id, False)
        rows.append(
            {
                "cells": [
                    item.id,
                    item.name,
                    f"{item.size:,}",
                    item.sha256[:16] + "…",
                    item.status,
                    "✔ intact" if ok else "✘ MISMATCH",
                ],
                "style": None if ok else "danger",
                "ref": f"evidence:{item.id}",
            }
        )
    blocks: list[Block] = [
        kv(
            [
                ("Case", case.name, "accent"),
                ("Title", case.title or "-"),
                ("Items", len(items)),
                (
                    "Integrity",
                    "VERIFIED" if check and check.verified else "FAILED",
                    "ok" if check and check.verified else "danger",
                ),
            ]
        ),
        section("ITEMS"),
        table(["ID", "NAME", "BYTES", "SHA-256", "STATUS", "INTEGRITY"], rows, ["l", "l", "r", "l", "l", "l"]),
        text(
            "Originals are stored read-only and content-addressed; every action is in a hash-chained custody log.",
            style="note",
        ),
    ]
    return Screen(
        "evidence",
        f"R$F EVIDENCE — {case.name}",
        blocks,
        subtitle="hashed, read-only, chain of custody",
        param=case.name,
    )


# ------------------------------------------------------------------ inspector


def inspect(ctx: RafContext, ref: str) -> Screen:
    if ref.startswith("event:"):
        event = ctx.store.events.get(ref)
        if event is None:
            raise NotFoundError(f"Event '{ref}' does not exist.")
        names = _names(ctx, [i for i in (event.actor, event.target) if i])
        rows: list[Any] = [
            ("Time", format_ts(event.timestamp)),
            ("Type", event.event_type),
            ("Severity", event.severity.value, SEVERITY_STYLE.get(event.severity.value)),
            ("Actor", names.get(event.actor or "", "-"), None, event.actor),
            ("Target", names.get(event.target or "", "-"), None, event.target),
            ("Outcome", event.outcome or "-"),
            ("Source", event.source),
            ("Parser", event.parser),
        ]
        blocks: list[Block] = [kv(rows)]
        if event.message:
            blocks += [section("MESSAGE (imported, untrusted)"), text(event.message[:2000], style="dim")]
        if event.attributes:
            blocks += [section("ATTRIBUTES"), kv([(k, str(v)[:300]) for k, v in sorted(event.attributes.items())])]
        if event.objects:
            names = _names(ctx, [o.object_id for o in event.objects])
            blocks += [section("OBJECTS"), kv([(o.role, names[o.object_id], None, o.object_id) for o in event.objects])]
        return Screen("inspect", f"EVENT {event.event_type}", blocks, subtitle=event.id, param=event.id)
    if ref.startswith("finding:"):
        finding = ctx.store.findings.require(ref)
        blocks = [
            kv(
                [
                    ("Severity", finding.severity.value, SEVERITY_STYLE.get(finding.severity.value)),
                    ("Confidence", f"{finding.confidence:.2f} ({confidence_level(finding.confidence).value})"),
                    ("Product", f"{finding.product} / {finding.rule_id}"),
                    ("Status", finding.status.value),
                ]
            ),
            section("DESCRIPTION"),
            text(finding.description),
        ]
        if finding.recommendation:
            blocks += [section("RECOMMENDATION"), text(finding.recommendation)]
        if finding.explanation:
            blocks += [
                section("WHY"),
                kv(
                    [
                        (str(e.get("sign", "")) + str(e.get("points", "")), str(e.get("label", "")))
                        for e in finding.explanation
                    ]
                ),
            ]
        names = _names(ctx, finding.affected_objects[:20])
        blocks += [
            section("AFFECTED"),
            kv([(oid.split(":", 1)[0], names[oid], None, oid) for oid in finding.affected_objects[:20]]),
        ]
        return Screen("inspect", finding.title, blocks, subtitle=finding.id, param=finding.id)
    resolved = ctx.resolve(ref)
    obj = resolved.obj or ctx.store.objects.get(resolved.id)
    if obj is None:
        raise NotFoundError(f"'{ref}' is not an object, event or finding.")
    rows = [
        ("ID", obj.id),
        ("Type", obj.type),
        ("Confidence", f"{obj.confidence:.2f}"),
        ("First seen", format_ts(obj.first_seen) if obj.first_seen else "-"),
        ("Last seen", format_ts(obj.last_seen) if obj.last_seen else "-"),
        ("Source", obj.source),
    ]
    if obj.tags:
        rows.append(("Tags", ", ".join(obj.tags)))
    blocks = [kv(rows)]
    if obj.metadata:
        blocks += [section("METADATA"), kv([(k, str(v)[:200]) for k, v in sorted(obj.metadata.items())][:40])]
    rels = ctx.store.relationships.edges([obj.id], direction="both")[:40]
    if rels:
        names = _names(ctx, list({r.source_object for r in rels} | {r.target_object for r in rels}))
        blocks += [
            section("RELATIONSHIPS"),
            *[
                kv(
                    [
                        (
                            rel.relationship_type,
                            f"→ {names[rel.target_object]}"
                            if rel.source_object == obj.id
                            else f"← {names[rel.source_object]}",
                            None,
                            rel.target_object if rel.source_object == obj.id else rel.source_object,
                        )
                    ]
                )
                for rel in rels
            ],
        ]
    related = ctx.store.findings.list(object_id=obj.id, statuses=["OPEN", "ACKNOWLEDGED"], limit=10)
    if related:
        blocks += [
            section("FINDINGS"),
            table(
                ["SEVERITY", "FINDING"],
                [
                    {"cells": [f.severity.value, f.title], "style": SEVERITY_STYLE[f.severity.value], "ref": f.id}
                    for f in related
                ],
            ),
        ]
    return Screen("inspect", f"{obj.type.upper()} {obj.name}", blocks, subtitle=obj.id, param=obj.id)


# --------------------------------------------------------------------------- registry

PageBuilder = Callable[[RafContext, str | None], Screen]
PAGES: dict[str, PageBuilder] = {
    "home": home,
    "timeline": timeline,
    "trace": trace,
    "iam": iam,
    "blast": blast,
    "exposure": exposure,
    "policy": policy,
    "ghost": ghost,
    "graph": graph,
    "oracle": oracle,
    "findings": findings,
    "evidence": evidence,
}
PAGE_TITLES = {page: page.upper() for page in PAGES}
PAGE_PRODUCTS = {
    "timeline": "replay",
    "trace": "trace",
    "iam": "iam",
    "blast": "blast",
    "exposure": "exposure",
    "policy": "policy",
    "ghost": "ghost",
    "graph": "graph",
    "oracle": "oracle",
    "evidence": "evidence",
}


def screen(ctx: RafContext, page: str, param: str | None = None) -> dict[str, Any]:
    builder = PAGES.get(page)
    if builder is None:
        raise NotFoundError(f"Unknown R$F OS page '{page}'.", suggestions=[", ".join(PAGES)])
    product = PAGE_PRODUCTS.get(page)
    if product is not None:
        ctx.require_product(product)
    value = (param or "").strip() or None
    if value is not None and len(value) > 500:
        raise InvalidInputError("The page parameter is longer than 500 characters.")
    return builder(ctx, value).to_dict()
