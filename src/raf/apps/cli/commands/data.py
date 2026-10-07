"""Data commands: search, show (object inspector), objects, findings, incidents, jobs, audit."""

from __future__ import annotations

from typing import Any

import typer
from rich.markup import escape
from rich.text import Text

from raf.analysis.pivots import pivots_for
from raf.apps.cli import runtime as rt
from raf.core.jobs.manager import JobStatus
from raf.core.objects.models import Event, Finding, SecurityObject
from raf.core.objects.types import FindingStatus, Severity, validate_object_type

PANEL = "Data"

finding_app = typer.Typer(help="Inspect and triage a finding.", no_args_is_help=True)
job_app = typer.Typer(help="Inspect or cancel a job.", no_args_is_help=True)
audit_app = typer.Typer(help="R$F's own tamper-evident audit log.", invoke_without_command=True)


def _available_products() -> set[str]:
    registry = rt.ctx().registry
    if registry is None:
        return set()
    return {p.name for p in registry.products() if p.available}


def object_payload(obj: SecurityObject, *, limit: int = 50) -> dict[str, Any]:
    ctx = rt.ctx()
    store = ctx.store
    rels = store.relationships.edges([obj.id], direction="both", include_inactive=True)
    neighbor_ids = {r.target_object if r.source_object == obj.id else r.source_object for r in rels}
    names = {o.id: o.name for o in store.objects.get_many(neighbor_ids).values()}
    activity = store.events.object_activity([obj.id]).get(obj.id)
    return {
        "object": obj.model_dump(mode="json"),
        "relationships": [
            {
                **r.model_dump(mode="json"),
                "direction": "out" if r.source_object == obj.id else "in",
                "other": r.target_object if r.source_object == obj.id else r.source_object,
                "other_name": names.get(r.target_object if r.source_object == obj.id else r.source_object),
            }
            for r in rels[:limit]
        ],
        "relationship_count": len(rels),
        "activity": {"first_event": activity[0], "last_event": activity[1], "events": activity[2]}
        if activity
        else None,
        "findings": [f.model_dump(mode="json") for f in store.findings.list(object_id=obj.id, limit=20)],
        "provenance": [p.model_dump(mode="json") for p in store.provenance.for_subject(obj.id, limit=10)],
        "provenance_count": store.provenance.count_for_subject(obj.id),
        "pivots": [p.to_dict() for p in pivots_for(obj.id, obj.type, _available_products() or None)],
    }


def render_object(data: dict[str, Any]) -> None:
    obj = data["object"]
    c = rt.console()
    rt.header(f"{obj['name']}  ({obj['id']})")
    rows: list[tuple[str, Any]] = [
        ("Type", obj["type"]),
        ("Source", obj["source"]),
        ("First seen", obj.get("first_seen") or "-"),
        ("Last seen", obj.get("last_seen") or "-"),
        ("Confidence", rt.conf_text(obj["confidence"])),
        ("Observations", obj["observations"]),
    ]
    if obj.get("valid_to"):
        rows.append(("Valid until", obj["valid_to"]))
    if obj["tags"]:
        rows.append(("Tags", ", ".join(obj["tags"])))
    if obj["synthetic"]:
        rows.append(("Synthetic", Text("yes (generated data)", style="magenta")))
    if data.get("activity"):
        act = data["activity"]
        rows.append(("Events", f"{act['events']:,}  ({act['first_event']} .. {act['last_event']})"))
    rt.kv_block(rows, width=14)
    meta = obj.get("metadata") or {}
    if meta:
        c.print()
        c.print(Text("Metadata", style="bold"))
        for key in sorted(meta)[:40]:
            value = meta[key]
            text = value if isinstance(value, str) else repr(value)
            c.print(Text(f"  {key:<20}", style="dim") + Text(text[:200]))
    if data["relationships"]:
        c.print()
        c.print(Text(f"Relationships ({data['relationship_count']})", style="bold"))
        for rel in data["relationships"][:25]:
            arrow = "->" if rel["direction"] == "out" else "<-"
            line = Text(f"  {arrow} ")
            line.append(f"{rel['relationship_type']:<16}", style="cyan")
            line.append(rel.get("other_name") or rel["other"], style="bold")
            line.append(f"  {rel['other']}", style="dim")
            if rel.get("valid_to"):
                line.append(f"  ended {rel['valid_to']}", style="yellow")
            c.print(line)
        if data["relationship_count"] > 25:
            c.print(
                Text(f"  ... {data['relationship_count'] - 25} more (raf graph neighbors {obj['id']})", style="dim")
            )
    if data["findings"]:
        c.print()
        c.print(Text("Findings", style="bold"))
        for f in data["findings"]:
            c.print(Text("  ") + rt.sev_text(f["severity"]) + Text(f"  {f['title']}  ") + Text(f["id"], style="dim"))
    if data["provenance"]:
        c.print()
        c.print(Text(f"Provenance ({len(data['provenance'])} of {data['provenance_count']})", style="bold"))
        for p in data["provenance"]:
            c.print(
                Text(f"  {p['source']}", style="bold")
                + Text(
                    f"  record {p.get('record') or '-'}  parser {p.get('parser') or '-'}  observed "
                    f"{p.get('observed_at') or '-'}",
                    style="dim",
                )
            )
    if data["pivots"] and not rt.STATE.quiet:
        c.print()
        c.print(Text("Pivots", style="bold"))
        for p in data["pivots"]:
            c.print(Text(f"  [{p['key']}] {p['label']:<12}", style="bold") + Text(p["command"], style="cyan"))


def render_event(ev: Event) -> None:
    rt.header(f"EVENT {ev.event_type}", ev.id)
    rows: list[tuple[str, Any]] = [
        ("Time", rt.ts_text(ev.timestamp)),
        ("Type", ev.event_type),
        ("Action", ev.action),
        ("Outcome", ev.outcome or "-"),
        ("Actor", ev.actor or "-"),
        ("Target", ev.target or "-"),
        ("Severity", rt.sev_text(ev.severity)),
        ("Confidence", rt.conf_text(ev.confidence)),
        ("Source", ev.source),
        ("Parser", ev.parser),
        ("Record", ev.record or "-"),
        ("Raw ref", ev.raw_reference or "-"),
    ]
    if ev.synthetic:
        rows.append(("Synthetic", Text("yes (generated data)", style="magenta")))
    if ev.incidents:
        rows.append(("Incidents", ", ".join(ev.incidents)))
    rt.kv_block(rows, width=12)
    c = rt.console()
    if ev.message:
        c.print()
        c.print(Text(ev.message))
    if ev.objects:
        c.print()
        c.print(Text("Involved objects", style="bold"))
        for ref in ev.objects:
            c.print(Text(f"  {ref.role:<10}", style="dim") + Text(ref.object_id))
    if ev.attributes:
        c.print()
        c.print(Text("Attributes", style="bold"))
        for key in sorted(ev.attributes):
            c.print(Text(f"  {key:<20}", style="dim") + Text(str(ev.attributes[key])[:200]))
    if ev.raw:
        c.print()
        c.print(Text("Raw record (untrusted data)", style="bold"))
        c.print(Text(ev.raw[:1500], style="dim"))


def render_finding(f: Finding) -> None:
    rt.header(f.title, f.id)
    rt.kv_block(
        [
            ("Severity", rt.sev_text(f.severity)),
            ("Confidence", rt.conf_text(f.confidence)),
            ("Status", f.status.value),
            ("Product", f.product),
            ("Rule", f.rule_id),
            ("Created", rt.ts_text(f.created_at)),
            ("Updated", rt.ts_text(f.updated_at)),
        ],
        width=12,
    )
    c = rt.console()
    c.print()
    c.print(Text(f.description))
    if f.explanation:
        c.print()
        c.print(Text("Why", style="bold"))
        for factor in f.explanation:
            sign = factor.get("sign", "+")
            c.print(Text(f"  {sign} ", style="green" if sign == "-" else "red") + Text(str(factor.get("label", ""))))
    if f.affected_objects:
        c.print()
        c.print(Text("Affected objects", style="bold"))
        for oid in f.affected_objects[:20]:
            c.print(Text(f"  {oid}"))
    if f.evidence:
        c.print()
        c.print(Text("Evidence", style="bold"))
        for ev in f.evidence[:20]:
            c.print(Text(f"  {ev.kind:<12}", style="dim") + Text(ev.id) + Text(f"  {ev.note or ''}", style="dim"))
    if f.recommendation:
        c.print()
        c.print(Text("Recommendation", style="bold"))
        c.print(Text(f"  {f.recommendation}"))


def register(app: typer.Typer) -> None:
    @app.command("search", rich_help_panel=PANEL)
    def search_cmd(
        query: str, type_: list[str] = typer.Option(None, "--type", "-t"), limit: int = typer.Option(25, "--limit")
    ) -> None:
        """Search objects, incidents, findings by ID, name or alias."""
        ctx = rt.ctx()
        types = [validate_object_type(t) for t in type_] if type_ else None
        objs = ctx.store.objects.search(query, types=types, limit=limit)
        findings = ctx.store.findings.list(text=query, limit=10) if not types else []
        data = {
            "query": query,
            "objects": [o.model_dump(mode="json") for o in objs],
            "findings": [f.model_dump(mode="json") for f in findings],
        }

        def render() -> None:
            if not objs and not findings:
                rt.console().print(f"No results for '{escape(query)}'.")
                return
            if objs:
                rt.table(
                    ["TYPE", "NAME", "ID", "LAST SEEN"], [(o.type, o.name, o.id, rt.ts_text(o.last_seen)) for o in objs]
                )
            if findings:
                rt.console().print()
                rt.table(["SEVERITY", "FINDING", "ID"], [(rt.sev_text(f.severity), f.title, f.id) for f in findings])
            if objs:
                rt.next_steps([f"raf show {objs[0].id}"])

        rt.output("raf.search/v1", data, render)

    @app.command("show", rich_help_panel=PANEL)
    def show_cmd(
        ref: str = typer.Argument(..., help="Object ID, name, alias, event:..., finding:... or @last."),
        type_: str | None = typer.Option(None, "--type", "-t", help="Restrict name resolution to a type."),
    ) -> None:
        """Object inspector with relationships, provenance, findings and pivots."""
        ctx = rt.ctx()
        resolved = ctx.resolve(
            ref, types=[validate_object_type(type_)] if type_ else None, accept=("object", "event", "finding")
        )
        for n in resolved.notes:
            rt.note(n)
        if resolved.kind == "event":
            ev = ctx.store.events.get(resolved.id)
            assert ev is not None
            rt.output("raf.event/v1", ev.model_dump(mode="json"), lambda: render_event(ev))
            return
        if resolved.kind == "finding":
            finding = ctx.store.findings.require(resolved.id)
            rt.output("raf.finding/v1", finding.model_dump(mode="json"), lambda: render_finding(finding))
            return
        assert resolved.obj is not None
        ctx.refs.remember("incident" if resolved.obj.type == "incident" else "object", resolved.id)
        data = object_payload(resolved.obj)
        rt.output("raf.object/v1", data, lambda: render_object(data))

    @app.command("objects", rich_help_panel=PANEL)
    def objects_cmd(
        type_: list[str] = typer.Option(None, "--type", "-t"),
        tag: str | None = typer.Option(None),
        text: str | None = typer.Option(None, "--filter", help="Substring of name or ID."),
        limit: int = typer.Option(50),
        offset: int = typer.Option(0),
    ) -> None:
        """List objects (filter by type, tag or text; paginated)."""
        ctx = rt.ctx()
        types = [validate_object_type(t) for t in type_] if type_ else None
        objs = ctx.store.objects.list(types=types, tag=tag, text=text, limit=limit, offset=offset)
        total = ctx.store.objects.count(types=types, text=text) if tag is None else None
        data = {"items": [o.model_dump(mode="json") for o in objs], "total": total, "offset": offset, "limit": limit}

        def render() -> None:
            if not objs:
                rt.console().print("No objects match.")
                return
            rt.table(
                ["TYPE", "NAME", "ID", "SOURCE", "LAST SEEN"],
                [(o.type, o.name, o.id, o.source, rt.ts_text(o.last_seen)) for o in objs],
            )
            if total is not None and total > offset + len(objs):
                rt.note(f"Showing {offset + 1}-{offset + len(objs)} of {total:,}. Use --offset to page.")

        rt.output("raf.objects/v1", data, render)

    @app.command("findings", rich_help_panel=PANEL)
    def findings_cmd(
        severity: str | None = typer.Option(None, "--severity", "-s", help="Minimum severity."),
        product: str | None = typer.Option(None),
        status: list[str] = typer.Option(None),
        object_ref: str | None = typer.Option(None, "--object"),
        limit: int = typer.Option(50),
    ) -> None:
        """List findings from all products (severity and confidence are independent)."""
        ctx = rt.ctx()
        object_id = ctx.resolve(object_ref).id if object_ref else None
        statuses = [FindingStatus(s.upper()).value for s in status] if status else ["OPEN", "ACKNOWLEDGED"]
        items = ctx.store.findings.list(
            product=product,
            min_severity=Severity.parse(severity) if severity else None,
            statuses=statuses,
            object_id=object_id,
            limit=limit,
        )
        data = {"items": [f.model_dump(mode="json") for f in items]}

        def render() -> None:
            if not items:
                rt.console().print("No findings match.")
                return
            rt.table(
                ["SEVERITY", "CONFIDENCE", "PRODUCT", "TITLE", "ID"],
                [(rt.sev_text(f.severity), rt.conf_text(f.confidence), f.product, f.title, f.id) for f in items],
            )
            rt.next_steps([f"raf finding show {items[0].id}"])

        rt.output("raf.findings/v1", data, render)

    @finding_app.command("show")
    def finding_show(finding_id: str) -> None:
        """Show a finding with its explanation and evidence."""
        f = rt.ctx().store.findings.require(finding_id)
        rt.output("raf.finding/v1", f.model_dump(mode="json"), lambda: render_finding(f))

    def _set_status(finding_id: str, status: FindingStatus, note: str | None) -> None:
        ctx = rt.ctx()
        f = ctx.store.findings.set_status(finding_id, status, note)
        ctx.audit.record("finding.status", affected=[finding_id], details={"status": status.value, "note": note})
        rt.output("raf.finding/v1", f.model_dump(mode="json"), lambda: rt.success(f"{finding_id} -> {status.value}"))

    @finding_app.command("ack")
    def finding_ack(finding_id: str, note: str | None = typer.Option(None)) -> None:
        """Acknowledge a finding."""
        _set_status(finding_id, FindingStatus.ACKNOWLEDGED, note)

    @finding_app.command("resolve")
    def finding_resolve(finding_id: str, note: str | None = typer.Option(None)) -> None:
        """Mark a finding resolved."""
        _set_status(finding_id, FindingStatus.RESOLVED, note)

    @finding_app.command("false-positive")
    def finding_fp(finding_id: str, note: str | None = typer.Option(None)) -> None:
        """Mark a finding as a false positive (re-runs keep this decision)."""
        _set_status(finding_id, FindingStatus.FALSE_POSITIVE, note)

    @finding_app.command("reopen")
    def finding_reopen(finding_id: str, note: str | None = typer.Option(None)) -> None:
        """Reopen a finding."""
        _set_status(finding_id, FindingStatus.OPEN, note)

    @app.command("incidents", rich_help_panel=PANEL)
    def incidents_cmd() -> None:
        """List incidents."""
        items = rt.ctx().store.incidents.list()
        data = {"items": [i.model_dump(mode="json") for i in items]}

        def render() -> None:
            if not items:
                rt.console().print("No incidents yet.")
                rt.next_steps(["raf demo load", "raf evidence case create INC-001"])
                return
            rt.table(
                ["INCIDENT", "SEVERITY", "STATUS", "EVENTS", "START", "END", "TITLE"],
                [
                    (
                        i.name,
                        rt.sev_text(i.severity),
                        i.status,
                        f"{i.event_count:,}",
                        rt.ts_text(i.start),
                        rt.ts_text(i.end),
                        i.title,
                    )
                    for i in items
                ],
            )
            rt.next_steps([f"raf replay {items[0].name}", f"raf timeline {items[0].name}"])

        rt.output("raf.incidents/v1", data, render)

    @app.command("jobs", rich_help_panel=PANEL)
    def jobs_cmd(status: str | None = typer.Option(None), limit: int = typer.Option(20)) -> None:
        """List recent jobs."""
        ctx = rt.ctx()
        ctx.jobs.reconcile()
        items = ctx.jobs.list(limit=limit, status=JobStatus(status.upper()) if status else None)
        data = {"items": [j.model_dump(mode="json") for j in items]}

        def render() -> None:
            if not items:
                rt.console().print("No jobs yet.")
                return
            rt.table(
                ["JOB", "KIND", "STATUS", "PROGRESS", "CREATED", "DURATION", "TITLE"],
                [
                    (
                        j.id,
                        j.kind,
                        j.status.value,
                        f"{j.progress * 100:.0f}%",
                        rt.ts_text(j.created_at),
                        f"{(j.duration_ms or 0) / 1000:.1f}s",
                        j.title,
                    )
                    for j in items
                ],
            )

        rt.output("raf.jobs/v1", data, render)

    @job_app.command("show")
    def job_show(job_id: str) -> None:
        """Show a job's status, result and errors."""
        job = rt.ctx().jobs.require(job_id)
        rt.ctx().refs.remember("job", job.id)

        def render() -> None:
            rt.header(f"JOB {job.id}", job.title)
            rt.kv_block(
                [
                    ("Kind", job.kind),
                    ("Status", job.status.value),
                    ("Progress", f"{job.progress * 100:.0f}%"),
                    ("Created", rt.ts_text(job.created_at)),
                    ("Started", rt.ts_text(job.started_at)),
                    ("Finished", rt.ts_text(job.finished_at)),
                    ("Actor", job.actor),
                    ("Message", job.message or "-"),
                ]
            )
            if job.error:
                rt.console().print()
                rt.console().print(Text("Error", style="bold red"))
                rt.kv_block([(k, v) for k, v in job.error.items() if k != "traceback"])
            if job.result:
                rt.console().print()
                rt.console().print(Text("Result", style="bold"))
                for key, value in job.result.items():
                    if isinstance(value, list | dict):
                        value = f"({len(value)} entries; use --json)"
                    rt.kv_block([(key, value)])

        rt.output("raf.job/v1", job.model_dump(mode="json"), render)

    @job_app.command("cancel")
    def job_cancel(job_id: str) -> None:
        """Request cancellation of a queued or running job."""
        ctx = rt.ctx()
        job = ctx.jobs.cancel(job_id)
        ctx.audit.record("job.cancel", affected=[job_id])
        rt.output("raf.job/v1", job.model_dump(mode="json"), lambda: rt.success(f"{job.id}: {job.status.value}"))

    @audit_app.callback()
    def audit_list(
        typer_ctx: typer.Context, limit: int = typer.Option(30), operation: str | None = typer.Option(None)
    ) -> None:
        """Show recent audit entries (raf audit verify checks the hash chain)."""
        if typer_ctx.invoked_subcommand is not None:
            return
        entries = rt.ctx().audit.list(limit=limit, operation=operation)
        data = {"items": [e.to_dict() for e in entries]}
        rt.output(
            "raf.audit/v1",
            data,
            lambda: rt.table(
                ["#", "TIME", "ACTOR", "OPERATION", "RESULT", "AFFECTED"],
                [(e.id, rt.ts_text(e.ts), e.actor, e.operation, e.result, ", ".join(e.affected[:3])) for e in entries],
            ),
        )

    @audit_app.command("verify")
    def audit_verify() -> None:
        """Verify the audit log hash chain."""
        result = rt.ctx().audit.verify()

        def render() -> None:
            if result["valid"]:
                rt.success(f"Audit chain intact ({result['checked']} entries).")
            else:
                rt.warn(f"Audit chain broken at entry {result['broken_at']}.")

        rt.output("raf.audit.verify/v1", result, render)
        if not result["valid"]:
            raise typer.Exit(5)

    app.add_typer(finding_app, name="finding", rich_help_panel=PANEL)
    app.add_typer(job_app, name="job", rich_help_panel=PANEL)
    app.add_typer(audit_app, name="audit", rich_help_panel=PANEL)
