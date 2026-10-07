"""``raf timeline``: unified timelines for incidents, objects, analyses or the whole workspace."""

from __future__ import annotations

import shlex
from pathlib import Path

import typer
from rich.text import Text

from raf.core.query.scope import resolve_scope
from raf.core.timeutil import format_ts
from raf.products.timeline.service import EXPORT_FORMATS, GROUP_FIELDS, TimelineResult, TimelineService
from raf.sdk import cli as rt

app = typer.Typer(add_completion=False)


def _short(ts: object) -> str:
    text = format_ts(ts) if ts else "-"  # type: ignore[arg-type]
    return (text or "-").replace("T", " ").replace("Z", "")


def render_timeline(result: TimelineResult) -> None:
    scope = result.scope
    rt.header(f"R$F TIMELINE  {scope['label']}  ({scope['id']})")
    span = f"{_short(result.first)} → {_short(result.last)}" if result.first else "-"
    rows: list[tuple[str, object]] = [
        (
            "Events",
            f"{result.total:,}" + (f" (showing {len(result.items)})" if result.total > len(result.items) else ""),
        ),
        ("Window", span),
    ]
    if result.filters:
        rows.append(("Filters", " ".join(result.filters)))
    if result.groups:
        rows.append((f"By {result.group_by}", " · ".join(f"{g['key']} {g['count']}" for g in result.groups[:8])))
    rt.kv_block(rows, width=14)
    c = rt.console()
    if not result.items:
        c.print()
        c.print("No events match.")
        return
    if result.histogram and not rt.STATE.quiet:
        peak = max(b["count"] for b in result.histogram) or 1
        bars = "▁▂▃▄▅▆▇█"
        spark = "".join(
            bars[min(len(bars) - 1, int(b["count"] / peak * (len(bars) - 1)))] if b["count"] else " "
            for b in result.histogram
        )
        c.print(Text("Activity      ", style="dim") + Text(spark, style="cyan"))
    c.print()
    names = result.names
    rows_out = []
    for ev in result.items:
        actor = names.get(ev.actor or "", ev.actor or "-")
        target = names.get(ev.target or "", ev.target or "-")
        rows_out.append(
            (
                _short(ev.timestamp),
                rt.sev_text(ev.severity),
                ev.event_type,
                actor,
                ev.outcome or "",
                target,
                (ev.message or "")[:60],
            )
        )
    rt.table(["TIME", "SEV", "TYPE", "ACTOR", "OUTCOME", "TARGET", "DETAIL"], rows_out)
    if result.next_cursor:
        c.print(
            Text(
                f"... {result.total - len(result.items):,} more (use --limit, --from/--to, --filter or --export)",
                style="dim",
            )
        )


@app.command(
    "timeline",
    help="""Unified event timeline.

Forms: raf timeline INC-001 | raf timeline host WS-04 | raf timeline user alice | raf timeline analysis-3 |
raf timeline workspace
Filter language: --filter 'type:auth.* severity>=medium actor:bob "vpn"' (raf help query)""",
)
def timeline_cmd(
    words: list[str] = typer.Argument(None, help="Scope: [type] reference, incident, analysis or 'workspace'."),
    start: str | None = typer.Option(None, "--from", help="Start time (ISO, epoch, HH:MM within scope, +15m)."),
    end: str | None = typer.Option(None, "--to", help="End time."),
    event_type: list[str] = typer.Option(None, "--type", help="Event type or prefix (auth.*), repeatable."),
    category: list[str] = typer.Option(None, "--category", help="Category (auth, process, network ...)."),
    severity: str | None = typer.Option(None, "--severity", help="Minimum severity."),
    filter_text: str | None = typer.Option(None, "--filter", help="Filter expression (raf help query)."),
    group_by: str = typer.Option("category", "--group-by", help="Group counts by: " + ", ".join(GROUP_FIELDS)),
    limit: int = typer.Option(50, "--limit", min=1, max=10000),
    reverse: bool = typer.Option(False, "--reverse", help="Newest first."),
    cursor: str | None = typer.Option(None, "--cursor", help="Continue from a previous page."),
    export: Path | None = typer.Option(None, "--export", help="Export all matching events to a file."),
    fmt: str = typer.Option("csv", "--format", help="Export format: " + ", ".join(EXPORT_FORMATS)),
) -> None:
    ctx = rt.ctx()
    service = TimelineService(ctx)
    scope = resolve_scope(ctx, words or [])
    for message in scope.notes:
        rt.note(message)
    anchor_lo, anchor_hi = ctx.store.events.bounds(scope.event_query())
    window = (anchor_lo, anchor_hi) if anchor_lo and anchor_hi else None
    query, terms = service.query(
        scope,
        start=rt.parse_time_option(start, anchor=anchor_lo, window=window),
        end=rt.parse_time_option(end, anchor=anchor_lo, window=window),
        types=event_type,
        categories=category,
        severity=severity,
        filter_text=filter_text,
    )
    if export is not None:
        info = service.export(scope, query, fmt, export)
        ctx.audit.record("timeline.export", affected=[scope.id], details=info)
        rt.output(
            "raf.timeline.export/v1",
            info,
            lambda: rt.success(
                f"Exported {info['events']:,} events to {info['path']} ({fmt}, sha256 {info['sha256'][:16]}...)"
            ),
        )
        return
    result = service.timeline(scope, query, terms, limit=limit, cursor=cursor, descending=reverse, group_by=group_by)

    def render() -> None:
        render_timeline(result)
        pivots = []
        if scope.kind == "incident":
            pivots += [f"raf replay {shlex.quote(scope.label)}", f"raf graph {shlex.quote(scope.label)}"]
        elif scope.kind == "object":
            pivots += [f"raf trace {shlex.quote(scope.id)}", f"raf graph {shlex.quote(scope.id)}"]
        pivots.append(f"raf timeline {shlex.join(words or ['workspace'])} --export timeline.csv")
        rt.next_steps(pivots)

    rt.output("raf.timeline/v1", result.to_json_dict(), render)
