"""``raf lens``: explore any scope of security data (events, objects, findings, pivots)."""

from __future__ import annotations

import typer
from rich.text import Text

from raf.products.lens.service import LensResult, LensService
from raf.sdk import cli as rt

app = typer.Typer(add_completion=False)

_BLOCKS = " ▁▂▃▄▅▆▇█"


def _spark(values: list[int]) -> str:
    peak = max(values, default=0)
    if not peak:
        return ""
    return "".join(_BLOCKS[min(8, round(v / peak * 8))] for v in values)


def render_lens(result: LensResult, limit: int) -> None:
    scope = result.scope
    rt.header(f"R$F LENS  {scope.get('label') or scope.get('id')}", scope.get("id"))
    rows: list[tuple[str, object]] = [("Events", f"{result.total:,}")]
    if result.first and result.last:
        rows.append(("Window", f"{rt.ts_text(result.first)} → {rt.ts_text(result.last)}"))
    if result.filters:
        rows.append(("Filters", "; ".join(result.filters)))
    if result.histogram:
        rows.append(("Activity", _spark([b["count"] for b in result.histogram])))
    if result.involved:
        rows.append(("Involves", " · ".join(f"{i['type']} {i['count']}" for i in result.involved[:8])))
    rt.kv_block(rows, width=10)
    c = rt.console()
    if result.groups:
        c.print()
        rt.table(
            [(result.group_by or "group").upper(), "EVENTS"],
            [(g["key"] or "-", g["count"]) for g in result.groups[:12]],
        )
    if result.top_objects:
        c.print()
        rt.table(
            ["MOST INVOLVED", "TYPE", "EVENTS", "CRITICALITY", "ID"],
            [(t["name"], t["type"], t["count"], t["criticality"] or "", t["id"]) for t in result.top_objects[:12]],
        )
    if result.relationships:
        c.print()
        rt.table(
            ["RELATIONSHIP", "DIRECTION", "COUNT"],
            [(r["type"], r["direction"], r["count"]) for r in result.relationships],
        )
    if result.findings:
        c.print()
        rt.table(
            ["SEVERITY", "RELATED FINDING", "PRODUCT"],
            [(rt.sev_text(f.severity), f.title, f.product) for f in result.findings[:8]],
        )
    if result.items:
        c.print()
        rt.table(
            ["TIME", "TYPE", "ACTOR", "TARGET", "MESSAGE"],
            [
                (
                    rt.ts_text(e.timestamp),
                    e.event_type,
                    result.names.get(e.actor or "", e.actor or ""),
                    result.names.get(e.target or "", e.target or ""),
                    (e.message or "")[:70],
                )
                for e in result.items[:limit]
            ],
        )
        if result.total > len(result.items[:limit]):
            rt.note(f"{result.total - len(result.items[:limit]):,} more; narrow with --filter or use raf timeline")
    if not result.total:
        c.print(Text("No events in this scope.", style="dim"))


@app.command(
    "lens",
    help="""Explore security data: events, involved objects, findings and pivots.

  raf lens                                  the whole workspace
  raf lens 10.30.0.5                        an IP: what it touched, then pivot to graph/trace/exposure
  raf lens INC-001 --group-by actor
  raf lens --source raven-inc001.pcap       data from one imported capture
  raf lens ev-0005                          events parsed from one evidence item
  raf lens alice --filter 'type=auth.* outcome=failure'

--filter, --source, --from and --to narrow the scope; they never widen it.""",
)
def lens_cmd(
    words: list[str] = typer.Argument(None, help="Scope: object, incident, analysis, evidence item or nothing."),
    filter_text: str | None = typer.Option(None, "--filter", "-f", help="Filter expression (see raf help query)."),
    source: str | None = typer.Option(None, "--source", help="Only events whose source contains this text."),
    start: str | None = typer.Option(None, "--from"),
    end: str | None = typer.Option(None, "--to"),
    group_by: str = typer.Option(
        "event_type", "--group-by", help="category, event_type, actor, target, severity, source or outcome."
    ),
    limit: int = typer.Option(20, "--limit", min=1, max=1000),
    buckets: int = typer.Option(48, "--buckets", min=4, max=500),
) -> None:
    ctx = rt.ctx()
    service = LensService(ctx)
    scope = service.scope_for(list(words or []))
    for message in scope.notes:
        rt.note(message)
    result = service.query(
        scope,
        filter_text=filter_text,
        source=source,
        start=rt.parse_time_option(start),
        end=rt.parse_time_option(end),
        group_by=group_by,
        buckets=buckets,
        limit=limit,
    )
    if scope.kind == "object":
        ctx.refs.remember("object", scope.id)

    def render() -> None:
        render_lens(result, limit)
        top = result.top_objects[0]["id"] if result.top_objects else None
        steps = [p["command"] for p in result.pivots.get(top, [])[:3]] if top else []
        rt.next_steps(steps or ["raf timeline workspace"])

    rt.output("raf.lens/v1", result.to_json_dict(), render)
