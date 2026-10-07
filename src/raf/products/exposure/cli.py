"""``raf exposure``: contextual exposure of every asset, with explanations."""

from __future__ import annotations

import typer
from rich.text import Text

from raf.core.risk.exposure import AssetExposure
from raf.products.exposure.service import ExposureReport, ExposureService, level_rank, parse_level
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    help="""Contextual asset exposure (not a CVSS sort).

  raf exposure                 rank assets, record HIGH/CRITICAL findings
  raf exposure show VPN-01     explain one asset's score factor by factor""",
)

_LEVEL_STYLE = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "bold red", "CRITICAL": "bold white on red"}


def _level(level: str, score: int) -> Text:
    return Text(f"{level} {score}", style=_LEVEL_STYLE.get(level, ""))


def render_report(report: ExposureReport, items: list[AssetExposure], limit: int) -> None:
    rt.header("R$F EXPOSURE")
    m = report.metrics
    rt.kv_block(
        [
            ("Assets", len(report.items)),
            (
                "By level",
                ", ".join(f"{lv} {report.by_level.get(lv, 0)}" for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
            ),
            ("Entry points", m.entry_points),
            ("Reachable", m.reachable_assets),
            ("Exposed critical", m.exposed_critical_assets),
            ("Findings", f"{report.findings} recorded, {report.resolved} resolved"),
        ],
        width=18,
    )
    for note in report.notes:
        rt.note(note)
    rt.console().print()
    rows = []
    for item in items[:limit]:
        top = [f.label for f in item.factors if f.sign == "+"][:2]
        rows.append(
            (
                item.object["name"],
                item.object["type"],
                item.object["criticality"] or "",
                _level(item.level, item.score),
                item.internet,
                "; ".join(top),
            )
        )
    rt.table(["ASSET", "TYPE", "CRITICALITY", "EXPOSURE", "INTERNET", "TOP FACTORS"], rows)
    if len(items) > limit:
        rt.note(f"{len(items) - limit} more; use --limit or --min-level")


def render_item(item: AssetExposure) -> None:
    obj = item.object
    rt.header(f"R$F EXPOSURE  {obj['name']}", obj["id"])
    rt.kv_block(
        [
            ("Exposure", _level(item.level, item.score)),
            ("Criticality", obj["criticality"] or "unknown"),
            ("Internet", item.internet),
            ("Entry points", len(item.entry_points)),
            ("Controllers", len(item.controllers)),
            ("Methodology", item.methodology),
        ],
        width=14,
    )
    c = rt.console()
    c.print()
    c.print(Text("Score factors", style="bold"))
    for f in item.factors:
        c.print(Text(f"  {f.sign}{f.points:>3}  ", style="red" if f.sign == "+" else "green") + Text(f.label))
    if item.vulnerabilities:
        c.print()
        rt.table(
            ["VULNERABILITY", "CVSS", "EXPLOIT", "VIA", "SUMMARY"],
            [
                (v["name"], f"{v['cvss']:.1f}", "yes" if v["exploit_available"] else "", v["via"] or "", v["summary"])
                for v in item.vulnerabilities
            ],
        )
    if item.entry_points:
        c.print()
        rt.table(
            ["ENTRY POINT", "KIND", "NETWORK HOPS", "PATH"],
            [(e.name, e.kind, e.hops, " → ".join(e.path)) for e in item.entry_points[:12]],
        )
    if item.controllers:
        c.print()
        rt.table(
            ["CAN OBTAIN CONTROL", "TYPE", "PRIVILEGED", "VIA CREDENTIALS", "PATH"],
            [
                (
                    ctl.name,
                    ctl.type,
                    "yes" if ctl.privileged else "",
                    "yes" if ctl.via_credentials else "",
                    " → ".join(ctl.path),
                )
                for ctl in item.controllers[:12]
            ],
        )
    if item.stepping_stone_to:
        c.print()
        c.print(Text("Stepping stone to", style="bold"))
        for s in item.stepping_stone_to[:5]:
            c.print(Text(f"  {s['name']}: " + " → ".join(s["path"])))


@app.callback(invoke_without_command=True)
def exposure_cmd(
    ctx_: typer.Context,
    min_level: str | None = typer.Option(None, "--min-level", help="Only show assets at or above this level."),
    asset_type: str | None = typer.Option(None, "--type", help="host, service, cloud_resource or container."),
    limit: int = typer.Option(25, "--limit", min=1),
    no_save: bool = typer.Option(False, "--no-save", help="Do not record findings."),
) -> None:
    if ctx_.invoked_subcommand is not None:
        return
    ctx = rt.ctx()
    threshold = parse_level(min_level)
    report = ExposureService(ctx).report(persist=not no_save)
    items = [
        i
        for i in report.items
        if (threshold is None or level_rank(i.level) >= level_rank(threshold))
        and (asset_type is None or i.object["type"] == asset_type)
    ]
    if not no_save:
        ctx.audit.record(
            "exposure.analyze",
            affected=[i.object["id"] for i in items[:20]],
            details={"assets": len(report.items), "findings": report.findings},
        )
    data = report.to_json_dict() | {"items": [i.to_json_dict() for i in items]}

    def render() -> None:
        render_report(report, items, limit)
        if items:
            rt.next_steps(
                [
                    f"raf exposure show {items[0].object['id']}",
                    f"raf blast {items[0].object['id']}",
                    "raf findings --product exposure",
                ]
            )

    rt.output("raf.exposure/v1", data, render)


@app.command("show", help="Explain one asset's exposure factor by factor.")
def show_cmd(ref: str = typer.Argument(..., help="Asset (VPN-01, DB-01, production, @last).")) -> None:
    ctx = rt.ctx()
    resolved = ctx.resolve(ref)
    for message in resolved.notes:
        rt.note(message)
    ctx.refs.remember("object", resolved.id)
    item = ExposureService(ctx).assess(resolved.id)

    def render() -> None:
        render_item(item)
        rt.next_steps(
            [
                f"raf blast {resolved.id}",
                f"raf graph {resolved.id}",
                f"raf ghost clone current fix-{resolved.id.split(':', 1)[-1]}",
            ]
        )

    rt.output("raf.exposure.asset/v1", item.to_json_dict(), render)
