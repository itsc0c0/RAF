"""``raf blast``: blast radius of a hypothetical compromise."""

from __future__ import annotations

import typer
from rich.text import Text

from raf.products.blast.service import BlastResult, BlastService
from raf.sdk import cli as rt

app = typer.Typer(add_completion=False)

_LEVEL_STYLE = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "bold red", "CRITICAL": "bold white on red"}


def render_blast(result: BlastResult, show_all: bool) -> None:
    rt.header("R$F BLAST")
    risk = result.risk
    rt.kv_block(
        [
            ("Target", f"{result.target['name']}  ({result.target['id']})"),
            ("Reachable assets", f"{result.reachable_assets}"),
            ("Controllable", f"{result.controllable_assets}"),
            ("Critical assets", f"{result.critical_assets}"),
            ("Privilege paths", f"{result.privileged_paths}"),
            ("Identities", f"{len(result.identity_propagation)}"),
            ("Max depth", f"{result.max_depth}"),
            ("Risk", Text(f"{risk.level} ({risk.score}/100)", style=_LEVEL_STYLE.get(risk.level, ""))),
        ],
        width=20,
    )
    c = rt.console()
    if result.primary_path:
        c.print()
        c.print(Text("Primary path", style="bold"))
        c.print()
        steps: list[tuple[str, str, str | None]] = []
        for hop in result.primary_path:
            label = hop.relationship_type if hop.forward else f"{hop.relationship_type} (reverse)"
            steps.append((hop.source_name, "", f"{label}  [{hop.mode}, {hop.confidence:.2f}]"))
        last = result.primary_path[-1]
        steps.append((last.target_name, last.target, None))
        rt.render_chain(steps)
        c.print()
        c.print(Text("Why each step is traversable", style="bold"))
        for i, hop in enumerate(result.primary_path, 1):
            c.print(Text(f"  {i}. {hop.why}", style="dim"))
    if risk.factors:
        c.print()
        c.print(Text(f"Risk factors ({risk.methodology})", style="bold"))
        for f in risk.factors:
            c.print(
                Text(f"  {f.sign} ", style="red" if f.sign == "+" else "green")
                + Text(f"{f.label}")
                + Text(f"  ({f.sign}{f.points})", style="dim")
            )
    critical = [b for b in result.direct + result.indirect if b.criticality in ("high", "critical")]
    if critical:
        c.print()
        rt.table(
            ["CRITICAL/HIGH ASSET", "TYPE", "DEPTH", "MODE", "CONFIDENCE", "VIA"],
            [
                (
                    b.name,
                    b.type,
                    b.depth,
                    b.mode,
                    f"{b.confidence:.2f}",
                    "privileged" if b.privileged_path else (b.via_vulnerability or ""),
                )
                for b in critical[:20]
            ],
        )
    if show_all:
        c.print()
        everything = sorted(result.direct + result.indirect, key=lambda b: (b.depth, b.id))
        rt.table(
            ["REACHED", "TYPE", "DEPTH", "MODE", "CONFIDENCE"],
            [(b.name, b.type, b.depth, b.mode, f"{b.confidence:.2f}") for b in everything],
        )


@app.command(
    "blast",
    help="""Estimate the blast radius of a hypothetical compromise.

Defensive model over existing relationships: identity, network and trust propagation with
explainable hops and an explainable risk score (docs/risk-model.md). No exploitation is performed.""",
)
def blast_cmd(
    ref: str = typer.Argument(..., help="Object assumed compromised (USER-17, WS-04, svc-deploy, @last)."),
    max_depth: int | None = typer.Option(None, "--max-depth", min=1, max=12),
    min_confidence: float | None = typer.Option(None, "--min-confidence", min=0.0, max=1.0),
    at: str | None = typer.Option(None, "--at", help="Use the graph as of this time."),
    show_all: bool = typer.Option(False, "--all", help="List every reached object."),
) -> None:
    ctx = rt.ctx()
    resolved = ctx.resolve(ref)
    for message in resolved.notes:
        rt.note(message)
    ctx.refs.remember("object", resolved.id)
    result = BlastService(ctx).blast(
        resolved.id, max_depth=max_depth, min_confidence=min_confidence, at=rt.parse_time_option(at)
    )

    def render() -> None:
        render_blast(result, show_all)
        rt.next_steps(
            [
                f"raf graph {resolved.id}",
                f"raf trace {resolved.id}",
                f"raf ghost clone current test-{resolved.id.split(':', 1)[-1]}",
            ]
        )

    rt.output("raf.blast/v1", result.to_json_dict(), render)
