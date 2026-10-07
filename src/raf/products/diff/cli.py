"""``raf diff A B``: compare two security states."""

from __future__ import annotations

import typer
from rich.text import Text

from raf.products.diff.service import CATEGORIES, DiffResult, DiffService, validate_category
from raf.sdk import cli as rt

app = typer.Typer(add_completion=False)

_IMPORTANCE_STYLE = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "dim"}
_SIGN = {"added": "+", "removed": "-", "changed": "~"}


def render_diff(result: DiffResult, limit: int, only: str | None) -> None:
    rt.header(f"R$F DIFF  {result.a} → {result.b}")
    rt.kv_block(
        [
            ("Objects", f"{result.totals['objects_a']:,} → {result.totals['objects_b']:,}"),
            ("Relationships", f"{result.totals['relationships_a']:,} → {result.totals['relationships_b']:,}"),
            (
                "Changes",
                f"{result.totals['changes']:,}  (HIGH {result.importance['HIGH']}, "
                f"MEDIUM {result.importance['MEDIUM']}, LOW {result.importance['LOW']})",
            ),
        ],
        width=15,
    )
    c = rt.console()
    if not result.changes:
        c.print()
        c.print("No differences.")
        return
    c.print()
    rows = [
        (cat, str(v["added"]), str(v["removed"]), str(v["changed"]))
        for cat in CATEGORIES
        if (v := result.summary.get(cat))
    ]
    rt.table(["CATEGORY", "ADDED", "REMOVED", "CHANGED"], rows)
    shown = [ch for ch in result.changes if only is None or ch.category == only]
    if rt.STATE.quiet:
        shown = [ch for ch in shown if ch.importance == "HIGH"]
    c.print()
    for change in shown[:limit]:
        line = Text(f"{_SIGN[change.change]} ", style="green" if change.change == "removed" else "bold")
        line.append(f"{change.importance:<6} ", style=_IMPORTANCE_STYLE[change.importance])
        line.append(f"{change.category:<15} ", style="cyan")
        line.append(change.label)
        line.append(f"  — {change.reason}", style="dim")
        c.print(line)
    if len(shown) > limit:
        c.print(Text(f"... {len(shown) - limit} more (use --limit or --json)", style="dim"))


@app.command(
    "diff",
    help="""Compare security states.

States: a snapshot name, 'current' (the live workspace), or ghost:<model>.
Examples: raf diff before after | raf diff morning current | raf diff before ghost:hardened""",
)
def diff_cmd(
    a: str = typer.Argument(..., help="Baseline state."),
    b: str = typer.Argument(..., help="State to compare against the baseline."),
    only: str | None = typer.Option(None, "--only", help="Show one category: " + ", ".join(CATEGORIES)),
    limit: int = typer.Option(60, "--limit", min=1),
) -> None:
    only = validate_category(only) if only is not None else None
    ctx = rt.ctx()
    result = DiffService(ctx).diff(a, b)
    ctx.audit.record("diff.compare", affected=[a, b], details={"changes": result.totals["changes"]})

    def render() -> None:
        render_diff(result, limit, only)
        rt.next_steps(["raf diff ... --only privileges", "raf snapshot list"])

    rt.output("raf.diff/v1", result.to_json_dict(), render)
