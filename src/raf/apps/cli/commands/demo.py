"""``raf demo``: load the Raven Industries demonstration dataset."""

from __future__ import annotations

import typer
from rich.text import Text

from raf.analysis.demo import load_demo
from raf.sdk import cli as rt

demo_app = typer.Typer(help="Demonstration data (fictional Raven Industries).", no_args_is_help=True)


@demo_app.command("load")
def demo_load() -> None:
    """Load Raven Industries: inventory, a working day of events, incident INC-001 and its evidence."""
    ctx = rt.ctx()
    result = load_demo(ctx)

    def render() -> None:
        rt.header("R$F DEMO  Raven Industries", "Synthetic organization; all data is fictional.")
        c = rt.console()
        width = max((len(step["name"]) for step in result.steps), default=30) + 2
        for step in result.steps:
            mark = Text("✓ ", style="green") if step["status"] == "ok" else Text("- ", style="dim")
            detail = step["detail"]
            if isinstance(detail, dict):
                detail = ", ".join(f"{k} {_fmt(v)}" for k, v in detail.items() if v not in (None, "") and k != "job")
            c.print(mark + Text(f"{step['name']:<{width}}") + Text(str(detail), style="dim"))
        rt.next_steps(result.suggestions, title="Explore")

    rt.output("raf.demo/v1", result.to_dict(), render)


def _fmt(value: object) -> str:
    if isinstance(value, dict):
        return "(" + ", ".join(f"{k} {v}" for k, v in value.items()) + ")"
    return str(value)


def register(app: typer.Typer) -> None:
    app.add_typer(demo_app, name="demo", rich_help_panel="Platform")
