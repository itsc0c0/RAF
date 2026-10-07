"""``raf forge``: synthetic security telemetry and scenarios (clearly marked synthetic)."""

from __future__ import annotations

from pathlib import Path

import typer

from raf.data.synth import GENERATORS
from raf.products.forge.service import ForgeResult, ForgeService, catalog
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    help="""Synthetic security telemetry. Every record is marked synthetic.

  raf forge auth --count 10000             authentication events for the workspace population
  raf forge dns --count 5000 --noise 0.1   DNS with 10% unusual-but-benign records
  raf forge scenario suspicious-access --seed 99
  raf forge web --count 2000 -o web.jsonl  write a file instead of importing""",
)


def render_result(result: ForgeResult) -> None:
    rt.success(f"Generated {result.records:,} synthetic record(s): {result.kind} (seed {result.seed}).")
    rows: list[tuple[str, object]] = [
        ("Population", result.population),
        ("Window", f"{rt.ts_text(result.window['start'])} → {rt.ts_text(result.window['end'])}"),
    ]
    if result.incident:
        rows.append(("Incident", result.incident))
    if result.output:
        rows.append(("Written to", result.output))
    if result.job:
        rows.append(
            ("Imported", f"{result.job}" + (f" ({result.report.events_created} new events)" if result.report else ""))
        )
    rt.kv_block(rows, width=12)
    steps = []
    if result.incident and result.job:
        steps += [f"raf timeline {result.incident}", f"raf replay {result.incident}"]
        if result.subject:
            steps += [f"raf trace {result.subject}", f"raf blast {result.subject}"]
    elif result.job:
        steps += ["raf timeline workspace --filter synthetic=true", f"raf jobs show {result.job}"]
    elif result.output:
        steps.append(f"raf import {result.output} --synthetic")
    rt.next_steps(steps)


def _generator_command(kind: str) -> None:
    @app.command(kind, help=f"Generate synthetic {kind} telemetry.")
    def command(
        count: int = typer.Option(1000, "--count", "-n", min=1),
        seed: int = typer.Option(42, "--seed"),
        start: str | None = typer.Option(None, "--start", help="Window start (default: day after the newest event)."),
        hours: float = typer.Option(24.0, "--hours", help="Window length."),
        noise: float = typer.Option(0.05, "--noise", min=0.0, max=1.0, help="Share of unusual-but-benign records."),
        population: str = typer.Option("auto", "--population", help="auto, workspace, raven or generic."),
        output: Path | None = typer.Option(None, "--output", "-o", help="Write JSONL here instead of importing."),
        ingest: bool = typer.Option(False, "--ingest", help="With --output: also import."),
    ) -> None:
        ctx = rt.ctx()
        result = ForgeService(ctx).telemetry(
            kind,
            count=count,
            seed=seed,
            start=rt.parse_time_option(start),
            hours=hours,
            noise=noise,
            population=population,
            output=output,
            ingest=output is None or ingest,
        )
        rt.output("raf.forge/v1", result.to_json_dict(), lambda: render_result(result))

    command.__name__ = f"forge_{kind}"


for _kind in GENERATORS:
    _generator_command(_kind)


@app.command("scenario", help="Generate a modeled security scenario (events only, no payloads).")
def scenario_cmd(
    name: str = typer.Argument(..., help="suspicious-access, credential-risk or lateral-movement."),
    seed: int = typer.Option(42, "--seed"),
    start: str | None = typer.Option(None, "--start", help="Scenario day (default: day after the newest event)."),
    population: str = typer.Option("auto", "--population", help="auto, workspace, raven or generic."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSONL here instead of importing."),
    ingest: bool = typer.Option(False, "--ingest", help="With --output: also import."),
) -> None:
    ctx = rt.ctx()
    result = ForgeService(ctx).scenario(
        name,
        seed=seed,
        start=rt.parse_time_option(start),
        population=population,
        output=output,
        ingest=output is None or ingest,
    )
    rt.output("raf.forge/v1", result.to_json_dict(), lambda: render_result(result))


@app.command("list", help="Available generators and scenarios.")
def list_cmd() -> None:
    data = catalog()

    def render() -> None:
        rt.table(["GENERATOR", "PRODUCES"], [(g["name"], g["description"]) for g in data["generators"]])
        rt.console().print()
        rt.table(["SCENARIO", "MODELS"], [(s["name"], s["description"]) for s in data["scenarios"]])

    rt.output("raf.forge.catalog/v1", data, render)
