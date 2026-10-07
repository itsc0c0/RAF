"""``raf range``: synthetic organizations (create, start, tick, stop, reset, destroy, status)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.text import Text

from raf.products.range.service import (
    PRESETS,
    RangeRun,
    RangeService,
    RangeState,
    config_defaults,
    load_config_file,
    preset_table,
)
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    help="""Synthetic organizations for training and testing (all data is fictional).

  raf range create raven --seed 42          Raven Industries (the demo organization)
  raf range create acme --employees 50      a generic organization (presets: acme, small-office, enterprise)
  raf range start raven [--hours 24]        generate routine activity in simulated time
  raf range tick raven --hours 8            advance a running range
  raf range status raven | stop | reset | destroy""",
)

_STATUS_STYLE = {"running": "bold green", "created": "cyan", "stopped": "yellow"}


def _state_rows(state: RangeState) -> list[tuple[str, Any]]:
    return [
        ("Status", Text(state.status, style=_STATUS_STYLE.get(state.status, ""))),
        ("Preset", state.preset),
        ("Seed", state.seed),
        ("Simulated clock", rt.ts_text(state.clock)),
        ("Periods", state.periods),
        ("Jobs", ", ".join(state.jobs[-4:]) + (" ..." if len(state.jobs) > 4 else "")),
    ]


def render_run(run: RangeRun, headline: str) -> None:
    rt.success(headline)
    rows = _state_rows(run.state)
    if run.window:
        rows.append(("Window", f"{rt.ts_text(run.window['start'])} → {rt.ts_text(run.window['end'])}"))
    if run.report is not None:
        rows.append(
            (
                "Ingested",
                f"{run.report.objects_created} new objects, {run.report.relationships_created} "
                f"new relationships, {run.report.events_created} events",
            )
        )
    if run.purged is not None:
        rows.append(
            (
                "Removed",
                f"{run.purged.objects} objects, {run.purged.relationships} relationships, "
                f"{run.purged.events} events (kept {run.purged.shared_objects} shared objects)",
            )
        )
    rt.kv_block(rows, width=16)


def _overrides(
    employees: int | None,
    workstations: int | None,
    servers: int | None,
    departments: str | None,
    services: str | None,
    mfa_rate: float | None,
    segmentation: bool | None,
    event_rate: int | None,
    vulnerabilities: int | None,
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "employees": employees,
        "workstations": workstations,
        "servers": servers,
        "mfa_rate": mfa_rate,
        "segmentation": segmentation,
        "event_rate": event_rate,
        "vulnerabilities": vulnerabilities,
    }
    if departments:
        values["departments"] = [d.strip() for d in departments.split(",") if d.strip()]
    if services:
        values["services"] = [s.strip() for s in services.split(",") if s.strip()]
    return {k: v for k, v in values.items() if v is not None}


@app.command("create", help="Create a synthetic organization in the current workspace.")
def create_cmd(
    name: str = typer.Argument(..., help="Range name; a preset name (raven, acme ...) selects that preset."),
    preset: str | None = typer.Option(None, "--preset", help="raven, acme, small-office or enterprise."),
    seed: int = typer.Option(42, "--seed", help="Deterministic seed."),
    config: Path | None = typer.Option(None, "--config", help="YAML/JSON file with organization settings."),
    employees: int | None = typer.Option(None, "--employees"),
    workstations: int | None = typer.Option(None, "--workstations"),
    servers: int | None = typer.Option(None, "--servers"),
    departments: str | None = typer.Option(None, "--departments", help="Comma-separated."),
    services: str | None = typer.Option(None, "--services", help="Comma-separated (dns, web, database ...)."),
    mfa_rate: float | None = typer.Option(None, "--mfa-rate", min=0.0, max=1.0),
    segmentation: bool | None = typer.Option(None, "--segmentation/--no-segmentation"),
    event_rate: int | None = typer.Option(None, "--event-rate", help="Events per active user-hour."),
    vulnerabilities: int | None = typer.Option(None, "--vulnerabilities"),
    start: str | None = typer.Option(None, "--start", help="Simulated start time (default 2026-10-05T00:00Z)."),
) -> None:
    ctx = rt.ctx()
    settings: dict[str, Any] = load_config_file(config) if config else {}
    settings.update(
        _overrides(
            employees, workstations, servers, departments, services, mfa_rate, segmentation, event_rate, vulnerabilities
        )
    )
    run = RangeService(ctx).create(
        name, preset=preset, seed=seed, config=settings or None, start=rt.parse_time_option(start)
    )

    def render() -> None:
        render_run(run, f"Range '{run.state.name}' created ({run.state.preset}, seed {run.state.seed}).")
        rt.next_steps([f"raf range start {run.state.name}", f"raf range status {run.state.name}", "raf graph stats"])

    rt.output("raf.range.run/v1", run.to_json_dict(), render)


@app.command("start", help="Start (or resume) a range: generate routine activity for the next period.")
def start_cmd(name: str = typer.Argument(...), hours: float = typer.Option(24.0, "--hours")) -> None:
    ctx = rt.ctx()
    run = RangeService(ctx).start(name, hours=hours)

    def render() -> None:
        render_run(run, f"Range '{run.state.name}' is running.")
        rt.next_steps(
            [f"raf range tick {run.state.name} --hours 8", "raf timeline workspace", f"raf range stop {run.state.name}"]
        )

    rt.output("raf.range.run/v1", run.to_json_dict(), render)


@app.command("tick", help="Advance a running range by N simulated hours.")
def tick_cmd(name: str = typer.Argument(...), hours: float = typer.Option(24.0, "--hours")) -> None:
    ctx = rt.ctx()
    run = RangeService(ctx).tick(name, hours=hours)
    rt.output("raf.range.run/v1", run.to_json_dict(), lambda: render_run(run, f"Range '{run.state.name}' advanced."))


@app.command("stop", help="Stop generating activity (data stays).")
def stop_cmd(name: str = typer.Argument(...)) -> None:
    ctx = rt.ctx()
    state = RangeService(ctx).stop(name)

    def render() -> None:
        rt.success(f"Range '{state.name}' stopped at simulated time {rt.ts_text(state.clock)}.")

    rt.output("raf.range.state/v1", state.to_json_dict(), render)


@app.command("reset", help="Remove everything the range generated and recreate its inventory (same seed).")
def reset_cmd(name: str = typer.Argument(...)) -> None:
    ctx = rt.ctx()
    service = RangeService(ctx)
    state = service.get(name)
    rt.confirm(
        f"Reset range '{state.name}'?",
        [f"Data from {len(state.jobs)} range job(s) will be removed and the inventory recreated."],
    )
    run = service.reset(state.name)
    rt.output("raf.range.run/v1", run.to_json_dict(), lambda: render_run(run, f"Range '{run.state.name}' reset."))


@app.command("destroy", help="Remove everything the range generated and forget the range.")
def destroy_cmd(name: str = typer.Argument(...)) -> None:
    ctx = rt.ctx()
    service = RangeService(ctx)
    state = service.get(name)
    rt.confirm(
        f"Destroy range '{state.name}'?",
        [
            f"Data from {len(state.jobs)} range job(s) will be removed. "
            "Objects also contributed by other imports are kept."
        ],
    )
    run = service.destroy(state.name)

    def render() -> None:
        assert run.purged is not None
        rt.success(
            f"Range '{state.name}' destroyed: removed {run.purged.objects} objects, "
            f"{run.purged.relationships} relationships and {run.purged.events} events."
        )

    rt.output("raf.range.run/v1", run.to_json_dict(), render)


@app.command("status", help="Show a range (or every range) with live counts.")
def status_cmd(name: str | None = typer.Argument(None)) -> None:
    ctx = rt.ctx()
    service = RangeService(ctx)
    if name is None:
        ranges = service.ranges()

        def render_all() -> None:
            if not ranges:
                rt.console().print("No ranges in this workspace.")
                rt.next_steps(["raf range create raven --seed 42", "raf range presets"])
                return
            rt.table(
                ["RANGE", "PRESET", "SEED", "STATUS", "SIMULATED CLOCK", "JOBS"],
                [(r.name, r.preset, r.seed, r.status, rt.ts_text(r.clock), len(r.jobs)) for r in ranges],
            )

        rt.output("raf.range.list/v1", {"items": [r.to_json_dict() for r in ranges]}, render_all)
        return
    data = service.status(name)

    def render() -> None:
        state = RangeState.model_validate(data["state"])
        org = data["organization"]
        rt.header(f"R$F RANGE  {state.name}", org.get("description"))
        rt.kv_block(
            _state_rows(state)
            + [
                (
                    "Organization",
                    f"{org.get('employees')} employees, {org.get('workstations')} workstations, "
                    f"{org.get('servers')} servers ({org.get('domain')})",
                ),
                ("Networks", ", ".join(org.get("networks", []))),
                ("Services", ", ".join(org.get("services", []))),
                (
                    "Live data",
                    f"{data['live']['objects']} objects, {data['live']['relationships']} relationships, "
                    f"{data['live']['events']} events",
                ),
            ]
            + (
                [("Controls", ", ".join(f"{k}={v}" for k, v in org["controls"].items()))] if org.get("controls") else []
            ),
            width=16,
        )

    rt.output("raf.range.status/v1", data, render)


@app.command("list", help="Ranges in this workspace.")
def list_cmd() -> None:
    status_cmd(None)


@app.command("presets", help="Available presets and configuration keys.")
def presets_cmd() -> None:
    table = preset_table()

    def render() -> None:
        rt.table(["PRESET", "DESCRIPTION"], [(p["name"], p["description"]) for p in table])
        rt.console().print()
        rt.console().print(
            Text("Configuration keys (--config file or options): ", style="bold")
            + Text(", ".join(f"{k}={v}" for k, v in config_defaults().items()))
        )

    rt.output("raf.range.presets/v1", {"items": table, "defaults": config_defaults(), "names": sorted(PRESETS)}, render)
