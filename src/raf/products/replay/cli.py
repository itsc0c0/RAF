"""``raf replay``: reconstruct an incident (or any scope) over time."""

from __future__ import annotations

import time
from datetime import datetime

import typer
from rich.text import Text

from raf.core.errors import InvalidInputError
from raf.core.query.scope import resolve_scope
from raf.core.timeutil import format_ts
from raf.products.replay.service import ReplayService, ReplayState, ReplayTimeline, group_steps
from raf.sdk import cli as rt

app = typer.Typer(add_completion=False)

SPEEDS = (0.25, 0.5, 1.0, 2.0, 5.0, 10.0)
_STYLE = {"INFO": "", "LOW": "cyan", "MEDIUM": "yellow", "HIGH": "bold red", "CRITICAL": "bold white on red"}


def _hms(value: object) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, datetime):
        text = format_ts(value) or ""
    else:
        text = ""
    return text[11:19] if len(text) >= 19 else text


def scrubber(timeline: ReplayTimeline, at: object, width: int = 40) -> list[Text]:
    start, end = timeline.start, timeline.end
    span = max((end - start).total_seconds(), 1.0)
    pos = int(min(max((at - start).total_seconds() / span, 0.0), 1.0) * (width - 1))  # type: ignore[operator]
    bar = "─" * pos + "●" + "─" * (width - 1 - pos)
    left = _hms(start)
    pad = " " * (len(left) + 1 + pos)
    return [
        Text(f"{left} ", style="dim") + Text(bar, style="cyan") + Text(f" {_hms(end)}", style="dim"),
        Text(pad + "▲", style="bold"),
        Text(pad[: max(0, len(pad) - 3)] + _hms(at), style="bold"),
    ]


def render_overview(timeline: ReplayTimeline, limit: int) -> None:
    rt.header(f"R$F REPLAY  {timeline.title}")
    duration = timeline.end - timeline.start
    rt.kv_block(
        [
            (
                "Window",
                f"{format_ts(timeline.start)} → {format_ts(timeline.end)} ({int(duration.total_seconds() // 60)}m)",
            ),
            ("Events", f"{len(timeline.steps):,}"),
            ("Objects", f"{len(timeline.objects):,}"),
            ("Context", f"{len(timeline.initial_relationships):,} relationships valid at start"),
            ("State hash", timeline.final_state_hash[:16] + " (deterministic)"),
        ],
        width=12,
    )
    c = rt.console()
    for note in timeline.notes:
        c.print(Text(f"Note: {note}", style="yellow"))
    c.print()
    c.print(Text("Sequence", style="bold"))
    grouped = group_steps(timeline.steps)
    for step, count in grouped[:limit]:
        line = Text(f"{_hms(step.timestamp)}  ", style="dim")
        line.append(f"{step.severity.value:<8}", style=_STYLE.get(step.severity.value, ""))
        prefix = f"{count}x " if count > 1 else ""
        line.append(prefix + step.summary)
        if step.sessions_opened:
            line.append("  [new session]", style="green")
        if step.removed_relationships:
            line.append("  [relationship ended]", style="yellow")
        c.print(line)
    if len(grouped) > limit:
        c.print(Text(f"... {len(grouped) - limit} more (raf replay ... --json, or --from/--to)", style="dim"))


def render_state(timeline: ReplayTimeline, state: ReplayState) -> None:
    rt.header(f"R$F REPLAY  {timeline.title}  @ {format_ts(state.at)}")
    c = rt.console()
    for line in scrubber(timeline, state.at):
        c.print(line)
    c.print()
    rt.kv_block(
        [
            ("Step", f"{state.step_index + 1} / {len(timeline.steps)}"),
            ("Objects", len(state.objects)),
            ("Relationships", len(state.relationships)),
            ("State hash", state.state_hash[:16]),
        ],
        width=15,
    )

    def name(object_id: str | None) -> str:
        if not object_id:
            return "-"
        return str(timeline.objects.get(object_id, {}).get("name", object_id))

    sections: list[tuple[str, list[str]]] = [
        (
            "Active sessions",
            [
                f"{name(s['user'])} @ {name(s['host'])} since {_hms(s['since'])}"
                + (f" from {name(s.get('source'))}" if s.get("source") else "")
                for s in state.sessions
            ],
        ),
        (
            "Running processes",
            [
                f"{name(p['process'])} on {name(p.get('host'))}"
                + (f" ({p['command_line']})" if p.get("command_line") else "")
                for p in state.processes
            ],
        ),
        (
            "Recent network flows (10 min)",
            [
                f"{name(f['source'])} → {name(f['destination'])}"
                + (f":{f['port']}" if f.get("port") else "")
                + (f" {int(f['bytes_out']) / 1e6:.1f} MB" if f.get("bytes_out") else "")
                for f in state.recent_flows
            ],
        ),
        (
            "File activity",
            [
                f"{_hms(f['at'])} {f['operation']} {name(f['file'])} by {name(f.get('actor'))}"
                for f in state.files[-10:]
            ],
        ),
        (
            "Identity changes",
            [f"{_hms(i['at'])} {i['change']} {name(i.get('target'))}" for i in state.identity_changes],
        ),
        ("Alerts", [f"{_hms(a['at'])} {a['severity']} {a['message']}" for a in state.alerts]),
    ]
    for title, items in sections:
        c.print()
        c.print(Text(f"{title} ({len(items)})", style="bold"))
        for item in items[:15] or ["none"]:
            c.print(Text(f"  {item}", style="dim" if item == "none" else ""))


def render_changes(timeline: ReplayTimeline, changes: dict[str, object]) -> None:
    rt.header(f"R$F REPLAY  {timeline.title}  {changes['from']} → {changes['to']}")
    c = rt.console()
    labels = [
        ("new_objects", "New objects"),
        ("added_relationships", "New relationships"),
        ("removed_relationships", "Ended relationships"),
        ("sessions_opened", "New sessions"),
        ("sessions_closed", "Closed sessions"),
        ("processes", "Processes"),
        ("flows", "Network flows"),
        ("files", "File activity"),
        ("identity_changes", "Identity activity"),
        ("alerts", "Alerts / findings"),
    ]
    rows = []
    for key, label in labels:
        value = changes.get(key)
        rows.append((label, f"{len(value) if isinstance(value, list) else value}"))
    rt.kv_block([("Events", changes["events"]), *rows], width=20)
    new_objects = changes.get("new_objects")
    if isinstance(new_objects, list) and new_objects:
        c.print()
        c.print(Text("New objects", style="bold"))
        for oid in new_objects[:25]:
            c.print(
                Text(f"  {timeline.objects.get(oid, {}).get('name', oid)}  ", style="bold") + Text(oid, style="dim")
            )


def play(timeline: ReplayTimeline, speed: float) -> None:
    """Compressed playback: at 1x one minute of incident time plays in one second (max 2s per step)."""
    c = rt.console()
    rt.header(f"R$F REPLAY  {timeline.title}  ▶ {speed}x")
    previous = None
    try:
        for step, count in group_steps(timeline.steps):
            if previous is not None:
                gap = (step.timestamp - previous).total_seconds()
                time.sleep(min(max(gap / 60.0 / speed, 0.03), 2.0))
            previous = step.timestamp
            line = Text(f"{_hms(step.timestamp)}  ", style="dim")
            line.append(f"{step.severity.value:<8}", style=_STYLE.get(step.severity.value, ""))
            line.append((f"{count}x " if count > 1 else "") + step.summary)
            c.print(line)
    except KeyboardInterrupt:
        c.print(Text("❚❚ paused (interrupted)", style="yellow"))


@app.command(
    "replay",
    help="""Replay an incident (or any scope) deterministically.

  raf replay INC-001                       sequence overview
  raf replay INC-001 --at "23:04:41"       system state at a moment
  raf replay INC-001 --from 23:00 --to 23:10   changes within a window
  raf replay INC-001 --play --speed 2      compressed terminal playback (0.25x .. 10x)""",
)
def replay_cmd(
    words: list[str] = typer.Argument(..., help="Incident (INC-001), object, analysis or 'workspace'."),
    at: str | None = typer.Option(None, "--at", help="Show the state at this time (HH:MM[:SS], ISO, +10m)."),
    start: str | None = typer.Option(None, "--from", help="Window start."),
    end: str | None = typer.Option(None, "--to", help="Window end."),
    play_: bool = typer.Option(False, "--play", help="Animated playback in the terminal."),
    speed: float = typer.Option(1.0, "--speed", help="Playback speed: 0.25, 0.5, 1, 2, 5, 10."),
    no_context: bool = typer.Option(False, "--no-context", help="Do not include relationships valid at start."),
    limit: int = typer.Option(80, "--limit", min=1),
) -> None:
    if speed not in SPEEDS:
        raise InvalidInputError(f"Unsupported speed {speed}.", hint="Use 0.25, 0.5, 1, 2, 5 or 10.")
    ctx = rt.ctx()
    service = ReplayService(ctx)
    scope = resolve_scope(ctx, words)
    window = service.window_for(scope)
    anchor = window[0]
    bounds = (window[0], window[1]) if window[0] and window[1] else None
    t_from = rt.parse_time_option(start, anchor=anchor, window=bounds)
    t_to = rt.parse_time_option(end, anchor=anchor, window=bounds)
    timeline = service.build(scope, include_context=not no_context)
    ctx.audit.record(
        "replay.build",
        affected=[scope.id],
        details={"steps": len(timeline.steps), "state_hash": timeline.final_state_hash},
    )
    if at:
        moment = rt.parse_time_option(at, anchor=anchor, window=bounds)
        assert moment is not None
        state = service.state_at(timeline, moment)
        rt.output(
            "raf.replay.state/v1",
            state.to_json_dict() | {"scope": timeline.scope},
            lambda: render_state(timeline, state),
        )
        return
    if t_from or t_to:
        changes = service.changes(timeline, t_from or timeline.start, t_to or timeline.end)
        rt.output(
            "raf.replay.window/v1", changes | {"scope": timeline.scope}, lambda: render_changes(timeline, changes)
        )
        return
    if play_ and not rt.STATE.json:
        play(timeline, speed)
        return

    def render() -> None:
        render_overview(timeline, limit)
        label = scope.label
        middle = timeline.start + (timeline.end - timeline.start) / 2
        rt.next_steps(
            [
                f'raf replay {label} --at "{_hms(middle)}"',
                f"raf replay {label} --play --speed 5",
                f"raf graph {label}",
                f"raf timeline {label}",
            ]
        )

    rt.output("raf.replay/v1", timeline.to_json_dict(), render)
