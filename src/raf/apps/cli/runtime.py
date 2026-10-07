"""Per-invocation CLI state, context access and output primitives.

Global flags (``--json``, ``--quiet``, ``--no-color``, ``--debug``, ``--yes``,
``--workspace NAME``) are accepted anywhere on the command line; ``run()``
extracts them before Click parses the remaining arguments.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel
from pydantic_core import to_jsonable_python
from rich.console import Console
from rich.table import Table
from rich.text import Text

from raf.core.context.app import RafContext, open_context
from raf.core.errors import ConfirmationRequired
from raf.core.objects.types import Severity, confidence_level
from raf.core.timeutil import format_ts


@dataclass
class CliState:
    json: bool = False
    quiet: bool = False
    no_color: bool = False
    debug: bool = False
    yes: bool = False
    workspace: str | None = None
    argv: list[str] = field(default_factory=list)
    _ctx: RafContext | None = None
    _console: Console | None = None
    _err: Console | None = None


STATE = CliState()


def reset_state() -> None:
    global STATE
    if STATE._ctx is not None:
        STATE._ctx.close()
    STATE = CliState()


def console() -> Console:
    if STATE._console is None:
        no_color = STATE.no_color or bool(os.environ.get("NO_COLOR"))
        STATE._console = Console(
            no_color=no_color, soft_wrap=True, highlight=False, force_terminal=None if not no_color else False
        )
    return STATE._console


def err_console() -> Console:
    if STATE._err is None:
        no_color = STATE.no_color or bool(os.environ.get("NO_COLOR"))
        STATE._err = Console(stderr=True, no_color=no_color, soft_wrap=True, highlight=False)
    return STATE._err


def ctx() -> RafContext:
    """The application context for this invocation (opened lazily, once)."""
    if STATE._ctx is None:
        from raf.apps.cli.registry import build_registry

        command = "raf " + " ".join(STATE.argv)
        STATE._ctx = open_context(
            workspace=STATE.workspace, interface="cli", command=command[:1000], registry=build_registry()
        )
        if not STATE.json and STATE.no_color is False and STATE._ctx.settings.get("core.color") is False:
            STATE.no_color = True
            STATE._console = None
    return STATE._ctx


def close_ctx() -> None:
    if STATE._ctx is not None:
        STATE._ctx.close()
        STATE._ctx = None


# --------------------------------------------------------------------------- JSON output


def to_jsonable(data: Any) -> Any:
    if isinstance(data, BaseModel):
        return data.model_dump(mode="json")
    return to_jsonable_python(data, fallback=str)


def emit_json(schema: str, data: Any) -> None:
    """Write a stable JSON document: ``{"schema": "raf.<name>/v1", ...}``."""
    payload = to_jsonable(data)
    if isinstance(payload, dict):
        document = {"schema": schema, **payload}
    else:
        document = {"schema": schema, "items": payload}
    sys.stdout.write(json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n")
    sys.stdout.flush()


def output(schema: str, data: Any, render: Callable[[], None]) -> None:
    """Emit JSON when ``--json`` is set, else call the human renderer."""
    if STATE.json:
        emit_json(schema, data)
    else:
        render()


# --------------------------------------------------------------------------- human output helpers

SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def sev_text(severity: Severity | str) -> Text:
    sev = Severity.parse(severity)
    return Text(sev.value, style=SEVERITY_STYLE.get(sev, ""))


def conf_text(confidence: float) -> Text:
    level = confidence_level(confidence)
    style = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}[level.value]
    return Text(f"{level.value} ({confidence:.2f})", style=style)


def ts_text(value: datetime | None) -> str:
    return format_ts(value) or "-"


def header(title: str, subtitle: str | None = None) -> None:
    if STATE.quiet:
        return
    c = console()
    c.print()
    c.print(Text(title, style="bold"))
    c.print(Text("─" * max(40, len(title)), style="dim"))
    if subtitle:
        c.print(Text(subtitle, style="dim"))


def kv_block(rows: Iterable[tuple[str, Any]], width: int = 20) -> None:
    c = console()
    for key, value in rows:
        line = Text(f"{key:<{width}}", style="dim")
        if isinstance(value, Text):
            line.append_text(value)
        else:
            line.append(str(value))
        c.print(line)


def table(columns: Sequence[str], rows: Iterable[Sequence[Any]], *, title: str | None = None) -> None:
    t = Table(
        show_header=True,
        header_style="bold",
        box=None,
        pad_edge=False,
        title=title,
        title_justify="left",
        show_edge=False,
    )
    for col in columns:
        t.add_column(col, overflow="fold")
    for row in rows:
        t.add_row(*[cell if isinstance(cell, Text) else Text(str(cell)) for cell in row])
    console().print(t)


def next_steps(commands: Iterable[str], title: str = "Next") -> None:
    """Suggested pivots; never executed automatically."""
    items = [c for c in commands if c]
    if STATE.quiet or not items:
        return
    c = console()
    c.print()
    c.print(Text(f"{title}:", style="bold"))
    for command in dict.fromkeys(items):
        c.print(Text(f"  {command}", style="cyan"))


def note(message: str) -> None:
    if not STATE.quiet:
        err_console().print(Text(message, style="dim"))


def warn(message: str) -> None:
    err_console().print(Text(f"warning: {message}", style="yellow"))


def success(message: str) -> None:
    if not STATE.quiet:
        console().print(Text(message, style="green"))


def confirm(prompt: str, details: Sequence[str] = ()) -> None:
    """Require confirmation for destructive operations (``--yes`` skips)."""
    if STATE.yes:
        return
    c = err_console()
    c.print(Text(prompt, style="bold yellow"))
    for line in details:
        c.print(Text(f"  {line}"))
    if not sys.stdin.isatty():
        raise ConfirmationRequired(
            "Confirmation required for a destructive operation.", hint="Re-run with --yes to confirm non-interactively."
        )
    answer = input("Type 'yes' to continue: ").strip().lower()
    if answer != "yes":
        raise ConfirmationRequired("Operation aborted; nothing was changed.")


def ref_text(object_id: str, name: str | None = None) -> Text:
    text = Text(name or object_id, style="bold")
    if name and name != object_id:
        text.append(f"  {object_id}", style="dim")
    return text
