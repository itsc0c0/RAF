"""Interactive ``raf >`` shell."""

from __future__ import annotations

import contextlib
import shlex
from collections.abc import Callable, Sequence
from pathlib import Path

from rich.text import Text

from raf.apps.cli import runtime as rt
from raf.core.workspace.manager import RafHome

Dispatcher = Callable[[Sequence[str]], int]


def _setup_history() -> None:
    try:
        import readline
    except ImportError:  # pragma: no cover - Windows without pyreadline
        return
    history = RafHome.from_env().root / "shell_history"
    with contextlib.suppress(OSError):
        readline.read_history_file(history)
    readline.set_history_length(1000)
    import atexit

    def _save() -> None:
        with contextlib.suppress(OSError):
            Path(history).parent.mkdir(parents=True, exist_ok=True)
            readline.write_history_file(history)

    atexit.register(_save)


def run_shell(dispatch: Dispatcher) -> None:
    from raf.apps.cli.commands.platform import show_banner

    _setup_history()
    flags = (rt.STATE.workspace, rt.STATE.no_color, rt.STATE.debug)
    show_banner()
    rt.close_ctx()
    console = rt.console()
    console.print()
    console.print(
        Text("Type a command without the 'raf' prefix (help, products, graph alice ...). 'exit' quits.", style="dim")
    )
    while True:
        try:
            line = input("raf > ")
        except (EOFError, KeyboardInterrupt):
            console.print()
            return
        line = line.strip()
        if not line:
            continue
        if line in {"exit", "quit", ":q"}:
            return
        if line == "clear":
            console.clear()
            continue
        try:
            args = shlex.split(line)
        except ValueError as exc:
            console.print(Text(f"Could not parse command: {exc}", style="red"))
            continue
        if args and args[0] == "raf":
            args = args[1:]
        from raf.apps.cli.main import extract_global_flags

        rt.reset_state()
        rt.STATE.workspace, rt.STATE.no_color, rt.STATE.debug = flags
        rest = extract_global_flags(args)
        rt.STATE.argv = args
        if rest:
            dispatch(rest)
