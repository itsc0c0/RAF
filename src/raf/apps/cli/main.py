"""The ``raf`` command-line interface.

Every security capability. One command away.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import traceback
from collections.abc import Iterable, Sequence
from typing import Any, TextIO, cast

import typer
from rich.text import Text

from raf.apps.cli.clickcompat import Abort, ClickException, Exit
from raf.apps.cli.commands import data as data_cmds
from raf.apps.cli.commands import platform as platform_cmds
from raf.apps.cli.commands import workspace as workspace_cmds
from raf.apps.cli.registry import RafGroup
from raf.core.context.app import RafContext, open_context
from raf.core.errors import RafError
from raf.core.logging import configure_logging, log_file
from raf.core.workspace.manager import RafHome
from raf.sdk import cli as rt

app = typer.Typer(
    name="raf",
    cls=RafGroup,
    help="R$F (pronounced RAF): Every security capability. One command away.",
    no_args_is_help=False,
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    pretty_exceptions_enable=False,
)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    workspace: str | None = typer.Option(None, "--workspace", "-w", help="Workspace to use for this command."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only essential output."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colors."),
    debug: bool = typer.Option(False, "--debug", help="Verbose diagnostics and full tracebacks."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm destructive operations."),
    version: bool = typer.Option(False, "--version", help="Show the R$F version and exit (details: raf version)."),
) -> None:
    """R$F security platform. Run without arguments for the interactive shell."""
    if version:
        from raf.version import RAF_VERSION

        rt.console().print(f"R$F {RAF_VERSION}")
        raise typer.Exit()
    # Global flags are normally extracted by run(); honor them here too when invoked directly.
    rt.STATE.workspace = workspace or rt.STATE.workspace
    rt.STATE.json = json_output or rt.STATE.json
    rt.STATE.quiet = quiet or rt.STATE.quiet
    rt.STATE.no_color = no_color or rt.STATE.no_color
    rt.STATE.debug = debug or rt.STATE.debug
    rt.STATE.yes = yes or rt.STATE.yes
    if ctx.invoked_subcommand is None:
        platform_cmds.show_banner()


def _context_factory(state: rt.CliState) -> RafContext:
    from raf.analysis.providers import install_state_providers
    from raf.apps.cli.registry import build_registry

    command = "raf " + " ".join(state.argv)
    ctx = open_context(workspace=state.workspace, interface="cli", command=command[:1000], registry=build_registry())
    install_state_providers(ctx)  # e.g. ghost:<model> for raf diff and raf snapshot
    return ctx


rt.set_context_factory(_context_factory)

platform_cmds.register(app)
workspace_cmds.register(app)
data_cmds.register(app)


def _register_optional() -> None:
    """Command modules that depend on later layers register themselves if present."""
    import importlib

    for module_name in (
        "raf.apps.cli.commands.ingest",
        "raf.apps.cli.commands.demo",
        "raf.apps.cli.commands.snapshots",
        "raf.apps.cli.commands.analyze",
        "raf.apps.cli.commands.serve",
        "raf.apps.cli.commands.bundle",
        "raf.apps.cli.commands.tui",
    ):
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name != module_name:
                raise
            continue
        module.register(app)


_register_optional()

_GLOBAL_BOOL = {
    "--json": "json",
    "--quiet": "quiet",
    "-q": "quiet",
    "--no-color": "no_color",
    "--debug": "debug",
    "--yes": "yes",
    "-y": "yes",
}


def extract_global_flags(argv: Sequence[str]) -> list[str]:
    rest: list[str] = []
    items = list(argv)
    i = 0
    while i < len(items):
        arg = items[i]
        if arg == "--":
            rest.extend(items[i:])
            break
        if arg in _GLOBAL_BOOL:
            setattr(rt.STATE, _GLOBAL_BOOL[arg], True)
        elif arg in ("--workspace", "-w") and i + 1 < len(items):
            rt.STATE.workspace = items[i + 1]
            i += 1
        elif arg.startswith("--workspace="):
            rt.STATE.workspace = arg.split("=", 1)[1]
        else:
            rest.append(arg)
        i += 1
    return rest


def render_error(error: RafError) -> None:
    if rt.STATE.json:
        rt.emit_json("raf.error/v1", {"error": error.to_dict()})
        return
    c = rt.err_console()
    c.print()
    c.print(Text(f"R$F: {error.message}", style="bold red"))
    if error.reason:
        c.print()
        c.print(Text("Reason:", style="bold"))
        c.print(Text(f"  {error.reason}"))
    if error.hint:
        c.print()
        c.print(Text(error.hint, style="yellow"))
    if error.suggestions:
        c.print()
        c.print(Text("Try:", style="bold"))
        for suggestion in error.suggestions:
            c.print(Text(f"  {suggestion}", style="cyan"))
    if rt.STATE.debug:
        c.print(Text(traceback.format_exc(), style="dim"))


def render_internal(exc: BaseException) -> None:
    log_path = log_file()
    logging.getLogger("raf.cli").error("internal error", exc_info=exc, extra={"file_only": True})
    if rt.STATE.json:
        rt.emit_json(
            "raf.error/v1",
            {
                "error": {
                    "code": "raf.internal",
                    "message": "Internal error.",
                    "type": type(exc).__name__,
                    "detail": str(exc)[:500],
                }
            },
        )
        return
    c = rt.err_console()
    c.print(Text("R$F hit an internal error. This is a bug in R$F, not in your data.", style="bold red"))
    c.print(Text(f"  {type(exc).__name__}: {str(exc)[:300]}"))
    if rt.STATE.debug:
        c.print(Text(traceback.format_exc(), style="dim"))
    else:
        logged = f" (also logged to {log_path})" if log_path is not None else ""
        c.print(Text(f"Run again with --debug for the full traceback{logged}.", style="dim"))


class OutputClosed(OSError):
    """The reader of stdout went away (``raf ... | head``): stop quietly, it is not an error.

    Deliberately not a BrokenPipeError and without an errno: Click (``EPIPE``) and Rich (``BrokenPipeError``)
    would turn it into exit status 1. Being an OSError, logging still swallows it like any write error.
    """


class _PipeGuard:
    """``sys.stdout`` / ``sys.stderr`` during one ``raf`` run.

    When a write or flush fails because the reading end of a pipe was closed, the stream's file descriptor
    is redirected to the null device, so nothing can fail again (the flush at interpreter exit included).
    On stdout the command then stops: :class:`OutputClosed` is raised and :func:`run` exits with status 0.
    On stderr only the diagnostics are lost and the command goes on. Everything else is delegated.
    SIGPIPE handling is left alone: the API server runs in the same code base.
    """

    def __init__(self, stream: TextIO, *, stop: bool) -> None:
        self._stream = stream
        self._stop = stop

    def write(self, text: str) -> int:
        try:
            return self._stream.write(text)
        except BrokenPipeError as exc:
            self._closed(exc)
            return len(text)

    def writelines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.write(line)

    def flush(self) -> None:
        try:
            self._stream.flush()
        except BrokenPipeError as exc:
            self._closed(exc)

    def _closed(self, exc: BrokenPipeError) -> None:
        with contextlib.suppress(OSError, ValueError):  # no file descriptor (io.UnsupportedOperation is both)
            devnull = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(devnull, self._stream.fileno())
            finally:
                os.close(devnull)
        if self._stop:
            raise OutputClosed("output closed") from exc

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def dispatch(args: Sequence[str]) -> int:
    command = typer.main.get_command(app)
    try:
        # Without standalone mode Click *returns* the code of a ``typer.Exit(n)`` raised by a command.
        result = command.main(args=list(args), prog_name="raf", standalone_mode=False)
        return result if isinstance(result, int) and not isinstance(result, bool) else 0
    except OutputClosed:
        return 0
    except Exit as exc:
        return int(exc.exit_code)
    except Abort:
        with contextlib.suppress(OutputClosed):
            rt.err_console().print("Aborted.")
        return 130
    except ClickException as exc:
        with contextlib.suppress(OutputClosed):  # the reader went away: the exit status still tells
            if rt.STATE.json:
                rt.emit_json("raf.error/v1", {"error": {"code": "raf.usage", "message": exc.format_message()}})
            else:
                from typer import rich_utils

                rich_utils.rich_format_error(exc)
        return int(exc.exit_code)
    except RafError as exc:
        with contextlib.suppress(OutputClosed):
            render_error(exc)
        return exc.exit_code
    except KeyboardInterrupt:
        with contextlib.suppress(OutputClosed):
            rt.err_console().print("Interrupted.")
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level boundary renders, never dumps raw traces
        with contextlib.suppress(OutputClosed):
            render_internal(exc)
        return 1
    finally:
        rt.close_ctx()


def _log_settings() -> tuple[str, bool]:
    """``core.log_level`` and ``core.log_file``: defaults < global < workspace config < ``RAF_CORE_*``.

    Read before logging exists, quietly: an unreadable or invalid configuration means the defaults here, and
    the command reports the problem (and any warning about the files) when it opens its workspace.
    """
    logging.disable(logging.CRITICAL)
    try:
        settings = rt.settings()
        return str(settings.get("core.log_level")), bool(settings.get("core.log_file"))
    except RafError:
        return "WARNING", True
    finally:
        logging.disable(logging.NOTSET)


def _command(rest: list[str]) -> int:
    if not rest:
        if sys.stdin.isatty() and sys.stdout.isatty() and not rt.STATE.json:
            from raf.apps.cli.shell import run_shell

            run_shell(dispatch)
            return 0
        rest = ["status"]
    return dispatch(rest)


def run(argv: Sequence[str] | None = None) -> None:
    raw = list(sys.argv[1:] if argv is None else argv)
    rt.reset_state()
    rest = extract_global_flags(raw)
    rt.STATE.argv = raw
    level, write_log_file = _log_settings()
    home = RafHome.from_env()
    configure_logging(level, log_dir=home.logs_dir if write_log_file else None, debug=rt.STATE.debug)
    stdout, stderr = sys.stdout, sys.stderr
    # A stream is None when Python started without it (`raf ... >&-`): its output goes nowhere.
    sinks = [open(os.devnull, "w", encoding="utf-8") for stream in (stdout, stderr) if stream is None]  # noqa: SIM115
    sys.stdout = cast(TextIO, _PipeGuard(stdout if stdout is not None else sinks[0], stop=True))
    sys.stderr = cast(TextIO, _PipeGuard(stderr if stderr is not None else sinks[-1], stop=False))
    try:
        code = _command(rest)
        sys.stdout.flush()  # a reader that went away shows up here, not at interpreter exit
    except OutputClosed:
        code = 0  # like ripgrep: `raf ... | head` is not a failure
    finally:
        sys.stdout, sys.stderr = stdout, stderr
        for sink in sinks:
            sink.close()
    sys.exit(code)


if __name__ == "__main__":  # pragma: no cover
    run()
