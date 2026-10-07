"""The ``raf`` command-line interface.

Every security capability. One command away.
"""

from __future__ import annotations

import logging
import os
import sys
import traceback
from collections.abc import Sequence

import typer
from rich.text import Text

from raf.apps.cli import runtime as rt
from raf.apps.cli.clickcompat import Abort, ClickException, Exit
from raf.apps.cli.commands import data as data_cmds
from raf.apps.cli.commands import platform as platform_cmds
from raf.apps.cli.commands import workspace as workspace_cmds
from raf.apps.cli.registry import RafGroup
from raf.core.errors import RafError
from raf.core.logging import configure_logging
from raf.core.workspace.manager import RafHome

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
) -> None:
    """R$F security platform. Run without arguments for the interactive shell."""
    # Global flags are normally extracted by run(); honor them here too when invoked directly.
    rt.STATE.workspace = workspace or rt.STATE.workspace
    rt.STATE.json = json_output or rt.STATE.json
    rt.STATE.quiet = quiet or rt.STATE.quiet
    rt.STATE.no_color = no_color or rt.STATE.no_color
    rt.STATE.debug = debug or rt.STATE.debug
    rt.STATE.yes = yes or rt.STATE.yes
    if ctx.invoked_subcommand is None:
        platform_cmds.show_banner()


platform_cmds.register(app)
workspace_cmds.register(app)
data_cmds.register(app)


def _register_optional() -> None:
    """Command modules that depend on later layers register themselves if present."""
    import importlib

    for module_name in (
        "raf.apps.cli.commands.ingest",
        "raf.apps.cli.commands.snapshots",
        "raf.apps.cli.commands.analyze",
        "raf.apps.cli.commands.serve",
        "raf.apps.cli.commands.bundle",
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
    log_path = RafHome.from_env().logs_dir / "raf.log"
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
        c.print(Text(f"Run again with --debug for the full traceback (also logged to {log_path}).", style="dim"))


def dispatch(args: Sequence[str]) -> int:
    command = typer.main.get_command(app)
    try:
        command.main(args=list(args), prog_name="raf", standalone_mode=False)
        return 0
    except Exit as exc:
        return int(exc.exit_code)
    except Abort:
        rt.err_console().print("Aborted.")
        return 130
    except ClickException as exc:
        if rt.STATE.json:
            rt.emit_json("raf.error/v1", {"error": {"code": "raf.usage", "message": exc.format_message()}})
        else:
            from typer import rich_utils

            rich_utils.rich_format_error(exc)
        return int(exc.exit_code)
    except RafError as exc:
        render_error(exc)
        return exc.exit_code
    except KeyboardInterrupt:
        rt.err_console().print("Interrupted.")
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level boundary renders, never dumps raw traces
        render_internal(exc)
        return 1
    finally:
        rt.close_ctx()


def run(argv: Sequence[str] | None = None) -> None:
    raw = list(sys.argv[1:] if argv is None else argv)
    rt.reset_state()
    rest = extract_global_flags(raw)
    rt.STATE.argv = raw
    level = os.environ.get("RAF_CORE_LOG_LEVEL", "WARNING")
    home = RafHome.from_env()
    configure_logging(level, log_dir=home.logs_dir, debug=rt.STATE.debug)
    if not rest:
        if sys.stdin.isatty() and sys.stdout.isatty() and not rt.STATE.json:
            from raf.apps.cli.shell import run_shell

            run_shell(dispatch)
            sys.exit(0)
        rest = ["status"]
    code = dispatch(rest)
    sys.exit(code)


if __name__ == "__main__":  # pragma: no cover
    run()
