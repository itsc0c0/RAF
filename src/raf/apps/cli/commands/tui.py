"""``raf tui``: R$F OS, the full-screen terminal control panel.

The panel itself is the ``raf-os`` binary (Rust + Ratatui, built from ``tui/``). ``raf tui`` starts
the R$F API in this process on a random loopback port with a one-time bearer token, runs the
panel in the terminal, and stops the API when the panel exits. Nothing listens beyond loopback and
the token never leaves the two processes.
"""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import typer

from raf.core.errors import DependencyUnavailableError, InvalidInputError
from raf.sdk import cli as rt

BINARY = "raf-os"
PAGES = (
    "home",
    "timeline",
    "trace",
    "iam",
    "blast",
    "exposure",
    "policy",
    "ghost",
    "graph",
    "oracle",
    "findings",
    "evidence",
)
_REPO = Path(__file__).resolve().parents[5]
BUILD_HINT = "Build it once with: cargo build --release --manifest-path tui/Cargo.toml (needs Rust)"


def find_binary() -> Path | None:
    """``RAF_OS_BIN``, then the repository build (``tui/target/release``), the virtual environment, PATH."""
    candidates: list[Path] = []
    configured = os.environ.get("RAF_OS_BIN")
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates += [
        _REPO / "tui" / "target" / "release" / BINARY,
        _REPO / "tui" / "target" / "debug" / BINARY,
        Path(sys.executable).parent / BINARY,
    ]
    found = shutil.which(BINARY)
    if found:
        candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


@contextlib.contextmanager
def _quiet_console() -> Iterator[None]:
    """Keep log records off the terminal while the full-screen panel owns it (the log file keeps them)."""
    handlers = [
        h
        for name in ("raf", "")
        for h in logging.getLogger(name).handlers
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
    ]
    levels = [h.level for h in handlers]
    for handler in handlers:
        handler.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        for handler, level in zip(handlers, levels, strict=True):
            handler.setLevel(level)


@contextlib.contextmanager
def local_api(workspace: str) -> Iterator[tuple[str, str]]:
    """Run the API on 127.0.0.1:<random> with a fresh token; yields (base URL, token)."""
    import uvicorn

    from raf.apps.api.app import create_app

    token = secrets.token_urlsafe(32)
    application = create_app(host="127.0.0.1", token=token, serve_ui=False)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    config = uvicorn.Config(application, log_config=None, log_level="warning", access_log=False, lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, name="raf-os-api", daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise DependencyUnavailableError("The local R$F API for R$F OS did not start.")
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}/api/v1", token
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


def register(app: typer.Typer) -> None:
    @app.command(
        "tui",
        rich_help_panel="Platform",
        help="""R$F OS: the full-screen terminal control panel (mouse and keyboard).

  raf tui                      open on HOME
  raf tui --page ghost         open on a page (home, timeline, trace, iam, blast, exposure, policy,
                               ghost, graph, oracle, findings, evidence)
  raf tui --dump blast         print one page as plain text (no terminal UI)

Keys: ←/→ pages, ↑/↓ scroll, / change subject, Enter inspect, ? help, q quit.
The panel is the raf-os binary built from tui/ (cargo build --release --manifest-path tui/Cargo.toml).""",
    )
    def tui_cmd(
        page: str = typer.Option("home", "--page", "-p", help="Page to open."),
        param: str | None = typer.Option(None, "--param", help="Subject/parameter for --page or --dump."),
        dump: str | None = typer.Option(None, "--dump", help="Print this page as plain text and exit."),
        width: int = typer.Option(100, "--width", min=60, max=400, help="Width for --dump."),
        no_boot: bool = typer.Option(False, "--no-boot", help="Skip the boot animation."),
        no_mouse: bool = typer.Option(False, "--no-mouse", help="Disable mouse capture."),
    ) -> None:
        if rt.STATE.json:
            raise InvalidInputError(
                "raf tui is a terminal interface and has no JSON output.",
                hint="Screens are available as JSON from the API: GET /api/v1/tui/screen/<page>",
            )
        chosen = (dump or page).lower()
        if chosen not in PAGES:
            raise InvalidInputError(f"Unknown page '{chosen}'.", hint="Pages: " + ", ".join(PAGES))
        if dump is None and not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise InvalidInputError(
                "raf tui needs an interactive terminal.", hint=f"Print a page instead: raf tui --dump {chosen}"
            )
        binary = find_binary()
        if binary is None:
            raise DependencyUnavailableError(
                "R$F OS (the terminal panel) is not built yet.",
                reason="the raf-os binary was not found (RAF_OS_BIN, tui/target/release, the virtualenv, PATH)",
                hint=BUILD_HINT,
            )
        ctx = rt.ctx()
        workspace = ctx.workspace.name
        ctx.audit.record("tui.session", details={"page": chosen, "dump": dump is not None})
        rt.close_ctx()
        args = [str(binary)]
        if dump is not None:
            args += ["--dump", chosen, "--width", str(width)]
        else:
            args += ["--page", chosen]
            if no_boot:
                args.append("--no-boot")
            if no_mouse:
                args.append("--no-mouse")
        if param:
            args += ["--param", param]
        with _quiet_console(), local_api(workspace) as (base, token):
            env: dict[str, Any] = {
                **os.environ,
                "RAF_OS_API": base,
                "RAF_OS_TOKEN": token,
                "RAF_OS_WORKSPACE": workspace,
            }
            env.pop("RAF_API_TOKEN", None)
            completed = subprocess.run(args, env=env, check=False)
        if completed.returncode not in (0, 130):
            raise typer.Exit(completed.returncode)
