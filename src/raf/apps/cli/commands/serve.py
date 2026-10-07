"""``raf serve``: run the local API and web workbench."""

from __future__ import annotations

import os
import secrets

import typer
from rich.text import Text

from raf.apps.api.security import is_loopback
from raf.core.errors import DependencyUnavailableError
from raf.sdk import cli as rt


def register(app: typer.Typer) -> None:
    @app.command("serve", rich_help_panel="Platform")
    def serve_cmd(
        host: str | None = typer.Option(None, "--host", help="Bind address (default 127.0.0.1)."),
        port: int | None = typer.Option(None, "--port", help="Port (default 8765)."),
        no_ui: bool = typer.Option(False, "--no-ui", help="Serve only the API."),
        allow_host: list[str] = typer.Option(None, "--allow-host", help="Extra Host header names to accept."),
    ) -> None:
        """Start the R$F API and web UI (loopback by default; remote binding requires a token)."""
        ctx = rt.ctx()
        bind = host or str(ctx.settings.get("api.host"))
        bind_port = port or int(ctx.settings.get("api.port"))
        token = ctx.settings.secret("api.token") or os.environ.get("RAF_API_TOKEN")
        generated = False
        if not is_loopback(bind) and not token:
            token = secrets.token_urlsafe(32)
            generated = True
        try:
            import uvicorn
        except ImportError as exc:  # pragma: no cover - uvicorn is a core dependency
            raise DependencyUnavailableError("uvicorn is not installed.") from exc
        from raf.apps.api.app import create_app, find_web_dist

        application = create_app(
            host=bind,
            token=token if not is_loopback(bind) else None,
            allowed_hosts=set(allow_host or []),
            serve_ui=not no_ui,
        )
        ctx.audit.record("api.serve", details={"host": bind, "port": bind_port, "remote": not is_loopback(bind)})
        workspace = ctx.workspace.name
        rt.close_ctx()
        c = rt.console()
        c.print()
        c.print(Text("R$F", style="bold"))
        c.print()
        base = f"http://{bind if ':' not in bind else f'[{bind}]'}:{bind_port}"
        rt.kv_block(
            [("API", f"{base}/api/v1"), ("UI", f"{base}/" if not no_ui else "disabled"), ("Docs", f"{base}/api/docs")],
            width=8,
        )
        c.print()
        c.print(Text(f"Workspace: {workspace}", style="cyan"))
        if not no_ui and find_web_dist() is None:
            c.print(Text("The web UI is not built yet: cd web && npm install && npm run build", style="yellow"))
        if not is_loopback(bind):
            c.print(Text("Remote binding: every API request needs 'Authorization: Bearer <token>'.", style="yellow"))
            if generated:
                c.print(Text(f"Generated token (shown once): {token}", style="bold yellow"))
        c.print(Text("Press Ctrl+C to stop.", style="dim"))
        uvicorn.run(application, host=bind, port=bind_port, log_level="warning")
