"""Platform commands: version, status, help, products, plugins."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.text import Text

from raf.apps.cli import runtime as rt
from raf.apps.cli.clickcompat import Context, is_group
from raf.apps.cli.helptopics import HELP_TOPICS
from raf.apps.cli.registry import build_registry
from raf.core.errors import NotFoundError
from raf.version import RAF_VERSION, versions

PANEL = "Platform"

product_app = typer.Typer(help="Inspect, enable or disable a product.", no_args_is_help=True)
plugin_app = typer.Typer(help="Manage third-party plugins (install, trust, inspect).", no_args_is_help=True)


def _status_data() -> dict[str, object]:
    ctx = rt.ctx()
    stats = ctx.store.stats()
    registry = ctx.registry or build_registry()
    products = registry.products()
    return {
        "raf_version": RAF_VERSION,
        "core": "ONLINE",
        "database": "ONLINE",
        "workspace": ctx.workspace.name,
        "workspace_path": str(ctx.workspace.path),
        "products": {"total": len(products), "available": sum(1 for p in products if p.available)},
        "data": stats,
        "findings_by_severity": ctx.store.findings.count_by_severity(statuses=["OPEN"]),
        "oracle_provider": ctx.settings.get("oracle.provider"),
    }


def show_banner() -> None:
    data = _status_data()
    if rt.STATE.json:
        rt.emit_json("raf.status/v1", data)
        return
    c = rt.console()
    c.print()
    c.print(Text("R$F Security Platform", style="bold"))
    c.print(Text("─" * 36, style="dim"))
    products = data["products"]
    assert isinstance(products, dict)
    rt.kv_block(
        [
            ("Core", Text("ONLINE", style="green")),
            ("Database", Text("ONLINE", style="green")),
            ("Products", f"{products['available']}"),
            ("Workspace", Text(str(data["workspace"]), style="bold cyan")),
        ],
        width=12,
    )
    stats = data["data"]
    assert isinstance(stats, dict)
    if not any(stats.values()):
        c.print()
        c.print("No workspace data yet.")
        rt.next_steps(["raf demo load", "raf analyze <file>", "raf range create demo", "raf help"], title="Try")
    else:
        c.print()
        rt.kv_block([(k.title(), f"{v:,}") for k, v in stats.items()], width=12)


def register(app: typer.Typer) -> None:
    @app.command("version", rich_help_panel=PANEL)
    def version_cmd() -> None:
        """Show R$F and schema versions."""
        data = versions()
        rt.output("raf.version/v1", data, lambda: rt.kv_block([(k, v) for k, v in data.items()], width=16))

    @app.command("status", rich_help_panel=PANEL)
    def status_cmd() -> None:
        """Platform, database, workspace and data status."""
        data = _status_data()

        def render() -> None:
            show_banner()
            sev = data["findings_by_severity"]
            assert isinstance(sev, dict)
            if any(sev.values()):
                rt.console().print()
                line = Text("Open findings  ", style="dim")
                for name, count in sev.items():
                    if count:
                        line.append_text(rt.sev_text(name))
                        line.append(f" {count}  ")
                rt.console().print(line)

        rt.output("raf.status/v1", data, render)

    @app.command("help", rich_help_panel=PANEL)
    def help_cmd(topic: list[str] = typer.Argument(None, help="Command path or topic (objects, query, refs).")) -> None:
        """Help for a command (raf help replay) or a topic (raf help objects)."""
        from raf.apps.cli.main import app as root_app

        parts = topic or []
        if len(parts) == 1 and parts[0] in HELP_TOPICS:
            rt.console().print(HELP_TOPICS[parts[0]])
            return
        root = typer.main.get_command(root_app)
        context = Context(root, info_name="raf")
        command: Any = root
        for part in parts:
            if not is_group(command):
                break
            sub = command.get_command(context, part)
            if sub is None:
                raise NotFoundError(
                    f"No command or help topic named '{part}'.",
                    hint="Topics: " + ", ".join(sorted(HELP_TOPICS)),
                    suggestions=["raf help"],
                )
            command = sub
            context = Context(command, info_name=part, parent=context)
        typer.echo(command.get_help(context))
        if not parts:
            rt.console().print(Text("Topics: " + ", ".join(sorted(HELP_TOPICS)) + "  (raf help <topic>)", style="dim"))

    @app.command("products", rich_help_panel=PANEL)
    def products_cmd() -> None:
        """List products with their status."""
        registry = rt.ctx().registry or build_registry()
        infos = registry.products()
        data = {"items": [i.to_dict() for i in infos]}

        def render() -> None:
            rt.header("R$F PRODUCTS")
            rows = []
            for info in infos:
                status = info.display_status
                style = {
                    "STABLE": "green",
                    "BETA": "cyan",
                    "ALPHA": "yellow",
                    "EXPERIMENTAL": "magenta",
                    "DISABLED": "dim",
                    "UNAVAILABLE": "red",
                }.get(status, "")
                label = status + (" (optional)" if info.manifest.optional else "")
                rows.append((info.manifest.display_name, Text(label, style=style), info.manifest.description))
            rt.table(["PRODUCT", "STATUS", "DESCRIPTION"], rows)
            rt.next_steps(["raf product info <name>", "raf help <product>"])

        rt.output("raf.products/v1", data, render)

    @product_app.command("info")
    def product_info(name: str) -> None:
        """Show a product's manifest, status and dependencies."""
        registry = rt.ctx().registry or build_registry()
        info = registry.info(name)
        data = info.to_dict() | {"dependents": registry.dependents(name)}

        def render() -> None:
            m = info.manifest
            rt.header(f"R$F {m.display_name.upper()}", m.description)
            rt.kv_block(
                [
                    ("Status", info.display_status),
                    ("Maturity", m.status.value),
                    ("Version", m.version),
                    ("Source", info.source),
                    ("Commands", ", ".join(m.commands or [m.name]) or "-"),
                    ("Depends on", ", ".join(m.depends_on) or "-"),
                    ("Used by", ", ".join(data["dependents"]) or "-"),
                    ("Docs", m.docs or "-"),
                ]
            )
            if info.unavailable_reason:
                rt.console().print(Text(f"Unavailable: {info.unavailable_reason}", style="yellow"))

        rt.output("raf.product/v1", data, render)

    @product_app.command("enable")
    def product_enable(name: str) -> None:
        """Enable a product."""
        ctx = rt.ctx()
        registry = ctx.registry or build_registry()
        info = registry.enable(name)
        ctx.audit.record("product.enable", affected=[name])
        rt.output("raf.product/v1", info.to_dict(), lambda: rt.success(f"Enabled {info.manifest.display_name}."))

    @product_app.command("disable")
    def product_disable(name: str) -> None:
        """Disable a product (its commands and API routes become unavailable)."""
        ctx = rt.ctx()
        registry = ctx.registry or build_registry()
        dependents = [d for d in registry.dependents(name) if registry.is_available(d)]
        info = registry.disable(name)
        ctx.audit.record("product.disable", affected=[name], details={"dependents": dependents})

        def render() -> None:
            rt.success(f"Disabled {info.manifest.display_name}.")
            if dependents:
                rt.warn("these products depend on it and are now unavailable: " + ", ".join(dependents))

        rt.output("raf.product/v1", info.to_dict() | {"affected_dependents": dependents}, render)

    @app.command("install", rich_help_panel=PANEL)
    def install_cmd(
        source: str = typer.Argument(..., help="Local plugin directory (remote registry: future)."),
    ) -> None:
        """Install a product plugin (installed plugins stay disabled until trusted)."""
        ctx = rt.ctx()
        registry = ctx.registry or build_registry()
        path = Path(source)
        if not path.exists():
            # Not a local path: ask the (future) remote registry to fetch it into a staging directory.
            path = registry.remote.fetch(source, None, ctx.home.root / "staging")
        info = registry.install_plugin(path)
        ctx.audit.record("plugin.install", affected=[info.name], details={"source": source})

        def render() -> None:
            rt.success(f"Installed plugin {info.name} {info.manifest.version} (disabled, untrusted).")
            rt.warn("plugins run code in-process. Review it, then trust it explicitly.")
            rt.kv_block([("Permissions", ", ".join(info.manifest.permissions) or "none")])
            rt.next_steps([f"raf plugin trust {info.name}"])

        rt.output("raf.plugin/v1", info.to_dict(), render)

    @app.command("uninstall", rich_help_panel=PANEL)
    def uninstall_cmd(name: str) -> None:
        """Remove an installed plugin."""
        ctx = rt.ctx()
        registry = ctx.registry or build_registry()
        rt.confirm(f"Uninstall plugin '{name}'?", [f"Removes {ctx.home.plugins_dir / name}"])
        result = registry.uninstall_plugin(name)
        ctx.audit.record("plugin.uninstall", affected=[name])
        rt.output("raf.plugin.uninstall/v1", result, lambda: rt.success(f"Uninstalled {name}."))

    @plugin_app.command("list")
    def plugin_list() -> None:
        """List installed plugins."""
        registry = rt.ctx().registry or build_registry()
        items = [i.to_dict() for i in registry.products() if i.source == "plugin"]

        def render() -> None:
            if not items:
                rt.console().print("No plugins installed.")
                rt.next_steps(["raf install ./path/to/plugin", "raf help plugins"])
                return
            rt.table(
                ["PLUGIN", "VERSION", "TRUSTED", "STATUS", "PERMISSIONS"],
                [
                    (i["name"], i["version"], "yes" if i["trusted"] else "no", i["status"], ", ".join(i["permissions"]))
                    for i in items
                ],
            )

        rt.output("raf.plugins/v1", {"items": items}, render)

    @plugin_app.command("trust")
    def plugin_trust(name: str) -> None:
        """Trust a plugin's current files (records their SHA-256) and enable it."""
        ctx = rt.ctx()
        registry = ctx.registry or build_registry()
        info = registry.info(name)
        rt.confirm(
            f"Trust plugin '{name}'? It will run with your privileges.",
            [f"Requested permissions: {', '.join(info.manifest.permissions) or 'none'}"],
        )
        info = registry.trust_plugin(name)
        ctx.audit.record("plugin.trust", affected=[name])
        rt.output("raf.plugin/v1", info.to_dict(), lambda: rt.success(f"Trusted and enabled {name}."))

    @plugin_app.command("verify")
    def plugin_verify(name: str) -> None:
        """Check that a trusted plugin's files are unchanged."""
        registry = rt.ctx().registry or build_registry()
        ok = registry.verify_plugin(name)
        data = {"name": name, "unchanged": ok}
        rt.output(
            "raf.plugin.verify/v1",
            data,
            lambda: (
                rt.success(f"{name}: files match the trusted hash.")
                if ok
                else rt.warn(f"{name}: not trusted or modified.")
            ),
        )

    app.add_typer(product_app, name="product", rich_help_panel=PANEL)
    app.add_typer(plugin_app, name="plugin", rich_help_panel=PANEL)
