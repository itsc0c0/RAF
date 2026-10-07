"""Workspace, configuration and secret commands."""

from __future__ import annotations

import getpass
import os
from pathlib import Path

import typer
from rich.text import Text

from raf.core.config.loader import keyring_delete, keyring_get, keyring_set, set_value, unset_value
from raf.core.config.schema import KEYS, get_key
from raf.core.errors import InvalidInputError
from raf.core.workspace.manager import RafHome, WorkspaceManager
from raf.sdk import cli as rt

PANEL = "Workspace"

workspace_app = typer.Typer(help="Create, switch, export and delete workspaces.", no_args_is_help=True)
config_app = typer.Typer(
    help="Layered configuration (defaults < global < workspace < env < flags).", no_args_is_help=True
)
secret_app = typer.Typer(help="Secrets in the OS keyring (never in plaintext config).", no_args_is_help=True)


def _manager() -> WorkspaceManager:
    home = RafHome.from_env()
    home.ensure()
    return WorkspaceManager(home)


@workspace_app.command("create")
def ws_create(
    name: str,
    description: str = typer.Option("", "--description", "-d"),
    use: bool = typer.Option(False, "--use", help="Switch to the new workspace."),
) -> None:
    """Create a workspace."""
    manager = _manager()
    ws = manager.create(name, description)
    if use:
        manager.use(ws.name)
    rt.STATE.workspace = ws.name
    rt.ctx().audit.record("workspace.create", affected=[ws.name], details={"description": description})
    data = {"name": ws.name, "path": str(ws.path), "current": use}

    def render() -> None:
        rt.success(f"Created workspace '{ws.name}'.")
        rt.next_steps([] if use else [f"raf workspace use {ws.name}"])

    rt.output("raf.workspace/v1", data, render)


@workspace_app.command("use")
def ws_use(name: str) -> None:
    """Make a workspace current."""
    manager = _manager()
    ws = manager.use(name)
    rt.output(
        "raf.workspace/v1",
        {"name": ws.name, "path": str(ws.path), "current": True},
        lambda: rt.success(f"Workspace '{ws.name}' is now current."),
    )


@workspace_app.command("list")
def ws_list() -> None:
    """List workspaces."""
    infos = _manager().list()
    data = {"items": [i.to_dict() for i in infos]}

    def render() -> None:
        rt.table(
            ["", "WORKSPACE", "CREATED", "DESCRIPTION"],
            [
                (Text("*", style="green") if i.current else "", i.name, i.created_at or "-", i.description)
                for i in infos
            ],
        )

    rt.output("raf.workspaces/v1", data, render)


@workspace_app.command("info")
def ws_info(name: str | None = typer.Argument(None)) -> None:
    """Show workspace location, size and data counts."""
    if name:
        rt.STATE.workspace = name
    ctx = rt.ctx()
    ws_bytes = ctx.workspace.disk_usage()
    data = {
        "name": ctx.workspace.name,
        "path": str(ctx.workspace.path),
        "bytes": ws_bytes,
        "metadata": ctx.workspace.metadata(),
        "data": ctx.store.stats(),
    }

    def render() -> None:
        rt.header(f"WORKSPACE {ctx.workspace.name}")
        rt.kv_block([("Path", data["path"]), ("Size", f"{ws_bytes / 1e6:.1f} MB")])
        stats = data["data"]
        assert isinstance(stats, dict)
        rt.kv_block([(k.title(), f"{v:,}") for k, v in stats.items()])

    rt.output("raf.workspace.info/v1", data, render)


@workspace_app.command("delete")
def ws_delete(name: str) -> None:
    """Delete a workspace and ALL its data (requires confirmation or --yes)."""
    manager = _manager()
    ws = manager.get(name)
    manager.require_not_current_env(name)
    rt.STATE.workspace = name
    stats = rt.ctx().store.stats()
    rt.close_ctx()
    rt.confirm(
        f"Delete workspace '{name}'? This cannot be undone.",
        [
            f"Directory: {ws.path}",
            f"Objects: {stats['objects']:,}  Relationships: {stats['relationships']:,}  Events: {stats['events']:,}",
            f"Findings: {stats['findings']:,}  plus evidence copies, snapshots, ranges and labs",
        ],
    )
    summary = manager.delete(name)
    rt.output("raf.workspace.delete/v1", summary, lambda: rt.success(f"Deleted workspace '{name}'."))


def register(app: typer.Typer) -> None:
    app.add_typer(workspace_app, name="workspace", rich_help_panel=PANEL)
    app.add_typer(config_app, name="config", rich_help_panel=PANEL)
    app.add_typer(secret_app, name="secret", rich_help_panel=PANEL)


# --------------------------------------------------------------------------- config


def _scope_path(scope: str) -> Path:
    if scope == "global":
        home = RafHome.from_env()
        home.ensure()
        return home.config_path
    if scope == "workspace":
        return rt.ctx().workspace.config_path
    raise InvalidInputError(f"Unknown scope '{scope}'.", hint="Use --scope global or --scope workspace.")


@config_app.command("list")
def config_list() -> None:
    """Effective configuration with the layer each value comes from."""
    settings = rt.ctx().settings
    items = []
    for entry in settings.entries():
        if entry.secret:
            value = "set" if settings.secret(entry.key) else "not set"
        else:
            value = entry.value
        items.append(
            {
                "key": entry.key,
                "value": value,
                "origin": entry.origin,
                "secret": entry.secret,
                "description": entry.description,
            }
        )

    def render() -> None:
        rt.table(
            ["KEY", "VALUE", "ORIGIN", "DESCRIPTION"],
            [
                (i["key"], Text(str(i["value"]), style="yellow" if i["secret"] else ""), i["origin"], i["description"])
                for i in items
            ],
        )

    rt.output("raf.config/v1", {"items": items}, render)


@config_app.command("get")
def config_get(key: str) -> None:
    """Show one effective configuration value."""
    spec = get_key(key)
    settings = rt.ctx().settings
    value = ("set" if settings.secret(key) else "not set") if spec.secret else settings.get(key)
    data = {"key": key, "value": value, "origin": settings.origin(key)}
    rt.output("raf.config.value/v1", data, lambda: rt.console().print(f"{value}"))


@config_app.command("set")
def config_set(
    key: str, value: str, scope: str = typer.Option("global", "--scope", help="global or workspace")
) -> None:
    """Set a configuration value (secrets are refused; use env vars or 'raf secret set')."""
    path = _scope_path(scope)
    stored = set_value(path, key, value)
    rt.ctx().audit.record("config.set", affected=[key], details={"scope": scope, "value": stored})
    rt.output(
        "raf.config.value/v1",
        {"key": key, "value": stored, "scope": scope, "path": str(path)},
        lambda: rt.success(f"{key} = {stored}  ({scope}: {path})"),
    )


@config_app.command("unset")
def config_unset(key: str, scope: str = typer.Option("global", "--scope")) -> None:
    """Remove a value from a configuration layer."""
    path = _scope_path(scope)
    removed = unset_value(path, key)
    rt.ctx().audit.record("config.unset", affected=[key], details={"scope": scope, "removed": removed})
    rt.output(
        "raf.config.unset/v1",
        {"key": key, "removed": removed, "scope": scope},
        lambda: (
            rt.success(f"Removed {key} from {scope} config.")
            if removed
            else rt.note(f"{key} was not set in {scope} config.")
        ),
    )


@config_app.command("path")
def config_path() -> None:
    """Show configuration file locations."""
    home = RafHome.from_env()
    data = {"global": str(home.config_path), "workspace": str(rt.ctx().workspace.config_path), "env_prefix": "RAF_"}
    rt.output("raf.config.paths/v1", data, lambda: rt.kv_block(list(data.items())))


@config_app.command("keys")
def config_keys() -> None:
    """Document every configuration key."""
    items = [
        {
            "key": k.key,
            "type": k.type.__name__,
            "default": k.default,
            "env": k.env_var,
            "secret": k.secret,
            "choices": list(k.choices) if k.choices else None,
            "description": k.description,
        }
        for k in KEYS
    ]
    rt.output(
        "raf.config.keys/v1",
        {"items": items},
        lambda: rt.table(
            ["KEY", "TYPE", "DEFAULT", "ENV"], [(i["key"], i["type"], i["default"], i["env"]) for i in items]
        ),
    )


# --------------------------------------------------------------------------- secrets


@secret_app.command("set")
def secret_set(key: str) -> None:
    """Store a secret in the OS keyring (prompted, never echoed)."""
    get_key(key)
    value = getpass.getpass(f"Value for {key}: ")
    if not value:
        raise InvalidInputError("Empty secret; nothing stored.")
    keyring_set(key, value)
    rt.ctx().audit.record("secret.set", affected=[key])
    rt.output("raf.secret/v1", {"key": key, "stored": True}, lambda: rt.success(f"Stored {key} in the OS keyring."))


@secret_app.command("delete")
def secret_delete(key: str) -> None:
    """Remove a secret from the OS keyring."""
    removed = keyring_delete(key)
    rt.ctx().audit.record("secret.delete", affected=[key], details={"removed": removed})
    rt.output(
        "raf.secret/v1",
        {"key": key, "removed": removed},
        lambda: rt.success(f"Removed {key}.") if removed else rt.note(f"{key} was not in the keyring."),
    )


@secret_app.command("status")
def secret_status() -> None:
    """Show which secrets are configured and where (values are never shown)."""
    items = []
    for spec in KEYS:
        if not spec.secret:
            continue
        source = "env" if os.environ.get(spec.env_var) else ("keyring" if keyring_get(spec.key) else "not set")
        items.append({"key": spec.key, "source": source, "env": spec.env_var})
    rt.output(
        "raf.secrets/v1",
        {"items": items},
        lambda: rt.table(["SECRET", "SOURCE", "ENV VAR"], [(i["key"], i["source"], i["env"]) for i in items]),
    )
