"""Product registry wiring and lazy product command loading for the CLI."""

from __future__ import annotations

import copy
import functools
import logging
from collections.abc import Collection
from typing import Any

import typer
from rich.markup import escape
from typer.core import TyperGroup

from raf.apps.cli.clickcompat import Command
from raf.core.errors import ProductDisabledError, RafError
from raf.core.plugins.registry import ProductRegistry
from raf.core.workspace.manager import RafHome
from raf.products.catalog import builtin_manifests

log = logging.getLogger("raf.cli")

CATEGORY_PANELS = {
    "investigation": "Investigate",
    "exposure": "Exposure",
    "synthetic": "Synthetic environments",
    "analysis": "Specialized analysis",
    "ai": "AI reasoning",
    "plugin": "Plugins",
}

_warned: set[tuple[str, str]] = set()


@functools.lru_cache(maxsize=1)
def build_registry() -> ProductRegistry:
    return ProductRegistry(RafHome.from_env(), builtin_manifests())


def command_table(
    registry: ProductRegistry, reserved: Collection[str] = ()
) -> tuple[dict[str, tuple[str, str | None]], list[tuple[str, str, str]]]:
    """Top-level product commands: ``{command: (product, cli import path)}``, plus the plugin
    commands that are ignored as ``(plugin, command, owner)``.

    Built-in commands win: a plugin command never replaces a command of R$F itself (``reserved``),
    of a built-in product or of a plugin listed before it (plugins are ordered by name).
    """
    mapping: dict[str, tuple[str, str | None]] = {}
    plugins = []
    for name, manifest in registry.manifests().items():
        if not manifest.cli:
            continue
        if registry.is_plugin(name):
            plugins.append((name, manifest))
            continue
        for command in manifest.commands or [name]:
            mapping[command] = (name, manifest.cli)
    ignored: list[tuple[str, str, str]] = []
    for name, manifest in plugins:
        for command in manifest.commands or [name]:
            if command in reserved:
                ignored.append((name, command, "R$F itself"))
            elif command in mapping and mapping[command][0] != name:
                ignored.append((name, command, f"product '{mapping[command][0]}'"))
            else:
                mapping[command] = (name, manifest.cli)
    return mapping, ignored


def product_commands(registry: ProductRegistry, reserved: Collection[str] = ()) -> dict[str, tuple[str, str | None]]:
    """Map top-level command name -> (product name, cli import path)."""
    return command_table(registry, reserved)[0]


def _warn_ignored(ignored: list[tuple[str, str, str]]) -> None:
    for plugin, command, owner in ignored:
        if (plugin, command) not in _warned:
            _warned.add((plugin, command))
            log.warning("plugin %s: command '%s' is ignored, %s already provides it", plugin, command, owner)


def _disabled_stub(command: str, product: str, reason: str | None, panel: str) -> Any:
    stub_app = typer.Typer(add_completion=False)

    @stub_app.command(
        command,
        help=escape(f"[unavailable: {reason or 'unknown reason'}]"),  # help text is Rich markup
        rich_help_panel=panel,
        context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
    )
    def _run(args: list[str] = typer.Argument(None)) -> None:
        build_registry().require(product)  # raises why, with the commands that fix it
        raise ProductDisabledError(f"R$F {product.title()} is not available.", reason=reason)

    return typer.main.get_command(stub_app)


def _click_command(value: Any) -> Any:
    """A product's ``cli`` object as a Click command (a Typer app is converted)."""
    if isinstance(value, typer.Typer):
        return typer.main.get_command(value)
    if isinstance(value, Command) or (callable(getattr(value, "main", None)) and hasattr(value, "params")):
        return value
    raise TypeError(f"expected a Typer app or a Click command, got {type(value).__name__}")


@functools.lru_cache(maxsize=64)
def load_product_command(command: str) -> Any:
    registry = build_registry()
    mapping = product_commands(registry)
    if command not in mapping:
        return None
    product, import_path = mapping[command]
    assert import_path is not None
    info = registry.info(product)
    panel = CATEGORY_PANELS.get(info.manifest.category if info.source == "builtin" else "plugin", "Products")
    if not info.available:
        return _disabled_stub(command, product, info.unavailable_reason, panel)
    try:
        loaded = registry.load_attr(product, import_path, _click_command)
    except RafError:
        # a broken product must not break `raf --help` or other commands (the registry logged why)
        return _disabled_stub(command, product, registry.info(product).unavailable_reason, panel)
    click_cmd = copy.copy(loaded)  # one object per name: a Click command may be listed under several
    click_cmd.name = command
    setattr(click_cmd, "rich_help_panel", panel)  # noqa: B010 - attribute only exists on Typer classes
    return click_cmd


class RafGroup(TyperGroup):
    """Root command group: core commands plus lazily loaded product commands."""

    def list_commands(self, ctx: Any) -> list[str]:
        core = super().list_commands(ctx)
        mapping, ignored = command_table(build_registry(), core)
        _warn_ignored(ignored)
        return core + [c for c in mapping if c not in core]

    def get_command(self, ctx: Any, cmd_name: str) -> Any:
        command = super().get_command(ctx, cmd_name)
        if command is not None:
            return command
        return load_product_command(cmd_name)
