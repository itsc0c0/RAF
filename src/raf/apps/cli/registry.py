"""Product registry wiring and lazy product command loading for the CLI."""

from __future__ import annotations

import functools
import importlib
from typing import Any

import typer
from typer.core import TyperGroup

from raf.core.errors import ProductDisabledError
from raf.core.plugins.registry import ProductRegistry
from raf.core.workspace.manager import RafHome
from raf.products.catalog import builtin_manifests

CATEGORY_PANELS = {
    "investigation": "Investigate",
    "exposure": "Exposure",
    "synthetic": "Synthetic environments",
    "analysis": "Specialized analysis",
    "ai": "AI reasoning",
    "plugin": "Plugins",
}


@functools.lru_cache(maxsize=1)
def build_registry() -> ProductRegistry:
    return ProductRegistry(RafHome.from_env(), builtin_manifests())


def product_commands(registry: ProductRegistry) -> dict[str, tuple[str, str | None]]:
    """Map top-level command name -> (product name, cli import path)."""
    mapping: dict[str, tuple[str, str | None]] = {}
    for name, manifest in registry.manifests().items():
        if not manifest.cli:
            continue
        for command in manifest.commands or [name]:
            mapping[command] = (name, manifest.cli)
    return mapping


def _disabled_stub(command: str, product: str, reason: str | None) -> Any:
    stub_app = typer.Typer(add_completion=False)

    @stub_app.command(
        command,
        help=f"[unavailable: {reason}]",
        context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
    )
    def _run(args: list[str] = typer.Argument(None)) -> None:
        raise ProductDisabledError(
            f"R$F {product.title()} is not available.",
            reason=reason,
            suggestions=[f"raf product enable {product}", "raf products"],
        )

    return typer.main.get_command(stub_app)


@functools.lru_cache(maxsize=64)
def load_product_command(command: str) -> Any:
    registry = build_registry()
    mapping = product_commands(registry)
    if command not in mapping:
        return None
    product, import_path = mapping[command]
    info = registry.info(product)
    if not info.available:
        return _disabled_stub(command, product, info.unavailable_reason)
    assert import_path is not None
    try:
        if info.source == "plugin":
            typer_app = registry.load_plugin_attr(product, import_path)
        else:
            module_name, attr = import_path.split(":", 1)
            typer_app = getattr(importlib.import_module(module_name), attr)
    except (ImportError, AttributeError) as exc:
        # a broken product must not break `raf --help` or other commands
        return _disabled_stub(command, product, f"failed to load: {exc}")
    click_cmd = typer.main.get_command(typer_app) if isinstance(typer_app, typer.Typer) else typer_app
    click_cmd.name = command
    panel = CATEGORY_PANELS.get(info.manifest.category if info.source == "builtin" else "plugin", "Products")
    setattr(click_cmd, "rich_help_panel", panel)  # noqa: B010 - attribute only exists on Typer classes
    return click_cmd


class RafGroup(TyperGroup):
    """Root command group: core commands plus lazily loaded product commands."""

    def list_commands(self, ctx: Any) -> list[str]:
        core = super().list_commands(ctx)
        products = [c for c in product_commands(build_registry()) if c not in core]
        return core + products

    def get_command(self, ctx: Any, cmd_name: str) -> Any:
        command = super().get_command(ctx, cmd_name)
        if command is not None:
            return command
        return load_product_command(cmd_name)
