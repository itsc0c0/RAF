"""Wires product-provided state sources into the core (application layer).

Core defines extension points (e.g. ``STATE_PROVIDERS`` for ``ghost:<model>``);
products implement them; this module connects the two without creating
product-to-product imports.
"""

from __future__ import annotations

import importlib

from raf.core.context.app import RafContext
from raf.core.snapshots.service import STATE_PROVIDERS


def install_state_providers(ctx: RafContext) -> None:
    available = {p.name for p in ctx.registry.products() if p.available} if ctx.registry else set()
    if "ghost" in available and "ghost" not in STATE_PROVIDERS:
        try:
            module = importlib.import_module("raf.products.ghost.service")
        except ModuleNotFoundError:
            return
        STATE_PROVIDERS["ghost"] = module.ghost_state_provider
