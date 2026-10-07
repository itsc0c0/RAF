"""Parser registry for a context: core parsers plus those contributed by available products and
trusted plugins (manifest ``parsers``). Lives in core so every product (Evidence, analyze
pipelines ...) imports data with the same set of parsers."""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING

from raf.core.errors import RafError
from raf.core.ingestion.registry import ParserRegistry

if TYPE_CHECKING:
    from raf.core.context.app import RafContext

log = logging.getLogger("raf.ingestion")


def build_parser_registry(ctx: RafContext) -> ParserRegistry:
    registry = ParserRegistry.default()
    if ctx.registry is None:
        return registry
    for info in ctx.registry.products():
        if not info.available:
            continue
        for import_path in info.manifest.parsers:
            try:
                if info.source == "plugin":
                    parser = ctx.registry.load_plugin_attr(info.name, import_path)
                else:
                    module_name, attr = import_path.split(":", 1)
                    parser = getattr(importlib.import_module(module_name), attr)
            except (RafError, ImportError, AttributeError) as exc:
                log.warning("parser %s from %s unavailable: %s", import_path, info.name, exc)
                continue
            registry.register_parser(parser)
    return registry
