"""Parser registry for a context: core parsers plus those contributed by available products and
trusted plugins (manifest ``parsers``). Lives in core so every product (Evidence, analyze
pipelines ...) imports data with the same set of parsers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from raf.core.errors import RafError
from raf.core.ingestion.base import Parser
from raf.core.ingestion.registry import ParserRegistry

if TYPE_CHECKING:
    from raf.core.context.app import RafContext

log = logging.getLogger("raf.ingestion")


def _parser_class(value: Any) -> type[Parser]:
    if isinstance(value, type) and issubclass(value, Parser) and isinstance(getattr(value, "name", None), str):
        return value
    raise TypeError(f"expected a Parser subclass with a name, got {type(value).__name__}")


def build_parser_registry(ctx: RafContext) -> ParserRegistry:
    """Core parsers, then those of available products. A product whose parser fails to load is
    reported unavailable (and skipped); a plugin parser cannot replace a parser that is already
    registered under its name (built-in names win)."""
    registry = ParserRegistry.default()
    if ctx.registry is None:
        return registry
    for info in ctx.registry.products():
        if not info.available or not info.manifest.parsers:
            continue
        try:
            parsers = [ctx.registry.load_attr(info.name, path, _parser_class) for path in info.manifest.parsers]
        except RafError as exc:  # the registry logged why and reports the product unavailable
            log.debug("parsers of %s skipped: %s", info.name, exc)
            continue
        for parser in parsers:
            if info.source == "plugin" and parser.name in {p.name for p in registry.parsers()}:
                log.warning("parser '%s' of plugin %s ignored: a parser with that name exists", parser.name, info.name)
                continue
            registry.register_parser(parser)
    return registry
