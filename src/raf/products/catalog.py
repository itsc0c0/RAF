"""Catalog of built-in R$F products.

Each product package exposes ``raf.products.<name>.manifest.MANIFEST``. The
catalog only imports manifests (cheap); CLI, API and service modules are
imported lazily when a product is actually used.
"""

from __future__ import annotations

import importlib
import importlib.util

from raf.core.plugins.manifest import ProductManifest

#: Display order follows the investigation flow of the signature workflow.
BUILTIN_PRODUCTS: tuple[str, ...] = (
    "graph",
    "timeline",
    "trace",
    "replay",
    "diff",
    "blast",
    "iam",
    "policy",
    "exposure",
    "ghost",
    "range",
    "forge",
    "lab",
    "protocol",
    "vault",
    "dependency",
    "evidence",
    "surface",
    "lens",
    "oracle",
)


def builtin_manifests() -> list[ProductManifest]:
    manifests: list[ProductManifest] = []
    for name in BUILTIN_PRODUCTS:
        module_name = f"raf.products.{name}.manifest"
        try:
            if importlib.util.find_spec(module_name) is None:
                continue
        except ModuleNotFoundError:
            continue
        module = importlib.import_module(module_name)
        manifests.append(module.MANIFEST)
    return manifests
