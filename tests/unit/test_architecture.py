"""Architecture rules, enforced on the source tree (every import, including function-level ones).

Layers, from the bottom up:

    raf.core      the platform (models, storage, ingestion, graph, risk, ...)
    raf.data      synthetic datasets (Raven Industries, generators); uses only core
    raf.sdk       runtime for product CLIs and API routers; uses only core
    raf.products  one package per product; uses core, data and sdk, plus the products its
                  manifest lists in ``depends_on`` (never the application layers)
    raf.analysis  application services shared by CLI and API (demo, analyze, ingest, ...)
    raf.apps      the CLI and the HTTP API

A layer may only import layers below it. This keeps products independent (no circular
architecture between products) and lets the CLI and the API share the same application layer.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Iterator
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "raf"
ALLOWED = {
    "core": {"core"},
    "data": {"core", "data"},
    "sdk": {"core", "sdk"},
    "products": {"core", "data", "sdk"},
    "analysis": {"core", "data", "sdk", "products", "analysis"},
    "apps": {"core", "data", "sdk", "products", "analysis", "apps"},
}
ALWAYS = {"version"}  # raf.version is a leaf module every layer may use


def _imports(path: Path) -> Iterator[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.lineno, node.module


def _modules() -> Iterator[tuple[Path, list[str]]]:
    for path in sorted(SRC.rglob("*.py")):
        yield path, list(path.relative_to(SRC).with_suffix("").parts)


def _depends_on(product: str) -> set[str]:
    manifest = importlib.import_module(f"raf.products.{product}.manifest").MANIFEST
    return set(manifest.depends_on)


def test_layers_only_import_downwards() -> None:
    violations = []
    for path, parts in _modules():
        layer = parts[0] if len(parts) > 1 else None
        if layer not in ALLOWED:
            continue
        for line, module in _imports(path):
            target = module.split(".")
            if target[0] != "raf" or len(target) < 2 or target[1] in ALWAYS:
                continue
            if target[1] not in ALLOWED[layer] and not (layer == "products" and target[1] == "products"):
                violations.append(f"{path.relative_to(SRC.parent)}:{line} ({layer}) imports {module}")
    assert not violations, "layering violations:\n" + "\n".join(violations)


def test_products_only_import_declared_dependencies() -> None:
    violations = []
    for path, parts in _modules():
        if parts[0] != "products" or len(parts) < 3:
            continue
        product = parts[1]
        allowed = {product} | _depends_on(product)
        for line, module in _imports(path):
            target = module.split(".")
            if target[:2] == ["raf", "products"] and len(target) > 2 and target[2] not in allowed:
                violations.append(
                    f"{path.relative_to(SRC.parent)}:{line} imports {module} "
                    f"(add '{target[2]}' to depends_on of {product}, or move shared code to core)"
                )
    assert not violations, "undeclared product dependencies:\n" + "\n".join(violations)


def test_every_product_package_has_a_valid_manifest() -> None:
    from raf.products.catalog import BUILTIN_PRODUCTS

    packages = sorted(p.name for p in (SRC / "products").iterdir() if (p / "__init__.py").is_file())
    assert packages == sorted(BUILTIN_PRODUCTS)
    for name in packages:
        manifest = importlib.import_module(f"raf.products.{name}.manifest").MANIFEST
        assert manifest.name == name and set(manifest.depends_on) <= set(packages)
        assert name not in manifest.depends_on
