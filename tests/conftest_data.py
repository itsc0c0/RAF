"""Session-cached Raven demo workspace, copied per test for speed and isolation."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from raf.core.context.app import RafContext, open_context

_TEMPLATE: dict[str, Path] = {}


def _build_template(base: Path) -> Path:
    home = base / "template-home"
    from raf.analysis.demo import load_demo
    from raf.core.plugins.registry import ProductRegistry
    from raf.core.workspace.manager import RafHome
    from raf.products.catalog import builtin_manifests

    env = {"RAF_HOME": str(home)}
    registry = ProductRegistry(RafHome.from_env(env), builtin_manifests())
    ctx = open_context(env=env, registry=registry)
    try:
        load_demo(ctx)
    finally:
        ctx.close()
    return home


@pytest.fixture(scope="session")
def raven_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if "home" not in _TEMPLATE:
        _TEMPLATE["home"] = _build_template(tmp_path_factory.mktemp("raven"))
    return _TEMPLATE["home"]


@pytest.fixture
def raven_home(raven_template: Path, raf_home: Path) -> Path:
    if raf_home.exists():
        shutil.rmtree(raf_home)
    shutil.copytree(raven_template, raf_home)
    return raf_home


@pytest.fixture
def raven(raven_home: Path) -> Iterator[RafContext]:
    from raf.core.plugins.registry import ProductRegistry
    from raf.core.workspace.manager import RafHome
    from raf.products.catalog import builtin_manifests

    env = {"RAF_HOME": str(raven_home)}
    ctx = open_context(env=env, registry=ProductRegistry(RafHome.from_env(env), builtin_manifests()))
    yield ctx
    ctx.close()
