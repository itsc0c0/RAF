"""Plugins cannot run unverified code or break the platform, through the CLI and the API."""

from __future__ import annotations

import importlib.util
import marshal
import sys
import uuid
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.apps.cli.helptopics import HELP_TOPICS
from raf.core.plugins.registry import ProductRegistry
from raf.core.workspace.manager import RafHome
from raf.products.catalog import builtin_manifests

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

TYPER_APP = """\
import typer

app = typer.Typer(add_completion=False)


@app.command("{command}", help="Test command {command}.")
def main() -> None:
    print("{output}")
"""

CLICK_COMMAND = """\
import click


@click.command(help="Plain Click command.")
def cmd() -> None:
    click.echo("click ran")
"""

API_ROUTER = """\
from fastapi import APIRouter

inner = APIRouter()


@inner.get("/deep")
def deep() -> dict[str, bool]:
    return {"deep": True}


router = APIRouter()
router.include_router(inner, prefix="/inner")


@router.get("/hello")
def hello() -> dict[str, str]:
    return {"hello": "world"}


@router.post("")
def post_root() -> dict[str, bool]:
    return {"plugin": True}
"""


@pytest.fixture(autouse=True)
def _forget_plugin_modules(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(sys, "dont_write_bytecode", False)  # Python would write bytecode if R$F let it
    path, modules = list(sys.path), set(sys.modules)
    yield
    sys.path[:] = path
    for name in set(sys.modules) - modules:
        if name.startswith("rafplug_"):
            del sys.modules[name]


def make_plugin(base: Path, name: str, manifest: str, modules: dict[str, str]) -> tuple[Path, str]:
    """A plugin source directory with a uniquely named package (``PKG`` in ``manifest``)."""
    package = f"rafplug_{uuid.uuid4().hex[:10]}"
    root = base / f"src-{name}"
    (root / package).mkdir(parents=True)
    header = f"name: {name}\nversion: '1'\ndescription: {name} test plugin\n"
    (root / "raf-plugin.yaml").write_text(header + manifest.replace("PKG", package))
    (root / package / "__init__.py").write_text("")
    for module, source in modules.items():
        (root / package / f"{module}.py").write_text(source)
    return root, package


def install(cli: Any, root: Path, name: str) -> None:
    assert cli("install", str(root)).exit_code == 0
    assert cli("--yes", "plugin", "trust", name).exit_code == 0


def client(raf_home: Path) -> TestClient:
    return TestClient(create_app(env={"RAF_HOME": str(raf_home)}, serve_ui=False), base_url="http://127.0.0.1")


# --------------------------------------------------------------------------- CLI


def test_planted_bytecode_never_runs(cli: Any, raf_home: Path, tmp_path: Path) -> None:
    root, pkg = make_plugin(
        tmp_path,
        "pyc-cli",
        "cli: PKG.cli:app\ncommands: [pyccli]\n",
        {"cli": TYPER_APP.format(command="pyccli", output="from source")},
    )
    install(cli, root, "pyc-cli")
    module = raf_home / "plugins" / "pyc-cli" / pkg / "cli.py"
    planted = TYPER_APP.format(command="pyccli", output="from planted bytecode")
    st = module.stat()  # a timestamp header that matches the source: stock Python would load it
    header = (0).to_bytes(4, "little") + int(st.st_mtime).to_bytes(4, "little") + st.st_size.to_bytes(4, "little")
    cache = Path(importlib.util.cache_from_source(str(module)))
    cache.parent.mkdir()
    cache.write_bytes(importlib.util.MAGIC_NUMBER + header + marshal.dumps(compile(planted, str(module), "exec")))
    assert cli("plugin", "verify", "pyc-cli").exit_code == 0
    result = cli("pyccli")
    assert result.exit_code == 0 and result.stdout.strip() == "from source"
    assert sorted(p.name for p in (raf_home / "plugins" / "pyc-cli").rglob("*.pyc")) == [cache.name]


def test_help_survives_modified_and_broken_plugins(cli: Any, raf_home: Path, tmp_path: Path) -> None:
    modified, pkg = make_plugin(
        tmp_path,
        "mod-test",
        "cli: PKG.cli:app\ncommands: [modtest]\n",
        {"cli": TYPER_APP.format(command="modtest", output="x")},
    )
    install(cli, modified, "mod-test")
    broken, _ = make_plugin(
        tmp_path, "broken-test", "cli: PKG.cli:app\ncommands: [brokentest]\n", {"cli": "def broken(:\n"}
    )
    install(cli, broken, "broken-test")
    with (raf_home / "plugins" / "mod-test" / pkg / "cli.py").open("a") as handle:
        handle.write("# changed after trust\n")

    for args in (["--help"], ["help"]):
        result = cli(*args)
        assert result.exit_code == 0, result.stderr
        assert "[unavailable: plugin 'mod-test' was modified after it was trusted]" in result.stdout
        assert "[unavailable: failed to load" in result.stdout and "SyntaxError" in result.stdout
        assert "graph" in result.stdout  # everything else is still there
    products = {p["name"]: p for p in cli("--json", "products").json()["items"]}
    assert products["mod-test"]["status"] == "UNAVAILABLE"
    assert products["mod-test"]["unavailable_reason"] == "plugin 'mod-test' was modified after it was trusted"
    plugins = {p["name"]: p for p in cli("--json", "plugin", "list").json()["items"]}
    assert plugins["mod-test"]["status"] == "UNAVAILABLE"

    result = cli("--json", "modtest")
    error = result.json()["error"]
    assert result.exit_code == 5 and error["code"] == "raf.security_violation"
    assert error["suggestions"] == ["raf plugin verify mod-test"]
    result = cli("--json", "brokentest")
    error = result.json()["error"]
    assert result.exit_code == 4 and error["code"] == "raf.product_disabled" and "SyntaxError" in error["reason"]
    assert cli("--yes", "uninstall", "broken-test").exit_code == 0


def test_untrusted_plugin_suggests_trust(cli: Any, raf_home: Path, tmp_path: Path) -> None:
    root, _ = make_plugin(
        tmp_path,
        "new-test",
        "cli: PKG.cli:app\ncommands: [newtest]\n",
        {"cli": TYPER_APP.format(command="newtest", output="x")},
    )
    assert cli("install", str(root)).exit_code == 0
    result = cli("--json", "newtest")
    assert result.exit_code == 4
    assert result.json()["error"]["suggestions"] == ["raf plugin trust new-test"]
    assert cli("product", "enable", "new-test").exit_code == 4  # refused: trusting is the step that enables


def test_plugin_verify_exit_codes(cli: Any, raf_home: Path, tmp_path: Path) -> None:
    root, pkg = make_plugin(tmp_path, "verify-test", "", {"mod": "VALUE = 1\n"})
    assert cli("plugin", "verify", "verify-test").exit_code == 3  # not installed
    assert cli("install", str(root)).exit_code == 0
    assert cli("plugin", "verify", "verify-test").exit_code == 4  # untrusted: no trusted hash yet
    assert cli("--yes", "plugin", "trust", "verify-test").exit_code == 0
    assert cli("plugin", "verify", "verify-test").exit_code == 0
    (raf_home / "plugins" / "verify-test" / pkg / "mod.py").write_text("VALUE = 2\n")
    result = cli("--json", "plugin", "verify", "verify-test")
    assert result.exit_code == 5 and result.json()["unchanged"] is False  # integrity failure


def test_help_topics_are_printed_literally(cli: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(HELP_TOPICS, "brackets-test", "commands: [example]\n[bold]not markup[/bold]\n")
    result = cli("help", "brackets-test")
    assert result.exit_code == 0
    assert "commands: [example]" in result.stdout and "[bold]not markup[/bold]" in result.stdout


def test_plugin_commands_never_replace_builtin_ones(cli: Any, raf_home: Path, tmp_path: Path) -> None:
    root, _ = make_plugin(tmp_path, "multi", "cli: PKG.cli:cmd\ncommands: [multi-a, multi-b]\n", {"cli": CLICK_COMMAND})
    install(cli, root, "multi")
    help_text = cli("--help").stdout
    assert "multi-a" in help_text and "multi-b" in help_text  # a Click command listed under two names
    assert cli("multi-a").stdout.strip() == "click ran" and cli("multi-b").stdout.strip() == "click ran"

    clash, _ = make_plugin(tmp_path, "clash", "cli: PKG.cli:cmd\ncommands: [status]\n", {"cli": CLICK_COMMAND})
    result = cli("install", str(clash))
    assert result.exit_code == 4 and "which R$F itself already provides" in result.stderr

    # a manifest changed (and trusted) after installation still cannot take over a built-in command
    manifest = raf_home / "plugins" / "multi" / "raf-plugin.yaml"
    manifest.write_text(manifest.read_text().replace("[multi-a, multi-b]", "[timeline, status, multi-b]"))
    assert cli("--yes", "plugin", "trust", "multi").exit_code == 0
    result = cli("--help")
    assert result.exit_code == 0
    assert "plugin multi: command 'timeline' is ignored, product 'timeline' already provides it" in result.stderr
    assert "plugin multi: command 'status' is ignored, R$F itself already provides it" in result.stderr
    timeline = cli("--json", "timeline")
    assert timeline.exit_code == 0 and timeline.json()["schema"] == "raf.timeline/v1"


def test_plugin_parsers_cannot_replace_builtin_ones_or_break_imports(cli: Any, raf_home: Path, tmp_path: Path) -> None:
    parser = (
        "from raf.core.ingestion.parsers.structured import CsvParser\n\n\n"
        "class Shadow(CsvParser):\n    name = 'csv'\n    version = '6.6'\n"
    )
    root, pkg = make_plugin(tmp_path, "parsers", "parsers: [PKG.parser:Shadow]\n", {"parser": parser})
    install(cli, root, "parsers")
    data = tmp_path / "data.csv"
    data.write_text("host,owner\nWS-01,it\n")
    result = cli("--json", "import", str(data))
    assert result.exit_code == 0 and result.json()["parser"] == "csv/1.0"
    assert "parser 'csv' of plugin parsers ignored" in result.stderr

    (raf_home / "plugins" / "parsers" / pkg / "parser.py").write_text("raise RuntimeError('boom at import')\n")
    assert cli("--yes", "plugin", "trust", "parsers").exit_code == 0
    del sys.modules[f"{pkg}.parser"]  # the next `raf` is a new process
    result = cli("--json", "import", str(data))
    assert result.exit_code == 0 and result.json()["parser"] == "csv/1.0"
    assert "RuntimeError: boom at import" in result.stderr


# --------------------------------------------------------------------------- API


def test_api_starts_with_a_broken_plugin(cli: Any, raf_home: Path, tmp_path: Path) -> None:
    root, _ = make_plugin(tmp_path, "broken-api", "api: PKG.api:router\n", {"api": "raise RuntimeError('boom')\n"})
    install(cli, root, "broken-api")
    with client(raf_home) as api:
        assert api.get("/api/v1/health").status_code == 200
        info = api.get("/api/v1/products/broken-api").json()
        assert info["status"] == "UNAVAILABLE" and "RuntimeError: boom" in info["unavailable_reason"]
        assert api.get("/api/v1/broken-api/hello").status_code == 404
        assert api.get("/api/v1/timeline").status_code == 200


def test_unavailable_products_answer_503_while_the_server_runs(cli: Any, raf_home: Path, tmp_path: Path) -> None:
    root, _ = make_plugin(tmp_path, "dep-api", "api: PKG.api:router\ndepends_on: [graph]\n", {"api": API_ROUTER})
    install(cli, root, "dep-api")
    assert cli("product", "disable", "lens").exit_code == 0
    with client(raf_home) as api:
        assert api.get("/api/v1/dep-api/hello").json() == {"hello": "world"}
        assert api.get("/api/v1/dep-api/inner/deep").json() == {"deep": True}
        assert api.post("/api/v1/products/timeline/disable").json()["status"] == "DISABLED"
        response = api.get("/api/v1/timeline")
        assert response.status_code == 503 and response.json()["error"]["code"] == "raf.product_disabled"
        assert api.post("/api/v1/products/timeline/enable").status_code == 200
        assert api.get("/api/v1/timeline").status_code == 200

        other_process = ProductRegistry(RafHome(raf_home), builtin_manifests())  # raf product disable graph
        other_process.disable("graph")
        page = api.get("/api/v1/tui/screen/graph")  # R$F OS pages check their product per request too
        assert page.status_code == 503 and page.json()["error"]["code"] == "raf.product_disabled"
        assert api.get("/api/v1/graph/stats").status_code == 503
        for path in ("/api/v1/dep-api/hello", "/api/v1/dep-api/inner/deep"):
            blocked = api.get(path)
            assert blocked.status_code == 503
            assert blocked.json()["error"]["reason"] == "requires 'graph', which is unavailable"
            assert blocked.json()["error"]["suggestions"] == ["raf product enable graph"]
        other_process.enable("graph")
        assert api.get("/api/v1/dep-api/hello").status_code == 200

        query = {"q": "type:auth.login"}
        assert api.get("/api/v1/lens/query", params=query).status_code == 503  # disabled when the server started
        assert api.post("/api/v1/products/lens/enable").status_code == 200
        assert api.get("/api/v1/lens/query", params=query).status_code == 200


def test_plugin_routes_cannot_use_paths_of_builtin_routes(cli: Any, raf_home: Path, tmp_path: Path) -> None:
    root, _ = make_plugin(tmp_path, "objects", "api: PKG.api:router\n", {"api": API_ROUTER})
    install(cli, root, "objects")
    raw = "from starlette.routing import Route\nfrom fastapi import APIRouter\n\nrouter = APIRouter()\n"
    raw += "router.routes.append(Route('/raw', lambda request: None))\n"
    unguarded, _ = make_plugin(tmp_path, "raw-api", "api: PKG.api:router\n", {"api": raw})
    install(cli, unguarded, "raw-api")
    with client(raf_home) as api:
        assert api.post("/api/v1/objects").status_code == 405  # the plugin's POST was not mounted there
        assert api.get("/api/v1/objects/hello").status_code == 404
        info = api.get("/api/v1/products/raw-api").json()
        assert info["status"] == "UNAVAILABLE" and "unsupported route '/raw'" in info["unavailable_reason"]
        assert api.get("/api/v1/raw-api/raw").status_code == 404
