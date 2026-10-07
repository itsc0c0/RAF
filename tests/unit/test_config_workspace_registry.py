from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import marshal
import os
import re
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from raf.core.config.loader import load_settings, read_toml, set_value
from raf.core.errors import (
    ConfigError,
    ConflictError,
    InvalidInputError,
    NotFoundError,
    ProductDisabledError,
    RafError,
    SecurityViolation,
)
from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.core.plugins.registry import ProductRegistry, directory_hash
from raf.core.workspace.manager import RafHome, WorkspaceManager


def test_config_precedence(tmp_path: Path) -> None:
    global_cfg, ws_cfg = tmp_path / "g.toml", tmp_path / "w.toml"
    set_value(global_cfg, "graph.default_depth", "3")
    set_value(global_cfg, "blast.max_depth", "4")
    set_value(ws_cfg, "blast.max_depth", "5")
    settings = load_settings(global_cfg, ws_cfg, env={"RAF_GRAPH_MAX_NODES": "99"}, overrides={"iam.dormant_days": 7})
    assert settings.get("graph.default_depth") == 3 and settings.origin("graph.default_depth") == "global"
    assert settings.get("blast.max_depth") == 5 and settings.origin("blast.max_depth") == "workspace"
    assert settings.get("graph.max_nodes") == 99 and settings.origin("graph.max_nodes") == "env"
    assert settings.get("iam.dormant_days") == 7 and settings.origin("iam.dormant_days") == "override"
    assert settings.get("vault.max_file_kb") == 2048 and settings.origin("vault.max_file_kb") == "default"


def test_config_rejects_secrets_and_bad_values(tmp_path: Path) -> None:
    cfg = tmp_path / "c.toml"
    with pytest.raises(ConfigError):
        set_value(cfg, "oracle.api_key", "sk-123")
    with pytest.raises(ConfigError):
        set_value(cfg, "oracle.provider", "skynet")
    with pytest.raises(ConfigError):
        set_value(cfg, "nope.key", "1")
    assert read_toml(cfg) == {}
    # A secret planted in a file is ignored, env wins.
    cfg.write_text('[oracle]\napi_key = "planted"\n')
    settings = load_settings(cfg, env={"RAF_ORACLE_API_KEY": "from-env"})
    assert settings.secret("oracle.api_key") == "from-env"
    assert load_settings(cfg, env={}).secret("oracle.api_key") is None


def test_workspaces(tmp_path: Path) -> None:
    home = RafHome(tmp_path / "home")
    manager = WorkspaceManager(home, env={})
    manager.create("lab")
    with pytest.raises(ConflictError):
        manager.create("lab")
    with pytest.raises(InvalidInputError):
        manager.create("../escape")
    manager.use("lab")
    assert manager.current_name() == "lab"
    assert [i.name for i in manager.list()] == ["lab"]
    summary = manager.delete("lab")
    assert summary["name"] == "lab" and not (home.workspaces_dir / "lab").exists()
    assert manager.current_name() == "default"
    with pytest.raises(NotFoundError):
        manager.get("lab")
    assert WorkspaceManager(home, env={"RAF_WORKSPACE": "other"}).current_name() == "other"


def _manifest(name: str, deps: list[str] | None = None, cli: str | None = None) -> ProductManifest:
    return ProductManifest(
        name=name,
        display_name=name.title(),
        version="0.1.0",
        status=ProductStatus.BETA,
        description=name,
        depends_on=deps or [],
        cli=cli,
        commands=[name] if cli else [],
    )


@pytest.fixture
def isolated_imports(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Plugin packages imported by a test are forgotten afterwards (each test uses unique package names)."""
    monkeypatch.setattr(sys, "dont_write_bytecode", False)  # Python would write bytecode if R$F let it
    path, modules = list(sys.path), set(sys.modules)
    yield
    sys.path[:] = path
    for name in set(sys.modules) - modules:
        if name.startswith("rafplug_"):
            del sys.modules[name]


def _plugin(base: Path, name: str, modules: dict[str, str], manifest: str = "") -> tuple[Path, str]:
    """A plugin source directory with a uniquely named package (``PKG`` in ``manifest``); returns (dir, package)."""
    package = f"rafplug_{uuid.uuid4().hex[:10]}"
    root = base / f"{name}-src"
    (root / package).mkdir(parents=True)
    header = f"name: {name}\nversion: '1'\ndescription: test plugin\n"
    (root / "raf-plugin.yaml").write_text(header + manifest.replace("PKG", package))
    (root / package / "__init__.py").write_text("")
    for module, source in modules.items():
        (root / package / f"{module}.py").write_text(source)
    return root, package


def _plant_pyc(source: Path, code: str, *, unchecked_hash: bool = False) -> Path:
    """Write bytecode for ``code`` where Python caches ``source``, with a header Python accepts."""
    if unchecked_hash:  # PEP 552: never checked against the source
        header = (0b01).to_bytes(4, "little") + importlib.util.source_hash(source.read_bytes())
    else:  # timestamp-based: matches the source's mtime and size
        st = source.stat()
        header = (0).to_bytes(4, "little") + int(st.st_mtime).to_bytes(4, "little") + st.st_size.to_bytes(4, "little")
    cache = Path(importlib.util.cache_from_source(str(source)))
    cache.parent.mkdir(exist_ok=True)
    cache.write_bytes(importlib.util.MAGIC_NUMBER + header + marshal.dumps(compile(code, str(source), "exec")))
    return cache


def test_registry_availability_and_cycles(tmp_path: Path) -> None:
    home = RafHome(tmp_path / "home")
    registry = ProductRegistry(home, [_manifest("graph"), _manifest("blast", ["graph"])])
    assert registry.is_available("blast")
    registry.disable("graph")
    assert not registry.is_available("blast")
    assert "graph" in (registry.info("blast").unavailable_reason or "")
    registry.enable("graph")
    assert ProductRegistry(home, [_manifest("graph"), _manifest("blast", ["graph"])]).is_available("blast")
    with pytest.raises(InvalidInputError):
        ProductRegistry(home, [_manifest("aa", ["bb"]), _manifest("bb", ["aa"])])


def test_plugin_install_trust_and_tamper_detection(tmp_path: Path) -> None:
    home = RafHome(tmp_path / "home")
    plugin = tmp_path / "hello-plugin"
    (plugin / "hello_plugin").mkdir(parents=True)
    (plugin / "raf-plugin.yaml").write_text(
        "name: hello\nversion: 1.0.0\napi_version: 1\ndescription: Hello\ncommands: [hello]\n"
        "cli: hello_plugin.cli:app\npermissions: [read.objects]\n"
    )
    (plugin / "hello_plugin" / "__init__.py").write_text("")
    (plugin / "hello_plugin" / "cli.py").write_text("VALUE = 1\napp = None\n")
    registry = ProductRegistry(home, [_manifest("graph")])
    info = registry.install_plugin(plugin)
    assert not info.enabled and not info.trusted
    with pytest.raises(SecurityViolation):
        registry.load_plugin_attr("hello", "hello_plugin.cli:VALUE")
    registry.trust_plugin("hello")
    assert registry.info("hello").available
    assert registry.load_plugin_attr("hello", "hello_plugin.cli:VALUE") == 1
    (home.plugins_dir / "hello" / "hello_plugin" / "cli.py").write_text("VALUE = 2\n")
    assert not registry.verify_plugin("hello")
    with pytest.raises(SecurityViolation):
        registry.load_plugin_attr("hello", "hello_plugin.cli:VALUE")
    with pytest.raises(ConflictError):
        registry.uninstall_plugin("graph")
    registry.uninstall_plugin("hello")
    assert not (home.plugins_dir / "hello").exists()


def test_manifest_validation(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "raf-plugin.yaml").write_text("name: x\nversion: 1\napi_version: 99\ndescription: d\n")
    registry = ProductRegistry(RafHome(tmp_path / "h"), [])
    with pytest.raises(InvalidInputError):
        registry.install_plugin(bad)
    (bad / "raf-plugin.yaml").write_text("!!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(InvalidInputError):
        registry.install_plugin(bad)


def test_planted_bytecode_never_runs(tmp_path: Path, isolated_imports: None) -> None:
    home = RafHome(tmp_path / "home")
    marker = tmp_path / "pwned"
    src, pkg = _plugin(tmp_path, "pyc-test", {"mod": "VALUE = 'source'\n", "other": "VALUE = 'source'\n"})
    registry = ProductRegistry(home, [])
    registry.install_plugin(src)
    registry.trust_plugin("pyc-test")
    installed = home.plugins_dir / "pyc-test" / pkg
    payload = f"open({str(marker)!r}, 'w').close()\nVALUE = 'bytecode'\n"
    planted = [
        _plant_pyc(installed / "mod.py", payload),
        _plant_pyc(installed / "other.py", payload, unchecked_hash=True),
    ]
    for source in (installed / "mod.py", installed / "other.py"):  # stock Python would run the planted bytecode
        code = importlib.machinery.SourceFileLoader("probe", str(source)).get_code("probe")
        assert code is not None and "bytecode" in code.co_consts
    assert registry.verify_plugin("pyc-test")  # __pycache__ is not hashed: R$F never reads it
    assert registry.load_plugin_attr("pyc-test", f"{pkg}.mod:VALUE") == "source"
    assert registry.load_plugin_attr("pyc-test", f"{pkg}.other:VALUE") == "source"
    assert not marker.exists()
    # and no bytecode is written into the plugin directory either
    assert sorted((installed / "__pycache__").iterdir()) == sorted(planted)
    assert [p for p in (home.plugins_dir / "pyc-test").rglob("*.pyc") if p not in planted] == []


def _legacy_hash(root: Path) -> str:
    """The trust hash as recorded by earlier versions (existing trusted plugins must stay trusted)."""
    hasher = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        hasher.update(str(path.relative_to(root).as_posix()).encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


def test_trust_hash_is_stable_and_refuses_links(tmp_path: Path, isolated_imports: None) -> None:
    tree = tmp_path / "tree"
    for rel in ("a.py", "a-b/c.txt", "a/b.py", "a/b/c.py", ".hidden", "__pycache__/x.pyc", "pkg/__pycache__/y.pyc"):
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_text(rel)
    assert directory_hash(tree) == _legacy_hash(tree)

    home = RafHome(tmp_path / "home")
    src, _pkg = _plugin(tmp_path, "link-test", {"mod": "VALUE = 1\n"})
    registry = ProductRegistry(home, [])
    registry.install_plugin(src)
    registry.trust_plugin("link-test")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "__init__.py").write_text("raise SystemExit('not hashed')\n")
    # a directory symlink added after trust: earlier versions neither hashed nor noticed it
    (home.plugins_dir / "link-test" / "shadowing").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(SecurityViolation, match="symlink"):
        registry.verify_plugin("link-test")
    info = registry.info("link-test")
    assert not info.available and "symlink: shadowing" in (info.unavailable_reason or "")


def test_unavailable_plugins_explain_why_and_what_to_run(tmp_path: Path, isolated_imports: None) -> None:
    home = RafHome(tmp_path / "home")
    src, pkg = _plugin(tmp_path, "notes-test", {"cli": "VALUE = 1\n"}, "depends_on: [graph]\n")
    registry = ProductRegistry(home, [_manifest("graph")])
    registry.install_plugin(src)

    def error(name: str) -> RafError:
        with pytest.raises(RafError) as caught:
            registry.require(name)
        return caught.value

    untrusted = error("notes-test")
    assert isinstance(untrusted, ProductDisabledError) and untrusted.exit_code == 4 and untrusted.http_status == 503
    assert untrusted.reason == "plugin 'notes-test' is not trusted yet"
    assert untrusted.suggestions == ["raf plugin trust notes-test"]
    registry.trust_plugin("notes-test")
    registry.disable("graph")
    blocked = error("notes-test")
    assert blocked.reason == "requires 'graph', which is unavailable"
    assert blocked.suggestions == ["raf product enable graph"]
    registry.enable("graph")
    registry.disable("notes-test")
    assert error("notes-test").suggestions == ["raf product enable notes-test"]
    registry.trust_plugin("notes-test")  # "Trusted and enabled": trusting enables a disabled plugin
    assert registry.is_available("notes-test")

    module = home.plugins_dir / "notes-test" / pkg / "cli.py"
    module.write_text("VALUE = 2\n")
    modified = error("notes-test")
    assert isinstance(modified, SecurityViolation) and modified.exit_code == 5 and modified.http_status == 503
    assert modified.reason == "plugin 'notes-test' was modified after it was trusted"
    assert modified.suggestions == ["raf plugin verify notes-test"]
    assert registry.info("notes-test").display_status == "UNAVAILABLE"
    with pytest.raises(SecurityViolation):
        registry.load_attr("notes-test", f"{pkg}.cli:VALUE", lambda value: value)
    module.write_text("VALUE = 1\n")  # the hash covers content: restoring the file restores trust
    assert registry.is_available("notes-test")
    assert registry.load_attr("notes-test", f"{pkg}.cli:VALUE", lambda value: value) == 1


@pytest.mark.parametrize(
    "source",
    ["def broken(:\n", "raise RuntimeError('boom')\n", "raise SystemExit(3)\n", "import rafplug_not_installed\n"],
)
def test_plugin_code_that_fails_to_load_is_contained(tmp_path: Path, isolated_imports: None, source: str) -> None:
    home = RafHome(tmp_path / "home")
    src, pkg = _plugin(tmp_path, "broken-test", {"cli": source, "api": "VALUE = 1\n"})
    registry = ProductRegistry(home, [_manifest("graph")])
    registry.install_plugin(src)
    registry.trust_plugin("broken-test")
    with pytest.raises(ProductDisabledError) as caught:
        registry.load_attr("broken-test", f"{pkg}.cli:VALUE", lambda value: value)
    info = registry.info("broken-test")
    assert not info.available and info.unavailable_reason == caught.value.reason
    assert (info.unavailable_reason or "").startswith(f"failed to load {pkg}.cli:VALUE: ")
    assert caught.value.suggestions == ["raf product disable broken-test"]
    with pytest.raises(ProductDisabledError):  # its other contributions are not loaded any more
        registry.load_attr("broken-test", f"{pkg}.api:VALUE", lambda value: value)
    assert registry.is_available("graph")

    registry.trust_plugin("broken-test")  # trusting a fixed version clears the failure

    def expect_text(value: object) -> str:
        if not isinstance(value, str):
            raise TypeError(f"expected text, got {type(value).__name__}")
        return value

    with pytest.raises(ProductDisabledError):  # an object of the wrong kind counts as a failure too
        registry.load_attr("broken-test", f"{pkg}.api:VALUE", expect_text)
    assert "TypeError: expected text, got int" in (registry.info("broken-test").unavailable_reason or "")


def test_install_validates_dependencies_before_writing(tmp_path: Path, isolated_imports: None) -> None:
    home = RafHome(tmp_path / "home")
    registry = ProductRegistry(home, [_manifest("graph")])
    looping, _ = _plugin(tmp_path / "a", "self-dep", {}, "depends_on: [self-dep]\n")
    with pytest.raises(InvalidInputError, match="cycle: self-dep -> self-dep"):
        registry.install_plugin(looping)
    unknown, _ = _plugin(tmp_path / "b", "needs-x", {}, "depends_on: [graph, nosuch]\n")
    with pytest.raises(InvalidInputError, match="depends on 'nosuch', which is not installed"):
        registry.install_plugin(unknown)
    assert not (home.plugins_dir / "self-dep").exists() and not (home.plugins_dir / "needs-x").exists()
    assert not home.registry_path.exists()

    base, _ = _plugin(tmp_path / "c", "base", {})
    registry.install_plugin(base)
    top, _ = _plugin(tmp_path / "d", "top", {}, "depends_on: [base]\n")
    registry.install_plugin(top)
    registry.uninstall_plugin("base")  # "top" now depends on a plugin that is not installed ...
    assert not registry.is_available("top")
    closing, _ = _plugin(tmp_path / "e", "base", {}, "depends_on: [top]\n")
    with pytest.raises(InvalidInputError, match="cycle: base -> top -> base"):
        registry.install_plugin(closing)  # ... and a new "base" cannot close a cycle through it


def test_registry_survives_bad_entries(tmp_path: Path, isolated_imports: None) -> None:
    home = RafHome(tmp_path / "home")
    registry = ProductRegistry(home, [_manifest("graph")])
    src, _ = _plugin(tmp_path, "loop", {})
    registry.install_plugin(src)
    registry.trust_plugin("loop")
    # written by an earlier version (which saved before checking) or edited by hand
    manifest = home.plugins_dir / "loop" / "raf-plugin.yaml"
    manifest.write_text(manifest.read_text() + "depends_on: [loop]\n")
    state = json.loads(home.registry_path.read_text())
    state["plugins"]["../outside"] = {"trusted": True, "enabled": True}
    state["plugins"]["junk"] = "not an object"
    home.registry_path.write_text(json.dumps(state))

    reloaded = ProductRegistry(home, [_manifest("graph")])
    assert set(reloaded.manifests()) == {"graph", "loop"}
    info = reloaded.info("loop")
    assert not info.available and info.unavailable_reason == "dependency cycle: loop -> loop"
    assert reloaded.is_available("graph")
    reloaded.uninstall_plugin("loop")
    reloaded.uninstall_plugin("../outside")  # only the registry entry goes: nothing outside plugins/ is touched
    assert not (home.plugins_dir / "loop").exists() and home.root.exists()
    assert json.loads(home.registry_path.read_text())["plugins"] == {}
    home.registry_path.write_text("[1, 2]")  # not a JSON object: ignored
    assert set(ProductRegistry(home, [_manifest("graph")]).manifests()) == {"graph"}


def test_install_refuses_command_collisions(tmp_path: Path, isolated_imports: None) -> None:
    home = RafHome(tmp_path / "home")
    registry = ProductRegistry(home, [_manifest("timeline", cli="raf.products.timeline.cli:app")])
    reserved = {"status", "show"}
    cases = [
        ("shadow", "commands: [shadow, timeline]\n", "'timeline', which product 'timeline' already provides"),
        ("status", "", "'status', which R$F itself already provides"),  # the command defaults to the name
    ]
    for name, extra, message in cases:
        src, _ = _plugin(tmp_path / name, name, {"cli": "app = None\n"}, "cli: PKG.cli:app\n" + extra)
        with pytest.raises(ConflictError, match=re.escape(message)):
            registry.install_plugin(src, reserved_commands=reserved)
        assert not (home.plugins_dir / name).exists()
    first, _ = _plugin(tmp_path / "f", "first", {"cli": "app = None\n"}, "cli: PKG.cli:app\ncommands: [notes]\n")
    registry.install_plugin(first, reserved_commands=reserved)
    second, _ = _plugin(tmp_path / "s", "second", {"cli": "app = None\n"}, "cli: PKG.cli:app\ncommands: [notes]\n")
    with pytest.raises(ConflictError, match="product 'first'"):
        registry.install_plugin(second, reserved_commands=reserved)
    no_cli, _ = _plugin(tmp_path / "n", "show", {}, "commands: [timeline]\n")  # without a cli, no commands
    registry.install_plugin(no_cli, reserved_commands=reserved)


def test_registry_records_the_absolute_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_imports: None
) -> None:
    src, _ = _plugin(tmp_path, "relative", {})
    monkeypatch.chdir(tmp_path)
    home = RafHome(tmp_path / "home")
    ProductRegistry(home, []).install_plugin(Path(src.name))
    assert json.loads(home.registry_path.read_text())["plugins"]["relative"]["source"] == str(src.resolve())


def test_registry_refresh_sees_other_processes(tmp_path: Path) -> None:
    home = RafHome(tmp_path / "home")
    builtins = [_manifest("graph"), _manifest("blast", ["graph"])]
    server, cli = ProductRegistry(home, builtins), ProductRegistry(home, builtins)
    cli.disable("graph")
    assert server.is_available("blast")  # not re-read yet
    server.refresh()
    assert not server.is_available("blast")
    cli.enable("graph")
    server.refresh()
    assert server.is_available("blast")


def test_special_files_are_refused(tmp_path: Path, isolated_imports: None) -> None:
    home = RafHome(tmp_path / "home")
    registry = ProductRegistry(home, [])
    src, _ = _plugin(tmp_path, "fifo-test", {"mod": "VALUE = 1\n"})
    os.mkfifo(src / "pipe")
    with pytest.raises(SecurityViolation, match="special file"):
        registry.install_plugin(src)
    (src / "pipe").unlink()
    (src / ".git").mkdir()
    os.mkfifo(src / ".git" / "fsmonitor--daemon.ipc")  # .git is never copied: no reason to refuse it
    registry.install_plugin(src)
    registry.trust_plugin("fifo-test")
    assert not (home.plugins_dir / "fifo-test" / ".git").exists()
    os.mkfifo(home.plugins_dir / "fifo-test" / "pipe")  # hashing must not block on it
    info = registry.info("fifo-test")
    assert not info.available and "special file: pipe" in (info.unavailable_reason or "")
