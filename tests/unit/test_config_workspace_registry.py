from __future__ import annotations

from pathlib import Path

import pytest

from raf.core.config.loader import load_settings, read_toml, set_value
from raf.core.errors import ConfigError, ConflictError, InvalidInputError, NotFoundError, SecurityViolation
from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.core.plugins.registry import ProductRegistry
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


def _manifest(name: str, deps: list[str] | None = None) -> ProductManifest:
    return ProductManifest(
        name=name,
        display_name=name.title(),
        version="0.1.0",
        status=ProductStatus.BETA,
        description=name,
        depends_on=deps or [],
    )


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
