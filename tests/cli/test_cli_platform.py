from __future__ import annotations

from typing import Any


def test_help_and_version(cli: Any) -> None:
    result = cli("--help")
    assert result.exit_code == 0
    assert "Every security capability" in result.stdout
    version = cli("version", "--json")
    assert version.exit_code == 0
    assert version.json()["schema"] == "raf.version/v1"


def test_status_empty_state(cli: Any) -> None:
    result = cli("status")
    assert result.exit_code == 0
    assert "No workspace data yet" in result.stdout
    assert "raf demo load" in result.stdout
    data = cli("status", "--json").json()
    assert data["workspace"] == "default" and data["core"] == "ONLINE"


def test_global_flags_anywhere(cli: Any) -> None:
    assert cli("version", "--json").json()["raf"]
    assert cli("--json", "version").json()["raf"]


def test_workspace_lifecycle(cli: Any) -> None:
    assert cli("workspace", "create", "demo").exit_code == 0
    assert cli("workspace", "use", "demo").exit_code == 0
    listing = cli("workspace", "list", "--json").json()
    assert [w["name"] for w in listing["items"] if w["current"]] == ["demo"]
    refused = cli("workspace", "delete", "demo")
    assert refused.exit_code == 4  # non-interactive without --yes
    assert cli("workspace", "delete", "demo", "--yes").exit_code == 0


def test_errors_are_readable_and_structured(cli: Any) -> None:
    result = cli("show", "nobody")
    assert result.exit_code == 3
    assert "Traceback" not in result.stderr
    assert "No object named 'nobody'" in result.stderr
    as_json = cli("show", "nobody", "--json")
    assert as_json.json()["error"]["code"] == "raf.not_found"
    usage = cli("show")
    assert usage.exit_code == 2


def test_config_commands(cli: Any) -> None:
    assert cli("config", "set", "graph.default_depth", "3").exit_code == 0
    value = cli("config", "get", "graph.default_depth", "--json").json()
    assert value["value"] == 3 and value["origin"] == "global"
    secret = cli("config", "set", "oracle.api_key", "sk-xyz")
    assert secret.exit_code == 4 and "RAF_ORACLE_API_KEY" in secret.stderr


def test_help_topics(cli: Any) -> None:
    assert "R$F SECURITY OBJECT MODEL" in cli("help", "objects").stdout
    assert cli("help", "workspace").exit_code == 0
    assert cli("help", "no-such-thing").exit_code == 3


def test_audit_records_and_verifies(cli: Any) -> None:
    cli("workspace", "create", "x")
    cli("config", "set", "graph.default_depth", "2", "--workspace", "x")
    entries = cli("audit", "--json", "--workspace", "x").json()["items"]
    assert {e["operation"] for e in entries} >= {"workspace.create", "config.set"}
    assert cli("audit", "verify", "--workspace", "x").exit_code == 0
