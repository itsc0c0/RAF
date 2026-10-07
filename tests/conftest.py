"""Shared test fixtures. Every test gets an isolated RAF_HOME."""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Iterator
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext, open_context

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"


@pytest.fixture
def raf_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "rafhome"
    monkeypatch.setenv("RAF_HOME", str(home))
    monkeypatch.delenv("RAF_WORKSPACE", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("COLUMNS", "200")
    from raf.apps.cli import registry as cli_registry

    cli_registry.build_registry.cache_clear()
    cli_registry.load_product_command.cache_clear()
    return home


@pytest.fixture
def ctx(raf_home: Path) -> Iterator[RafContext]:
    context = open_context(env={"RAF_HOME": str(raf_home)})
    yield context
    context.close()


@dataclass
class CliResult:
    exit_code: int
    stdout: str
    stderr: str

    def json(self) -> Any:
        return json.loads(self.stdout)


def run_cli(*args: str, stdin: str = "") -> CliResult:
    from raf.apps.cli import registry as cli_registry
    from raf.apps.cli.main import run

    cli_registry.build_registry.cache_clear()
    cli_registry.load_product_command.cache_clear()
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin)
    code = 0
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                run(list(args))
            except SystemExit as exc:
                code = int(exc.code or 0)
    finally:
        sys.stdin = old_stdin
    return CliResult(code, out.getvalue(), err.getvalue())


@pytest.fixture
def cli(raf_home: Path) -> Any:
    return run_cli
