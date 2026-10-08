"""PostgreSQL: the migrations build the declared schema, and a workflow gives the results it gives on SQLite.

Opt-in: set ``RAF_TEST_POSTGRES_URL`` to the URL of a PostgreSQL server whose user may create
databases, e.g. ``postgresql+psycopg://postgres@127.0.0.1:5432/postgres`` (needs the ``postgres``
extra). Every test creates a database of its own and drops it afterwards. CI runs this module
against a ``postgres:16`` service.
"""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import FIXTURES, run_cli

POSTGRES_URL = os.environ.get("RAF_TEST_POSTGRES_URL", "")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="RAF_TEST_POSTGRES_URL is not set")

#: Every command of the workflow prints JSON; global flags come first.
WORKFLOW: list[tuple[str, ...]] = [
    ("status",),
    ("graph", "user", "alice"),
    ("graph", "INC-001"),
    ("blast", "alice"),
    ("blast", "DEV-01"),
    ("timeline", "INC-001", "--limit", "500"),
    ("timeline", "user", "alice", "--filter", "type:auth.* severity<=low"),
    ("timeline", "workspace", "--filter", '"vpn" bob', "--limit", "200"),
    ("timeline", "user", "alice", "--filter", "object:DEV-01"),
    ("timeline", "INC-001", "--filter", "confidence<0.9 outcome:failure", "--group-by", "actor"),
    ("lens", "INC-001"),
    ("lens", "alice", "--filter", "type=auth.*"),
    ("trace", "INC-001"),
    ("trace", "alice"),
    ("findings", "--limit", "500"),
    ("exposure",),
    ("iam", "show", "alice"),
    ("policy", "analyze"),
    ("replay", "INC-001"),
    ("search", "alice"),
    ("oracle", "ask", "Explain the most important security path in INC-001"),
    ("snapshot", "create", "before"),
    ("ghost", "clone", "current", "hardened"),
    ("ghost", "modify", "hardened", "--remove-access", "alice:production", "--isolate", "DEV-01"),
    ("ghost", "compare", "current", "hardened"),
    ("ghost", "simulate", "hardened"),
    ("diff", "ghost-hardened-base", "ghost:hardened"),
    ("analyze", "./fixtures/pcap/raven-inc001.pcap"),
    # a mixed log imported as plain text, then re-read in place by the multilog parser; detections
    ("analyze", "./fixtures/logs/raven-multisource.log", "--format", "text"),
    ("analyze", "./fixtures/logs/raven-multisource.log"),
    ("detect",),
    ("timeline", "workspace", "--filter", "type:db.query", "--limit", "100"),
    ("diff", "before", "current"),
    ("timeline", "workspace", "--filter", "category:network", "--limit", "500"),
    ("snapshot", "list"),
    ("--yes", "snapshot", "delete", "before"),
]

#: Values that depend on when or how fast the command ran, not on the data. A snapshot's state hash
#: covers the evidence objects, whose metadata holds their import time and path in the R$F home:
#: content hashes are compared item by item instead (test_content_hashes_match).
_VOLATILE_KEYS = {"duration_ms", "elapsed_ms", "elapsed", "seconds", "content_hash"}
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


@pytest.fixture
def postgres_url() -> Iterator[str]:
    """A fresh, empty database on the server of ``RAF_TEST_POSTGRES_URL``, dropped afterwards."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = f"raf_test_{secrets.token_hex(6)}"  # generated: never interpolates input
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        yield make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def test_migrations_build_the_declared_schema(postgres_url: str) -> None:
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from raf.core.storage.database import create_db_engine, migrate
    from raf.core.storage.schema import metadata

    engine = create_db_engine(postgres_url)
    try:
        assert migrate(engine)
        with engine.connect() as conn:
            assert compare_metadata(MigrationContext.configure(conn), metadata) == []
        assert not migrate(engine)  # already at the head revision
    finally:
        engine.dispose()


def test_workflow_gives_the_same_results_as_on_sqlite(
    postgres_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(FIXTURES.parent)  # the workflow uses ./fixtures/...
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("RAF_WORKSPACE", raising=False)
    started = datetime.now(UTC)
    results: dict[str, list[Any]] = {}
    for backend, url in (("sqlite", None), ("postgresql", postgres_url)):
        home = tmp_path / backend
        monkeypatch.setenv("RAF_HOME", str(home))
        if url is None:
            monkeypatch.delenv("RAF_STORAGE_URL", raising=False)
        else:
            monkeypatch.setenv("RAF_STORAGE_URL", url)
        _run(("--yes", "demo", "load"))
        results[backend] = [(command, _run(command)) for command in WORKFLOW]
    window = (started, datetime.now(UTC))
    reread = dict(results["postgresql"])[("analyze", "./fixtures/logs/raven-multisource.log")]
    timeline = next(step for step in reread["steps"] if step["name"] == "Timeline")
    assert timeline["stats"]["reparsed"] == timeline["stats"]["in_scope"] > 2000  # re-read in place
    _content_hashes_match(tmp_path / "sqlite", tmp_path / "postgresql", postgres_url)
    for (command, on_sqlite), (_command, on_postgres) in zip(results["sqlite"], results["postgresql"], strict=True):
        a = _normalize(on_sqlite, str(tmp_path / "sqlite"), window)
        b = _normalize(on_postgres, str(tmp_path / "postgresql"), window)
        differences = list(_differences(a, b))
        assert not differences, f"raf {' '.join(command)}: SQLite and PostgreSQL differ:\n" + "\n".join(
            differences[:20]
        )


def _content_hashes_match(sqlite_home: Path, postgres_home: Path, postgres_url: str) -> None:
    """Every object, relationship and finding has the same content hash in both workspaces (the content
    read back from PostgreSQL's JSONB hashes like SQLite's JSON), evidence objects aside (their metadata
    holds when and from where in the R$F home they were imported)."""
    from raf.core.context.app import open_context
    from raf.core.snapshots.service import SnapshotService

    states = []
    homes: list[tuple[Path, str | None]] = [(sqlite_home, None), (postgres_home, postgres_url)]
    for home, url in homes:
        env = {"RAF_HOME": str(home), **({"RAF_STORAGE_URL": url} if url else {})}
        ctx = open_context(env=env)
        try:
            assert ctx.store.engine.dialect.name == ("postgresql" if url else "sqlite")
            states.append(SnapshotService(ctx.store).current_state().hashes)
        finally:
            ctx.close()
    for kind in ("object", "relationship", "finding"):
        a, b = ({i: h for i, h in state[kind].items() if not i.startswith("evidence:")} for state in states)
        assert a.keys() == b.keys(), kind
        differing = sorted(i for i in a if a[i] != b[i])
        assert not differing, f"{kind} content hashes differ between SQLite and PostgreSQL: {differing[:10]}"


def _run(command: tuple[str, ...]) -> Any:
    result = run_cli(*command, "--json")
    assert result.exit_code == 0, f"raf {' '.join(command)} failed:\n{result.stdout}\n{result.stderr}"
    return result.json()


def _normalize(value: Any, home: str, window: tuple[datetime, datetime]) -> Any:
    """``value`` without what depends on the run: its R$F home and the wall-clock times of the run."""
    if isinstance(value, dict):
        return {k: _normalize(v, home, window) for k, v in value.items() if k not in _VOLATILE_KEYS}
    if isinstance(value, list):
        return [_normalize(v, home, window) for v in value]
    if isinstance(value, str):
        text = value.replace(home, "<home>")
        return _TIMESTAMP.sub(lambda m: "<now>" if _during(m.group(0), window) else m.group(0), text)
    return value


def _during(text: str, window: tuple[datetime, datetime]) -> bool:
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return False
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return window[0].replace(microsecond=0) <= moment <= window[1]


def _differences(a: Any, b: Any, path: str = "") -> Iterator[str]:
    if type(a) is not type(b):
        yield f"{path or '.'}: {a!r:.120} != {b!r:.120}"
    elif isinstance(a, dict):
        for key in sorted(a.keys() | b.keys()):
            if key not in a or key not in b:
                yield f"{path}.{key}: only on {'PostgreSQL' if key not in a else 'SQLite'}"
            else:
                yield from _differences(a[key], b[key], f"{path}.{key}")
    elif isinstance(a, list):
        if len(a) != len(b):
            yield f"{path}: {len(a)} items != {len(b)} items"
        for index, (x, y) in enumerate(zip(a, b, strict=False)):
            yield from _differences(x, y, f"{path}[{index}]")
    elif a != b:
        yield f"{path or '.'}: {a!r:.120} != {b!r:.120}"
