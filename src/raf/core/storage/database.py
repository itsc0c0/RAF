"""Engine creation and schema migrations.

SQLite is the zero-configuration default. Any SQLAlchemy URL can be configured
(``storage.url``); PostgreSQL is the intended production target. Migrations are
managed by Alembic; the expected head revision is kept in :data:`SCHEMA_HEAD`
so opening an up-to-date workspace does not need to load Alembic at all.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine, Table, create_engine, event, inspect, text
from sqlalchemy.dialects import postgresql as pg_dialect
from sqlalchemy.dialects import sqlite as sqlite_dialect

from raf.core.errors import StorageError

log = logging.getLogger("raf.storage")

#: Alembic head revision expected by this version of R$F.
SCHEMA_HEAD = "0001_initial"

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def sqlite_url(path: Path) -> str:
    return f"sqlite:///{path}"


def _sqlite_pragmas(dbapi_conn: sqlite3.Connection, _record: Any) -> None:
    cursor = dbapi_conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA cache_size=-65536")
    finally:
        cursor.close()


def create_db_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"timeout": 30, "check_same_thread": False})
        event.listen(engine, "connect", _sqlite_pragmas)
    else:
        engine = create_engine(url, pool_pre_ping=True)
    return engine


def _alembic_config(engine: Engine, connection: Connection | None = None) -> Any:
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False).replace("%", "%%"))
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        if not inspect(conn).has_table("alembic_version"):
            return None
        row = conn.execute(text("SELECT version_num FROM alembic_version")).first()
        return str(row[0]) if row else None


def migrate(engine: Engine) -> bool:
    """Upgrade the database to :data:`SCHEMA_HEAD`. Returns True if a migration ran."""
    try:
        revision = current_revision(engine)
    except Exception as exc:
        raise StorageError(
            "Could not open the R$F database.",
            reason=str(exc),
            hint="The workspace database may be corrupted; restore from a backup (raf workspace import).",
        ) from exc
    if revision == SCHEMA_HEAD:
        return False
    from alembic import command

    log.info("migrating database", extra={"from_revision": revision, "to_revision": SCHEMA_HEAD})
    with engine.begin() as conn:
        command.upgrade(_alembic_config(engine, conn), "head")
    return True


def alembic_head() -> str:
    """The head revision according to the migration scripts (used by tests)."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    head = ScriptDirectory.from_config(cfg).get_current_head()
    return str(head)


@contextmanager
def transaction(engine: Engine, conn: Connection | None = None) -> Iterator[Connection]:
    """Reuse ``conn`` when given (caller owns the transaction), else open one."""
    if conn is not None:
        yield conn
        return
    with engine.begin() as new_conn:
        yield new_conn


def chunks(items: Sequence[Any], size: int = 500) -> Iterator[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def upsert(
    conn: Connection, table: Table, rows: list[dict[str, Any]], keys: Sequence[str], update: bool = True
) -> None:
    """Portable INSERT .. ON CONFLICT for SQLite and PostgreSQL."""
    if not rows:
        return
    dialect = conn.dialect.name
    if dialect == "sqlite":
        stmt: Any = sqlite_dialect.insert(table)
    elif dialect == "postgresql":
        stmt = pg_dialect.insert(table)
    else:  # pragma: no cover - other backends are not supported yet
        raise StorageError(f"Database dialect '{dialect}' is not supported.")
    if update:
        update_cols = {c.key: stmt.excluded[c.key] for c in table.columns if c.key not in keys}
        stmt = stmt.on_conflict_do_update(index_elements=list(keys), set_=update_cols)
    else:
        stmt = stmt.on_conflict_do_nothing(index_elements=list(keys))
    for batch in chunks(rows, 1000):
        conn.execute(stmt, list(batch))
