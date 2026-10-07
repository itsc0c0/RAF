"""The workspace data store: one facade over the shared security model."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine

from raf.core.storage.database import create_db_engine, migrate, sqlite_url
from raf.core.storage.repos.analyses import AnalysisRepository
from raf.core.storage.repos.events import EventRepository
from raf.core.storage.repos.findings import FindingRepository
from raf.core.storage.repos.incidents import IncidentRepository
from raf.core.storage.repos.misc import CounterRepository, KVRepository, ProvenanceRepository
from raf.core.storage.repos.objects import ObjectRepository
from raf.core.storage.repos.relationships import RelationshipRepository


class Store:
    """Access to the canonical objects, relationships, events and findings of a workspace."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.objects = ObjectRepository(engine)
        self.relationships = RelationshipRepository(engine)
        self.events = EventRepository(engine)
        self.findings = FindingRepository(engine)
        self.provenance = ProvenanceRepository(engine)
        self.counters = CounterRepository(engine)
        self.kv = KVRepository(engine)
        self.incidents = IncidentRepository(engine, self.objects, self.events)
        self.analyses = AnalysisRepository(engine)

    @classmethod
    def open(cls, url: str, *, run_migrations: bool = True) -> Store:
        engine = create_db_engine(url)
        if run_migrations:
            migrate(engine)
        return cls(engine)

    @classmethod
    def open_sqlite(cls, path: Path) -> Store:
        path.parent.mkdir(parents=True, exist_ok=True)
        return cls.open(sqlite_url(path))

    @contextmanager
    def transaction(self) -> Iterator[Connection]:
        with self.engine.begin() as conn:
            yield conn

    def next_id(self, prefix: str) -> str:
        return f"{prefix}-{self.counters.next(prefix)}"

    def stats(self) -> dict[str, Any]:
        return {
            "objects": self.objects.count(),
            "relationships": self.relationships.count(),
            "events": self.events.count(),
            "findings": self.findings.count(),
            "incidents": len(self.incidents.list()),
        }

    def close(self) -> None:
        self.engine.dispose()
