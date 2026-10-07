"""Analysis records (``analysis-N``): what ``raf analyze`` detected, ran and produced."""

from __future__ import annotations

import builtins
from datetime import datetime
from typing import Any

from pydantic import Field
from sqlalchemy import Engine, func, select, update

from raf.core.objects.models import RafModel
from raf.core.storage import schema as s


class AnalysisRecord(RafModel):
    id: str
    input: str
    input_sha256: str | None = None
    detected_type: str
    status: str  # running | completed | partial | failed
    steps: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    suggestions: list[str] = Field(default_factory=list)
    job_id: str | None = None
    created_at: datetime

    @property
    def job_ids(self) -> list[str]:
        jobs = [self.job_id] if self.job_id else []
        extra = self.stats.get("job_ids")
        if isinstance(extra, list):
            jobs += [str(j) for j in extra if j and j not in jobs]
        return jobs


class AnalysisRepository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def save(self, record: AnalysisRecord) -> None:
        row = record.model_dump(mode="json")
        row["created_at"] = record.created_at
        with self.engine.begin() as c:
            exists = c.execute(select(s.analyses.c.id).where(s.analyses.c.id == record.id)).first()
            if exists:
                c.execute(update(s.analyses).where(s.analyses.c.id == record.id).values(**row))
            else:
                c.execute(s.analyses.insert().values(**row))

    def get(self, analysis_id: str) -> AnalysisRecord | None:
        with self.engine.connect() as c:
            row = c.execute(select(s.analyses).where(s.analyses.c.id == analysis_id)).first()
        return AnalysisRecord.model_validate(dict(row._mapping)) if row else None

    def list(self, limit: int = 50) -> builtins.list[AnalysisRecord]:
        stmt = select(s.analyses).order_by(s.analyses.c.created_at.desc(), s.analyses.c.id.desc()).limit(limit)
        with self.engine.connect() as c:
            return [AnalysisRecord.model_validate(dict(r._mapping)) for r in c.execute(stmt)]

    def count(self) -> int:
        with self.engine.connect() as c:
            return int(c.execute(select(func.count()).select_from(s.analyses)).scalar_one())
