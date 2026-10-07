"""Remove what specific jobs wrote, without touching data other sources also contributed.

Used by synthetic environments (R$F Range reset/destroy, Forge clean-up): every ingested object,
relationship and event records the job that produced it (events directly, objects and
relationships through provenance, which is kept for every subject a job touches). A subject is
deleted only when *all* of its provenance comes from the purged jobs; shared subjects are kept and
only lose the purged jobs' provenance records.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import Field

from raf.core.objects.models import RafModel
from raf.core.storage.repos.events import EventQuery
from raf.core.storage.store import Store


class PurgeStats(RafModel):
    jobs: list[str] = Field(default_factory=list)
    events: int = 0
    objects: int = 0
    relationships: int = 0
    shared_objects: int = 0
    shared_relationships: int = 0


def purge_jobs(store: Store, job_ids: Sequence[str]) -> PurgeStats:
    jobs = sorted(set(job_ids))
    stats = PurgeStats(jobs=jobs)
    if not jobs:
        return stats
    stats.events = store.events.delete(EventQuery(job_ids=jobs))
    rel_ids = store.provenance.subjects_for_jobs(jobs, kind="relationship")
    obj_ids = store.provenance.subjects_for_jobs(jobs, kind="object")
    owners = store.provenance.jobs_for_subjects(rel_ids | obj_ids)
    purged: set[str | None] = set(jobs)
    exclusive_rels = sorted(r for r in rel_ids if owners.get(r, set()) <= purged)
    exclusive_objs = sorted(o for o in obj_ids if owners.get(o, set()) <= purged)
    stats.shared_relationships = len(rel_ids) - len(exclusive_rels)
    stats.shared_objects = len(obj_ids) - len(exclusive_objs)
    with store.engine.begin() as conn:
        stats.relationships = store.relationships.delete(exclusive_rels, conn)
        stats.relationships += store.relationships.delete_touching(exclusive_objs, conn)
        stats.objects = store.objects.delete(exclusive_objs, conn)
        store.provenance.delete_for_subjects([*exclusive_rels, *exclusive_objs], conn)
        store.provenance.delete_for_jobs(jobs, conn)
    return stats
