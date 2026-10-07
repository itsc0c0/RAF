"""Job system for long-running operations.

Jobs are persisted in the workspace database so any interface (CLI, API, web
UI) can observe progress, inspect results and request cancellation. The CLI
runs jobs inline (still persisted); the API runs them on a worker pool.
Cancellation is cooperative: job code calls :meth:`JobContext.check_cancelled`.
"""

from __future__ import annotations

import builtins
import logging
import os
import threading
import time
import traceback
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, computed_field
from pydantic_core import to_jsonable_python
from sqlalchemy import Engine, select, update

from raf.core.errors import NotFoundError, OperationCancelled, RafError
from raf.core.objects.models import RafModel
from raf.core.storage import schema as s
from raf.core.storage.repos.misc import CounterRepository
from raf.core.timeutil import utcnow

log = logging.getLogger("raf.jobs")


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def terminal(self) -> bool:
        return self in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)


class Job(RafModel):
    id: str
    kind: str
    title: str
    status: JobStatus
    progress: float = 0.0
    message: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    actor: str = "unknown"
    cancel_requested: bool = False
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def duration_ms(self) -> float | None:
        if self.started_at is None:
            return None
        end = self.finished_at or utcnow()
        return round((end - self.started_at).total_seconds() * 1000, 1)


def _job_from_row(row: Any) -> Job:
    m = row._mapping
    return Job.model_construct(
        id=m["id"],
        kind=m["kind"],
        title=m["title"],
        status=JobStatus(m["status"]),
        progress=m["progress"],
        message=m["message"],
        params=dict(m["params"] or {}),
        result=m["result"],
        error=m["error"],
        actor=m["actor"],
        cancel_requested=bool(m["cancel_requested"]),
        created_at=m["created_at"],
        started_at=m["started_at"],
        finished_at=m["finished_at"],
    )


JobFunction = Callable[["JobContext"], dict[str, Any] | None]
ProgressCallback = Callable[[float, str | None], None]


class JobContext:
    """Handed to job functions: progress reporting and cooperative cancellation."""

    _MIN_INTERVAL = 0.4

    def __init__(self, manager: JobManager, job_id: str, on_progress: ProgressCallback | None = None) -> None:
        self.manager = manager
        self.job_id = job_id
        self._last_write = 0.0
        self._last_check = 0.0
        self._cancel = threading.Event()
        self._on_progress = on_progress

    def progress(self, fraction: float, message: str | None = None, *, force: bool = False) -> None:
        fraction = min(max(fraction, 0.0), 1.0)
        if self._on_progress is not None:
            self._on_progress(fraction, message)
        now = time.monotonic()
        if force or now - self._last_write >= self._MIN_INTERVAL:
            self._last_write = now
            self.manager._update(self.job_id, progress=fraction, message=message)

    def request_cancel(self) -> None:
        self._cancel.set()

    def cancelled(self) -> bool:
        if self._cancel.is_set():
            return True
        now = time.monotonic()
        if now - self._last_check >= self._MIN_INTERVAL:
            self._last_check = now
            if self.manager.cancel_requested(self.job_id):
                self._cancel.set()
        return self._cancel.is_set()

    def check_cancelled(self) -> None:
        if self.cancelled():
            raise OperationCancelled(f"Job {self.job_id} was cancelled.")


class JobManager:
    def __init__(self, engine: Engine, *, actor: str = "unknown", max_workers: int = 2) -> None:
        self.engine = engine
        self.actor = actor
        self.counters = CounterRepository(engine)
        self._executor: ThreadPoolExecutor | None = None
        self._max_workers = max_workers
        self._contexts: dict[str, JobContext] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ persistence
    def create(self, kind: str, title: str, params: dict[str, Any] | None = None) -> Job:
        job_id = f"job-{self.counters.next('job')}"
        stored_params = dict(to_jsonable_python(params or {}))
        stored_params["_pid"] = os.getpid()
        with self.engine.begin() as c:
            c.execute(
                s.jobs.insert().values(
                    id=job_id,
                    kind=kind,
                    title=title,
                    status=JobStatus.QUEUED.value,
                    progress=0.0,
                    message=None,
                    params=stored_params,
                    result=None,
                    error=None,
                    actor=self.actor,
                    cancel_requested=False,
                    created_at=utcnow(),
                )
            )
        return self.require(job_id)

    def _update(self, job_id: str, **values: Any) -> None:
        with self.engine.begin() as c:
            c.execute(update(s.jobs).where(s.jobs.c.id == job_id).values(**values))

    def get(self, job_id: str) -> Job | None:
        with self.engine.connect() as c:
            row = c.execute(select(s.jobs).where(s.jobs.c.id == job_id)).first()
        return _job_from_row(row) if row else None

    def require(self, job_id: str) -> Job:
        job = self.get(job_id)
        if job is None:
            raise NotFoundError(f"Job '{job_id}' does not exist.", suggestions=["raf jobs"])
        return job

    def list(self, *, limit: int = 50, status: JobStatus | None = None, kind: str | None = None) -> builtins.list[Job]:
        stmt = select(s.jobs).order_by(s.jobs.c.created_at.desc(), s.jobs.c.id.desc()).limit(limit)
        if status is not None:
            stmt = stmt.where(s.jobs.c.status == status.value)
        if kind:
            stmt = stmt.where(s.jobs.c.kind == kind)
        with self.engine.connect() as c:
            return [_job_from_row(r) for r in c.execute(stmt)]

    def cancel_requested(self, job_id: str) -> bool:
        with self.engine.connect() as c:
            row = c.execute(select(s.jobs.c.cancel_requested).where(s.jobs.c.id == job_id)).first()
        return bool(row and row[0])

    def cancel(self, job_id: str) -> Job:
        job = self.require(job_id)
        if job.status.terminal:
            return job
        if job.status == JobStatus.QUEUED:
            self._update(
                job_id,
                status=JobStatus.CANCELLED.value,
                cancel_requested=True,
                finished_at=utcnow(),
                message="cancelled before start",
            )
        else:
            self._update(job_id, cancel_requested=True, message="cancellation requested")
            with self._lock:
                ctx = self._contexts.get(job_id)
            if ctx is not None:
                ctx.request_cancel()
        return self.require(job_id)

    def reconcile(self) -> int:
        """Mark RUNNING jobs whose owning process no longer exists as FAILED (interrupted)."""
        fixed = 0
        for job in self.list(limit=200, status=JobStatus.RUNNING):
            pid = job.params.get("_pid")
            if isinstance(pid, int) and pid != os.getpid() and not _pid_alive(pid):
                self._update(
                    job.id,
                    status=JobStatus.FAILED.value,
                    finished_at=utcnow(),
                    error={"code": "raf.interrupted", "message": "The process running this job exited unexpectedly."},
                )
                fixed += 1
        return fixed

    # ------------------------------------------------------------------ execution
    def _execute(self, job: Job, fn: JobFunction, on_progress: ProgressCallback | None) -> Job:
        ctx = JobContext(self, job.id, on_progress)
        with self._lock:
            self._contexts[job.id] = ctx
        self._update(job.id, status=JobStatus.RUNNING.value, started_at=utcnow(), message="running")
        started = time.perf_counter()
        try:
            result = fn(ctx) or {}
            payload = to_jsonable_python(result)
            self._update(
                job.id,
                status=JobStatus.COMPLETED.value,
                progress=1.0,
                finished_at=utcnow(),
                result=payload,
                message="completed",
            )
        except OperationCancelled as exc:
            self._update(
                job.id, status=JobStatus.CANCELLED.value, finished_at=utcnow(), error=exc.to_dict(), message="cancelled"
            )
        except RafError as exc:
            self._update(
                job.id, status=JobStatus.FAILED.value, finished_at=utcnow(), error=exc.to_dict(), message=exc.message
            )
        except Exception as exc:
            log.error("job %s failed with an internal error", job.id, exc_info=True, extra={"file_only": True})
            self._update(
                job.id,
                status=JobStatus.FAILED.value,
                finished_at=utcnow(),
                message="internal error",
                error={
                    "code": "raf.internal",
                    "message": "Internal error while running the job.",
                    "type": type(exc).__name__,
                    "detail": str(exc)[:500],
                    "traceback": traceback.format_exc(limit=8)[-4000:],
                },
            )
        finally:
            with self._lock:
                self._contexts.pop(job.id, None)
            log.info(
                "job finished",
                extra={
                    "job_id": job.id,
                    "kind": job.kind,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )
        return self.require(job.id)

    def run_inline(
        self,
        kind: str,
        title: str,
        params: dict[str, Any] | None,
        fn: JobFunction,
        on_progress: ProgressCallback | None = None,
    ) -> Job:
        job = self.create(kind, title, params)
        return self._execute(job, fn, on_progress)

    def submit(self, kind: str, title: str, params: dict[str, Any] | None, fn: JobFunction) -> Job:
        job = self.create(kind, title, params)
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self._max_workers, thread_name_prefix="raf-job")
        current = self.require(job.id)
        future: Future[Job] = self._executor.submit(self._execute, current, fn, None)
        future.add_done_callback(lambda f: f.exception())  # errors are recorded on the job itself
        return current

    def shutdown(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True
