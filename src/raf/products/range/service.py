"""R$F Range: synthetic organizations for training and testing (lightweight simulation).

A range is generated into the current workspace: an inventory (users, identities, hosts,
services, networks, groups, roles, reachability, synthetic vulnerabilities) and, while it runs,
routine background activity produced in simulated time. Everything is deterministic for a
(preset/configuration, seed) pair and marked synthetic. Every write is an ingestion job recorded in
the range state, so ``reset`` and ``destroy`` remove exactly what the range wrote (data that other
imports also contributed is kept).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import ConflictError, InvalidInputError, NotFoundError
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions, IngestReport
from raf.core.jobs.manager import JobContext
from raf.core.objects.models import RafModel
from raf.core.storage.purge import PurgeStats, purge_jobs
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import parse_timestamp, utcnow
from raf.data import raven
from raf.data.synth import (
    OrgConfig,
    SyntheticOrg,
    TelemetryWindow,
    build_org,
    inventory_records,
    routine_activity,
)

NAMESPACE = "range"
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
MAX_HOURS = 24 * 14
MAX_CONFIG_BYTES = 256 * 1024
DEFAULT_START = datetime(2026, 10, 5, tzinfo=UTC)  # a Monday; Raven's baseline day before INC-001

PRESETS: dict[str, dict[str, Any]] = {
    "raven": {"description": "Raven Industries - the R$F demo organization (6 employees, 15 hosts, INC-001 world)"},
    "acme": {
        "description": "Mid-size company (spec example): 30 employees, 20 workstations, 5 servers",
        "config": {
            "employees": 30,
            "workstations": 20,
            "servers": 5,
            "departments": ["engineering", "finance", "hr", "operations"],
            "services": ["dns", "web", "database", "git"],
        },
    },
    "small-office": {
        "description": "Small office: 10 employees, flat network, mail and file services",
        "config": {
            "employees": 10,
            "workstations": 10,
            "servers": 2,
            "departments": ["operations", "sales"],
            "services": ["dns", "mail", "file"],
            "segmentation": False,
            "mfa_rate": 0.3,
        },
    },
    "enterprise": {
        "description": "Larger organization: 200 employees, 25 servers, all catalog services",
        "config": {
            "employees": 200,
            "workstations": 180,
            "servers": 25,
            "departments": [
                "engineering",
                "finance",
                "hr",
                "operations",
                "sales",
                "marketing",
                "legal",
                "support",
                "security",
            ],
            "services": [
                "dns",
                "directory",
                "web",
                "database",
                "git",
                "mail",
                "file",
                "ci",
                "vpn",
                "backup",
                "monitoring",
            ],
            "admins": 6,
            "vulnerabilities": 8,
            "event_rate": 6,
        },
    },
}


class RangeState(RafModel):
    name: str
    preset: str
    seed: int
    config: dict[str, Any] = Field(default_factory=dict)
    status: str = "created"  # created | running | stopped
    start: datetime
    clock: datetime
    periods: int = 0
    jobs: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    counts: dict[str, int] = Field(default_factory=dict)


class RangeRun(RafModel):
    state: RangeState
    job: str | None = None
    report: IngestReport | None = None
    window: dict[str, datetime] | None = None
    purged: PurgeStats | None = None


def validate_range_name(name: str) -> str:
    text = name.strip().lower()
    if not _NAME_RE.match(text):
        raise InvalidInputError(
            f"Invalid range name '{name}'.", hint="Use 2-41 lowercase letters, digits or '-', starting with a letter."
        )
    return text


def load_config_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise InvalidInputError(f"{path} is not a file.")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise InvalidInputError(f"{path.name} is larger than {MAX_CONFIG_BYTES // 1024} KB.")
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        data = yaml.safe_load(text) if path.suffix.lower() in (".yaml", ".yml") else json.loads(text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise InvalidInputError(f"{path.name} is not valid YAML/JSON: {str(exc).splitlines()[0][:160]}") from exc
    if not isinstance(data, dict):
        raise InvalidInputError("A range configuration must be a mapping.")
    return data


_CONFIG_FIELDS = {f.name for f in fields(OrgConfig)}
_ALIASES = {"event rate": "event_rate", "mfa": "mfa_rate", "security controls": "controls"}


def normalize_config(name: str, raw: dict[str, Any]) -> OrgConfig:
    data: dict[str, Any] = {}
    for key, value in raw.items():
        k = _ALIASES.get(str(key).strip().lower(), str(key).strip().lower().replace("-", "_").replace(" ", "_"))
        if k == "controls" and isinstance(value, dict):
            for ck, cv in value.items():
                ck = str(ck).lower().replace("-", "_")
                if ck in ("mfa", "mfa_rate"):
                    data["mfa_rate"] = float(cv) if not isinstance(cv, bool) else (1.0 if cv else 0.0)
                elif ck in ("segmentation", "edr"):
                    data[ck] = bool(cv)
            continue
        if k in ("name", "seed", "preset", "start", "description"):
            continue
        if k not in _CONFIG_FIELDS:
            raise InvalidInputError(
                f"Unknown range configuration key '{key}'.",
                hint="Known keys: " + ", ".join(sorted(_CONFIG_FIELDS - {"name"})),
            )
        data[k] = value
    try:
        for list_key in ("departments", "services"):
            if list_key in data:
                value = data[list_key]
                data[list_key] = [str(v).strip().lower() for v in (value if isinstance(value, list) else [value])]
        for int_key in ("employees", "workstations", "servers", "admins", "event_rate", "vulnerabilities"):
            if int_key in data:
                data[int_key] = int(data[int_key])
        if "mfa_rate" in data:
            data["mfa_rate"] = float(data["mfa_rate"])
    except (TypeError, ValueError) as exc:
        raise InvalidInputError(f"Invalid range configuration value: {exc}") from exc
    return OrgConfig(name=name, **data).validate()


class RangeService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.kv = ctx.store.kv

    # ------------------------------------------------------------------ state
    def ranges(self) -> list[RangeState]:
        return sorted((RangeState.model_validate(v) for v in self.kv.items(NAMESPACE).values()), key=lambda r: r.name)

    def get(self, name: str) -> RangeState:
        raw = self.kv.get(NAMESPACE, name.strip().lower())
        if raw is None:
            raise NotFoundError(
                f"Range '{name}' does not exist in this workspace.",
                suggestions=["raf range list", f"raf range create {name}"],
            )
        return RangeState.model_validate(raw)

    def _save(self, state: RangeState) -> None:
        state.updated_at = utcnow()
        self.kv.set(NAMESPACE, state.name, state.to_json_dict())

    # ------------------------------------------------------------------ organization
    def org_for(self, state: RangeState) -> SyntheticOrg | None:
        if state.preset == "raven":
            return None
        return build_org(normalize_config(state.name, state.config), state.seed)

    def _inventory(self, state: RangeState) -> list[dict[str, Any]]:
        if state.preset == "raven":
            return list(raven.inventory_records())
        org = self.org_for(state)
        assert org is not None
        return inventory_records(org)

    def _activity(self, state: RangeState, window: TelemetryWindow) -> list[dict[str, Any]]:
        if state.preset == "raven":
            records: list[dict[str, Any]] = []
            day = window.start.replace(hour=0, minute=0, second=0, microsecond=0)
            while day < window.end:
                for record in raven.routine_events(seed=state.seed + day.toordinal(), day=day):
                    when = parse_timestamp(record["timestamp"])
                    if window.contains(when):
                        records.append({**record, "synthetic": True, "tags": ["synthetic", f"range:{state.name}"]})
                day += timedelta(days=1)
            return records
        org = self.org_for(state)
        assert org is not None
        rate = int(normalize_config(state.name, state.config).event_rate)
        return routine_activity(org, window, state.seed, rate=rate, namespace=f"range-{state.name}")

    def _ingest(
        self, state: RangeState, records: list[dict[str, Any]], kind: str, title: str
    ) -> tuple[str, IngestReport | None]:
        source = f"range:{state.name}:{kind}:{state.periods}"

        def work(jc: JobContext) -> dict[str, Any]:
            pipeline = IngestionPipeline(self.ctx, job=jc)
            report = pipeline.ingest_records(
                records, source_name=source, options=IngestOptions(synthetic=True), label="raf-range/1.0"
            )
            return report.to_json_dict()

        job = self.ctx.jobs.run_inline(
            "range", title, {"range": state.name, "kind": kind, "records": len(records)}, work
        )
        report = IngestReport.model_validate(job.result) if job.result else None
        state.jobs.append(job.id)
        return job.id, report

    # ------------------------------------------------------------------ lifecycle
    def create(
        self,
        name: str,
        *,
        preset: str | None = None,
        seed: int = 42,
        config: dict[str, Any] | None = None,
        start: datetime | None = None,
    ) -> RangeRun:
        name = validate_range_name(name)
        if self.kv.get(NAMESPACE, name) is not None:
            raise ConflictError(
                f"Range '{name}' already exists.", suggestions=[f"raf range status {name}", f"raf range reset {name}"]
            )
        chosen = (preset or (name if name in PRESETS else "acme")).lower()
        if chosen not in PRESETS:
            raise InvalidInputError(f"Unknown preset '{chosen}'.", hint="Presets: " + ", ".join(sorted(PRESETS)))
        if not 0 <= seed <= 2**31:
            raise InvalidInputError("The seed must be between 0 and 2^31.")
        merged: dict[str, Any] = {}
        if chosen != "raven":
            merged = dict(PRESETS[chosen].get("config", {}))
            merged.update(config or {})
            normalize_config(name, merged)  # validate early
        elif config:
            raise InvalidInputError(
                "The raven preset is fixed; configuration options apply to generic presets.",
                hint=f"raf range create {name} --preset acme --employees 50",
            )
        begin = start or DEFAULT_START
        now = utcnow()
        state = RangeState(
            name=name, preset=chosen, seed=seed, config=merged, start=begin, clock=begin, created_at=now, updated_at=now
        )
        job, report = self._ingest(
            state, self._inventory(state), "inventory", f"Range {name}: {chosen} inventory (seed {seed})"
        )
        state.counts = self._counts(report)
        self._save(state)
        self.ctx.audit.record(
            "range.create", affected=[f"range:{name}"], details={"preset": chosen, "seed": seed, "job": job}
        )
        return RangeRun(state=state, job=job, report=report)

    def start(self, name: str, *, hours: float = 24.0) -> RangeRun:
        state = self.get(name)
        return self._advance(state, hours, "range.start")

    def tick(self, name: str, *, hours: float = 24.0) -> RangeRun:
        state = self.get(name)
        if state.status != "running":
            raise ConflictError(
                f"Range '{state.name}' is {state.status}; start it first.",
                suggestions=[f"raf range start {state.name}"],
            )
        return self._advance(state, hours, "range.tick")

    def _advance(self, state: RangeState, hours: float, operation: str) -> RangeRun:
        if not 0 < hours <= MAX_HOURS:
            raise InvalidInputError(f"--hours must be between 0 and {MAX_HOURS}.")
        window = TelemetryWindow.of(state.clock, hours)
        records = self._activity(state, window)
        job, report = self._ingest(
            state, records, "activity", f"Range {state.name}: activity {window.start:%Y-%m-%d %H:%M} +{hours:g}h"
        )
        state.status = "running"
        state.clock = window.end
        state.periods += 1
        for key, value in self._counts(report).items():
            state.counts[key] = state.counts.get(key, 0) + value
        self._save(state)
        self.ctx.audit.record(
            operation, affected=[f"range:{state.name}"], details={"job": job, "hours": hours, "events": len(records)}
        )
        return RangeRun(state=state, job=job, report=report, window={"start": window.start, "end": window.end})

    def stop(self, name: str) -> RangeState:
        state = self.get(name)
        if state.status != "running":
            raise ConflictError(f"Range '{state.name}' is not running ({state.status}).")
        state.status = "stopped"
        self._save(state)
        self.ctx.audit.record(
            "range.stop", affected=[f"range:{state.name}"], details={"clock": state.clock.isoformat()}
        )
        return state

    def reset(self, name: str) -> RangeRun:
        state = self.get(name)
        purged = purge_jobs(self.ctx.store, state.jobs)
        state.jobs, state.periods, state.status, state.clock, state.counts = [], 0, "created", state.start, {}
        job, report = self._ingest(
            state,
            self._inventory(state),
            "inventory",
            f"Range {state.name}: {state.preset} inventory (seed {state.seed}, reset)",
        )
        state.counts = self._counts(report)
        self._save(state)
        self.ctx.audit.record(
            "range.reset",
            affected=[f"range:{state.name}"],
            details={"purged": purged.model_dump(exclude={"jobs"}), "job": job},
        )
        return RangeRun(state=state, job=job, report=report, purged=purged)

    def destroy(self, name: str) -> RangeRun:
        state = self.get(name)
        purged = purge_jobs(self.ctx.store, state.jobs)
        self.kv.delete(NAMESPACE, state.name)
        self.ctx.audit.record(
            "range.destroy", affected=[f"range:{state.name}"], details={"purged": purged.model_dump(exclude={"jobs"})}
        )
        return RangeRun(state=state, purged=purged)

    def status(self, name: str) -> dict[str, Any]:
        state = self.get(name)
        store = self.ctx.store
        live = {
            "events": store.events.count(EventQuery(job_ids=state.jobs)) if state.jobs else 0,
            "objects": len(store.provenance.subjects_for_jobs(state.jobs, kind="object")) if state.jobs else 0,
            "relationships": len(store.provenance.subjects_for_jobs(state.jobs, kind="relationship"))
            if state.jobs
            else 0,
        }
        summary: dict[str, Any] = {"preset": state.preset, "description": PRESETS[state.preset]["description"]}
        org = self.org_for(state)
        if org is not None:
            summary.update(
                {
                    "employees": len(org.users),
                    "workstations": len(org.workstation_users()),
                    "servers": len(org.servers()),
                    "services": [s.name for s in org.services],
                    "networks": [n["name"] for n in org.networks],
                    "controls": org.controls,
                    "domain": org.domain,
                }
            )
        else:
            summary.update(
                {
                    "employees": len(raven.USERS),
                    "workstations": len(raven.USERS),
                    "servers": len(raven.HOSTS) - len(raven.USERS),
                    "services": [s["name"] for s in raven.SERVICES],
                    "networks": [n["name"] for n in raven.NETWORKS],
                    "domain": raven.DOMAIN,
                }
            )
        return {"state": state.to_json_dict(), "live": live, "organization": summary}

    @staticmethod
    def _counts(report: IngestReport | None) -> dict[str, int]:
        if report is None:
            return {}
        return {
            "objects": report.objects_created,
            "relationships": report.relationships_created,
            "events": report.events_created,
        }


def preset_table() -> list[dict[str, Any]]:
    return [
        {"name": name, "description": spec["description"], "config": spec.get("config", {})}
        for name, spec in sorted(PRESETS.items())
    ]


def config_defaults() -> dict[str, Any]:
    return {k: v for k, v in asdict(OrgConfig(name="example")).items() if k != "name"}
