"""R$F Forge: synthetic security telemetry and scenarios.

Telemetry is generated for a *population*: the users, workstations, servers, services and
identities of the current workspace when it has them (so generated events connect to the existing
graph), otherwise a small generic synthetic organization. Every record is marked synthetic and
tagged ``forge``; scenarios model suspicious behavior purely as events (no payloads, no real
credentials, reserved domains and documentation IP ranges only).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions, IngestReport
from raf.core.jobs.manager import JobContext
from raf.core.objects.models import RafModel
from raf.core.objects.types import Criticality
from raf.data.synth import (
    GENERATORS,
    SCENARIOS,
    OrgConfig,
    OrgHost,
    OrgService,
    OrgUser,
    SyntheticOrg,
    TelemetryWindow,
    build_org,
    generate,
    iter_jsonl,
    scenario,
)

MAX_COUNT = 1_000_000
MAX_HOURS = 24 * 90


class ForgeResult(RafModel):
    kind: str  # generator name or scenario:<name>
    seed: int
    population: str
    window: dict[str, datetime]
    records: int
    incident: str | None = None
    subject: str | None = None  # main actor of a scenario
    output: str | None = None
    job: str | None = None
    report: IngestReport | None = None
    sample: list[dict[str, Any]] = Field(default_factory=list)


def _crit(metadata: dict[str, Any], tags: list[str]) -> str:
    level = Criticality.of(metadata, tags)
    return level.value if level else "medium"


class ForgeService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------ population
    def workspace_population(self) -> SyntheticOrg | None:
        store = self.ctx.store
        users = list(store.objects.iter_all(types=["user"]))
        hosts = {h.id: h for h in store.objects.iter_all(types=["host"])}
        if not users or not hosts:
            return None
        owns = {
            r.source_object: r.target_object
            for r in store.relationships.iter_all(types=["OWNS"])
            if r.target_object in hosts and r.valid_to is None
        }
        org = SyntheticOrg(name=self.ctx.workspace.name, domain=f"{self.ctx.workspace.name}.example")
        owned_hosts = set(owns.values())
        for user in sorted(users, key=lambda u: u.id):
            ws = owns.get(user.id)
            org.users.append(
                OrgUser(
                    name=user.name,
                    full_name=str(user.metadata.get("full_name") or user.name),
                    department=str(user.metadata.get("department") or "staff"),
                    title=str(user.metadata.get("title") or ""),
                    workstation=hosts[ws].name if ws else None,
                    mfa=bool(user.metadata.get("mfa", True)),
                )
            )
        memberships = {
            r.source_object: r.target_object
            for r in store.relationships.iter_all(types=["MEMBER_OF"])
            if r.target_object.startswith("network:") and r.valid_to is None
        }
        for host in sorted(hosts.values(), key=lambda h: h.id):
            ip = str(host.metadata.get("ip") or "")
            if not ip:
                continue
            role = "workstation" if host.id in owned_hosts else str(host.metadata.get("role") or "server")
            org.hosts.append(
                OrgHost(
                    name=host.name,
                    ip=ip,
                    network=memberships.get(host.id, "network:unknown").split(":", 1)[1],
                    os=str(host.metadata.get("os") or "unknown"),
                    role=role,
                    criticality=_crit(host.metadata, host.tags),
                    internet_facing=bool(host.metadata.get("internet_facing")),
                    public_ip=host.metadata.get("public_ip"),
                )
            )
        if not org.hosts:
            return None
        for svc in store.objects.iter_all(types=["service"]):
            host_name = str(svc.metadata.get("host") or "")
            if host_name and org.host(host_name):
                org.services.append(
                    OrgService(
                        name=svc.name,
                        host=host_name,
                        port=int(svc.metadata.get("port") or 0),
                        protocol=str(svc.metadata.get("protocol") or "tcp"),
                        criticality=_crit(svc.metadata, svc.tags),
                        internet_facing=bool(svc.metadata.get("internet_facing")),
                    )
                )
        for ident in store.objects.iter_all(types=["identity"]):
            org.identities.append(
                {
                    "name": ident.name,
                    "kind": str(ident.metadata.get("kind") or "service"),
                    "owner": str(ident.metadata.get("owner") or ""),
                    "privileged": bool(ident.metadata.get("privileged")),
                    "mfa": bool(ident.metadata.get("mfa", False)),
                }
            )
        for group in store.objects.iter_all(types=["group"]):
            org.groups[group.name] = []
        return org

    def population(self, choice: str, seed: int) -> tuple[str, SyntheticOrg]:
        choice = choice.lower()
        if choice in ("auto", "workspace"):
            org = self.workspace_population()
            if org is not None:
                return "workspace", org
            if choice == "workspace":
                raise InvalidInputError(
                    "The workspace has no users with hosts to generate telemetry for.",
                    suggestions=["raf range create raven", "raf forge auth --population generic"],
                )
        if choice == "raven":
            from raf.data.synth import raven_org

            return "raven", raven_org()
        if choice in ("auto", "generic"):
            return "generic", build_org(
                OrgConfig(
                    name="forge",
                    employees=20,
                    workstations=20,
                    servers=4,
                    services=["dns", "web", "database", "git", "vpn"],
                ),
                seed,
            )
        raise InvalidInputError(f"Unknown population '{choice}'.", hint="Use auto, workspace, raven or generic.")

    def default_start(self) -> datetime:
        latest = self.ctx.store.events.bounds()[1]
        if latest is not None:
            return (latest + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        now = datetime.now(UTC)
        return now.replace(hour=0, minute=0, second=0, microsecond=0)

    # ------------------------------------------------------------------ generation
    def _deliver(
        self,
        kind: str,
        seed: int,
        population: str,
        window: TelemetryWindow,
        records: list[dict[str, Any]],
        *,
        output: Path | None,
        ingest: bool,
        incident: dict[str, Any] | None = None,
    ) -> ForgeResult:
        result = ForgeResult(
            kind=kind,
            seed=seed,
            population=population,
            records=len(records),
            window={"start": window.start, "end": window.end},
            incident=str(incident["name"]) if incident else None,
            sample=records[:3],
        )
        payload = ([incident] if incident else []) + records
        if output is not None:
            target = output.expanduser()
            if target.exists() and target.is_dir():
                raise InvalidInputError(f"{target} is a directory.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("w", encoding="utf-8") as fh:
                fh.writelines(iter_jsonl(payload))
            result.output = str(target)
        if ingest:

            def work(jc: JobContext) -> dict[str, Any]:
                pipeline = IngestionPipeline(self.ctx, job=jc)
                report = pipeline.ingest_records(
                    payload,
                    source_name=f"forge:{kind}:{seed}",
                    options=IngestOptions(synthetic=True),
                    label="raf-forge/1.0",
                )
                return report.to_json_dict()

            job = self.ctx.jobs.run_inline(
                "forge",
                f"Forge {kind} (seed {seed}, {len(records)} records)",
                {"kind": kind, "seed": seed, "records": len(records)},
                work,
            )
            result.job = job.id
            result.report = IngestReport.model_validate(job.result) if job.result else None
            if incident:
                self.ctx.refs.remember("incident", f"incident:{str(incident['name']).lower()}")
            self.ctx.refs.remember("job", job.id)
        self.ctx.audit.record(
            "forge.generate",
            affected=[result.output or f"job:{result.job}"],
            details={"kind": kind, "seed": seed, "records": len(records), "population": population, "ingested": ingest},
        )
        return result

    def telemetry(
        self,
        kind: str,
        *,
        count: int,
        seed: int,
        start: datetime | None = None,
        hours: float = 24.0,
        noise: float = 0.05,
        population: str = "auto",
        output: Path | None = None,
        ingest: bool = True,
    ) -> ForgeResult:
        if kind not in GENERATORS:
            raise InvalidInputError(f"Unknown generator '{kind}'.", hint="Generators: " + ", ".join(GENERATORS))
        if not 1 <= count <= MAX_COUNT:
            raise InvalidInputError(f"--count must be between 1 and {MAX_COUNT:,}.")
        if not 0.0 <= noise <= 1.0:
            raise InvalidInputError("--noise must be between 0 and 1.")
        if not 0 < hours <= MAX_HOURS:
            raise InvalidInputError(f"--hours must be between 0 and {MAX_HOURS}.")
        label, org = self.population(population, seed)
        window = TelemetryWindow.of(start or self.default_start(), hours)
        records = generate(kind, org, count=count, window=window, seed=seed, noise=noise)
        return self._deliver(kind, seed, label, window, records, output=output, ingest=ingest)

    def scenario(
        self,
        name: str,
        *,
        seed: int,
        start: datetime | None = None,
        population: str = "auto",
        output: Path | None = None,
        ingest: bool = True,
    ) -> ForgeResult:
        if name not in SCENARIOS:
            raise InvalidInputError(f"Unknown scenario '{name}'.", hint="Scenarios: " + ", ".join(sorted(SCENARIOS)))
        label, org = self.population(population, seed)
        begin = start or self.default_start()
        built = scenario(name, org, seed=seed, start=begin)
        window = TelemetryWindow.of(begin, 24)
        result = self._deliver(
            f"scenario:{name}",
            seed,
            label,
            window,
            built.records,
            output=output,
            ingest=ingest,
            incident=built.incident,
        )
        result.subject = built.subject
        return result


def catalog() -> dict[str, Any]:
    descriptions = {
        "auth": "logins, logouts and failures (noise: failures from unusual sources)",
        "dns": "DNS queries (noise: rare / NXDOMAIN names under rare.example)",
        "web": "HTTP requests (noise: 4xx/5xx responses)",
        "process": "process starts (noise: unusual images, modeled only)",
        "file": "file create/modify/read (noise: sensitive paths)",
        "identity": "group/role/account changes (noise: role assignments, new credentials)",
        "cloud": "cloud control-plane API calls (noise: policy changes from external sources)",
    }
    return {
        "generators": [{"name": g, "description": descriptions[g]} for g in GENERATORS],
        "scenarios": [{"name": n, "description": d} for n, d in sorted(SCENARIOS.items())],
    }
