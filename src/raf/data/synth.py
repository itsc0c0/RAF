"""Deterministic synthetic organizations and telemetry (shared by R$F Range and R$F Forge).

Everything produced here is fictional and marked synthetic: names use the reserved ``.example``
domains, external addresses come from the RFC 5737 documentation ranges, and "attacks" are
*modeled as events* - no payloads, exploits or real credentials exist anywhere.

The same (configuration, seed) always produces the same organization and the same events.
"""

from __future__ import annotations

import random
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from raf.core.ids import digest

# --------------------------------------------------------------------------- organization model

FIRST_NAMES = [
    "ada",
    "ben",
    "chloe",
    "dmitri",
    "elena",
    "farah",
    "george",
    "hana",
    "ivan",
    "julia",
    "kofi",
    "lena",
    "marco",
    "nadia",
    "oscar",
    "priya",
    "quinn",
    "rosa",
    "samir",
    "tara",
    "umar",
    "vera",
    "wei",
    "xenia",
    "yusuf",
    "zoe",
]
LAST_NAMES = [
    "adams",
    "baker",
    "cohen",
    "diaz",
    "evans",
    "fischer",
    "garcia",
    "haddad",
    "ito",
    "jensen",
    "khan",
    "lopez",
    "mendes",
    "novak",
    "okoro",
    "petrov",
    "quist",
    "rossi",
    "sato",
    "tanaka",
    "ueda",
    "varga",
    "wong",
    "yilmaz",
]
DEPARTMENT_TITLES = {
    "engineering": "Software engineer",
    "finance": "Financial analyst",
    "hr": "HR partner",
    "operations": "Systems administrator",
    "sales": "Account manager",
    "marketing": "Marketing specialist",
    "legal": "Counsel",
    "support": "Support engineer",
    "security": "Security analyst",
}
# service -> (host suffix, port, protocol, criticality, zone, internet facing)
SERVICE_CATALOG: dict[str, tuple[str, int, str, str, str, bool]] = {
    "dns": ("DC-01", 53, "dns", "high", "SERVERS", False),
    "directory": ("DC-01", 636, "ldaps", "critical", "SERVERS", False),
    "web": ("WEB-01", 443, "https", "medium", "DMZ", True),
    "database": ("DB-01", 5432, "postgres", "critical", "SERVERS", False),
    "git": ("GIT-01", 22, "ssh", "medium", "SERVERS", False),
    "mail": ("MAIL-01", 443, "https", "high", "DMZ", True),
    "file": ("FILE-01", 445, "smb", "high", "SERVERS", False),
    "ci": ("CI-01", 443, "https", "high", "SERVERS", False),
    "vpn": ("VPN-01", 443, "https", "high", "DMZ", True),
    "backup": ("BACKUP-01", 8443, "https", "high", "SERVERS", False),
    "monitoring": ("MON-01", 9090, "http", "medium", "SERVERS", False),
}
DOC_EXTERNAL_NETS = ("203.0.113", "198.51.100", "192.0.2")
BENIGN_EXTERNAL = [
    "updates.vendor.example",
    "docs.example.org",
    "mail.provider.example",
    "cdn.example.net",
    "news.example.com",
]


@dataclass
class OrgUser:
    name: str
    full_name: str
    department: str
    title: str
    workstation: str | None
    admin: bool = False
    mfa: bool = True


@dataclass
class OrgHost:
    name: str
    ip: str
    network: str
    os: str
    role: str
    criticality: str
    owner: str | None = None
    internet_facing: bool = False
    public_ip: str | None = None


@dataclass
class OrgService:
    name: str
    host: str
    port: int
    protocol: str
    criticality: str
    internet_facing: bool = False


@dataclass
class SyntheticOrg:
    name: str
    domain: str
    users: list[OrgUser] = field(default_factory=list)
    hosts: list[OrgHost] = field(default_factory=list)
    networks: list[dict[str, Any]] = field(default_factory=list)
    services: list[OrgService] = field(default_factory=list)
    groups: dict[str, list[str]] = field(default_factory=dict)
    roles: dict[str, dict[str, Any]] = field(default_factory=dict)
    identities: list[dict[str, Any]] = field(default_factory=list)
    reachability: list[tuple[str, str, list[str], str]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    controls: dict[str, Any] = field(default_factory=dict)

    def host(self, name: str) -> OrgHost | None:
        return next((h for h in self.hosts if h.name.lower() == name.lower()), None)

    def ip_of(self, name: str) -> str:
        host = self.host(name)
        return host.ip if host else "10.0.0.1"

    def workstation_users(self) -> list[OrgUser]:
        return [u for u in self.users if u.workstation]

    def servers(self) -> list[OrgHost]:
        return [h for h in self.hosts if h.role != "workstation"]

    def service_hosts(self, service: str) -> list[str]:
        return [s.host for s in self.services if s.name == service]


@dataclass
class OrgConfig:
    name: str
    employees: int = 30
    workstations: int = 20
    servers: int = 5
    departments: list[str] = field(default_factory=lambda: ["engineering", "finance", "hr", "operations"])
    services: list[str] = field(default_factory=lambda: ["dns", "web", "database", "git"])
    admins: int = 2
    mfa_rate: float = 0.8
    segmentation: bool = True
    edr: bool = True
    event_rate: int = 12  # events per active user per working hour
    vulnerabilities: int = 3

    def validate(self) -> OrgConfig:
        from raf.core.errors import InvalidInputError

        if not 1 <= self.employees <= 2000:
            raise InvalidInputError("employees must be between 1 and 2000.")
        if not 0 <= self.workstations <= 2000:
            raise InvalidInputError("workstations must be between 0 and 2000.")
        if not 0 <= self.servers <= 200:
            raise InvalidInputError("servers must be between 0 and 200.")
        if not 1 <= len(self.departments) <= 20:
            raise InvalidInputError("Give between 1 and 20 departments.")
        unknown = sorted(set(self.services) - set(SERVICE_CATALOG))
        if unknown:
            raise InvalidInputError(
                f"Unknown services: {', '.join(unknown)}.", hint="Known services: " + ", ".join(sorted(SERVICE_CATALOG))
            )
        if not 0.0 <= self.mfa_rate <= 1.0:
            raise InvalidInputError("mfa_rate must be between 0 and 1.")
        if not 1 <= self.event_rate <= 500:
            raise InvalidInputError("event_rate must be between 1 and 500 events per user-hour.")
        if not 0 <= self.vulnerabilities <= 50:
            raise InvalidInputError("vulnerabilities must be between 0 and 50.")
        if not 0 <= self.admins <= 50:
            raise InvalidInputError("admins must be between 0 and 50.")
        return self


def _slug(text: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in text.lower()).strip("-")


def build_org(config: OrgConfig, seed: int) -> SyntheticOrg:
    """A generic synthetic organization (deterministic for a configuration and seed)."""
    config.validate()
    rng = random.Random(f"org:{config.name}:{seed}")
    prefix = config.name.upper().replace("_", "-")[:12]
    org = SyntheticOrg(name=config.name, domain=f"{_slug(config.name)}.example")
    org.controls = {
        "mfa_rate": config.mfa_rate,
        "segmentation": config.segmentation,
        "edr": config.edr,
        "event_rate": config.event_rate,
    }
    has_dmz = any(SERVICE_CATALOG[s][5] for s in config.services)
    org.networks = [
        {"name": "INTERNET", "cidr": "0.0.0.0/0", "zone": "external"},
        {"name": f"{prefix}-CORP", "cidr": "10.10.0.0/16", "zone": "corporate"},
        {"name": f"{prefix}-SERVERS", "cidr": "10.20.0.0/16", "zone": "servers", "criticality": "high"},
    ]
    if has_dmz:
        org.networks.append({"name": f"{prefix}-DMZ", "cidr": "10.40.0.0/16", "zone": "dmz"})
    corp, servers_net, dmz = f"{prefix}-CORP", f"{prefix}-SERVERS", f"{prefix}-DMZ"
    # users
    used: set[str] = set()
    pairs = [(f, la) for la in LAST_NAMES for f in FIRST_NAMES]
    rng.shuffle(pairs)
    for index in range(config.employees):
        first, last = pairs[index % len(pairs)]
        base = f"{first[0]}{last}"
        name, n = base, 2
        while name in used:
            name, n = f"{base}{n}", n + 1
        used.add(name)
        department = config.departments[index % len(config.departments)]
        workstation = f"{prefix}-WS-{index + 1:02d}" if index < config.workstations else None
        org.users.append(
            OrgUser(
                name=name,
                full_name=f"{first.title()} {last.title()}",
                department=department,
                title=DEPARTMENT_TITLES.get(department, "Staff"),
                workstation=workstation,
                mfa=rng.random() < config.mfa_rate,
            )
        )
    ops_users = [u for u in org.users if u.department == "operations"] or org.users
    for user in ops_users[: config.admins]:
        user.admin = True
    # hosts
    for user in org.users:
        if user.workstation:
            octet = len([h for h in org.hosts if h.role == "workstation"]) + 20
            os_name = rng.choice(["windows-11", "windows-11", "macos-15", "ubuntu-24.04"])
            org.hosts.append(
                OrgHost(
                    name=user.workstation,
                    ip=f"10.10.{1 + octet // 250}.{octet % 250 + 1}",
                    network=corp,
                    os=os_name,
                    role="workstation",
                    criticality="medium",
                    owner=user.name,
                )
            )
    server_index = 0
    for service in config.services:
        suffix, port, protocol, crit, zone, internet = SERVICE_CATALOG[service]
        host_name = f"{prefix}-{suffix}"
        network = dmz if zone == "DMZ" else servers_net
        if org.host(host_name) is None:
            server_index += 1
            net_octet = 40 if zone == "DMZ" else 20
            org.hosts.append(
                OrgHost(
                    name=host_name,
                    ip=f"10.{net_octet}.0.{10 + server_index}",
                    network=network,
                    os="ubuntu-24.04" if suffix != "DC-01" else "windows-server-2022",
                    role=f"{service}-server",
                    criticality=crit,
                    owner=ops_users[0].name if ops_users else None,
                    internet_facing=internet,
                    public_ip=f"198.51.100.{100 + server_index}" if internet else None,
                )
            )
        else:
            existing = org.host(host_name)
            if existing is not None and _crit_rank(crit) > _crit_rank(existing.criticality):
                existing.criticality = crit
        org.services.append(
            OrgService(
                name=f"{_slug(config.name)}-{service}",
                host=host_name,
                port=port,
                protocol=protocol,
                criticality=crit,
                internet_facing=internet,
            )
        )
    while len(org.servers()) < config.servers:
        server_index += 1
        org.hosts.append(
            OrgHost(
                name=f"{prefix}-SRV-{server_index:02d}",
                ip=f"10.20.1.{10 + server_index}",
                network=servers_net,
                os="ubuntu-24.04",
                role="app-server",
                criticality=rng.choice(["medium", "high"]),
            )
        )
    # groups, roles, identities
    for department in config.departments:
        org.groups[department] = [f"user:{u.name}" for u in org.users if u.department == department]
    org.groups["all-staff"] = [f"user:{u.name}" for u in org.users]
    admins = [u for u in org.users if u.admin]
    org.identities = [
        {"name": f"adm-{u.name}", "kind": "admin", "owner": u.name, "privileged": True, "mfa": u.mfa} for u in admins
    ]
    org.groups["it-admins"] = [f"identity:adm-{u.name}" for u in admins]
    server_names = [h.name for h in org.servers()]
    org.roles["server-admin"] = {
        "privileged": True,
        "holders": ["group:it-admins"],
        "grants": [("ADMIN_OF", f"host:{s}", {}) for s in server_names],
    }
    for svc in org.services:
        role = f"{svc.name.split('-', 1)[-1]}-user"
        holders = (
            ["group:all-staff"]
            if svc.internet_facing or svc.name.endswith(("dns", "mail"))
            else [f"group:{config.departments[0]}"]
        )
        if svc.name.endswith("database"):
            holders = []
        org.roles[role] = {
            "privileged": False,
            "holders": holders,
            "grants": [("CAN_ACCESS", f"service:{svc.name}", {"access": "use"})],
        }
        if svc.name.endswith(("database", "ci", "backup")):
            svc_identity = f"svc-{svc.name.split('-', 1)[-1]}"
            org.identities.append(
                {
                    "name": svc_identity,
                    "kind": "service",
                    "owner": admins[0].name if admins else "",
                    "privileged": svc.name.endswith(("ci", "backup")),
                    "mfa": False,
                }
            )
    # reachability (network policy); without segmentation internal zones are flat ("any")
    slug = _slug(config.name)

    def ports_or_any(ports: list[str]) -> list[str]:
        return ports if config.segmentation else ["any"]

    server_ports = sorted(
        {f"tcp/{s.port}" if s.protocol != "dns" else "udp/53" for s in org.services if not s.internet_facing}
    )
    org.reachability.append((corp, servers_net, ports_or_any(server_ports or ["tcp/443"]), f"{slug}-fw:corp-servers"))
    org.reachability.append((corp, "INTERNET", ["tcp/80", "tcp/443"], f"{slug}-fw:corp-egress"))
    org.reachability.append((servers_net, "INTERNET", ["tcp/443"], f"{slug}-fw:servers-egress"))
    if has_dmz:
        public_ports = sorted({f"tcp/{s.port}" for s in org.services if s.internet_facing})
        org.reachability.append(("INTERNET", dmz, public_ports, f"{slug}-fw:internet-dmz"))
        org.reachability.append((corp, dmz, ["tcp/443"], f"{slug}-fw:corp-dmz"))
        org.reachability.append((dmz, servers_net, ports_or_any(["tcp/5432", "tcp/8443"]), f"{slug}-fw:dmz-servers"))
    # synthetic vulnerabilities
    candidates = sorted(org.services, key=lambda s: s.name)
    for index in range(min(config.vulnerabilities, len(candidates))):
        affected = candidates[rng.randrange(len(candidates))]
        cvss = round(rng.uniform(4.0, 9.8), 1)
        org.vulnerabilities.append(
            {
                "id": f"SIM-{slug.upper()}-{seed % 10000:04d}-{index + 1:02d}",
                "cvss": cvss,
                "affects": f"service:{affected.name}",
                "exploit_available": cvss >= 8.5 and rng.random() < 0.5,
                "summary": f"Synthetic advisory for {affected.name} (range {config.name}).",
            }
        )
    return org


def _crit_rank(level: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(level, -1)


def raven_org() -> SyntheticOrg:
    """Raven Industries (the demo organization) in the generic org model, for Forge populations."""
    from raf.data import raven

    org = SyntheticOrg(name="raven", domain=raven.DOMAIN)
    for user in raven.USERS:
        org.users.append(
            OrgUser(
                name=user["name"],
                full_name=user["full_name"],
                department=user["department"],
                title=user["title"],
                workstation=user["workstation"],
                admin=user["name"] in ("sarah", "frank"),
            )
        )
    for host in raven.HOSTS:
        org.hosts.append(
            OrgHost(
                name=host["name"],
                ip=host["ip"],
                network=host["network"],
                os=host["os"],
                role=host["role"],
                criticality=host["criticality"],
                owner=host.get("owner"),
                internet_facing=bool(host.get("internet_facing")),
                public_ip=host.get("public_ip"),
            )
        )
    for svc in raven.SERVICES:
        org.services.append(
            OrgService(
                name=svc["name"],
                host=svc["host"],
                port=svc["port"],
                protocol=svc["protocol"],
                criticality=svc["criticality"],
                internet_facing=bool(svc.get("internet_facing")),
            )
        )
    org.identities = [dict(i) for i in raven.IDENTITIES]
    org.networks = [dict(n) for n in raven.NETWORKS]
    return org


# --------------------------------------------------------------------------- inventory records


def _obj(otype: str, name: str, **fields: Any) -> dict[str, Any]:
    record: dict[str, Any] = {"kind": "object", "type": otype, "name": name, "synthetic": True}
    record.update({k: v for k, v in fields.items() if v is not None})
    return record


def _rel(source: str, rtype: str, target: str, **metadata: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "kind": "relationship",
        "source": source,
        "type": rtype,
        "target": target,
        "confidence": 0.95,
        "synthetic": True,
    }
    if metadata:
        record["metadata"] = metadata
    return record


def inventory_records(org: SyntheticOrg) -> list[dict[str, Any]]:
    tag = f"range:{org.name}"
    records: list[dict[str, Any]] = [
        _obj("organization", org.name.title(), key=org.name, metadata={"domain": org.domain}, tags=[tag])
    ]
    for net in org.networks:
        records.append(
            _obj(
                "network",
                net["name"],
                metadata={"cidr": net["cidr"], "zone": net["zone"]},
                criticality=net.get("criticality"),
                tags=[tag],
            )
        )
    for host in org.hosts:
        meta: dict[str, Any] = {"os": host.os, "role": host.role, "ip": host.ip}
        if host.owner:
            meta["owner"] = host.owner
        if host.public_ip:
            meta["public_ip"] = host.public_ip
        if org.controls.get("edr") is not None:
            meta["edr"] = bool(org.controls.get("edr"))
        records.append(
            _obj(
                "host",
                host.name,
                metadata=meta,
                criticality=host.criticality,
                internet_facing=host.internet_facing or None,
                tags=[tag, host.role],
            )
        )
        records.append(_obj("ip", host.ip, metadata={"private": True}))
        records.append(_rel(f"host:{host.name}", "HAS_ADDRESS", f"ip:{host.ip}"))
        records.append(_rel(f"host:{host.name}", "MEMBER_OF", f"network:{host.network}"))
        if host.public_ip:
            records.append(_obj("ip", host.public_ip, metadata={"private": False}))
            records.append(_rel(f"host:{host.name}", "HAS_ADDRESS", f"ip:{host.public_ip}"))
    for user in org.users:
        records.append(
            _obj(
                "user",
                user.name,
                metadata={
                    "full_name": user.full_name,
                    "department": user.department,
                    "title": user.title,
                    "email": f"{user.name}@{org.domain}",
                    "mfa": user.mfa,
                },
                aliases=[user.full_name],
                tags=[tag, "employee"],
            )
        )
        if user.workstation:
            records.append(_rel(f"user:{user.name}", "OWNS", f"host:{user.workstation}"))
    for ident in org.identities:
        records.append(
            _obj(
                "identity",
                ident["name"],
                metadata={"kind": ident["kind"], "owner": ident["owner"], "mfa": ident["mfa"]},
                privileged=ident["privileged"],
                tags=[tag, ident["kind"]],
            )
        )
        if ident["kind"] == "admin" and ident.get("owner"):
            records.append(_rel(f"user:{ident['owner']}", "HAS_IDENTITY", f"identity:{ident['name']}"))
    for group, members in sorted(org.groups.items()):
        records.append(_obj("group", group, tags=[tag]))
        records.extend(_rel(member, "MEMBER_OF", f"group:{group}") for member in members)
    for role, spec in sorted(org.roles.items()):
        records.append(_obj("role", role, privileged=spec["privileged"], tags=[tag]))
        records.extend(_rel(holder, "HAS_ROLE", f"role:{role}") for holder in spec["holders"])
        records.extend(_rel(f"role:{role}", rtype, target, **meta) for rtype, target, meta in spec["grants"])
    for svc in org.services:
        records.append(
            _obj(
                "service",
                svc.name,
                metadata={"port": svc.port, "protocol": svc.protocol, "host": svc.host},
                criticality=svc.criticality,
                internet_facing=svc.internet_facing or None,
                tags=[tag],
            )
        )
        records.append(_rel(f"host:{svc.host}", "RUNS", f"service:{svc.name}"))
        if svc.internet_facing:
            records.append(_rel("network:INTERNET", "CAN_REACH", f"service:{svc.name}", ports=[f"tcp/{svc.port}"]))
    for ident in org.identities:
        if ident["kind"] == "service":
            purpose = ident["name"].removeprefix("svc-")
            for host_name in [s.host for s in org.services if s.name.endswith(purpose)]:
                records.append(
                    _rel(f"host:{host_name}", "USES", f"identity:{ident['name']}", credential="service configuration")
                )
    for src, dst, ports, rule in org.reachability:
        records.append(_rel(f"network:{src}", "CAN_REACH", f"network:{dst}", ports=ports, policy=rule))
    for vuln in org.vulnerabilities:
        records.append(
            _obj(
                "vulnerability",
                vuln["id"],
                metadata={
                    "cvss": vuln["cvss"],
                    "summary": vuln["summary"],
                    "exploit_available": vuln["exploit_available"],
                    "synthetic": True,
                },
            )
        )
        records.append(_rel(f"vulnerability:{vuln['id']}", "AFFECTS", vuln["affects"]))
    return records


# --------------------------------------------------------------------------- telemetry


@dataclass
class TelemetryWindow:
    start: datetime
    end: datetime

    @classmethod
    def of(cls, start: datetime, hours: float) -> TelemetryWindow:
        return cls(start, start + timedelta(hours=hours))

    def contains(self, when: datetime) -> bool:
        return self.start <= when < self.end

    def random_time(self, rng: random.Random) -> datetime:
        span = max(1.0, (self.end - self.start).total_seconds())
        return self.start + timedelta(seconds=rng.uniform(0, span))


class _Out:
    def __init__(self, namespace: str, seed: int, tags: Sequence[str]) -> None:
        self.namespace = namespace
        self.seed = seed
        self.tags = list(tags)
        self.items: list[dict[str, Any]] = []

    def add(self, when: datetime, event_type: str, **fields: Any) -> dict[str, Any]:
        index = len(self.items)
        record: dict[str, Any] = {
            "kind": "event",
            "id": "event:" + digest(self.namespace, self.seed, index, length=24),
            "timestamp": when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": event_type,
            "synthetic": True,
            "tags": self.tags,
        }
        record.update({k: v for k, v in fields.items() if v is not None})
        self.items.append(record)
        return record


def _external_ip(rng: random.Random) -> str:
    return f"{rng.choice(DOC_EXTERNAL_NETS)}.{rng.randint(2, 254)}"


def _working(when: datetime) -> bool:
    return when.weekday() < 5 and 8 <= when.hour < 18


def routine_activity(
    org: SyntheticOrg, window: TelemetryWindow, seed: int, *, rate: int = 12, namespace: str = "routine"
) -> list[dict[str, Any]]:
    """Background activity of every employee with a workstation, hour by hour, plus scheduled jobs."""
    out = _Out(f"{org.name}:{namespace}:{window.start.isoformat()}", seed, ["synthetic", namespace])
    rng = random.Random(f"{org.name}:{seed}:{window.start.isoformat()}")
    hour = window.start.replace(minute=0, second=0, microsecond=0)
    internal = [s for s in org.services if not s.internet_facing]
    while hour < window.end:
        for user in org.workstation_users():
            ws = user.workstation or ""
            ws_ip = org.ip_of(ws)
            active = _working(hour) or rng.random() < 0.03
            if not active:
                continue
            if hour.hour == 8 or (not _working(hour)):
                t = hour + timedelta(minutes=rng.randint(0, 50))
                if window.contains(t):
                    if rng.random() < 0.08:
                        out.add(
                            t - timedelta(seconds=30),
                            "auth.failure",
                            actor=user.name,
                            target=ws,
                            outcome="failure",
                            severity="low",
                            attributes={"src_ip": ws_ip, "method": "kerberos", "reason": "bad password"},
                        )
                    out.add(
                        t,
                        "auth.login",
                        actor=user.name,
                        target=ws,
                        outcome="success",
                        attributes={
                            "src_ip": ws_ip,
                            "method": "kerberos",
                            "logon_type": "interactive",
                            "mfa": user.mfa,
                        },
                    )
            count = max(1, int(rng.gauss(rate, rate / 4)))
            for _ in range(count):
                t = hour + timedelta(seconds=rng.randint(0, 3599))
                if not window.contains(t):
                    continue
                kind = rng.random()
                if kind < 0.35:
                    domain = rng.choice([*BENIGN_EXTERNAL, f"intranet.{org.domain}", f"portal.{org.domain}"])
                    out.add(t, "dns.query", actor=ws, target=domain, attributes={"src_ip": ws_ip, "query_type": "A"})
                elif kind < 0.6:
                    out.add(
                        t,
                        "http.request",
                        actor=ws,
                        target=f"https://{rng.choice(BENIGN_EXTERNAL)}/",
                        outcome="success",
                        attributes={
                            "method": "GET",
                            "status": 200,
                            "user": user.name,
                            "src_ip": ws_ip,
                            "bytes": rng.randint(2_000, 90_000),
                        },
                    )
                elif kind < 0.85:
                    ws_host = org.host(ws)
                    windows = ws_host is not None and "windows" in ws_host.os
                    image = rng.choice(
                        ["chrome.exe", "outlook.exe", "excel.exe", "teams.exe"]
                        if windows
                        else ["/usr/bin/bash", "/usr/bin/python3", "/usr/bin/git", "/usr/bin/vim"]
                    )
                    out.add(
                        t,
                        "process.start",
                        actor=user.name,
                        host=ws,
                        attributes={"image": image, "pid": rng.randint(1000, 60000), "command_line": image},
                    )
                elif internal:
                    svc = rng.choice(internal)
                    out.add(
                        t,
                        "service.access",
                        actor=user.name,
                        target=svc.name,
                        outcome="success",
                        attributes={"src_ip": ws_ip, "dst_ip": org.ip_of(svc.host), "dst_port": svc.port},
                    )
                    out.add(
                        t + timedelta(seconds=1),
                        "network.connection",
                        actor=ws,
                        target=org.ip_of(svc.host),
                        attributes={
                            "src_ip": ws_ip,
                            "dst_ip": org.ip_of(svc.host),
                            "dst_port": svc.port,
                            "protocol": "tcp",
                        },
                    )
            if hour.hour == 17 and _working(hour):
                t = hour + timedelta(minutes=rng.randint(0, 50))
                if window.contains(t):
                    out.add(t, "auth.logout", actor=user.name, target=ws, attributes={"src_ip": ws_ip})
        # scheduled jobs of service identities
        for ident in org.identities:
            if ident["kind"] != "service" or hour.hour not in (2, 10, 14):
                continue
            hosts = [s.host for s in org.services if s.name.endswith(ident["name"].removeprefix("svc-"))]
            if not hosts:
                continue
            t = hour + timedelta(minutes=5)
            if window.contains(t):
                out.add(
                    t,
                    "auth.login",
                    actor=ident["name"],
                    target=hosts[0],
                    outcome="success",
                    attributes={"src_ip": org.ip_of(hosts[0]), "method": "key", "logon_type": "service"},
                )
        hour += timedelta(hours=1)
    return out.items


# --------------------------------------------------------------------------- Forge generators


GENERATORS = ("auth", "dns", "web", "process", "file", "identity", "cloud")


def generate(
    kind: str, org: SyntheticOrg, *, count: int, window: TelemetryWindow, seed: int, noise: float = 0.05
) -> list[dict[str, Any]]:
    """``count`` synthetic events of one kind spread over the window; ``noise`` is the share of
    unusual-but-benign records (failures, odd hours, rare destinations)."""
    out = _Out(
        f"forge:{org.name}:{kind}:{window.start.isoformat()}:{count}:{noise}", seed, ["synthetic", "forge", kind]
    )
    rng = random.Random(f"forge:{kind}:{seed}")
    users = org.workstation_users() or org.users
    if not users:
        return []
    servers = org.servers() or org.hosts
    for _ in range(count):
        user = rng.choice(users)
        ws = user.workstation or (servers[0].name if servers else "host")
        ws_ip = org.ip_of(ws)
        odd = rng.random() < noise
        t = window.random_time(rng)
        if kind == "auth":
            target = rng.choice([ws] * 4 + [h.name for h in servers[:6]])
            if odd:
                out.add(
                    t,
                    "auth.failure",
                    actor=user.name,
                    target=target,
                    outcome="failure",
                    severity="low",
                    attributes={
                        "src_ip": _external_ip(rng) if rng.random() < 0.5 else ws_ip,
                        "method": "password",
                        "reason": rng.choice(["bad password", "unknown user"]),
                    },
                )
            else:
                out.add(
                    t,
                    "auth.login",
                    actor=user.name,
                    target=target,
                    outcome="success",
                    attributes={
                        "src_ip": ws_ip,
                        "method": rng.choice(["kerberos", "publickey", "password+otp"]),
                        "mfa": user.mfa,
                    },
                )
        elif kind == "dns":
            domain = (
                f"{rng.choice(['cdn', 'api', 'assets', 'telemetry'])}{rng.randint(1, 999)}.rare.example"
                if odd
                else rng.choice([*BENIGN_EXTERNAL, f"intranet.{org.domain}"])
            )
            out.add(
                t,
                "dns.query",
                actor=ws,
                target=domain,
                attributes={
                    "src_ip": ws_ip,
                    "query_type": rng.choice(["A", "AAAA"]),
                    "rcode": "NXDOMAIN" if odd and rng.random() < 0.5 else "NOERROR",
                },
            )
        elif kind == "web":
            host = rng.choice(BENIGN_EXTERNAL)
            path = rng.choice(["/", "/index.html", "/api/v1/items", "/docs", "/login"])
            status = rng.choice([403, 404, 500]) if odd else 200
            out.add(
                t,
                "http.request",
                actor=ws,
                target=f"https://{host}{path}",
                outcome="success" if status == 200 else "failure",
                attributes={
                    "method": rng.choice(["GET", "GET", "POST"]),
                    "status": status,
                    "user": user.name,
                    "src_ip": ws_ip,
                    "bytes": rng.randint(500, 200_000),
                    "user_agent": "Mozilla/5.0 (synthetic)",
                },
            )
        elif kind == "process":
            image = rng.choice(
                ["/usr/bin/curl", "powershell.exe -enc (modeled)", "/usr/bin/nc (modeled)"]
                if odd
                else ["/usr/bin/python3", "/usr/bin/git", "chrome.exe", "excel.exe"]
            )
            out.add(
                t,
                "process.start",
                actor=user.name,
                host=ws,
                attributes={
                    "image": image.split(" ")[0],
                    "pid": rng.randint(1000, 60000),
                    "command_line": image,
                    "parent_image": "explorer.exe",
                },
            )
        elif kind == "file":
            path = rng.choice(
                [f"/home/{user.name}/notes.txt", f"/home/{user.name}/report.xlsx", f"/home/{user.name}/build.log"]
            )
            if odd:
                path = rng.choice(["/etc/cron.d/backup", f"/home/{user.name}/.ssh/authorized_keys"])
            out.add(
                t,
                rng.choice(["file.create", "file.modify", "file.read"]),
                actor=user.name,
                host=ws,
                target=path,
                attributes={"size": rng.randint(100, 5_000_000)},
            )
        elif kind == "identity":
            group = rng.choice(sorted(org.groups) or ["all-staff"])
            event_type = rng.choice(["iam.group.add", "iam.group.remove", "iam.role.assign", "iam.user.enable"])
            if odd:
                event_type = rng.choice(["iam.role.assign", "iam.credential.create", "iam.user.disable"])
            admin = next((i["name"] for i in org.identities if i["kind"] == "admin"), "it-admin")
            out.add(
                t,
                event_type,
                actor=admin,
                target=user.name,
                outcome="success",
                message=f"{event_type} for {user.name} (synthetic)",
                attributes={"group": group, "ticket": f"SIM-{rng.randint(1000, 9999)}"},
            )
        elif kind == "cloud":
            action = rng.choice(["GetObject", "PutObject", "ListBuckets", "DescribeInstances"])
            if odd:
                action = rng.choice(["PutBucketPolicy", "CreateAccessKey", "DeleteTrail"])
            resource = rng.choice([f"{org.name}-backups", f"{org.name}-logs", f"{org.name}-artifacts"])
            out.add(
                t,
                "cloud.api",
                actor=f"svc-{org.name}-automation" if rng.random() < 0.5 else user.name,
                target=resource,
                outcome="success",
                attributes={
                    "action": action,
                    "src_ip": _external_ip(rng) if odd else ws_ip,
                    "region": "synthetic-1",
                    "provider": "synthetic-cloud",
                },
            )
        else:
            from raf.core.errors import InvalidInputError

            raise InvalidInputError(f"Unknown generator '{kind}'.", hint="Use: " + ", ".join(GENERATORS))
    out.items.sort(key=lambda r: (r["timestamp"], r["id"]))
    return out.items


# --------------------------------------------------------------------------- scenarios


@dataclass
class Scenario:
    name: str
    title: str
    description: str
    records: list[dict[str, Any]]
    incident: dict[str, Any]
    subject: str  # the user at the center of the story


SCENARIOS = {
    "suspicious-access": "Off-hours VPN login with an unusual source, first-time access to a sensitive server, "
    "bulk file read and a large outbound transfer (all modeled)",
    "credential-risk": "A token written to a developer's file, a service account used from that host, a new "
    "access key and a password-spray pattern against an admin account (all modeled)",
    "lateral-movement": "A workstation session followed by remote logons across hosts with an admin identity "
    "(benign remote sessions, modeled)",
}


def scenario(name: str, org: SyntheticOrg, *, seed: int, start: datetime) -> Scenario:
    if name not in SCENARIOS:
        from raf.core.errors import InvalidInputError

        raise InvalidInputError(f"Unknown scenario '{name}'.", hint="Scenarios: " + ", ".join(sorted(SCENARIOS)))
    rng = random.Random(f"scenario:{name}:{seed}")
    incident_name = f"SIM-{name.upper()}-{seed}"
    out = _Out(f"scenario:{org.name}:{name}:{start.isoformat()}", seed, ["synthetic", "forge", f"scenario:{name}"])
    users = [u for u in org.workstation_users() if not u.admin] or org.users
    user = users[rng.randrange(len(users))]
    servers = sorted(org.servers(), key=lambda h: (-_crit_rank(h.criticality), h.name))
    sensitive = servers[0] if servers else None
    attacker_ip = f"203.0.113.{rng.randint(10, 250)}"
    common: dict[str, Any] = {"incident": incident_name}
    t = start.replace(hour=2, minute=rng.randint(5, 20), second=0, microsecond=0)
    if name == "suspicious-access":
        vpn = next((h for h in org.hosts if "vpn" in h.role.lower() or "vpn" in h.name.lower()), None)
        entry = vpn.name if vpn else (user.workstation or "host")
        for i in range(rng.randint(3, 6)):
            out.add(
                t + timedelta(seconds=7 * i),
                "auth.failure",
                actor=user.name,
                target=entry,
                outcome="failure",
                severity="low",
                attributes={"src_ip": attacker_ip, "method": "password", "protocol": "vpn"},
                **common,
            )
        t += timedelta(minutes=2)
        out.add(
            t,
            "auth.login",
            actor=user.name,
            target=entry,
            outcome="success",
            severity="medium",
            message=f"VPN login for {user.name} at an unusual hour from {attacker_ip}",
            attributes={"src_ip": attacker_ip, "method": "password", "mfa": False, "protocol": "vpn"},
            **common,
        )
        if sensitive is not None:
            t += timedelta(minutes=3)
            out.add(
                t,
                "auth.login",
                actor=user.name,
                target=sensitive.name,
                outcome="success",
                severity="medium",
                message=f"First logon of {user.name} to {sensitive.name}",
                attributes={"src_ip": org.ip_of(entry), "method": "password", "protocol": "ssh", "first_time": True},
                **common,
            )
            t += timedelta(minutes=2)
            out.add(
                t,
                "process.start",
                actor=user.name,
                host=sensitive.name,
                attributes={
                    "image": "/usr/bin/find",
                    "pid": rng.randint(2000, 60000),
                    "command_line": "find /srv/data -name *.csv",
                },
                **common,
            )
            t += timedelta(minutes=3)
            out.add(
                t,
                "file.read",
                actor=user.name,
                host=sensitive.name,
                target="/srv/data/customers.csv",
                severity="medium",
                attributes={"size": 48_200_000},
                **common,
            )
            t += timedelta(minutes=2)
            out.add(
                t,
                "dns.query",
                actor=sensitive.name,
                target="files.exfil-test.example",
                severity="medium",
                attributes={"src_ip": sensitive.ip, "query_type": "A", "answers": ["198.51.100.23"]},
                **common,
            )
            t += timedelta(minutes=1)
            out.add(
                t,
                "network.connection",
                actor=sensitive.name,
                target="198.51.100.23",
                severity="high",
                message="Large outbound transfer to a reserved test address (modeled)",
                attributes={
                    "src_ip": sensitive.ip,
                    "dst_ip": "198.51.100.23",
                    "dst_port": 443,
                    "protocol": "tcp",
                    "bytes_out": 48_350_112,
                },
                **common,
            )
            out.add(
                t + timedelta(minutes=1),
                "alert",
                actor=sensitive.name,
                target=sensitive.name,
                severity="high",
                message="Unusual off-hours data access followed by outbound transfer",
                attributes={"rule": "SIM-ANOMALY-01", "tool": "synthetic-edr"},
                **common,
            )
        out.add(
            t + timedelta(minutes=10),
            "auth.logout",
            actor=user.name,
            target=entry,
            attributes={"src_ip": attacker_ip},
            **common,
        )
    elif name == "credential-risk":
        dev_host = user.workstation or (servers[-1].name if servers else "host")
        service_id = next((i["name"] for i in org.identities if i["kind"] == "service"), f"svc-{org.name}-deploy")
        admin = next((i["name"] for i in org.identities if i["kind"] == "admin"), None)
        token_path = f"/home/{user.name}/project/.env"
        out.add(
            t,
            "file.create",
            actor=user.name,
            host=dev_host,
            target=token_path,
            severity="medium",
            message="A file containing an access token was written (value modeled, redacted)",
            attributes={"contains_secret": True, "secret_kind": "api token", "redacted": "tok_****1a2b"},
            relationships=[
                {
                    "source": f"host:{dev_host}",
                    "type": "USES",
                    "target": f"identity:{service_id}",
                    "metadata": {"credential_location": token_path, "synthetic": True},
                }
            ],
            **common,
        )
        t += timedelta(minutes=12)
        target_host = sensitive.name if sensitive else dev_host
        out.add(
            t,
            "auth.login",
            actor=service_id,
            target=target_host,
            outcome="success",
            severity="medium",
            message=f"{service_id} used from a developer workstation",
            attributes={"src_ip": org.ip_of(dev_host), "method": "token", "unusual_source": True},
            **common,
        )
        t += timedelta(minutes=5)
        out.add(
            t,
            "iam.credential.create",
            actor=user.name,
            target=service_id,
            outcome="success",
            severity="medium",
            message=f"New access key created for {service_id}",
            attributes={"key_id": f"SIMKEY{rng.randint(100000, 999999)}"},
            **common,
        )
        if admin:
            sources = [h.name for h in org.hosts if h.role == "workstation"][:5]
            for i, host in enumerate(sources):
                out.add(
                    t + timedelta(minutes=20, seconds=11 * i),
                    "auth.failure",
                    actor=admin,
                    target=host,
                    outcome="failure",
                    severity="low",
                    attributes={"src_ip": org.ip_of(host), "method": "password", "reason": "bad password"},
                    **common,
                )
    else:  # lateral-movement
        admin_ident = next((i["name"] for i in org.identities if i["kind"] == "admin"), None)
        hops = [h.name for h in org.hosts if h.role == "workstation"][:3] + [h.name for h in servers[:2]]
        source = user.workstation or (hops[0] if hops else "host")
        out.add(
            t,
            "auth.login",
            actor=user.name,
            target=source,
            outcome="success",
            attributes={"src_ip": org.ip_of(source), "method": "kerberos"},
            **common,
        )
        previous = source
        for hop in hops:
            if hop == previous:
                continue
            t += timedelta(minutes=rng.randint(2, 9))
            actor = admin_ident or user.name
            out.add(
                t,
                "auth.login",
                actor=actor,
                target=hop,
                outcome="success",
                severity="medium",
                message=f"Remote logon {previous} -> {hop} with {actor}",
                attributes={"src_ip": org.ip_of(previous), "method": "ntlm", "logon_type": "remote-interactive"},
                **common,
            )
            out.add(
                t + timedelta(seconds=3),
                "network.connection",
                actor=previous,
                target=org.ip_of(hop),
                attributes={
                    "src_ip": org.ip_of(previous),
                    "dst_ip": org.ip_of(hop),
                    "dst_port": 3389,
                    "protocol": "tcp",
                },
                **common,
            )
            previous = hop
    events = sorted(out.items, key=lambda r: (r["timestamp"], r["id"]))
    times = [e["timestamp"] for e in events]
    incident = {
        "kind": "incident",
        "name": incident_name,
        "title": f"Synthetic scenario: {name}",
        "severity": "medium",
        "status": "open",
        "description": SCENARIOS[name] + " (synthetic, R$F Forge)",
        "start": times[0] if times else None,
        "end": times[-1] if times else None,
        "tags": ["synthetic", "forge", f"scenario:{name}"],
    }
    return Scenario(
        name=name,
        title=f"Synthetic scenario: {name}",
        description=SCENARIOS[name],
        records=events,
        incident=incident,
        subject=user.name,
    )


def iter_jsonl(records: Sequence[dict[str, Any]]) -> Iterator[str]:
    import json

    for record in records:
        yield json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
