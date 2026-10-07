"""Surface analysis rules: explainable findings about the authorized external attack surface.

Every finding starts from a baseline severity for its rule and moves one level per named factor
(criticality, Internet exposure, ownership, intended exposure ...); each step is an
``explanation`` entry ``{"factor", "label", "sign"}`` (``+`` raises, ``-`` lowers), so a finding
always says why it has its severity. Rules only judge assets inside the authorized scope (except
``out-of-scope-asset``) and never consult the network: the imported data is all they see.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from raf.core.ids import finding_id, object_id
from raf.core.objects.models import EvidenceRef, Finding
from raf.core.objects.types import Severity
from raf.core.timeutil import format_ts
from raf.products.surface.graph import MAX_CHAIN, RESOLUTION_TYPES, DnsEntry, SurfaceModel
from raf.products.surface.model import PRODUCT, is_internal_address, name_covers

RULES: tuple[str, ...] = (
    "out-of-scope-asset",
    "unowned-asset",
    "expired-certificate",
    "expiring-certificate",
    "certificate-name-mismatch",
    "dangling-dns",
    "exposed-sensitive-service",
    "public-cloud-storage",
    "shadow-asset",
    "internal-address-in-dns",
)
DEFAULT_EXPIRING_DAYS = 30

_LEVELS = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
_KIND_LABEL = {
    "domain": "domain",
    "ip": "address",
    "service": "service",
    "cloud_asset": "cloud asset",
    "certificate": "certificate",
}
_HIGH = ("high", "critical")
_INHERITANCE = {
    "ip": " or the host or cloud asset that holds it",
    "service": " or the host running it",
    "domain": " or the cloud asset it names",
}

#: Ports where clients address the server by name (SNI / certificate name checks apply).
TLS_NAME_PORTS = frozenset(
    {443, 465, 563, 587, 636, 853, 989, 990, 992, 993, 995, 2083, 2087, 4443, 5061, 5986, 6443, 8443, 8883, 9443, 10443}
)

#: port -> (service, category, baseline severity when internet-facing)
SENSITIVE_PORTS: dict[int, tuple[str, str, Severity]] = {
    21: ("FTP", "file transfer", Severity.MEDIUM),
    22: ("SSH", "remote administration", Severity.MEDIUM),
    23: ("Telnet", "remote administration", Severity.HIGH),
    135: ("MS-RPC", "remote administration", Severity.HIGH),
    139: ("NetBIOS", "file sharing", Severity.HIGH),
    161: ("SNMP", "device management", Severity.MEDIUM),
    445: ("SMB", "file sharing", Severity.HIGH),
    623: ("IPMI", "out-of-band management", Severity.HIGH),
    1433: ("SQL Server", "database", Severity.HIGH),
    1521: ("Oracle Database", "database", Severity.HIGH),
    2049: ("NFS", "file sharing", Severity.HIGH),
    2375: ("Docker API", "container management", Severity.CRITICAL),
    2376: ("Docker API", "container management", Severity.HIGH),
    3306: ("MySQL", "database", Severity.HIGH),
    3389: ("RDP", "remote desktop", Severity.HIGH),
    5432: ("PostgreSQL", "database", Severity.HIGH),
    5900: ("VNC", "remote desktop", Severity.HIGH),
    5984: ("CouchDB", "database", Severity.HIGH),
    5985: ("WinRM", "remote administration", Severity.HIGH),
    5986: ("WinRM", "remote administration", Severity.HIGH),
    6379: ("Redis", "database", Severity.HIGH),
    9042: ("Cassandra", "database", Severity.HIGH),
    9200: ("Elasticsearch", "database", Severity.HIGH),
    11211: ("memcached", "database", Severity.HIGH),
    27017: ("MongoDB", "database", Severity.HIGH),
}
#: product-name patterns (longest first) -> (service, category, baseline severity)
PRODUCT_PATTERNS: tuple[tuple[str, str, str, Severity], ...] = (
    ("terminal services", "RDP", "remote desktop", Severity.HIGH),
    ("remote desktop", "RDP", "remote desktop", Severity.HIGH),
    ("elasticsearch", "Elasticsearch", "database", Severity.HIGH),
    ("oracle database", "Oracle Database", "database", Severity.HIGH),
    ("postgresql", "PostgreSQL", "database", Severity.HIGH),
    ("opensearch", "OpenSearch", "database", Severity.HIGH),
    ("sql server", "SQL Server", "database", Severity.HIGH),
    ("memcached", "memcached", "database", Severity.HIGH),
    ("cassandra", "Cassandra", "database", Severity.HIGH),
    ("dropbear", "SSH", "remote administration", Severity.MEDIUM),
    ("mongodb", "MongoDB", "database", Severity.HIGH),
    ("openssh", "SSH", "remote administration", Severity.MEDIUM),
    ("mariadb", "MariaDB", "database", Severity.HIGH),
    ("postgres", "PostgreSQL", "database", Severity.HIGH),
    ("couchdb", "CouchDB", "database", Severity.HIGH),
    ("telnet", "Telnet", "remote administration", Severity.HIGH),
    ("mysql", "MySQL", "database", Severity.HIGH),
    ("mssql", "SQL Server", "database", Severity.HIGH),
    ("redis", "Redis", "database", Severity.HIGH),
    ("winrm", "WinRM", "remote administration", Severity.HIGH),
    ("samba", "SMB", "file sharing", Severity.HIGH),
    ("rdp", "RDP", "remote desktop", Severity.HIGH),
    ("vnc", "VNC", "remote desktop", Severity.HIGH),
    ("ssh", "SSH", "remote administration", Severity.MEDIUM),
    ("smb", "SMB", "file sharing", Severity.HIGH),
)
_PRODUCT_RES = tuple(
    (re.compile(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])"), label, category, base)
    for p, label, category, base in PRODUCT_PATTERNS
)
BASTION_ROLES = frozenset({"bastion", "bastion-host", "bastion_host"})
TRUST_ROLES = frozenset({"remote-access", "vpn", "sso", "identity-provider", "login", "authentication"})
SENSITIVE_CLASSIFICATIONS = frozenset(
    {"confidential", "restricted", "internal", "secret", "sensitive", "pii", "personal", "private"}
)
SENSITIVE_NAME_HINTS = ("backup", "dump", "export", "private", "secret", "logs", "database")
_RECOMMEND = {
    "remote administration": "Remove direct Internet exposure: reach it through the VPN or a hardened bastion with "
    "MFA, or restrict it to known source addresses. If nobody needs it any more, decommission the host.",
    "remote desktop": "Remove direct Internet exposure: publish remote desktop only through the VPN or a gateway "
    "with MFA, or restrict source addresses. If the host is a leftover (a forgotten jump host), decommission it.",
    "database": "Databases must not be reachable from the Internet: bind them to private addresses or block the "
    "port at the firewall, and rotate credentials if the exposure was long-lived.",
    "file sharing": "Block file-sharing protocols at the perimeter; publish files through an authenticated "
    "application instead.",
    "file transfer": "Replace cleartext FTP with an authenticated, encrypted transfer service or remove it.",
    "device management": "Restrict management protocols to the management network.",
    "out-of-band management": "Keep out-of-band management interfaces on an isolated management network.",
    "container management": "Never expose the container engine API: bind it locally or protect it with mutual TLS "
    "on a private network.",
}


class Assessment:
    """A severity built from a baseline and named factors (the finding's explanation)."""

    def __init__(self, base: Severity, factor: str, label: str, *, ceiling: Severity = Severity.CRITICAL) -> None:
        self.level = _LEVELS.index(base)
        self.ceiling = _LEVELS.index(ceiling)
        self.explanation: list[dict[str, Any]] = [
            {"factor": factor, "label": f"{label} (baseline {base.value})", "sign": "+"}
        ]

    def up(self, factor: str, label: str) -> None:
        before = self.level
        self.level = min(self.ceiling, self.level + 1)
        effect = "raises severity" if self.level > before else "severity is already at the rule's maximum"
        self.explanation.append({"factor": factor, "label": f"{label} - {effect}", "sign": "+"})

    def down(self, factor: str, label: str) -> None:
        before = self.level
        self.level = max(1, self.level - 1)
        effect = "lowers severity" if self.level < before else "severity is already at the rule's minimum"
        self.explanation.append({"factor": factor, "label": f"{label} - {effect}", "sign": "-"})

    def note(self, factor: str, label: str, sign: str = "+") -> None:
        self.explanation.append({"factor": factor, "label": label, "sign": sign})

    @property
    def severity(self) -> Severity:
        return _LEVELS[self.level]


@dataclass(slots=True)
class RuleContext:
    model: SurfaceModel
    reference: datetime
    expiring_days: int
    now: datetime

    def finding(
        self,
        rule: str,
        subject: str,
        *,
        title: str,
        description: str,
        assessment: Assessment,
        confidence: float,
        affected: list[str],
        evidence: list[EvidenceRef],
        recommendation: str,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            id=finding_id(PRODUCT, rule, subject),
            title=title[:512],
            description=description,
            severity=assessment.severity,
            confidence=confidence,
            product=PRODUCT,
            rule_id=rule,
            affected_objects=list(dict.fromkeys(affected)),
            evidence=_dedupe(evidence),
            recommendation=recommendation,
            explanation=assessment.explanation,
            created_at=self.now,
            updated_at=self.now,
            tags=["surface", rule],
            metadata=metadata or {},
        )

    def scope_evidence(self, oid: str) -> list[EvidenceRef]:
        match = self.model.scope_match(oid)
        if match.entry is None:
            return []
        entry = match.entry
        note = "authorized scope entry" + (f" ({entry.authorization})" if entry.authorization else "")
        return [EvidenceRef(kind="external", id=f"surface.scope:{entry.target}", note=note)]


def _dedupe(evidence: list[EvidenceRef]) -> list[EvidenceRef]:
    seen: set[tuple[str, str]] = set()
    result: list[EvidenceRef] = []
    for ref in evidence:
        if (ref.kind, ref.id) not in seen:
            seen.add((ref.kind, ref.id))
            result.append(ref)
    return result[:30]


def _obj(oid: str, note: str | None = None) -> EvidenceRef:
    return EvidenceRef(kind="object", id=oid, note=note)


def _rec(entry: DnsEntry) -> EvidenceRef:
    return EvidenceRef(kind="relationship", id=entry.rel_id, note=f"DNS {entry.describe()} ({entry.view} view)")


def _join(items: list[str], limit: int = 5) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _day(value: datetime) -> str:
    return value.strftime("%Y-%m-%d")


def _criticality(m: SurfaceModel, oid: str) -> tuple[str | None, str]:
    """The asset's criticality, or that of the host running/holding it."""
    level = m.criticality(oid)
    if level is not None:
        return level, m.label(oid)
    for host in m.hosts_of(oid):
        host_level = m.criticality(host)
        if host_level is not None:
            return host_level, f"host {m.name(host)}"
    return None, m.name(oid)


# --------------------------------------------------------------------------- out-of-scope-asset


def out_of_scope(ctx: RuleContext) -> list[Finding]:
    m = ctx.model
    candidates = {
        oid
        for oid in m.surface_ids
        if m.kind(oid) in ("domain", "ip", "service", "cloud_asset")
        and m.is_asset(oid)
        and m.scope_match(oid).status == "out"
    }

    def parent(oid: str) -> str | None:
        """Related candidates fold into one finding: endpoints into their cloud asset, services into
        their address, names into their closest flagged parent name."""
        if m.kind(oid) in ("domain", "ip"):
            for cloud in m.cloud_assets_at(oid):
                if cloud in candidates:
                    return cloud
        if m.kind(oid) == "domain":
            return m.parent_of(oid, candidates)
        if m.kind(oid) == "service":
            for port in m.service_ports(oid):
                address = m.port_address_id(port)
                if address in candidates:
                    return address
        return None

    groups: dict[str, list[str]] = defaultdict(list)
    for oid in sorted(candidates):
        head, seen = oid, {oid}
        while (up := parent(head)) is not None and up not in seen:
            seen.add(up)
            head = up
        groups[head].append(oid)
    findings: list[Finding] = []
    for head, grouped in sorted(groups.items()):
        members = [head, *sorted(x for x in grouped if x != head)]
        name = m.label(head)
        kind = m.kind(head)
        assessment = Assessment(
            Severity.LOW,
            "outside-scope",
            f"{_KIND_LABEL.get(kind, kind)} {name} is not covered by any authorized scope entry "
            f"(scope: {m.scope.summary()})",
            ceiling=Severity.MEDIUM,
        )
        inventoried = [m.label(x) for x in members if "inventory" in m.sources(x)]
        if inventoried:
            assessment.up("inventory-claim", f"the asset inventory lists {_join(inventoried)} as the organization's")
        claimed = sorted({owner for x in members for owner in m.direct_owners(x)})
        if claimed:
            assessment.note(
                "owner-claim",
                f"the inventory names owner {_join(claimed)}; ownership is not accepted for assets outside the "
                "authorized scope",
            )
        exposed = [m.label(x) for x in members if m.internet_facing(x)[0]]
        if exposed:
            assessment.note("internet-facing", f"recorded as internet-facing: {_join(exposed)}")
        if len(members) > 1:
            assessment.note("related", f"also outside the scope: {_join([m.label(x) for x in members[1:]], 8)}")
        how = m.describe_sources(head)
        if kind == "cloud_asset":
            meta = m.meta(head)
            suggestion = f"{meta.get('provider')}:{meta.get('account')}" if meta.get("account") else m.key(head)
        elif kind == "service":
            ports = m.service_ports(head)
            address = m.port_address_id(ports[0]) if ports else None
            suggestion = m.key(address) if address else m.key(head)
        else:
            suggestion = m.key(head)
        evidence = [_obj(x, "outside the authorized scope") for x in members]
        evidence += [_rec(r) for x in members for r in m.records_of(x)]
        findings.append(
            ctx.finding(
                "out-of-scope-asset",
                head,
                title=f"Outside the authorized scope: {name}"
                + (f" (+{len(members) - 1} related)" if len(members) > 1 else ""),
                description=f"{name} is referenced by the organization's surface data ({how}), but no authorized "
                "scope entry covers it. R$F records and shows it, but never treats it as owned: ownership, "
                "certificate, DNS and exposure rules are not applied to assets outside the scope.",
                assessment=assessment,
                confidence=0.9,
                affected=members,
                evidence=evidence,
                recommendation=f"Confirm who controls {name}. If it belongs to the organization, add it to the "
                f"authorized scope with an authorization reference (raf surface scope add {suggestion} "
                "--owner TEAM --authorization REF). If it is a third party's (for example an agency-hosted site), "
                "record that in the inventory and do not assess it.",
                metadata={"members": members, "scope": m.scope.summary()},
            )
        )
    return findings


# --------------------------------------------------------------------------- unowned-asset


def unowned(ctx: RuleContext) -> list[Finding]:
    m = ctx.model
    findings: list[Finding] = []
    for oid in m.surface_ids:
        kind = m.kind(oid)
        if kind not in ("domain", "ip", "service", "cloud_asset"):
            continue
        if "inventory" not in m.sources(oid) or m.inactive(oid) or not m.scope_match(oid).in_scope:
            continue
        if m.ownership(oid).owned:
            continue
        hosts = m.hosts_of(oid)
        label = m.label(oid) if kind == "service" else f"{_KIND_LABEL[kind]} {m.name(oid)}"
        if hosts:
            label += f" ({_join([m.name(h) for h in hosts], 2)})"
        inherit = _INHERITANCE.get(kind, "")
        assessment = Assessment(
            Severity.LOW,
            "no-owner",
            f"no owner is recorded for {label} (inventory owner field, owner records{inherit})",
            ceiling=Severity.HIGH,
        )
        exposed, why = m.internet_facing(oid)
        if exposed:
            assessment.up("internet-facing", why)
        level, subject = _criticality(m, oid)
        if level in _HIGH:
            assessment.up("criticality", f"{subject} has criticality {level}")
        findings.append(
            ctx.finding(
                "unowned-asset",
                oid,
                title=f"No accountable owner: {label}",
                description=f"{label} is in the authorized scope and in the asset inventory, but nobody is recorded "
                "as its owner. Renewals, patches and incident notifications for it have nowhere to go.",
                assessment=assessment,
                confidence=0.8,
                affected=[oid, *hosts],
                evidence=[_obj(oid, "no owner recorded"), *ctx.scope_evidence(oid)],
                recommendation="Record an owner (the inventory's owner field or an owner record). If nobody claims "
                "the asset, plan its decommissioning.",
            )
        )
    return findings


# --------------------------------------------------------------------------- certificates


def certificates(ctx: RuleContext) -> list[Finding]:
    m = ctx.model
    findings: list[Finding] = []
    for cert in m.surface_of("certificate"):
        if "inventory" not in m.sources(cert) or m.status(cert) == "removed" or not m.scope_match(cert).in_scope:
            continue
        not_after = m.timestamp(cert, "not_after")
        if not_after is None:
            continue
        remaining = not_after - ctx.reference
        ports = m.certificate_ports(cert)
        endpoints = _join([m.key(p) for p in ports]) if ports else "no recorded endpoint"
        exposed = [why for p in ports for facing, why in [m.internet_facing(p)] if facing]
        services = [s for p in ports for s in m.port_services(p)]
        critical = [(m.name(s), level) for s in services for level, _ in [_criticality(m, s)] if level in _HIGH]
        cn = m.name(cert)
        names = _join(m.certificate_names(cert)) or cn
        issuer = m.meta(cert).get("issuer") or "unknown issuer"
        if remaining.total_seconds() <= 0:
            rule = "expired-certificate"
            days = math.floor(-remaining.total_seconds() / 86400)
            if ports:
                assessment = Assessment(
                    Severity.MEDIUM,
                    "expired",
                    f"the certificate for {cn} expired on {_day(not_after)} ({days} days before the reference time) "
                    f"and is still presented at {endpoints}",
                    ceiling=Severity.HIGH,
                )
            else:
                assessment = Assessment(
                    Severity.LOW,
                    "expired",
                    f"the certificate for {cn} expired on {_day(not_after)}; it is not presented at any recorded "
                    "endpoint",
                    ceiling=Severity.HIGH,
                )
            title = f"Expired certificate: {cn} (expired {_day(not_after)})"
            description = (
                f"The certificate for {names} ({issuer}) expired on {_day(not_after)} (reference time "
                f"{format_ts(ctx.reference)}). Clients refuse the connection or show a warning that trains users "
                "to click through - the same warning an interception produces."
            )
            recommendation = (
                f"Renew the certificate and deploy it on {endpoints}; automate renewal (for example ACME) so "
                "expiry cannot recur."
            )
        elif remaining <= timedelta(days=ctx.expiring_days):
            rule = "expiring-certificate"
            days = math.floor(remaining.total_seconds() / 86400)
            assessment = Assessment(
                Severity.LOW,
                "expiring",
                f"the certificate for {cn} expires on {_day(not_after)}, in {days} days "
                f"(threshold {ctx.expiring_days} days)",
                ceiling=Severity.HIGH,
            )
            if remaining <= timedelta(days=7):
                assessment.up("imminent", "less than 7 days left")
            title = f"Certificate expires in {days} days: {cn}"
            description = (
                f"The certificate for {names} ({issuer}) expires on {_day(not_after)}, {days} days after the "
                f"reference time {format_ts(ctx.reference)}. It is presented at {endpoints}."
            )
            recommendation = (
                f"Renew it before {_day(not_after)} and deploy the new certificate on {endpoints}; prefer automated "
                "renewal so this does not depend on someone remembering."
            )
        else:
            continue
        if exposed:
            assessment.up("internet-facing", exposed[0])
        if critical:
            assessment.up("criticality", f"presented by {critical[0][0]} (criticality {critical[0][1]})")
        findings.append(
            ctx.finding(
                rule,
                cert,
                title=title,
                description=description,
                assessment=assessment,
                confidence=0.95,
                affected=[cert, *ports, *services],
                evidence=[_obj(cert, f"not_after {format_ts(not_after)}"), *[_obj(p, "presents it") for p in ports]],
                recommendation=recommendation,
                metadata={
                    "not_after": format_ts(not_after),
                    "days": days,
                    "reference_time": format_ts(ctx.reference),
                },
            )
        )
    return findings


# --------------------------------------------------------------------------- certificate-name-mismatch


def name_mismatch(ctx: RuleContext) -> list[Finding]:
    m = ctx.model
    findings: list[Finding] = []
    for port in m.surface_of("port"):
        certs = m.port_certificates(port)
        if not certs or not m.scope_match(port).in_scope:
            continue
        address = m.port_address_id(port)
        if address is None:
            continue
        names: dict[str, list[DnsEntry]] = {}
        if address.startswith("domain:") and m.scope.match_domain(m.key(address)) is not None:
            names[m.key(address)] = []
        if address.startswith("domain:") or m.port_number(port) in TLS_NAME_PORTS:
            for name, chain in m.names_reaching(address).items():
                if m.scope.match_domain(name) is not None:
                    names.setdefault(name, chain)
        if not names:
            continue
        cert_names = {c: m.certificate_names(c) for c in certs}
        uncovered = [n for n in names if not any(name_covers(p, n) for c in certs for p in cert_names[c])]
        if not uncovered:
            continue
        offered = sorted({p for c in certs for p in cert_names[c]}) or [m.name(c) for c in certs]
        label = m.key(port)
        assessment = Assessment(
            Severity.LOW,
            "name-mismatch",
            f"{label} presents a certificate for {_join(offered)} but is reached as {_join(uncovered)}",
            ceiling=Severity.HIGH,
        )
        exposed, why = m.internet_facing(port)
        if exposed:
            assessment.up("internet-facing", why)
        services = m.port_services(port)
        for service in services:
            role = str(m.meta(service).get("role") or "")
            level, _subject = _criticality(m, service)
            if role in TRUST_ROLES or level in _HIGH:
                reason = f"role {role}" if role in TRUST_ROLES else f"criticality {level}"
                assessment.up(
                    "trusted-service",
                    f"{m.label(service)} ({reason}): users who learn to accept certificate warnings here are "
                    "exposed to credential interception",
                )
                break
        if any(m.meta(c).get("self_signed") is True for c in certs):
            assessment.note("self-signed", "the certificate is self-signed: clients cannot validate it either")
        chains = [" → ".join(e.describe() for e in names[n]) for n in uncovered if names[n]]
        findings.append(
            ctx.finding(
                "certificate-name-mismatch",
                port,
                title=f"Certificate name mismatch at {label}: {_join(uncovered, 3)}",
                description=f"Clients that connect to {_join(uncovered)} reach {label}"
                + (f" (DNS: {'; '.join(chains)})" if chains else "")
                + f" and are offered a certificate for {_join(offered)}. They get a certificate error - or ignore "
                "it, which is exactly what an interception relies on. R$F only knows the certificates recorded "
                "for this endpoint.",
                assessment=assessment,
                confidence=0.8,
                affected=[port, *certs, *services, *[object_id("domain", n) for n in uncovered]],
                evidence=[
                    *[_obj(c, "presented certificate") for c in certs],
                    *[_rec(e) for n in uncovered for e in names[n]],
                ],
                recommendation=f"Deploy a certificate whose names include {_join(uncovered)} on {label}, or correct "
                "the DNS records if those names should not point here.",
                metadata={"endpoint": label, "names": uncovered, "certificate_names": offered},
            )
        )
    return findings


# --------------------------------------------------------------------------- dangling-dns


def _name_state(m: SurfaceModel, name_id: str, depth: int, seen: frozenset[str]) -> tuple[bool, str]:
    """Whether a name leads to something live according to the imported data, and why not."""
    name = m.key(name_id)
    if m.inactive(name_id):
        return False, f"{name} is marked {m.status(name_id)} in the inventory"
    if m.inventoried_name(name_id):
        return True, ""
    records = m.resolution(name_id)
    if not records:
        if any(r.rtype in RESOLUTION_TYPES for r in m.records_of(name_id)):
            return False, f"{name} only has internal-view records, so it does not resolve from the Internet"
        return False, f"{name} has no inventory record and no A, AAAA or CNAME record in the imported data"
    if depth >= MAX_CHAIN:
        return True, ""
    reasons: list[str] = []
    for record in records:
        if record.rtype == "CNAME":
            if record.target_id in seen:
                reasons.append(f"{name} is part of a CNAME loop")
                continue
            live, why = _name_state(m, record.target_id, depth + 1, seen | {record.target_id})
        else:
            live = not m.inactive(record.target_id)
            why = f"{record.value} is marked {m.status(record.target_id)}"
        if live:
            return True, ""
        reasons.append(why)
    return False, "; ".join(dict.fromkeys(reasons))


def dangling(ctx: RuleContext) -> list[Finding]:
    m = ctx.model
    findings: list[Finding] = []
    for entry in m.records:
        if entry.view != "external" or entry.rtype not in RESOLUTION_TYPES:
            continue
        if m.scope.match_domain(entry.name) is None:
            continue
        if entry.rtype == "CNAME":
            live, why = _name_state(m, entry.target_id, 1, frozenset({entry.name_id, entry.target_id}))
            if live:
                continue
            if m.scope_match(entry.target_id).in_scope:
                assessment = Assessment(
                    Severity.MEDIUM, "dangling-cname", f"{entry.name} is an alias of {entry.value}, but {why}"
                )
                assessment.note(
                    "target-in-scope",
                    f"{entry.value} is inside the authorized scope, so only the organization can re-create it",
                    sign="-",
                )
                impact = f"anyone who re-creates {entry.value} decides what {entry.name} serves"
            else:
                assessment = Assessment(
                    Severity.HIGH, "dangling-cname", f"{entry.name} is an alias of {entry.value}, but {why}"
                )
                assessment.note(
                    "takeover",
                    f"{entry.value} is outside the authorized scope: whoever can claim it (for example by registering "
                    f"the same name at the provider) serves content as {entry.name}",
                )
                impact = f"whoever claims {entry.value} serves content and receives cookies as {entry.name}"
            recommendation = f"Delete the {entry.name} record or point it at a live, owned target. Until then {impact}."
        else:
            if is_internal_address(entry.value):
                continue
            if m.inactive(entry.target_id):
                in_scope = m.scope_match(entry.target_id).in_scope
                why = f"{entry.value} is marked {m.status(entry.target_id)} in the inventory"
                assessment = Assessment(
                    Severity.MEDIUM if in_scope else Severity.HIGH,
                    "retired-address",
                    f"{entry.name} points to {entry.value}, which is marked {m.status(entry.target_id)}",
                )
            elif not m.scope_match(entry.target_id).in_scope and not m.known_address(entry.target_id):
                why = f"{entry.value} is outside the authorized ranges and not in the inventory"
                assessment = Assessment(
                    Severity.HIGH,
                    "unknown-address",
                    f"{entry.name} points to {entry.value}, which is outside the authorized ranges and not in the "
                    "inventory",
                )
                assessment.note(
                    "released-address",
                    "if the address was released (for example a cloud public IP), whoever holds it now receives "
                    f"traffic for {entry.name}",
                )
            else:
                continue
            recommendation = (
                f"Remove or correct the {entry.name} record: an address the organization no longer holds must not "
                "keep receiving its traffic."
            )
        level = m.criticality(entry.name_id)
        if level in _HIGH:
            assessment.up("criticality", f"{entry.name} has criticality {level}")
        findings.append(
            ctx.finding(
                "dangling-dns",
                f"{entry.name_id}|{entry.rtype}|{entry.target_id}",
                title=f"Dangling DNS record: {entry.describe()}",
                description=f"The external DNS record {entry.describe()} leads nowhere the organization controls: "
                f"{why}. This is judged from the imported data only (R$F never resolves names), so confirm "
                "before acting.",
                assessment=assessment,
                confidence=0.7,
                affected=[entry.name_id, entry.target_id],
                evidence=[_rec(entry), _obj(entry.target_id, why), *ctx.scope_evidence(entry.name_id)],
                recommendation=recommendation,
                metadata={"record": entry.describe(), "name_id": entry.name_id, "reason": why},
            )
        )
    return findings


# --------------------------------------------------------------------------- exposed-sensitive-service


def _detect(port: int | None, product: str) -> tuple[str, str, Severity, str] | None:
    if port is not None and port in SENSITIVE_PORTS:
        label, category, base = SENSITIVE_PORTS[port]
        return label, category, base, f"port {port}"
    lowered = product.lower()
    for pattern, label, category, base in _PRODUCT_RES:
        if pattern.search(lowered):
            return label, category, base, f"product {product!r}"
    return None


def exposed_services(ctx: RuleContext) -> list[Finding]:
    m = ctx.model
    findings: list[Finding] = []
    for service in m.surface_of("service"):
        if "inventory" not in m.sources(service) or m.inactive(service) or not m.scope_match(service).in_scope:
            continue
        if not m.internet_facing(service)[0]:
            continue
        meta = m.meta(service)
        port = meta.get("port") if isinstance(meta.get("port"), int) else None
        product = str(meta.get("product") or "")
        detected = _detect(port, product)
        if detected is None:
            continue
        label, category, base, how = detected
        ports = [p for p in m.service_ports(service) if m.scope_match(p).in_scope] or m.service_ports(service)
        endpoint = m.key(ports[0]) if ports else m.name(service)
        hosts = m.hosts_of(service)
        host_text = f" (host {_join([m.name(h) for h in hosts], 2)})" if hosts else ""
        subject = (
            m.label(service)
            if ":" in m.name(service)
            else m.name(service) + (f" ({product})" if product else "") + f" on {endpoint}"
        )
        assessment = Assessment(
            base,
            "sensitive-service",
            f"{label} ({category}, identified by {how}) on {endpoint} is recorded as internet-facing",
        )
        level, subject = _criticality(m, service)
        if level in _HIGH:
            assessment.up("criticality", f"{subject} has criticality {level}")
        role = str(meta.get("role") or "")
        if role in BASTION_ROLES:
            assessment.down("bastion", f"role {role}: a deliberately exposed, hardened entry point")
        ownership = m.ownership(service)
        if not ownership.owned:
            assessment.up("no-owner", "no accountable owner is recorded, so nobody is known to patch or monitor it")
        findings.append(
            ctx.finding(
                "exposed-sensitive-service",
                service,
                title=f"Internet-facing {label} on {endpoint}",
                description=f"{subject}{host_text} is recorded as internet-facing. Internet-facing {category} "
                "services are a primary target for password spraying, credential stuffing and exploitation of "
                "unpatched vulnerabilities.",
                assessment=assessment,
                confidence=0.85,
                affected=[service, *ports, *hosts],
                evidence=[_obj(service, how), *[_obj(p) for p in ports], *ctx.scope_evidence(service)],
                recommendation=_RECOMMEND.get(
                    category, "Remove direct Internet exposure or restrict source addresses."
                ),
                metadata={"service": label, "category": category, "endpoint": endpoint},
            )
        )
    return findings


# --------------------------------------------------------------------------- public-cloud-storage


def public_storage(ctx: RuleContext) -> list[Finding]:
    m = ctx.model
    findings: list[Finding] = []
    for cloud in m.surface_of("cloud_asset"):
        if "inventory" not in m.sources(cloud) or m.inactive(cloud) or not m.scope_match(cloud).in_scope:
            continue
        meta = m.meta(cloud)
        if not m.is_storage(cloud) or meta.get("public") is not True:
            continue
        name = m.name(cloud)
        where = f"{meta.get('provider')} {meta.get('kind')}" + (
            f" in {meta.get('account')}" if meta.get("account") else ""
        )
        assessment = Assessment(Severity.MEDIUM, "public-storage", f"{name} ({where}) allows public access")
        classification = str(meta.get("classification") or "")
        if classification == "public":
            assessment.down("classified-public", "its data classification is 'public'")
        elif classification in SENSITIVE_CLASSIFICATIONS:
            assessment.up("classification", f"its data classification is '{classification}'")
        else:
            assessment.note(
                "no-classification",
                "no data classification is recorded, so R$F cannot tell whether public access is intended",
            )
        level = m.criticality(cloud)
        if level in _HIGH:
            assessment.up("criticality", f"criticality {level}")
        hint = next((h for h in SENSITIVE_NAME_HINTS if h in name.lower()), None)
        if hint and classification != "public":
            assessment.up("name", f"its name suggests non-public content ('{hint}')")
        findings.append(
            ctx.finding(
                "public-cloud-storage",
                cloud,
                title=f"Public cloud storage: {name}",
                description=f"{name} ({where}) is recorded as publicly accessible. Anyone who knows or guesses "
                "its name can read (and with listing enabled, enumerate) its content.",
                assessment=assessment,
                confidence=0.9,
                affected=[cloud, *m.targets(cloud, "HAS_ADDRESS")],
                evidence=[_obj(cloud, "public: true"), *ctx.scope_evidence(cloud)],
                recommendation=f"Confirm that everything in {name} is meant to be public. If not, block public "
                "access (account-level setting), remove public policies, and review access logs for downloads. If "
                "it is intended, keep the content minimal, disable listing and enable access logging.",
                metadata={"classification": classification or None},
            )
        )
    return findings


# --------------------------------------------------------------------------- shadow-asset


def shadow(ctx: RuleContext, dangling_names: set[str]) -> list[Finding]:
    m = ctx.model
    findings: list[Finding] = []
    for name_id in m.org_names():
        if "dns" not in m.sources(name_id) or name_id in dangling_names:
            continue
        records = m.resolution(name_id)
        name = m.key(name_id)
        if not records or m.scope.match_domain(name) is None:
            continue
        if m.inventoried_name(name_id) or m.inactive(name_id):
            continue
        assessment = Assessment(
            Severity.LOW,
            "not-inventoried",
            f"{name} has DNS records ({_join([r.describe() for r in records], 3)}) but no record in the asset "
            "inventory",
            ceiling=Severity.HIGH,
        )
        unknown = [
            r.value
            for r in records
            if r.rtype in ("A", "AAAA")
            and not is_internal_address(r.value)
            and m.scope_match(r.target_id).in_scope
            and not m.known_address(r.target_id)
        ]
        known = [
            r.value + (f" ({_join([m.name(h) for h in m.hosts_of(r.target_id)])})" if m.hosts_of(r.target_id) else "")
            for r in records
            if (r.rtype in ("A", "AAAA") and m.known_address(r.target_id))
            or (r.rtype == "CNAME" and m.inventoried_name(r.target_id))
        ]
        if unknown:
            assessment.up(
                "unknown-system",
                f"it resolves to {_join(unknown)} inside the authorized ranges, which is not in the inventory "
                "either: an unknown system on the organization's addresses",
            )
        if known:
            assessment.note("known-target", f"it resolves to {_join(known)}, which the inventory knows", sign="-")
        findings.append(
            ctx.finding(
                "shadow-asset",
                name_id,
                title=f"Shadow asset: {name} is in DNS but not in the inventory",
                description=f"{name} is published in the organization's DNS but is not part of its asset inventory, "
                "so nobody is known to own, patch or monitor what answers there.",
                assessment=assessment,
                confidence=0.75,
                affected=[name_id, *[r.target_id for r in records]],
                evidence=[*[_rec(r) for r in records], *ctx.scope_evidence(name_id)],
                recommendation=f"Find out who created {name} and what runs there. Add it to the asset inventory "
                "with an owner, or delete the record if it is no longer needed.",
            )
        )
    return findings


# --------------------------------------------------------------------------- internal-address-in-dns


def internal_addresses(ctx: RuleContext) -> list[Finding]:
    m = ctx.model
    findings: list[Finding] = []
    for entry in m.records:
        if entry.view != "external" or entry.rtype not in ("A", "AAAA") or not is_internal_address(entry.value):
            continue
        if m.scope.match_domain(entry.name) is None:
            continue
        assessment = Assessment(
            Severity.LOW,
            "internal-address",
            f"the external DNS name {entry.name} resolves to the internal address {entry.value}",
            ceiling=Severity.MEDIUM,
        )
        hosts = m.hosts_of(entry.target_id)
        for host in hosts:
            level = m.criticality(host)
            if level in _HIGH:
                role = m.meta(host).get("role")
                assessment.up(
                    "critical-host",
                    f"the address belongs to {m.name(host)}"
                    + (f" ({role}, criticality {level})" if role else f" (criticality {level})")
                    + ": the record tells anyone where it is",
                )
                break
        findings.append(
            ctx.finding(
                "internal-address-in-dns",
                f"{entry.name_id}|{entry.target_id}",
                title=f"Internal address in external DNS: {entry.name} → {entry.value}",
                description=f"The external DNS view publishes {entry.describe()}, an internal, non-routable address. "
                "It does not make the system reachable, but it discloses internal addressing and naming to anyone "
                "who looks.",
                assessment=assessment,
                confidence=0.9,
                affected=[entry.name_id, entry.target_id, *hosts],
                evidence=[_rec(entry), *[_obj(h, "holds the address") for h in hosts]],
                recommendation=f"Publish {entry.name} only in the internal DNS view (split horizon), or remove it "
                "from the external zone.",
            )
        )
    return findings


def evaluate(model: SurfaceModel, *, reference: datetime, expiring_days: int, now: datetime) -> list[Finding]:
    """All surface findings for the model (none when no authorized scope is configured)."""
    if not model.scope.configured:
        return []
    ctx = RuleContext(model, reference, expiring_days, now)
    dangling_findings = dangling(ctx)
    dangling_names = {str(f.metadata.get("name_id")) for f in dangling_findings}
    findings = (
        out_of_scope(ctx)
        + unowned(ctx)
        + certificates(ctx)
        + name_mismatch(ctx)
        + dangling_findings
        + exposed_services(ctx)
        + public_storage(ctx)
        + shadow(ctx, dangling_names)
        + internal_addresses(ctx)
    )
    unique = {f.id: f for f in findings}
    return sorted(unique.values(), key=lambda f: (-f.severity.rank, f.rule_id, f.id))
