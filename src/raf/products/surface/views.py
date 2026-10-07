"""Read-only views of the surface: asset listings, the domain tree and the summary."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.objects.models import Finding, RafModel
from raf.products.surface.graph import DnsEntry, SurfaceModel
from raf.products.surface.model import ASSET_KINDS, DNS_TYPES, is_internal_address, strip_unsafe
from raf.products.surface.rules import DEFAULT_EXPIRING_DAYS
from raf.products.surface.scope import ScopeEntry

MAX_TREE_NODES = 500


class SurfaceAsset(RafModel):
    id: str
    kind: str
    name: str
    asset: bool  # False: a reference (a name seen only as a DNS target or in a certificate)
    scope: str  # in | out | unknown
    scope_entry: str | None = None
    scope_via: str | None = None
    owners: list[str] = Field(default_factory=list)
    owner_via: str | None = None
    claimed_owners: list[str] = Field(default_factory=list)  # recorded, not accepted (outside the scope)
    status: str = "active"
    sources: list[str] = Field(default_factory=list)
    internet_facing: bool = False
    criticality: str | None = None
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    findings: int = 0


class SurfaceSummary(RafModel):
    workspace: str
    scope_configured: bool
    scope: list[ScopeEntry] = Field(default_factory=list)
    assets: int = 0
    references: int = 0
    by_kind: dict[str, int] = Field(default_factory=dict)
    in_scope: int = 0
    out_of_scope: int = 0
    unscoped: int = 0
    internet_facing: int = 0
    owners: list[str] = Field(default_factory=list)
    reference_time: datetime
    reference_source: str
    findings_open: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_rule: dict[str, int] = Field(default_factory=dict)
    top_findings: list[dict[str, Any]] = Field(default_factory=list)
    tree: list[dict[str, Any]] = Field(default_factory=list)
    addresses: list[dict[str, Any]] = Field(default_factory=list)
    cloud: list[dict[str, Any]] = Field(default_factory=list)
    outside: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False
    notes: list[str] = Field(default_factory=list)


def _clean(value: Any) -> Any:
    """Neutralize control characters in every string of a view payload (metadata written by other
    imports is displayed too)."""
    if isinstance(value, str):
        return strip_unsafe(value)
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _day(value: datetime | None) -> str | None:
    return value.strftime("%Y-%m-%d") if value else None


def certificate_state(
    model: SurfaceModel, cert: str, reference: datetime, expiring_days: int
) -> tuple[str, int | None]:
    """valid | expiring | expired | unknown, and whole days left (negative when expired)."""
    not_after = model.timestamp(cert, "not_after")
    if not_after is None:
        return "unknown", None
    seconds = (not_after - reference).total_seconds()
    days = int(seconds // 86400)
    if seconds <= 0:
        return "expired", days
    if seconds <= expiring_days * 86400:
        return "expiring", days
    return "valid", days


class SurfaceViews:
    def __init__(
        self,
        model: SurfaceModel,
        *,
        reference: datetime,
        findings: list[Finding] | None = None,
        expiring_days: int = DEFAULT_EXPIRING_DAYS,
    ) -> None:
        self.model = model
        self.reference = reference
        self.expiring_days = expiring_days
        self.findings = findings or []
        self.finding_counts: Counter[str] = Counter(
            oid for f in self.findings for oid in dict.fromkeys(f.affected_objects)
        )

    # ------------------------------------------------------------------ assets
    def asset(self, oid: str) -> SurfaceAsset:
        m = self.model
        kind = m.kind(oid)
        match = m.scope_match(oid)
        ownership = m.ownership(oid)
        owners, claimed = list(ownership.owners), []
        if match.status == "out":
            owners, claimed = [], list(m.direct_owners(oid))
        details, summary = self._details(oid, kind)
        return SurfaceAsset(
            id=oid,
            kind=kind,
            name=m.name(oid),
            asset=m.is_asset(oid),
            scope=match.status,
            scope_entry=match.entry.target if match.entry else None,
            scope_via=match.via,
            owners=owners,
            owner_via=ownership.via if owners else None,
            claimed_owners=claimed,
            status=m.status(oid),
            sources=sorted(m.sources(oid)),
            internet_facing=m.internet_facing(oid)[0],
            criticality=m.criticality(oid),
            summary=strip_unsafe(summary),
            details=_clean(details),
            findings=self.finding_counts.get(oid, 0),
        )

    def assets(
        self, *, kind: str | None = None, scope: str = "all", include_references: bool = False
    ) -> list[SurfaceAsset]:
        m = self.model
        items: list[SurfaceAsset] = []
        for oid in m.surface_ids:
            oid_kind = m.kind(oid)
            if oid_kind not in ASSET_KINDS or (kind is not None and oid_kind != kind):
                continue
            if not include_references and not m.is_asset(oid):
                continue
            status = m.scope_match(oid).status
            if (scope == "in" and status != "in") or (scope == "out" and status != "out"):
                continue
            items.append(self.asset(oid))
        order = {k: i for i, k in enumerate(ASSET_KINDS)}
        return sorted(items, key=lambda a: (order.get(a.kind, 9), a.scope != "in", a.name.lower(), a.id))

    def _details(self, oid: str, kind: str) -> tuple[dict[str, Any], str]:
        m = self.model
        meta = m.meta(oid)
        if kind == "domain":
            records = [{"type": r.rtype, "value": r.value, "view": r.view} for r in self._sorted_records(oid)]
            details: dict[str, Any] = {"records": records}
            for key in ("registrar", "expires", "notes"):
                if meta.get(key):
                    details[key] = meta[key]
            if isinstance(meta.get("txt"), list):
                details["txt"] = meta["txt"]
            parts = [f"{r['type']} {r['value']}" + (" (internal)" if r["view"] == "internal" else "") for r in records]
            if not records:
                parts.append("no DNS records")
            return details, "; ".join(parts[:3]) + (f"; +{len(parts) - 3}" if len(parts) > 3 else "")
        if kind == "ip":
            hosts = [m.name(h) for h in m.hosts_of(oid)]
            names = sorted(m.names_reaching(oid))
            services = [m.name(s) for s in m.services_at(oid)]
            details = {"hosts": hosts, "names": names, "services": services, "private": is_internal_address(m.key(oid))}
            for key in ("provider", "asn"):
                if meta.get(key):
                    details[key] = meta[key]
            parts = hosts + [str(meta[k]) for k in ("asn", "provider") if meta.get(k)]
            if names:
                parts.append("names: " + ", ".join(names[:3]) + (" ..." if len(names) > 3 else ""))
            if details["private"]:
                parts.append("internal address")
            return details, " · ".join(parts)
        if kind == "service":
            ports = m.service_ports(oid)
            endpoints = [m.key(p) for p in ports]
            details = {
                "endpoints": endpoints,
                "port": meta.get("port"),
                "transport": meta.get("transport") or "tcp",
                "product": meta.get("product"),
                "role": meta.get("role"),
                "hosts": [m.name(h) for h in m.hosts_of(oid)],
            }
            parts = [f"{meta.get('port')}/{meta.get('transport') or 'tcp'}"] if meta.get("port") else []
            if meta.get("product"):
                parts.append(str(meta["product"]))
            if meta.get("internet_facing") is True:
                parts.append("internet-facing")
            if endpoints:
                parts.append("at " + ", ".join(endpoints[:2]))
            return details, " · ".join(parts)
        if kind == "certificate":
            state, days = certificate_state(m, oid, self.reference, self.expiring_days)
            endpoints = [m.key(p) for p in m.certificate_ports(oid)]
            names = m.certificate_names(oid)
            details = {
                "names": names,
                "issuer": meta.get("issuer"),
                "not_before": meta.get("not_before"),
                "not_after": meta.get("not_after"),
                "state": state,
                "days_remaining": days,
                "endpoints": endpoints,
                "self_signed": meta.get("self_signed"),
                "fingerprint_sha256": meta.get("fingerprint_sha256"),
            }
            parts = [names[0] + (f" +{len(names) - 1}" if len(names) > 1 else "")] if names else []
            not_after = m.timestamp(oid, "not_after")
            if state == "expired":
                parts.append(f"EXPIRED {_day(not_after)}")
            elif state in ("valid", "expiring"):
                parts.append(f"until {_day(not_after)} ({days} days)")
            if meta.get("self_signed") is True:
                parts.append("self-signed")
            if endpoints:
                parts.append("at " + ", ".join(endpoints[:2]))
            return details, " · ".join(parts)
        if kind == "cloud_asset":
            details = {
                k: meta.get(k)
                for k in ("provider", "account", "kind", "region", "public", "classification", "endpoint", "address")
                if meta.get(k) is not None
            }
            where = "/".join(str(meta[k]) for k in ("provider", "account") if meta.get(k))
            parts = [f"{where} {meta.get('kind') or ''}".strip()]
            parts.append("public" if meta.get("public") is True else "private" if meta.get("public") is False else "")
            if meta.get("classification"):
                parts.append(f"data: {meta['classification']}")
            return details, " · ".join(p for p in parts if p)
        return {}, ""

    # ------------------------------------------------------------------ tree
    def _endpoints(self, address_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        m = self.model
        services: list[dict[str, Any]] = []
        certificates: list[dict[str, Any]] = []
        for port in sorted(m.ports_at(address_id)):
            for service in m.port_services(port):
                meta = m.meta(service)
                services.append(
                    {
                        "id": service,
                        "name": m.name(service),
                        "endpoint": m.key(port),
                        "port": meta.get("port"),
                        "transport": meta.get("transport") or "tcp",
                        "product": meta.get("product"),
                        "internet_facing": meta.get("internet_facing") is True,
                        "status": m.status(service),
                    }
                )
            for cert in m.port_certificates(port):
                state, days = certificate_state(m, cert, self.reference, self.expiring_days)
                certificates.append(
                    {
                        "id": cert,
                        "name": m.name(cert),
                        "endpoint": m.key(port),
                        "not_after": m.meta(cert).get("not_after"),
                        "state": state,
                        "days_remaining": days,
                    }
                )
        return services, certificates

    def _sorted_records(self, oid: str) -> list[DnsEntry]:
        order = {t: i for i, t in enumerate(DNS_TYPES)}
        return sorted(self.model.records_of(oid), key=lambda r: (order.get(r.rtype, 9), r.view, r.value))

    def _record(self, record_type: str, value: str, view: str, target: str) -> dict[str, Any]:
        m = self.model
        entry: dict[str, Any] = {"type": record_type, "value": value, "view": view, "target": target}
        if record_type in ("A", "AAAA"):
            entry["hosts"] = [m.name(h) for h in m.hosts_of(target)]
            entry["scope"] = m.scope_match(target).status
            entry["internal"] = is_internal_address(value)
        if record_type in ("A", "AAAA", "CNAME"):
            services, certificates = self._endpoints(target)
            entry["services"] = services
            entry["certificates"] = certificates
            if record_type == "CNAME":
                entry["status"] = m.status(target)
                entry["cloud"] = [
                    {
                        "id": c,
                        "name": m.name(c),
                        "kind": m.meta(c).get("kind"),
                        "provider": m.meta(c).get("provider"),
                        "public": m.meta(c).get("public") is True,
                    }
                    for c in m.cloud_assets_at(target)
                ]
        return entry

    def tree(self) -> tuple[list[dict[str, Any]], bool]:
        m = self.model
        names = set(m.org_names())
        children: dict[str | None, list[str]] = {}
        for oid in names:
            children.setdefault(m.parent_of(oid, names), []).append(oid)
        budget = [MAX_TREE_NODES]

        def order(oid: str) -> tuple[int, str]:
            return ({"in": 0, "unknown": 1, "out": 2}[m.scope_match(oid).status], m.key(oid))

        def node(oid: str) -> dict[str, Any] | None:
            if budget[0] <= 0:
                return None
            budget[0] -= 1
            match = m.scope_match(oid)
            ownership = m.ownership(oid)
            records = [self._record(r.rtype, r.value, r.view, r.target_id) for r in self._sorted_records(oid)]
            txt = m.meta(oid).get("txt")
            kids = [n for n in (node(c) for c in sorted(children.get(oid, []), key=order)) if n is not None]
            return {
                "id": oid,
                "name": m.key(oid),
                "scope": match.status,
                "scope_entry": match.entry.target if match.entry else None,
                "owners": list(ownership.owners) if match.status != "out" else [],
                "claimed_owners": m.direct_owners(oid) if match.status == "out" else [],
                "status": m.status(oid),
                "inventoried": m.inventoried_name(oid),
                "records": records,
                "txt": [str(t) for t in txt] if isinstance(txt, list) else [],
                "children": kids,
                "findings": self.finding_counts.get(oid, 0),
            }

        roots = [n for n in (node(r) for r in sorted(children.get(None, []), key=order)) if n is not None]
        return _clean(roots), budget[0] <= 0

    # ------------------------------------------------------------------ summary
    def summary(self, *, workspace: str, scope: list[ScopeEntry], reference_source: str) -> SurfaceSummary:
        m = self.model
        assets = [oid for oid in m.surface_ids if m.kind(oid) in ASSET_KINDS and m.is_asset(oid)]
        references = [oid for oid in m.surface_ids if m.kind(oid) in ASSET_KINDS and not m.is_asset(oid)]
        statuses = Counter(m.scope_match(oid).status for oid in assets)
        owners = sorted(
            {o for oid in assets if m.scope_match(oid).status != "out" for o in m.ownership(oid).owners},
            key=str.lower,
        )
        tree, truncated = self.tree()
        reached: set[str] = set()

        def collect(nodes: list[dict[str, Any]]) -> None:
            for item in nodes:
                for record in item["records"]:
                    reached.add(record["target"])
                collect(item["children"])

        collect(tree)
        addresses = [
            self.asset(oid).model_dump(mode="json")
            for oid in assets
            if m.kind(oid) == "ip" and oid not in reached and m.scope_match(oid).status != "out"
        ]
        cloud = [
            self.asset(oid).model_dump(mode="json")
            for oid in assets
            if m.kind(oid) == "cloud_asset" and m.scope_match(oid).status != "out"
        ]
        outside = [
            self.asset(oid).model_dump(mode="json")
            for oid in assets
            if m.kind(oid) in ("ip", "service", "cloud_asset") and m.scope_match(oid).status == "out"
        ]
        open_findings = [f for f in self.findings if f.status.value == "OPEN"]
        notes: list[str] = []
        if not m.scope.configured:
            notes.append(
                "No authorized scope is configured: nothing is treated as owned and no findings are produced. "
                "Add scope with: raf surface scope add <domain|cidr|ip|provider:account> --owner TEAM "
                "--authorization REF"
            )
        if truncated:
            notes.append(f"The domain tree shows the first {MAX_TREE_NODES} names.")
        return SurfaceSummary(
            workspace=workspace,
            scope_configured=m.scope.configured,
            scope=scope,
            assets=len(assets),
            references=len(references),
            by_kind=dict(sorted(Counter(m.kind(oid) for oid in assets).items())),
            in_scope=statuses.get("in", 0),
            out_of_scope=statuses.get("out", 0),
            unscoped=statuses.get("unknown", 0),
            internet_facing=sum(1 for oid in assets if m.internet_facing(oid)[0]),
            owners=owners,
            reference_time=self.reference,
            reference_source=reference_source,
            findings_open=len(open_findings),
            findings_by_severity=dict(Counter(f.severity.value for f in open_findings)),
            findings_by_rule=dict(sorted(Counter(f.rule_id for f in open_findings).items())),
            top_findings=[
                {"id": f.id, "title": f.title, "severity": f.severity.value, "rule": f.rule_id}
                for f in open_findings[:10]
            ],
            tree=tree,
            addresses=addresses,
            cloud=cloud,
            outside=outside,
            truncated=truncated,
            notes=notes,
        )
