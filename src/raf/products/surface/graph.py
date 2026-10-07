"""The surface as loaded from the workspace.

``SurfaceModel`` holds the objects Surface wrote (``metadata.surface``), their neighbors, and the
active relationships between them, and derives what rules and views need: authorized-scope
coverage, ownership (recorded or inherited from the host that holds an address or runs a
service), the DNS records of each name, endpoints, presented certificates and exposure.
"""

from __future__ import annotations

import contextlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from raf.core.errors import InvalidInputError
from raf.core.ids import object_id
from raf.core.objects.models import Relationship, SecurityObject
from raf.core.objects.types import Criticality
from raf.core.storage.store import Store
from raf.core.timeutil import parse_timestamp
from raf.products.surface.model import (
    STORAGE_TYPES,
    is_internal_address,
    is_ip,
    normalize_hostname,
    parent_names,
    safe_display,
    strip_unsafe,
)
from raf.products.surface.scope import Scope, ScopeMatch

SURFACE_TYPES = (
    "domain",
    "ip",
    "service",
    "port",
    "certificate",
    "cloud_resource",
    "organization",
    "host",
    "user",
    "group",
)
SURFACE_RELATIONSHIPS = (
    "RESOLVES_TO",
    "RELATED_TO",
    "PART_OF",
    "OWNS",
    "HAS_ADDRESS",
    "RUNS",
    "LISTENS_ON",
    "PRESENTS",
    "ISSUED_FOR",
)
KIND_OF_TYPE = {
    "domain": "domain",
    "ip": "ip",
    "service": "service",
    "certificate": "certificate",
    "cloud_resource": "cloud_asset",
    "port": "port",
    "host": "host",
    "organization": "owner",
    "user": "owner",
    "group": "owner",
}
TYPE_OF_KIND = {
    "domain": "domain",
    "ip": "ip",
    "service": "service",
    "certificate": "certificate",
    "cloud_asset": "cloud_resource",
}
SOURCE_LABELS = {
    "inventory": "asset inventory",
    "dns": "DNS records",
    "dns-target": "DNS answers",
    "endpoint": "service or cloud endpoints",
    "certificate": "certificate names",
}
RESOLUTION_TYPES = ("A", "AAAA", "CNAME")
INACTIVE_STATUSES = ("decommissioned", "removed")
MAX_CHAIN = 8


@dataclass(frozen=True, slots=True)
class DnsEntry:
    """One DNS record from surface data (an active RESOLVES_TO / RELATED_TO relationship)."""

    rel_id: str
    name_id: str
    name: str
    rtype: str
    target_id: str
    value: str
    view: str

    def describe(self) -> str:
        return f"{self.name} {self.rtype} {self.value}"


@dataclass(frozen=True, slots=True)
class Ownership:
    owners: tuple[str, ...] = ()
    via: str | None = None  # None: recorded on the asset itself

    @property
    def owned(self) -> bool:
        return bool(self.owners)

    def describe(self) -> str:
        if not self.owners:
            return "no owner"
        text = ", ".join(self.owners)
        return f"{text} (via {self.via})" if self.via else text


def _key(oid: str) -> str:
    """The natural key of an ID. Objects written by other imports may carry anything, so control
    characters are neutralized here: every name and key Surface shows goes through it."""
    return strip_unsafe(oid.split(":", 1)[1] if ":" in oid else oid)


def _type(oid: str) -> str:
    return oid.split(":", 1)[0]


class SurfaceModel:
    def __init__(self, objects: dict[str, SecurityObject], relationships: Iterable[Relationship], scope: Scope) -> None:
        self.objects = objects
        self.scope = scope
        self.out: dict[str, list[Relationship]] = defaultdict(list)
        self.inc: dict[str, list[Relationship]] = defaultdict(list)
        self.records: list[DnsEntry] = []
        self._records_of: dict[str, list[DnsEntry]] = defaultdict(list)
        self._records_to: dict[str, list[DnsEntry]] = defaultdict(list)
        for rel in sorted(relationships, key=lambda r: r.id):
            if rel.valid_to is not None:
                continue
            self.out[rel.source_object].append(rel)
            self.inc[rel.target_object].append(rel)
            record_type = rel.metadata.get("record_type")
            if (
                rel.relationship_type in ("RESOLVES_TO", "RELATED_TO")
                and isinstance(record_type, str)
                and rel.source_object.startswith("domain:")
            ):
                entry = DnsEntry(
                    rel_id=rel.id,
                    name_id=rel.source_object,
                    name=_key(rel.source_object),
                    rtype=record_type,
                    target_id=rel.target_object,
                    value=_key(rel.target_object),
                    view=str(rel.metadata.get("view") or "external"),
                )
                self.records.append(entry)
                self._records_of[entry.name_id].append(entry)
                self._records_to[entry.target_id].append(entry)
        self.surface_ids = sorted(oid for oid, obj in objects.items() if isinstance(obj.metadata.get("surface"), dict))
        self._scope_cache: dict[str, ScopeMatch] = {}
        self._sources: dict[str, frozenset[str]] = {}

    @classmethod
    def load(cls, store: Store, scope: Scope) -> SurfaceModel:
        objects: dict[str, SecurityObject] = {}
        for obj in store.objects.iter_all(types=SURFACE_TYPES):
            if isinstance(obj.metadata.get("surface"), dict):
                objects[obj.id] = obj
        # one streaming pass over the relevant relationship types is much faster than batched
        # per-object queries; only active relationships touching surface objects are kept
        relationships = (
            [
                rel
                for rel in store.relationships.iter_all(types=SURFACE_RELATIONSHIPS)
                if rel.valid_to is None and (rel.source_object in objects or rel.target_object in objects)
            ]
            if objects
            else []
        )
        neighbors = {r.source_object for r in relationships} | {r.target_object for r in relationships}
        objects.update(store.objects.get_many(neighbors - set(objects)))
        hosts = [oid for oid in objects if oid.startswith("host:") and "surface" not in objects[oid].metadata]
        extra = store.relationships.edges(hosts, direction="in", types=["OWNS"]) if hosts else []
        known = {r.id for r in relationships}
        relationships = relationships + [r for r in extra if r.id not in known]
        owners = {r.source_object for r in extra} - set(objects)
        objects.update(store.objects.get_many(owners))
        return cls(objects, relationships, scope)

    # ------------------------------------------------------------------ basics
    def obj(self, oid: str) -> SecurityObject | None:
        return self.objects.get(oid)

    def name(self, oid: str) -> str:
        obj = self.objects.get(oid)
        return safe_display(obj.name, 300) if obj is not None and obj.name else _key(oid)

    def label(self, oid: str) -> str:
        """A readable label: services without a name are shown by product and endpoint."""
        name = self.name(oid)
        if self.kind(oid) == "service" and ":" in name:
            product = self.meta(oid).get("product")
            ports = self.service_ports(oid)
            endpoint = self.key(ports[0]) if ports else name
            return f"{product} on {endpoint}" if isinstance(product, str) and product else f"service on {endpoint}"
        return name

    def describe_sources(self, oid: str) -> str:
        return ", ".join(SOURCE_LABELS.get(s, s) for s in sorted(self.sources(oid)) if s != "owner") or "references"

    @staticmethod
    def key(oid: str) -> str:
        return _key(oid)

    @staticmethod
    def kind(oid: str) -> str:
        prefix = oid[: oid.find(":")] if ":" in oid else oid
        return KIND_OF_TYPE.get(prefix, prefix)

    def meta(self, oid: str) -> dict[str, Any]:
        obj = self.objects.get(oid)
        return obj.metadata if obj is not None else {}

    def sources(self, oid: str) -> frozenset[str]:
        cached = self._sources.get(oid)
        if cached is None:
            surface = self.meta(oid).get("surface")
            raw = surface.get("sources") if isinstance(surface, dict) else None
            cached = frozenset(str(s) for s in raw) if isinstance(raw, list) else frozenset()
            self._sources[oid] = cached
        return cached

    def is_asset(self, oid: str) -> bool:
        """Assets are what the organization's data declares; references are names seen only as
        DNS targets or in certificates, and addresses seen only as DNS answers."""
        sources = self.sources(oid)
        kind = self.kind(oid)
        if kind == "domain":
            return bool(sources & {"inventory", "dns", "endpoint"})
        if kind == "ip":
            return bool(sources & {"inventory", "endpoint"})
        if kind in ("service", "certificate", "cloud_asset"):
            return "inventory" in sources
        return False

    def status(self, oid: str) -> str:
        value = self.meta(oid).get("status")
        return str(value) if isinstance(value, str) and value else "active"

    def inactive(self, oid: str) -> bool:
        return self.status(oid) in INACTIVE_STATUSES

    def criticality(self, oid: str) -> str | None:
        obj = self.objects.get(oid)
        if obj is None:
            return None
        level = Criticality.of(obj.metadata, obj.tags)
        return level.value if level else None

    def timestamp(self, oid: str, key: str) -> datetime | None:
        value = self.meta(oid).get(key)
        if not isinstance(value, str) or not value:
            return None
        try:
            return parse_timestamp(value)
        except InvalidInputError:
            return None

    def surface_of(self, *kinds: str) -> list[str]:
        return [oid for oid in self.surface_ids if self.kind(oid) in kinds]

    def targets(self, oid: str, rel_type: str) -> list[str]:
        return [r.target_object for r in self.out.get(oid, ()) if r.relationship_type == rel_type]

    def sources_of(self, oid: str, rel_type: str) -> list[str]:
        return [r.source_object for r in self.inc.get(oid, ()) if r.relationship_type == rel_type]

    # ------------------------------------------------------------------ DNS
    def records_of(self, name_id: str, *, external_only: bool = False) -> list[DnsEntry]:
        return [r for r in self._records_of.get(name_id, ()) if not external_only or r.view == "external"]

    def records_to(self, target_id: str) -> list[DnsEntry]:
        return list(self._records_to.get(target_id, ()))

    def resolution(self, name_id: str) -> list[DnsEntry]:
        """External A/AAAA/CNAME records of a name."""
        return [r for r in self.records_of(name_id, external_only=True) if r.rtype in RESOLUTION_TYPES]

    def names_reaching(self, address_id: str) -> dict[str, list[DnsEntry]]:
        """Names whose external A/AAAA/CNAME chain reaches ``address_id`` (with the chain)."""
        found: dict[str, list[DnsEntry]] = {}
        frontier: list[tuple[str, list[DnsEntry]]] = [(address_id, [])]
        seen = {address_id}
        while frontier:
            target, chain = frontier.pop()
            for entry in self.records_to(target):
                if entry.view != "external" or entry.rtype not in RESOLUTION_TYPES or entry.name_id in seen:
                    continue
                seen.add(entry.name_id)
                path = [entry, *chain]
                found[entry.name] = path
                if len(path) < MAX_CHAIN:
                    frontier.append((entry.name_id, path))
        return dict(sorted(found.items()))

    # ------------------------------------------------------------------ endpoints
    def port_address_id(self, port_id: str) -> str | None:
        for target in self.targets(port_id, "HAS_ADDRESS"):
            return target
        address = self.meta(port_id).get("address")
        if isinstance(address, str) and address:
            try:
                return object_id("ip" if is_ip(address) else "domain", address)
            except InvalidInputError:
                return None
        return None

    def ports_at(self, address_id: str) -> list[str]:
        return [s for s in self.sources_of(address_id, "HAS_ADDRESS") if s.startswith("port:")]

    def service_ports(self, service_id: str) -> list[str]:
        return self.targets(service_id, "LISTENS_ON")

    def port_services(self, port_id: str) -> list[str]:
        return self.sources_of(port_id, "LISTENS_ON")

    def port_certificates(self, port_id: str) -> list[str]:
        return [c for c in self.targets(port_id, "PRESENTS") if self.status(c) != "removed"]

    def certificate_ports(self, cert_id: str) -> list[str]:
        return self.sources_of(cert_id, "PRESENTS")

    def port_number(self, port_id: str) -> int | None:
        value = self.meta(port_id).get("port")
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    def hosts_of(self, oid: str) -> list[str]:
        """Hosts that hold an address (HAS_ADDRESS) or run a service (RUNS)."""
        rel_type = "RUNS" if oid.startswith("service:") else "HAS_ADDRESS"
        return [s for s in self.sources_of(oid, rel_type) if s.startswith("host:")]

    def cloud_assets_at(self, address_id: str) -> list[str]:
        return [s for s in self.sources_of(address_id, "HAS_ADDRESS") if s.startswith("cloud_resource:")]

    def services_at(self, address_id: str) -> list[str]:
        services: list[str] = []
        for port in self.ports_at(address_id):
            for service in self.port_services(port):
                if service not in services:
                    services.append(service)
        return services

    def certificate_names(self, cert_id: str) -> list[str]:
        meta = self.meta(cert_id)
        names: list[str] = []
        cn = meta.get("subject_cn")
        if isinstance(cn, str):
            with contextlib.suppress(InvalidInputError):  # a CN such as "VPN appliance" names no host
                names.append(normalize_hostname(cn, "subject_cn", wildcard=True))
        sans = meta.get("sans")
        if isinstance(sans, list):
            names.extend(str(s) for s in sans if isinstance(s, str) and str(s) not in names)
        return names

    def known_address(self, oid: str) -> bool:
        """An address (or name) the organization's data knows as an asset, not only as a DNS answer."""
        if self.sources(oid) & {"inventory", "endpoint"}:
            return True
        return any(s.startswith(("host:", "cloud_resource:", "port:")) for s in self.sources_of(oid, "HAS_ADDRESS"))

    def inventoried_name(self, domain_id: str) -> bool:
        """A name in the asset inventory: a domain record, or the endpoint of an inventoried service
        or cloud asset."""
        if "inventory" in self.sources(domain_id):
            return True
        if any("inventory" in self.sources(c) for c in self.cloud_assets_at(domain_id)):
            return True
        return any("inventory" in self.sources(s) for s in self.services_at(domain_id))

    # ------------------------------------------------------------------ exposure
    def internet_facing(self, oid: str) -> tuple[bool, str]:
        """Whether an asset is recorded as reachable from the Internet, and why."""
        kind = self.kind(oid)
        meta = self.meta(oid)
        if kind == "service":
            if meta.get("internet_facing") is True:
                return True, f"{self.name(oid)} is recorded as internet-facing"
            return False, ""
        if kind == "cloud_asset":
            if meta.get("public") is True or meta.get("internet_facing") is True:
                return True, f"cloud asset {self.name(oid)} is public"
            return False, ""
        if kind == "port":
            services = self.port_services(oid)
            for service in services:
                if self.internet_facing(service)[0]:
                    return True, f"service {self.name(service)} at {self.key(oid)} is internet-facing"
            address = self.port_address_id(oid)
            if address is not None:
                for cloud in self.cloud_assets_at(address):
                    if self.internet_facing(cloud)[0]:
                        return True, f"{self.key(oid)} belongs to public cloud asset {self.name(cloud)}"
                if not services and address.startswith("ip:") and not is_internal_address(self.key(address)):
                    return True, f"{self.key(oid)} is a public address (no service record says otherwise)"
            return False, ""
        if kind in ("ip", "domain"):
            for service in self.services_at(oid):
                if self.internet_facing(service)[0]:
                    return True, f"internet-facing service {self.name(service)} listens on it"
            for cloud in self.cloud_assets_at(oid):
                if self.internet_facing(cloud)[0]:
                    return True, f"it is the address of public cloud asset {self.name(cloud)}"
        return False, ""

    def is_storage(self, cloud_id: str) -> bool:
        return str(self.meta(cloud_id).get("kind") or "") in STORAGE_TYPES

    # ------------------------------------------------------------------ ownership
    def direct_owners(self, oid: str) -> list[str]:
        names: list[str] = []
        owner = self.meta(oid).get("owner")
        if isinstance(owner, str) and owner.strip():
            names.append(safe_display(owner, 100))
        for source in self.sources_of(oid, "OWNS"):
            names.append(safe_display(self.name(source), 100))
        unique: dict[str, str] = {}
        for name in names:
            unique.setdefault(name.lower(), name)
        return list(unique.values())

    def ownership(self, oid: str) -> Ownership:
        direct = self.direct_owners(oid)
        if direct:
            return Ownership(tuple(direct))
        kind = self.kind(oid)
        if kind in ("ip", "service"):
            for host in self.hosts_of(oid):
                owners = self.direct_owners(host)
                if owners:
                    return Ownership(tuple(owners), f"host {self.name(host)}")
        if kind in ("ip", "domain"):
            for cloud in self.cloud_assets_at(oid):
                owners = self.direct_owners(cloud)
                if owners:
                    return Ownership(tuple(owners), f"cloud asset {self.name(cloud)}")
        if kind == "certificate":
            for port in self.certificate_ports(oid):
                for service in self.port_services(port):
                    found = self.ownership(service)
                    if found.owned:
                        return Ownership(found.owners, f"service {self.name(service)}")
                address = self.port_address_id(port)
                for cloud in self.cloud_assets_at(address) if address else []:
                    owners = self.direct_owners(cloud)
                    if owners:
                        return Ownership(tuple(owners), f"cloud asset {self.name(cloud)}")
        return Ownership()

    # ------------------------------------------------------------------ scope
    def scope_match(self, oid: str) -> ScopeMatch:
        cached = self._scope_cache.get(oid)
        if cached is None:
            cached = self._scope_match(oid)
            self._scope_cache[oid] = cached
        return cached

    def _scope_match(self, oid: str) -> ScopeMatch:
        scope = self.scope
        if not scope.configured:
            return ScopeMatch("unknown")
        out = ScopeMatch("out")
        kind = self.kind(oid)
        key = self.key(oid)
        if kind in ("domain", "ip"):
            entry = scope.match_domain(key) if kind == "domain" else scope.match_ip(key)
            if entry is not None:
                return ScopeMatch("in", entry)
            for cloud in self.cloud_assets_at(oid):
                found = self._cloud_scope(cloud)
                if found.in_scope:
                    return ScopeMatch("in", found.entry, f"cloud asset {self.name(cloud)}")
            return out
        if kind == "port":
            address = self.port_address_id(oid)
            if address is not None:
                found = self.scope_match(address)
                if found.in_scope:
                    return ScopeMatch("in", found.entry, found.via or f"address {self.key(address)}")
            return out
        if kind == "service":
            for port in self.service_ports(oid):
                found = self.scope_match(port)
                if found.in_scope:
                    return ScopeMatch("in", found.entry, f"endpoint {self.key(port)}")
            return out
        if kind == "cloud_asset":
            return self._cloud_scope(oid)
        if kind == "certificate":
            for port in self.certificate_ports(oid):
                found = self.scope_match(port)
                if found.in_scope:
                    return ScopeMatch("in", found.entry, f"presented at {self.key(port)}")
            for name in self.certificate_names(oid):
                entry = scope.match_domain(name)
                if entry is not None:
                    return ScopeMatch("in", entry, f"name {name}")
            return out
        if kind == "host":
            for address in self.targets(oid, "HAS_ADDRESS"):
                found = self.scope_match(address)
                if found.in_scope:
                    return ScopeMatch("in", found.entry, f"address {self.key(address)}")
            return out
        return ScopeMatch("unknown")

    def _cloud_scope(self, cloud_id: str) -> ScopeMatch:
        meta = self.meta(cloud_id)
        provider, account = meta.get("provider"), meta.get("account")
        entry = self.scope.match_cloud(
            provider if isinstance(provider, str) else None, account if isinstance(account, str) else None
        )
        if entry is not None:
            return ScopeMatch("in", entry)
        for address in self.targets(cloud_id, "HAS_ADDRESS"):
            found_entry = self.scope.match_address(self.key(address))
            if found_entry is not None:
                return ScopeMatch("in", found_entry, f"address {self.key(address)}")
        return ScopeMatch("out")

    # ------------------------------------------------------------------ names
    def org_names(self) -> list[str]:
        """Domain objects the organization declares: inventory domain records and DNS record names."""
        return [d for d in self.surface_of("domain") if self.sources(d) & {"inventory", "dns"}]

    def parent_of(self, domain_id: str, among: set[str]) -> str | None:
        for parent in parent_names(self.key(domain_id)):
            candidate = f"domain:{parent}"
            if candidate in among:
                return candidate
        return None
