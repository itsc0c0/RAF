"""Surface records -> R$F-native records of the shared Security Object Model.

=================  =====================================================================
Record             Objects and relationships
=================  =====================================================================
domain             ``domain:<name>`` (+ ``<owner> OWNS domain``)
dns A / AAAA       ``domain:<name> RESOLVES_TO ip:<address>`` (metadata record_type, view, ttl)
dns CNAME          ``domain:<name> RESOLVES_TO domain:<target>``
dns MX / NS        ``domain:<name> RELATED_TO domain:<target>`` (metadata record_type, priority)
dns TXT            ``metadata.txt`` of ``domain:<name>``
(any name)         ``domain:<child> PART_OF domain:<closest ancestor named in the same inventory>``
ip                 ``ip:<address>`` (+ ``host:<server> HAS_ADDRESS ip``)
service            ``service:<name or address:port/proto> LISTENS_ON port:<address>:<port>``,
                   ``port HAS_ADDRESS ip|domain``, ``host:<server> RUNS service``
certificate        ``certificate:<sha256> ISSUED_FOR domain:<cn/san>``,
                   ``port:<endpoint> PRESENTS certificate``
cloud_asset        ``cloud_resource:<provider>/<account>/<type>/<name> HAS_ADDRESS domain|ip``
owner              ``organization|user|group:<owner> OWNS <asset>``
=================  =====================================================================

Every object written by Surface carries ``metadata.surface.sources`` (how surface data saw it:
inventory, dns, dns-target, certificate, endpoint, owner; a list that accumulates across imports)
and the ``surface`` tag. Relationships carry ``metadata.surface = true``, ``last_seen`` (the
inventory's ``as_of`` or the import time) and, for records with status ``removed``, ``valid_to``:
the relationship is ended, not deleted, so history stays queryable. No first-seen timestamps are
written, so existing relationships of the workspace keep their time semantics when merged.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from raf.core.errors import InvalidInputError
from raf.core.ids import object_id
from raf.core.timeutil import format_ts
from raf.products.surface.formats import SurfaceDocument
from raf.products.surface.model import (
    MAX_LINKED_NAMES,
    MAX_TXT,
    Endpoint,
    OwnerRef,
    cloud_key,
    is_internal_address,
    parent_names,
)
from raf.products.surface.records import (
    CertificateRecord,
    CloudAssetRecord,
    DnsRecord,
    DomainRecord,
    IpRecord,
    OwnerRecord,
    ParsedRecord,
    ServiceRecord,
    owner_type,
    parse_record,
)

RELATIONSHIP_CONFIDENCE = 0.9


@dataclass(frozen=True, slots=True)
class Ref:
    """An object reference by type and natural key (IDs are always derived by ``object_id``)."""

    type: str
    name: str
    key: str | None = None

    @property
    def id(self) -> str:
        return object_id(self.type, self.key if self.key is not None else self.name)

    def as_ref(self) -> dict[str, str]:
        data = {"type": self.type, "name": self.name}
        if self.key is not None:
            data["key"] = self.key
        return data


@dataclass(slots=True)
class NativeRecord:
    locator: str
    data: dict[str, Any]


@dataclass(slots=True)
class Rejected:
    locator: str
    reason: str
    raw: str | None = None


@dataclass(slots=True)
class Conversion:
    natives: list[NativeRecord] = field(default_factory=list)
    rejected: list[Rejected] = field(default_factory=list)
    accepted: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def records(self) -> int:
        return self.accepted + len(self.rejected)


def raw_excerpt(data: Any, limit: int = 2000) -> str | None:
    """A bounded, ASCII-escaped JSON excerpt of a rejected record (control characters escaped)."""
    try:
        text = json.dumps(data, ensure_ascii=True, default=str)
    except (RecursionError, ValueError, TypeError):
        return None
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def _reason(exc: InvalidInputError) -> str:
    return exc.message + (f" ({exc.hint})" if exc.hint else "")


class _Converter:
    def __init__(self, observed: datetime) -> None:
        self.observed = observed
        self.natives: list[NativeRecord] = []
        self.names: dict[str, str] = {}  # org names (domain records, DNS record names) -> first locator
        self.txt: dict[str, tuple[str, list[str]]] = {}
        self.clouds: dict[str, list[Ref]] = {}
        self.warnings: list[str] = []

    # ------------------------------------------------------------------ primitives
    def obj(
        self,
        locator: str,
        ref: Ref,
        source: str,
        metadata: dict[str, Any] | None = None,
        tags: Iterable[str] = (),
    ) -> Ref:
        meta = {k: v for k, v in (metadata or {}).items() if v is not None}
        meta["surface"] = {"sources": [source]}
        record: dict[str, Any] = {
            "kind": "object",
            "type": ref.type,
            "name": ref.name,
            "metadata": meta,
            "tags": sorted({"surface", *tags}),
        }
        if ref.key is not None:
            record["key"] = ref.key
        self.natives.append(NativeRecord(locator, record))
        return ref

    def rel(
        self,
        locator: str,
        source: Ref,
        rtype: str,
        target: Ref,
        metadata: dict[str, Any] | None = None,
        ended: datetime | None = None,
    ) -> None:
        meta: dict[str, Any] = {"surface": True}
        meta.update({k: v for k, v in (metadata or {}).items() if v is not None})
        record: dict[str, Any] = {
            "kind": "relationship",
            "source": source.as_ref(),
            "type": rtype,
            "target": target.as_ref(),
            "confidence": RELATIONSHIP_CONFIDENCE,
            "metadata": meta,
            "last_seen": format_ts(self.observed),
        }
        if ended is not None:
            record["valid_to"] = format_ts(ended)
        self.natives.append(NativeRecord(locator, record))

    def owner(self, locator: str, owner: OwnerRef | None, asset: Ref) -> None:
        if owner is None:
            return
        principal = self.obj(locator, Ref(owner_type(owner), owner.name), "owner")
        self.rel(locator, principal, "OWNS", asset)

    def endpoint(self, locator: str, endpoint: Endpoint) -> Ref:
        if endpoint.is_ip:
            address = self.obj(
                locator,
                Ref("ip", endpoint.address),
                "endpoint",
                {"private": is_internal_address(endpoint.address)},
            )
        else:
            address = self.obj(locator, Ref("domain", endpoint.address), "endpoint")
        port = self.obj(
            locator,
            Ref("port", endpoint.port_key),
            "endpoint",
            {"port": endpoint.port, "protocol": endpoint.transport, "address": endpoint.address},
        )
        self.rel(locator, port, "HAS_ADDRESS", address)
        return port

    # ------------------------------------------------------------------ record kinds
    def domain(self, r: DomainRecord) -> None:
        ref = self.obj(
            r.locator,
            Ref("domain", r.name),
            "inventory",
            {
                "owner": r.owner.name if r.owner else None,
                "registrar": r.registrar,
                "expires": format_ts(r.expires),
                "status": r.status,
                "criticality": r.criticality,
                "notes": r.notes,
            },
            r.tags,
        )
        self.names.setdefault(r.name, r.locator)
        self.owner(r.locator, r.owner, ref)

    def dns(self, r: DnsRecord) -> None:
        name = self.obj(r.locator, Ref("domain", r.name), "dns")
        self.names.setdefault(r.name, r.locator)
        ended = (r.removed_at or self.observed) if r.removed else None
        meta: dict[str, Any] = {"record_type": r.rtype, "view": r.view, "ttl": r.ttl}
        if r.rtype in ("A", "AAAA"):
            address = self.obj(r.locator, Ref("ip", r.value), "dns-target", {"private": is_internal_address(r.value)})
            self.rel(r.locator, name, "RESOLVES_TO", address, meta, ended)
        elif r.rtype == "CNAME":
            target = self.obj(r.locator, Ref("domain", r.value), "dns-target")
            self.rel(r.locator, name, "RESOLVES_TO", target, meta, ended)
        elif r.rtype in ("MX", "NS"):
            target = self.obj(r.locator, Ref("domain", r.value), "dns-target")
            self.rel(r.locator, name, "RELATED_TO", target, {**meta, "priority": r.priority}, ended)
        elif not r.removed:
            _first, values = self.txt.setdefault(r.name, (r.locator, []))
            if r.value not in values:
                values.append(r.value)

    def ip(self, r: IpRecord) -> None:
        ref = self.obj(
            r.locator,
            Ref("ip", r.address),
            "inventory",
            {
                "owner": r.owner.name if r.owner else None,
                "provider": r.provider,
                "asn": r.asn,
                "status": r.status,
                "criticality": r.criticality,
                "notes": r.notes,
                "private": is_internal_address(r.address),
            },
            r.tags,
        )
        if r.server:
            host = self.obj(r.locator, Ref("host", r.server), "inventory")
            self.rel(r.locator, host, "HAS_ADDRESS", ref)
        self.owner(r.locator, r.owner, ref)

    def service(self, r: ServiceRecord) -> None:
        endpoint = r.endpoint
        ref = self.obj(
            r.locator,
            Ref("service", r.name or endpoint.service_key),
            "inventory",
            {
                "port": endpoint.port,
                "transport": endpoint.transport,
                "product": r.product,
                "internet_facing": r.internet_facing,
                "owner": r.owner.name if r.owner else None,
                "criticality": r.criticality,
                "role": r.role,
                "status": r.status,
                "notes": r.notes,
                "hostname": r.hostname,
                "addresses": [endpoint.address],
            },
            r.tags,
        )
        port = self.endpoint(r.locator, endpoint)
        self.rel(r.locator, ref, "LISTENS_ON", port)
        if r.server:
            host = self.obj(r.locator, Ref("host", r.server), "inventory")
            self.rel(r.locator, host, "RUNS", ref)
            if endpoint.is_ip:
                self.rel(r.locator, host, "HAS_ADDRESS", Ref("ip", endpoint.address))
        self.owner(r.locator, r.owner, ref)

    def certificate(self, r: CertificateRecord) -> None:
        ref = self.obj(
            r.locator,
            Ref("certificate", r.cn or r.names[0], key=r.key),
            "inventory",
            {
                "subject_cn": r.cn,
                "sans": r.sans,
                "issuer": r.issuer,
                "serial": r.serial,
                "not_before": format_ts(r.not_before),
                "not_after": format_ts(r.not_after),
                "fingerprint_sha256": r.fingerprint,
                "self_signed": r.self_signed,
                "owner": r.owner.name if r.owner else None,
                "status": "removed" if r.removed else "active",
                "notes": r.notes,
            },
            r.tags,
        )
        concrete = [name for name in r.names if not name.startswith("*.")]
        if len(concrete) > MAX_LINKED_NAMES:
            self.warnings.append(f"{r.locator}: certificate names beyond {MAX_LINKED_NAMES} are kept in metadata only")
        for name in concrete[:MAX_LINKED_NAMES]:
            domain = self.obj(r.locator, Ref("domain", name), "certificate")
            self.rel(r.locator, ref, "ISSUED_FOR", domain)
        ended = self.observed if r.removed else None
        for endpoint in r.presented_by:
            port = self.endpoint(r.locator, endpoint)
            self.rel(r.locator, port, "PRESENTS", ref, ended=ended)
        self.owner(r.locator, r.owner, ref)

    def cloud_asset(self, r: CloudAssetRecord) -> None:
        ref = self.obj(
            r.locator,
            Ref("cloud_resource", r.name, key=cloud_key(r.provider, r.account, r.type, r.name)),
            "inventory",
            {
                "kind": r.type,
                "provider": r.provider,
                "account": r.account,
                "region": r.region,
                "public": r.public,
                "internet_facing": r.public,
                "classification": r.classification,
                "criticality": r.criticality,
                "owner": r.owner.name if r.owner else None,
                "status": r.status,
                "endpoint": r.endpoint,
                "address": r.address,
                "resource_id": r.resource_id,
                "notes": r.notes,
            },
            r.tags,
        )
        if r.endpoint:
            endpoint = self.obj(r.locator, Ref("domain", r.endpoint), "endpoint")
            self.rel(r.locator, ref, "HAS_ADDRESS", endpoint)
        if r.address:
            address = self.obj(r.locator, Ref("ip", r.address), "endpoint", {"private": is_internal_address(r.address)})
            self.rel(r.locator, ref, "HAS_ADDRESS", address)
        self.owner(r.locator, r.owner, ref)

    def resolve_asset(self, r: OwnerRecord) -> Ref:
        if r.asset_kind == "certificate":
            return Ref("certificate", r.asset, key=r.asset)
        if r.asset_kind != "cloud_asset":
            return Ref(r.asset_kind, r.asset)
        parts = r.asset.split("/")
        if len(parts) == 4 and all(parts):
            provider, account, kind, name = parts
            return Ref(
                "cloud_resource",
                name,
                key=cloud_key(provider.lower(), None if account == "-" else account.lower(), kind.lower(), name),
            )
        candidates = self.clouds.get(r.asset, [])
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            raise InvalidInputError(
                f"No cloud asset named {r.asset!r} in this inventory.",
                hint="Reference cloud assets from other imports as provider/account/type/name.",
            )
        raise InvalidInputError(
            f"Several cloud assets are named {r.asset!r}.", hint="Use provider/account/type/name to pick one."
        )

    def owner_record(self, r: OwnerRecord) -> None:
        asset = self.resolve_asset(r)
        principal = self.obj(r.locator, Ref(owner_type(r.owner), r.owner.name), "owner")
        ended = (r.removed_at or self.observed) if r.removed else None
        self.rel(r.locator, principal, "OWNS", asset, {"contact": r.contact}, ended)

    # ------------------------------------------------------------------ document
    def run(self, parsed: list[ParsedRecord]) -> list[Rejected]:
        rejected: list[Rejected] = []
        for item in parsed:
            if isinstance(item.record, CloudAssetRecord):
                r = item.record
                ref = Ref("cloud_resource", r.name, key=cloud_key(r.provider, r.account, r.type, r.name))
                if ref not in self.clouds.setdefault(r.name, []):
                    self.clouds[r.name].append(ref)
        for item in parsed:
            record = item.record
            try:
                if isinstance(record, DomainRecord):
                    self.domain(record)
                elif isinstance(record, DnsRecord):
                    self.dns(record)
                elif isinstance(record, IpRecord):
                    self.ip(record)
                elif isinstance(record, ServiceRecord):
                    self.service(record)
                elif isinstance(record, CertificateRecord):
                    self.certificate(record)
                elif isinstance(record, CloudAssetRecord):
                    self.cloud_asset(record)
                else:
                    self.owner_record(record)
            except InvalidInputError as exc:
                rejected.append(Rejected(record.locator, _reason(exc)))
        for name in sorted(self.names):
            for parent in parent_names(name):
                if parent in self.names:
                    self.rel(self.names[name], Ref("domain", name), "PART_OF", Ref("domain", parent))
                    break
        for name, (locator, values) in sorted(self.txt.items()):
            if len(values) > MAX_TXT:
                self.warnings.append(f"{name}: only the first {MAX_TXT} TXT values are kept")
            self.obj(locator, Ref("domain", name), "dns", {"txt": values[:MAX_TXT]})
        return rejected


def build(document: SurfaceDocument, *, observed: datetime) -> Conversion:
    """Validate every record of a document and convert the valid ones to native records."""
    result = Conversion()
    result.rejected.extend(Rejected(locator, reason) for locator, reason in document.rejections)
    parsed: list[ParsedRecord] = []
    unknown: Counter[str] = Counter()
    for item in document.items:
        try:
            record = parse_record(item)
        except InvalidInputError as exc:
            result.rejected.append(Rejected(item.locator, _reason(exc), raw_excerpt(item.data)))
            continue
        except RecursionError:
            result.rejected.append(Rejected(item.locator, "The record is nested too deeply."))
            continue
        parsed.append(record)
        unknown.update(record.unknown_fields)
    converter = _Converter(observed)
    failed = converter.run(parsed)
    failed_locators = {f.locator for f in failed}
    result.rejected.extend(failed)
    by_kind: Counter[str] = Counter(p.kind for p in parsed if p.record.locator not in failed_locators)
    result.accepted = sum(by_kind.values())
    result.by_kind = dict(sorted(by_kind.items()))
    result.natives = converter.natives
    result.warnings = list(document.warnings) + converter.warnings[:20]
    if unknown:
        shown = ", ".join(f"{name} ({count})" for name, count in unknown.most_common(8))
        result.warnings.append(f"unknown fields ignored: {shown}")
    return result
