"""Validation of surface inventory records into typed records.

Record kinds (field aliases in parentheses):

* ``domain``      name (domain, fqdn), owner, registrar, expires, status, criticality, notes, tags
* ``dns``         name, type (A, AAAA, CNAME, MX, NS, TXT), value, ttl, view (external|internal),
                  priority (MX), status (active|removed), removed_at
* ``ip``          address (ip), owner, provider, asn, host (server), status, criticality, notes, tags
* ``service``     ip or host (the endpoint), port, protocol (tcp|udp), product, name, internet_facing,
                  server (the host running it), owner, criticality, role, status, notes, tags
* ``certificate`` subject_cn (cn, subject), sans, issuer, serial, not_before, not_after,
                  fingerprint_sha256, presented_by (ip:port or host:port entries), self_signed,
                  owner, status (active|removed), notes
* ``cloud_asset`` provider, account, type (bucket, container, load_balancer, vm ...), name, public,
                  owner, region, endpoint (host name), address (ip), classification, criticality,
                  resource_id, status, notes, tags
* ``owner``       owner, asset (typed reference such as ``domain:www.raven.example``), asset_kind,
                  contact, status (active|removed), removed_at
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from raf.core.errors import InvalidInputError
from raf.products.surface.formats import RawItem
from raf.products.surface.model import (
    DNS_TYPES,
    MAX_ITEMS,
    MAX_NAMES,
    MAX_NOTE,
    MAX_TEXT,
    RECORD_KINDS,
    Endpoint,
    OwnerRef,
    clean_text,
    describe,
    is_ip,
    normalize_account,
    normalize_fingerprint,
    normalize_hostname,
    normalize_ip,
    normalize_resource_name,
    normalize_token,
    parse_bool,
    parse_criticality,
    parse_endpoint,
    parse_list,
    parse_owner,
    parse_port,
    parse_status,
    parse_time,
    parse_transport,
    parse_view,
    require_text,
)

MAX_FIELDS = 64
ASSET_STATUSES = ("active", "decommissioned")
RECORD_STATUSES = ("active", "removed")

_KIND_ALIASES = {
    "domain": "domain",
    "subdomain": "domain",
    "dns": "dns",
    "dns_record": "dns",
    "record": "dns",
    "ip": "ip",
    "address": "ip",
    "ip_address": "ip",
    "service": "service",
    "certificate": "certificate",
    "cert": "certificate",
    "cloud_asset": "cloud_asset",
    "cloud": "cloud_asset",
    "cloud_resource": "cloud_asset",
    "owner": "owner",
    "ownership": "owner",
}

#: Accepted field names per kind (aliases map to the canonical name).
FIELDS: dict[str, dict[str, str]] = {
    "domain": {
        "name": "name",
        "domain": "name",
        "fqdn": "name",
        "owner": "owner",
        "registrar": "registrar",
        "expires": "expires",
        "expiry": "expires",
        "expiration": "expires",
        "status": "status",
        "criticality": "criticality",
        "notes": "notes",
        "description": "notes",
        "tags": "tags",
    },
    "dns": {
        "name": "name",
        "host": "name",
        "fqdn": "name",
        "type": "type",
        "record_type": "type",
        "rtype": "type",
        "value": "value",
        "data": "value",
        "target": "value",
        "content": "value",
        "answer": "value",
        "ttl": "ttl",
        "view": "view",
        "priority": "priority",
        "preference": "priority",
        "status": "status",
        "removed_at": "removed_at",
        "notes": "notes",
    },
    "ip": {
        "address": "address",
        "ip": "address",
        "value": "address",
        "owner": "owner",
        "provider": "provider",
        "asn": "asn",
        "host": "host",
        "server": "host",
        "status": "status",
        "criticality": "criticality",
        "notes": "notes",
        "description": "notes",
        "tags": "tags",
    },
    "service": {
        "ip": "ip",
        "address": "ip",
        "host": "host",
        "hostname": "host",
        "fqdn": "host",
        "server": "server",
        "port": "port",
        "protocol": "protocol",
        "transport": "protocol",
        "product": "product",
        "software": "product",
        "name": "name",
        "service": "name",
        "internet_facing": "internet_facing",
        "exposed": "internet_facing",
        "public": "internet_facing",
        "owner": "owner",
        "criticality": "criticality",
        "role": "role",
        "status": "status",
        "notes": "notes",
        "description": "notes",
        "tags": "tags",
    },
    "certificate": {
        "subject_cn": "subject_cn",
        "cn": "subject_cn",
        "common_name": "subject_cn",
        "subject": "subject_cn",
        "sans": "sans",
        "san": "sans",
        "subject_alt_names": "sans",
        "names": "sans",
        "issuer": "issuer",
        "serial": "serial",
        "serial_number": "serial",
        "not_before": "not_before",
        "valid_from": "not_before",
        "not_after": "not_after",
        "valid_to": "not_after",
        "expires": "not_after",
        "fingerprint_sha256": "fingerprint_sha256",
        "fingerprint": "fingerprint_sha256",
        "sha256": "fingerprint_sha256",
        "presented_by": "presented_by",
        "endpoints": "presented_by",
        "endpoint": "presented_by",
        "self_signed": "self_signed",
        "owner": "owner",
        "status": "status",
        "notes": "notes",
        "tags": "tags",
    },
    "cloud_asset": {
        "provider": "provider",
        "account": "account",
        "account_id": "account",
        "subscription": "account",
        "project": "account",
        "type": "type",
        "resource_type": "type",
        "asset_type": "type",
        "name": "name",
        "public": "public",
        "publicly_accessible": "public",
        "owner": "owner",
        "region": "region",
        "endpoint": "endpoint",
        "hostname": "endpoint",
        "url": "endpoint",
        "address": "address",
        "ip": "address",
        "classification": "classification",
        "data_classification": "classification",
        "criticality": "criticality",
        "resource_id": "resource_id",
        "status": "status",
        "notes": "notes",
        "description": "notes",
        "tags": "tags",
    },
    "owner": {
        "owner": "owner",
        "team": "owner",
        "asset": "asset",
        "target": "asset",
        "asset_kind": "asset_kind",
        "asset_type": "asset_kind",
        "contact": "contact",
        "status": "status",
        "removed_at": "removed_at",
        "notes": "notes",
    },
}
_COMMON_IGNORED = frozenset({"kind", "format", "id", "source", "comment"})


# --------------------------------------------------------------------------- typed records


@dataclass(slots=True)
class DomainRecord:
    locator: str
    name: str
    owner: OwnerRef | None = None
    registrar: str | None = None
    expires: datetime | None = None
    status: str | None = None
    criticality: str | None = None
    notes: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DnsRecord:
    locator: str
    name: str
    rtype: str
    value: str
    view: str = "external"
    ttl: int | None = None
    priority: int | None = None
    removed: bool = False
    removed_at: datetime | None = None


@dataclass(slots=True)
class IpRecord:
    locator: str
    address: str
    owner: OwnerRef | None = None
    provider: str | None = None
    asn: str | None = None
    server: str | None = None
    status: str | None = None
    criticality: str | None = None
    notes: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ServiceRecord:
    locator: str
    endpoint: Endpoint
    name: str | None = None
    hostname: str | None = None
    server: str | None = None
    product: str | None = None
    internet_facing: bool | None = None
    owner: OwnerRef | None = None
    criticality: str | None = None
    role: str | None = None
    status: str | None = None
    notes: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CertificateRecord:
    locator: str
    key: str
    cn: str | None
    names: list[str]  # host names the certificate is valid for (CN when it is a host name, plus SANs)
    sans: list[str] = field(default_factory=list)
    issuer: str | None = None
    serial: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    fingerprint: str | None = None
    presented_by: list[Endpoint] = field(default_factory=list)
    self_signed: bool | None = None
    owner: OwnerRef | None = None
    removed: bool = False
    notes: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CloudAssetRecord:
    locator: str
    provider: str
    account: str | None
    type: str
    name: str
    public: bool | None = None
    owner: OwnerRef | None = None
    region: str | None = None
    endpoint: str | None = None
    address: str | None = None
    classification: str | None = None
    criticality: str | None = None
    resource_id: str | None = None
    status: str | None = None
    notes: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class OwnerRecord:
    locator: str
    owner: OwnerRef
    asset_kind: str
    asset: str  # normalized reference value (resolved to an object during conversion)
    contact: str | None = None
    removed: bool = False
    removed_at: datetime | None = None


SurfaceRecord = DomainRecord | DnsRecord | IpRecord | ServiceRecord | CertificateRecord | CloudAssetRecord | OwnerRecord


# --------------------------------------------------------------------------- parsing


class _Fields:
    """Field access by canonical name; remembers unknown field names."""

    def __init__(self, kind: str, data: dict[Any, Any]) -> None:
        aliases = FIELDS[kind]
        self.values: dict[str, Any] = {}
        self.unknown: list[str] = []
        for raw_key, value in data.items():
            key = raw_key.strip().lower().replace("-", "_").replace(" ", "_") if isinstance(raw_key, str) else None
            canonical = aliases.get(key) if key else None
            if canonical is None:
                if key not in _COMMON_IGNORED:
                    self.unknown.append(clean_text(str(raw_key), "field", limit=60, truncate=True) or "?")
                continue
            if canonical not in self.values or self.values[canonical] in (None, ""):
                self.values[canonical] = value

    def get(self, name: str) -> Any:
        value = self.values.get(name)
        return None if value == "" else value


def _tags(fields: _Fields) -> list[str]:
    tags: list[str] = []
    for item in parse_list(fields.get("tags"), "tags", limit=50):
        text = clean_text(item, "tags", limit=64)
        if text and text not in tags:
            tags.append(text)
    return tags


def _notes(fields: _Fields) -> str | None:
    return clean_text(fields.get("notes"), "notes", limit=MAX_NOTE, truncate=True)


def _server(value: Any) -> str | None:
    text = clean_text(value, "server", limit=100)
    if text is not None and ("/" in text or text.count(":") > 1):
        raise InvalidInputError("'server' must be a host name such as VPN-01.")
    return text


def _domain(locator: str, f: _Fields) -> DomainRecord:
    return DomainRecord(
        locator=locator,
        name=normalize_hostname(f.get("name"), "name", wildcard=False),
        owner=parse_owner(f.get("owner")),
        registrar=clean_text(f.get("registrar"), "registrar"),
        expires=parse_time(f.get("expires"), "expires"),
        status=parse_status(f.get("status"), ASSET_STATUSES) if f.get("status") is not None else None,
        criticality=parse_criticality(f.get("criticality")),
        notes=_notes(f),
        tags=_tags(f),
    )


def _int_field(value: Any, field_name: str, maximum: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise InvalidInputError(f"'{field_name}' must be a number.")
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    elif isinstance(value, str) and value.strip().isdecimal() and len(value.strip()) <= 10:
        number = int(value.strip())
    else:
        raise InvalidInputError(f"'{field_name}' must be a number.")
    if not 0 <= number <= maximum:
        raise InvalidInputError(f"'{field_name}' must be between 0 and {maximum}.")
    return number


def _dns(locator: str, f: _Fields) -> DnsRecord:
    name = normalize_hostname(f.get("name"), "name", wildcard=True)
    rtype = require_text(f.get("type"), "type", limit=10).upper()
    if rtype not in DNS_TYPES:
        raise InvalidInputError(
            f"Unsupported DNS record type {rtype!r}.", hint="Supported types: " + ", ".join(DNS_TYPES) + "."
        )
    raw_value = f.get("value")
    priority = _int_field(f.get("priority"), "priority", 65535)
    value: str
    if rtype in ("A", "AAAA"):
        value = normalize_ip(raw_value, "value")
        if (":" in value) != (rtype == "AAAA"):
            raise InvalidInputError(f"{rtype} records need an IPv{'6' if rtype == 'AAAA' else '4'} address.")
    elif rtype == "MX":
        text = require_text(raw_value, "value", limit=300)
        parts = text.split()
        if len(parts) == 2 and parts[0].isdecimal() and len(parts[0]) <= 5:
            priority = int(parts[0]) if priority is None else priority
            text = parts[1]
        value = normalize_hostname(text, "value")
    elif rtype in ("CNAME", "NS"):
        value = normalize_hostname(raw_value, "value")
        if rtype == "CNAME" and value == name:
            raise InvalidInputError("A CNAME record cannot point to itself.")
    else:
        txt = clean_text(raw_value, "value", limit=512, truncate=True)
        if txt is None:
            raise InvalidInputError("'value' is required.")
        value = txt[1:-1] if len(txt) >= 2 and txt[0] == txt[-1] == '"' else txt
    status = parse_status(f.get("status"), RECORD_STATUSES)
    return DnsRecord(
        locator=locator,
        name=name,
        rtype=rtype,
        value=value,
        view=parse_view(f.get("view")),
        ttl=_int_field(f.get("ttl"), "ttl", 2**31 - 1),
        priority=priority if rtype == "MX" else None,
        removed=status == "removed",
        removed_at=parse_time(f.get("removed_at"), "removed_at"),
    )


def _asn(value: Any) -> str | None:
    text = clean_text(value, "asn", limit=20)
    if text is None:
        return None
    digits = text.upper().removeprefix("AS")
    if not digits.isdecimal() or len(digits) > 10:
        raise InvalidInputError("'asn' must look like AS64500.")
    return f"AS{int(digits)}"


def _ip(locator: str, f: _Fields) -> IpRecord:
    return IpRecord(
        locator=locator,
        address=normalize_ip(f.get("address"), "address"),
        owner=parse_owner(f.get("owner")),
        provider=clean_text(f.get("provider"), "provider"),
        asn=_asn(f.get("asn")),
        server=_server(f.get("host")),
        status=parse_status(f.get("status"), ASSET_STATUSES) if f.get("status") is not None else None,
        criticality=parse_criticality(f.get("criticality")),
        notes=_notes(f),
        tags=_tags(f),
    )


def _service(locator: str, f: _Fields) -> ServiceRecord:
    port = parse_port(f.get("port"))
    transport = parse_transport(f.get("protocol"))
    raw_ip, raw_host = f.get("ip"), f.get("host")
    hostname: str | None = None
    server = _server(f.get("server"))
    if raw_host is not None:
        host_text = require_text(raw_host, "host", limit=300)
        if is_ip(host_text) and raw_ip is None:
            raw_ip = host_text
        elif "." in host_text:
            hostname = normalize_hostname(host_text, "host")
        elif server is None:
            server = _server(host_text)
    if raw_ip is not None:
        endpoint = Endpoint(normalize_ip(raw_ip, "ip"), port, transport)
    elif hostname is not None:
        endpoint = Endpoint(hostname, port, transport)
    else:
        raise InvalidInputError(
            "A service needs an endpoint: 'ip' or a fully qualified 'host'.",
            hint="Name the server running it with 'server' (for example VPN-01).",
        )
    name = clean_text(f.get("name"), "name", limit=100)
    role = clean_text(f.get("role"), "role", limit=40)
    return ServiceRecord(
        locator=locator,
        endpoint=endpoint,
        name=name,
        hostname=hostname if endpoint.address != hostname else None,
        server=server,
        product=clean_text(f.get("product"), "product", limit=MAX_TEXT, truncate=True),
        internet_facing=parse_bool(f.get("internet_facing"), "internet_facing"),
        owner=parse_owner(f.get("owner")),
        criticality=parse_criticality(f.get("criticality")),
        role=role.lower() if role else None,
        status=parse_status(f.get("status"), ASSET_STATUSES) if f.get("status") is not None else None,
        notes=_notes(f),
        tags=_tags(f),
    )


def _common_name(value: Any) -> str | None:
    text = clean_text(value, "subject_cn", limit=300)
    if text is None:
        return None
    if "=" in text:  # a full subject such as "CN=www.raven.example, O=Raven"
        for part in text.replace(";", ",").split(","):
            key, sep, rest = part.strip().partition("=")
            if sep and key.strip().upper() == "CN":
                return rest.strip() or None
        return None
    return text


def _certificate(locator: str, f: _Fields) -> CertificateRecord:
    cn = _common_name(f.get("subject_cn"))
    sans: list[str] = []
    for item in parse_list(f.get("sans"), "sans", limit=MAX_NAMES):
        text = require_text(item, "sans", limit=300)
        if text.lower().startswith("dns:"):
            text = text[4:]
        if is_ip(text):
            continue  # IP SANs do not name DNS assets
        name = normalize_hostname(text, "sans", wildcard=True)
        if name not in sans:
            sans.append(name)
    names = list(sans)
    if cn is not None:
        try:
            cn_name = normalize_hostname(cn, "subject_cn", wildcard=True)
        except InvalidInputError:
            cn_name = None  # a CN such as "Raven VPN appliance" is not a host name
        if cn_name is not None and cn_name not in names:
            names.insert(0, cn_name)
    fingerprint = normalize_fingerprint(f.get("fingerprint_sha256"))
    issuer = clean_text(f.get("issuer"), "issuer", limit=300)
    serial = clean_text(f.get("serial"), "serial", limit=100)
    if fingerprint is not None:
        key = fingerprint
    elif issuer and serial:
        key = f"{issuer}|{serial}".lower()
    else:
        raise InvalidInputError("A certificate needs fingerprint_sha256, or issuer and serial, to identify it.")
    if cn is None and not names:
        raise InvalidInputError("A certificate needs a subject_cn or at least one SAN.")
    endpoints: list[Endpoint] = []
    for item in parse_list(f.get("presented_by"), "presented_by", limit=MAX_ITEMS):
        endpoint = parse_endpoint(item, "presented_by")
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    not_before = parse_time(f.get("not_before"), "not_before")
    not_after = parse_time(f.get("not_after"), "not_after")
    if not_before and not_after and not_after < not_before:
        raise InvalidInputError("'not_after' is earlier than 'not_before'.")
    self_signed = parse_bool(f.get("self_signed"), "self_signed")
    if self_signed is None and issuer and cn and issuer.lower() in (cn.lower(), f"cn={cn.lower()}"):
        self_signed = True
    return CertificateRecord(
        locator=locator,
        key=key,
        cn=cn,
        names=names,
        sans=sans,
        issuer=issuer,
        serial=serial,
        not_before=not_before,
        not_after=not_after,
        fingerprint=fingerprint,
        presented_by=endpoints,
        self_signed=self_signed,
        owner=parse_owner(f.get("owner")),
        removed=parse_status(f.get("status"), RECORD_STATUSES) == "removed",
        notes=_notes(f),
        tags=_tags(f),
    )


def _endpoint_host(value: Any) -> str | None:
    text = clean_text(value, "endpoint", limit=500)
    if text is None:
        return None
    if "://" in text:
        try:
            host = urlsplit(text).hostname
        except ValueError as exc:
            raise InvalidInputError("'endpoint' is not a valid URL or host name.") from exc
        if not host:
            raise InvalidInputError("'endpoint' is not a valid URL or host name.")
        text = host
    return normalize_hostname(text, "endpoint")


def _cloud_asset(locator: str, f: _Fields) -> CloudAssetRecord:
    classification = clean_text(f.get("classification"), "classification", limit=40)
    address = f.get("address")
    return CloudAssetRecord(
        locator=locator,
        provider=normalize_token(f.get("provider"), "provider"),
        account=normalize_account(f.get("account")),
        type=normalize_token(f.get("type"), "type").replace("-", "_"),
        name=normalize_resource_name(f.get("name")),
        public=parse_bool(f.get("public"), "public"),
        owner=parse_owner(f.get("owner")),
        region=clean_text(f.get("region"), "region", limit=64),
        endpoint=_endpoint_host(f.get("endpoint")),
        address=normalize_ip(address, "address") if address is not None else None,
        classification=classification.lower() if classification else None,
        criticality=parse_criticality(f.get("criticality")),
        resource_id=clean_text(f.get("resource_id"), "resource_id", limit=300),
        status=parse_status(f.get("status"), ASSET_STATUSES) if f.get("status") is not None else None,
        notes=_notes(f),
        tags=_tags(f),
    )


_ASSET_KINDS = {
    "domain": "domain",
    "ip": "ip",
    "service": "service",
    "certificate": "certificate",
    "cert": "certificate",
    "cloud_asset": "cloud_asset",
    "cloud_resource": "cloud_asset",
    "cloud": "cloud_asset",
    "host": "host",
}


def _owner(locator: str, f: _Fields) -> OwnerRecord:
    owner = parse_owner(f.get("owner"))
    if owner is None:
        raise InvalidInputError("'owner' is required.")
    text = require_text(f.get("asset"), "asset", limit=400)
    hint = clean_text(f.get("asset_kind"), "asset_kind", limit=20)
    kind = _ASSET_KINDS.get(hint.lower()) if hint else None
    if hint and kind is None:
        raise InvalidInputError(f"Unknown asset_kind {hint!r}.", hint="Use " + ", ".join(sorted(set(_ASSET_KINDS))))
    if kind is None:
        prefix, sep, rest = text.partition(":")
        if sep and prefix.strip().lower() in _ASSET_KINDS and rest.strip():
            kind, text = _ASSET_KINDS[prefix.strip().lower()], rest.strip()
        elif is_ip(text):
            kind = "ip"
        elif "." in text and " " not in text:
            kind = "domain"
        else:
            raise InvalidInputError(
                f"Cannot tell what kind of asset {text[:80]!r} is.",
                hint="Use a typed reference such as domain:www.raven.example, ip:198.51.100.10, service:vpn, "
                "certificate:<sha256> or cloud_asset:<name>.",
            )
    value: str
    if kind == "domain":
        value = normalize_hostname(text, "asset")
    elif kind == "ip":
        value = normalize_ip(text, "asset")
    elif kind == "certificate":
        try:
            value = normalize_fingerprint(text) or text
        except InvalidInputError:
            value = text.lower()  # an issuer|serial key
    elif kind == "service" and text.count(":") >= 1 and text.rsplit(":", 1)[-1].split("/")[0].isdecimal():
        value = parse_endpoint(text, "asset").service_key
    else:
        value = require_text(text, "asset", limit=255)
    status = parse_status(f.get("status"), RECORD_STATUSES)
    return OwnerRecord(
        locator=locator,
        owner=owner,
        asset_kind=kind,
        asset=value,
        contact=clean_text(f.get("contact"), "contact"),
        removed=status == "removed",
        removed_at=parse_time(f.get("removed_at"), "removed_at"),
    )


_PARSERS: dict[str, Callable[[str, _Fields], SurfaceRecord]] = {
    "domain": _domain,
    "dns": _dns,
    "ip": _ip,
    "service": _service,
    "certificate": _certificate,
    "cloud_asset": _cloud_asset,
    "owner": _owner,
}


@dataclass(slots=True)
class ParsedRecord:
    kind: str
    record: SurfaceRecord
    unknown_fields: list[str]


def parse_record(item: RawItem) -> ParsedRecord:
    """Validate one raw record; raises :class:`InvalidInputError` with a readable reason."""
    data = item.data
    if not isinstance(data, dict):
        raise InvalidInputError(f"Expected a record (an object), got {describe(data)}.")
    if len(data) > MAX_FIELDS:
        raise InvalidInputError(f"The record has {len(data)} fields (limit {MAX_FIELDS}).")
    raw_kind = clean_text(data.get("kind"), "kind", limit=40)
    kind = _KIND_ALIASES.get(raw_kind.lower().replace("-", "_")) if raw_kind else None
    if raw_kind and kind is None:
        raise InvalidInputError(
            f"Unknown record kind {raw_kind!r}.", hint="Record kinds: " + ", ".join(RECORD_KINDS) + "."
        )
    if item.kind is not None:
        if kind is not None and kind != item.kind:
            raise InvalidInputError(f"Record kind {kind!r} does not match its section ({item.kind}).")
        kind = item.kind
    if kind is None:
        raise InvalidInputError("The record has no 'kind'.", hint="Record kinds: " + ", ".join(RECORD_KINDS) + ".")
    fields = _Fields(kind, data)
    return ParsedRecord(kind, _PARSERS[kind](item.locator, fields), fields.unknown)


def owner_type(owner: OwnerRef) -> str:
    return owner.id.split(":", 1)[0]
