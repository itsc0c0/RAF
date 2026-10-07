"""Shared constants and normalization of untrusted surface-inventory values.

Every value read from an imported inventory (or an API body) goes through these helpers: control
characters, terminal escape sequences and bidi overrides are removed, lengths are bounded, names
and addresses are validated syntactically. Nothing is ever resolved, fetched or connected to.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from raf.core.errors import InvalidInputError
from raf.core.ids import object_id
from raf.core.timeutil import parse_timestamp

PRODUCT = "surface"
FORMAT = "raf-surface/1"
LABEL = "raf-surface/1.0"
SCOPE_NAMESPACE = "surface.scope"

MAX_DOCUMENT_BYTES = 20 * 1024 * 1024
MAX_RECORDS = 50_000
MAX_SCOPE_ENTRIES = 1_000
MAX_LINE_BYTES = 1024 * 1024
MAX_TEXT = 200
MAX_NOTE = 1_000
MAX_NAMES = 500  # names per certificate (CN + SANs)
MAX_ITEMS = 100  # entries of other list fields (presented_by, tags)
MAX_TXT = 20  # TXT values kept per name
MAX_LINKED_NAMES = 100  # ISSUED_FOR relationships per certificate

RECORD_KINDS = ("domain", "dns", "ip", "service", "certificate", "cloud_asset", "owner")
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")
SCOPE_KINDS = ("domain", "cidr", "ip", "cloud_account")
ASSET_KINDS = ("domain", "ip", "service", "certificate", "cloud_asset")
CRITICALITIES = ("low", "medium", "high", "critical")
STORAGE_TYPES = frozenset(
    {
        "bucket",
        "container",
        "blob_container",
        "storage_container",
        "storage_account",
        "object_storage",
        "file_share",
        "share",
    }
)

#: C0/C1 controls, DEL, zero-width characters, line/paragraph separators, bidi embeddings,
#: overrides and isolates, word joiners and the BOM: never kept in imported text.
_UNSAFE_RANGES = (
    (0x00, 0x1F),
    (0x7F, 0x9F),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2069),
    (0xFEFF, 0xFEFF),
)
_UNSAFE = {code: " " for low, high in _UNSAFE_RANGES for code in range(low, high + 1)}
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9._:@-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SPLIT_RE = re.compile(r"[\s,;|]+")

#: Non-routable / internal ranges. Documentation ranges (192.0.2.0/24, 198.51.100.0/24,
#: 203.0.113.0/24, 2001:db8::/32) are deliberately *not* listed: R$F demos use them as public
#: stand-ins, exactly like real public addresses.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)

_STATUS_ALIASES = {
    "active": "active",
    "live": "active",
    "in-use": "active",
    "in use": "active",
    "decommissioned": "decommissioned",
    "retired": "decommissioned",
    "inactive": "decommissioned",
    "removed": "removed",
    "deleted": "removed",
}
_OWNER_TYPES = {
    "organization": "organization",
    "org": "organization",
    "team": "organization",
    "user": "user",
    "group": "group",
}
_TRUE = frozenset({"true", "yes", "y", "1", "on"})
_FALSE = frozenset({"false", "no", "n", "0", "off"})


def describe(value: Any) -> str:
    """How a value's type is named in messages (never the value itself)."""
    if isinstance(value, dict):
        return "an object"
    if isinstance(value, list | tuple | set):
        return "a list"
    if isinstance(value, bool):
        return "a boolean"
    return type(value).__name__


# --------------------------------------------------------------------------- text


def clean_text(value: Any, field: str, *, limit: int = MAX_TEXT, truncate: bool = False) -> str | None:
    """A single-line printable string, or None when the value is absent or blank."""
    if value is None:
        return None
    if isinstance(value, datetime | date):
        value = value.isoformat()
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        raise InvalidInputError(f"'{field}' must be text, not {describe(value)}.")
    raw = str(value)
    if len(raw) > max(limit, 64) * 8:  # do not even normalize absurdly long values
        raise InvalidInputError(f"'{field}' is longer than {limit} characters.")
    text = " ".join(raw.translate(_UNSAFE).split())
    if not text:
        return None
    if len(text) > limit:
        if not truncate:
            raise InvalidInputError(f"'{field}' is longer than {limit} characters.")
        text = text[: limit - 3].rstrip() + "..."
    return text


def require_text(value: Any, field: str, *, limit: int = MAX_TEXT) -> str:
    text = clean_text(value, field, limit=limit)
    if text is None:
        raise InvalidInputError(f"'{field}' is required.")
    return text


def strip_unsafe(text: str) -> str:
    """Replace control, zero-width and bidi characters (keeps length and everything else)."""
    return text.translate(_UNSAFE)


def safe_display(value: Any, limit: int = MAX_TEXT) -> str:
    """Sanitize a value that is only displayed (never fails)."""
    text = " ".join(str(value).translate(_UNSAFE).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --------------------------------------------------------------------------- names and addresses


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    return True


def normalize_ip(value: Any, field: str = "address") -> str:
    text = require_text(value, field, limit=64).strip("[]")
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError as exc:
        raise InvalidInputError(f"'{field}': {text!r} is not a valid IP address.") from exc


@functools.lru_cache(maxsize=65536)
def is_internal_address(address: str) -> bool:
    """RFC 1918, CGNAT, loopback, link-local, unique-local, multicast and reserved addresses."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == net.version and ip in net for net in _INTERNAL_NETWORKS)


def normalize_hostname(value: Any, field: str = "name", *, wildcard: bool = False) -> str:
    """A fully qualified DNS name in lower case (IDN converted to its ASCII form)."""
    text = require_text(value, field, limit=300).lower().rstrip(".")
    if not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise InvalidInputError(f"'{field}': {text!r} is not a valid host name.") from exc
    if len(text) > 253:
        raise InvalidInputError(f"'{field}': host names are at most 253 characters long.")
    labels = text.split(".")
    if len(labels) < 2:
        raise InvalidInputError(
            f"'{field}': {text!r} is not a fully qualified name.", hint="Use a name such as www.raven.example."
        )
    for index, label in enumerate(labels):
        if label == "*" and index == 0 and wildcard:
            continue
        if not _LABEL_RE.match(label):
            raise InvalidInputError(f"'{field}': {text!r} is not a valid host name.")
    if labels[-1].isdigit():
        raise InvalidInputError(f"'{field}': {text!r} looks like an address, not a host name.")
    return text


def parent_names(name: str) -> list[str]:
    """Proper ancestors of a DNS name with at least two labels, nearest first."""
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels) - 1)]


def name_covers(pattern: str, name: str) -> bool:
    """Certificate name matching (RFC 6125): exact, or a ``*.`` wildcard for exactly one label."""
    if pattern == name:
        return True
    if pattern.startswith("*."):
        base = pattern[2:]
        head, _, rest = name.partition(".")
        return bool(head) and rest == base
    return False


# --------------------------------------------------------------------------- scalar fields


def parse_port(value: Any, field: str = "port") -> int:
    number: int | None = None
    if isinstance(value, bool) or value is None:
        number = None
    elif isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    elif isinstance(value, str) and 0 < len(value.strip()) <= 5 and value.strip().isdecimal():
        number = int(value.strip())
    if number is None or not 1 <= number <= 65535:
        raise InvalidInputError(f"'{field}' must be a port number between 1 and 65535.")
    return number


def parse_transport(value: Any) -> str:
    text = (clean_text(value, "protocol", limit=10) or "tcp").lower()
    if text not in ("tcp", "udp"):
        raise InvalidInputError(f"'protocol' must be tcp or udp, not {text!r}.")
    return text


def parse_bool(value: Any, field: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return None
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
    raise InvalidInputError(f"'{field}' must be true or false.")


def parse_time(value: Any, field: str) -> datetime | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool) or not isinstance(value, str | int | float | datetime | date):
        raise InvalidInputError(f"'{field}' must be a timestamp, not {describe(value)}.")
    try:
        return parse_timestamp(value)
    except InvalidInputError as exc:
        raise InvalidInputError(f"'{field}': {exc.message}") from exc


def parse_list(value: Any, field: str, *, limit: int = MAX_ITEMS) -> list[Any]:
    """A list of scalars: a list, or a string separated by commas, semicolons, '|' or spaces."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        if len(value) > limit * 300:
            raise InvalidInputError(f"'{field}' is too long.")
        items: list[Any] = [part for part in _SPLIT_RE.split(value) if part]
    elif isinstance(value, list | tuple):
        items = list(value)
    else:
        items = [value]
    if len(items) > limit:
        raise InvalidInputError(f"'{field}' has {len(items)} entries (limit {limit}).")
    for item in items:
        if isinstance(item, dict | list | tuple | set):
            raise InvalidInputError(f"'{field}' entries must be text, not {describe(item)}.")
    return items


def normalize_fingerprint(value: Any) -> str | None:
    text = clean_text(value, "fingerprint_sha256", limit=200)
    if text is None:
        return None
    hexed = text.lower().replace(":", "").replace(" ", "")
    if not _HEX64_RE.match(hexed):
        raise InvalidInputError("'fingerprint_sha256' must be 64 hexadecimal characters (a SHA-256 digest).")
    return hexed


def parse_criticality(value: Any) -> str | None:
    text = clean_text(value, "criticality", limit=20)
    if text is None:
        return None
    level = text.lower()
    if level not in CRITICALITIES:
        raise InvalidInputError(f"Unknown criticality {text!r}.", hint="Use low, medium, high or critical.")
    return level


def parse_status(value: Any, allowed: tuple[str, ...]) -> str:
    text = clean_text(value, "status", limit=40)
    if text is None:
        return "active"
    status = _STATUS_ALIASES.get(text.lower())
    if status is None or status not in allowed:
        raise InvalidInputError(f"Unknown status {text!r}.", hint="Use " + " or ".join(allowed) + ".")
    return status


def parse_view(value: Any) -> str:
    text = (clean_text(value, "view", limit=20) or "external").lower()
    if text in ("external", "public"):
        return "external"
    if text in ("internal", "private"):
        return "internal"
    raise InvalidInputError(f"Unknown DNS view {text!r}.", hint="Use external (default) or internal.")


def normalize_token(value: Any, field: str) -> str:
    text = require_text(value, field, limit=64).lower()
    if not _TOKEN_RE.match(text):
        raise InvalidInputError(f"'{field}' may only contain letters, digits, '.', '_' and '-'.")
    return text


def normalize_account(value: Any, field: str = "account") -> str | None:
    text = clean_text(value, field, limit=128)
    if text is None:
        return None
    account = text.lower()
    if not _ACCOUNT_RE.match(account):
        raise InvalidInputError(f"'{field}' may only contain letters, digits and . _ : @ -")
    return account


def normalize_resource_name(value: Any, field: str = "name") -> str:
    text = require_text(value, field, limit=255)
    if "/" in text:
        raise InvalidInputError(f"'{field}' must not contain '/'.")
    return text


@dataclass(frozen=True, slots=True)
class OwnerRef:
    id: str
    name: str


def parse_owner(value: Any, field: str = "owner") -> OwnerRef | None:
    """An owner: a team or organization by default; ``user:NAME`` and ``group:NAME`` are principals."""
    text = clean_text(value, field)
    if text is None:
        return None
    owner_type, name = "organization", text
    prefix, sep, rest = text.partition(":")
    if sep and prefix.strip().lower() in _OWNER_TYPES and rest.strip():
        owner_type, name = _OWNER_TYPES[prefix.strip().lower()], rest.strip()
    return OwnerRef(object_id(owner_type, name), name)


# --------------------------------------------------------------------------- endpoints


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A network endpoint: an IP address or host name, a port and a transport."""

    address: str
    port: int
    transport: str = "tcp"

    @property
    def is_ip(self) -> bool:
        return is_ip(self.address)

    @property
    def host_part(self) -> str:
        return f"[{self.address}]" if ":" in self.address else self.address

    @property
    def port_key(self) -> str:
        """Key of the ``port`` object (``198.51.100.20:443``; UDP ports carry ``/udp``)."""
        key = f"{self.host_part}:{self.port}"
        return key if self.transport == "tcp" else f"{key}/{self.transport}"

    @property
    def service_key(self) -> str:
        return f"{self.host_part}:{self.port}/{self.transport}"

    @property
    def address_id(self) -> str:
        return object_id("ip", self.address) if self.is_ip else object_id("domain", self.address)

    @property
    def port_id(self) -> str:
        return object_id("port", self.port_key)

    def label(self) -> str:
        return f"{self.host_part}:{self.port}" + ("" if self.transport == "tcp" else f"/{self.transport}")


def parse_endpoint(value: Any, field: str = "presented_by") -> Endpoint:
    """``198.51.100.20:443``, ``[2001:db8::1]:443``, ``shop.raven.example:443`` (default port 443),
    optionally followed by ``/tcp`` or ``/udp``."""
    text = require_text(value, field, limit=300)
    transport = "tcp"
    if text.lower().endswith(("/tcp", "/udp")):
        text, transport = text[:-4], text[-3:].lower()
    host, port = text, 443
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise InvalidInputError(f"'{field}': {text!r} is not a valid endpoint.")
        host, rest = text[1:end], text[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise InvalidInputError(f"'{field}': {text!r} is not a valid endpoint.")
            port = parse_port(rest[1:], field)
    elif text.count(":") == 1:
        host, _, port_text = text.partition(":")
        port = parse_port(port_text, field)
    if is_ip(host):
        return Endpoint(normalize_ip(host, field), port, transport)
    return Endpoint(normalize_hostname(host, field), port, transport)


def cloud_key(provider: str, account: str | None, kind: str, name: str) -> str:
    return f"{provider}/{account or '-'}/{kind}/{name}"
