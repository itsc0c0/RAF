"""The authorized scope: the targets an organization has explicitly declared as its own.

Entries live in the workspace key-value store (namespace ``surface.scope``):

* ``domain``        - the name and every name below it (``raven.example`` covers
  ``www.raven.example``; it does not cover ``notraven.example``);
* ``cidr``          - every address inside the range (prefixes broader than /8 or /32 are refused);
* ``ip``            - exactly that address;
* ``cloud_account`` - ``provider:account``: the cloud assets recorded in that account.

Assets outside the scope are recorded and shown, but never treated as owned. Scope entries are
only ever created by an explicit operator action (``raf surface scope add``, the API, or
``raf surface import --apply-scope`` after reviewing the file's ``scope`` section).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from raf.core.errors import ConflictError, InvalidInputError, NotFoundError, ResourceLimitExceeded
from raf.core.objects.models import RafModel
from raf.core.storage.repos.misc import KVRepository
from raf.core.timeutil import utcnow
from raf.products.surface.model import (
    MAX_SCOPE_ENTRIES,
    SCOPE_KINDS,
    SCOPE_NAMESPACE,
    clean_text,
    is_ip,
    normalize_account,
    normalize_hostname,
    normalize_ip,
    normalize_token,
    require_text,
)

log = logging.getLogger("raf.surface.scope")

MIN_IPV4_PREFIX = 8
MIN_IPV6_PREFIX = 32

_KIND_ALIASES = {
    "domain": "domain",
    "zone": "domain",
    "dns": "domain",
    "cidr": "cidr",
    "network": "cidr",
    "range": "cidr",
    "net": "cidr",
    "ip": "ip",
    "address": "ip",
    "cloud_account": "cloud_account",
    "cloud": "cloud_account",
    "account": "cloud_account",
}


class ScopeEntry(RafModel):
    target: str
    kind: str
    owner: str | None = None
    authorization: str | None = None
    added_at: datetime

    def describe(self) -> str:
        parts = [f"{self.kind} {self.target}"]
        if self.owner:
            parts.append(f"owner {self.owner}")
        parts.append(f"authorization {self.authorization}" if self.authorization else "no authorization reference")
        return ", ".join(parts)


def infer_kind(target: str) -> str:
    if "/" in target:
        return "cidr"
    if is_ip(target):
        return "ip"
    if ":" in target:
        return "cloud_account"
    return "domain"


def normalize_target(target: Any, kind: str | None = None) -> tuple[str, str]:
    """Validate a scope target and return ``(normalized target, kind)``."""
    text = require_text(target, "target", limit=300)
    if kind:
        chosen = _KIND_ALIASES.get(kind.strip().lower().replace("-", "_"))
        if chosen is None:
            raise InvalidInputError(f"Unknown scope kind {kind!r}.", hint="Use domain, cidr, ip or cloud_account.")
    else:
        chosen = infer_kind(text)
    if chosen == "domain":
        if text.startswith("*."):
            raise InvalidInputError(
                "Scope entries do not use wildcards.",
                hint=f"A domain entry already covers every name below it: {text[2:]}",
            )
        if is_ip(text) or "/" in text:
            raise InvalidInputError(f"{text!r} is an address, not a domain.", hint="Use --kind ip or --kind cidr.")
        return normalize_hostname(text, "target"), "domain"
    if chosen == "cidr":
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise InvalidInputError(f"{text!r} is not a valid CIDR range.") from exc
        minimum = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
        if network.prefixlen < minimum:
            raise InvalidInputError(
                f"{network} is too broad for an authorized scope.",
                hint=f"Declare the ranges the organization actually holds (/{minimum} or narrower).",
            )
        return str(network), "cidr"
    if chosen == "ip":
        return normalize_ip(text, "target"), "ip"
    provider, sep, account = text.partition(":")
    if not sep or not account.strip():
        raise InvalidInputError(
            f"{text!r} is not a cloud account.", hint="Use provider:account, for example examplecloud:raven-prod."
        )
    return f"{normalize_token(provider, 'provider')}:{normalize_account(account.strip())}", "cloud_account"


@dataclass(frozen=True, slots=True)
class ScopeMatch:
    """Whether something is inside the authorized scope, and which entry (or asset) says so."""

    status: str  # in | out | unknown (no scope configured)
    entry: ScopeEntry | None = None
    via: str | None = None

    @property
    def in_scope(self) -> bool:
        return self.status == "in"

    def describe(self) -> str:
        if self.status == "unknown":
            return "no authorized scope is configured"
        if self.status == "out":
            return "not covered by any authorized scope entry"
        assert self.entry is not None
        text = f"covered by scope entry {self.entry.target}"
        if self.via:
            text += f" (via {self.via})"
        return text


class Scope:
    """Coverage checks against a set of scope entries (most specific entry wins)."""

    def __init__(self, entries: list[ScopeEntry]) -> None:
        self.entries = sorted(entries, key=lambda e: (SCOPE_KINDS.index(e.kind), e.target))
        self._domains = [e for e in self.entries if e.kind == "domain"]
        self._networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ScopeEntry]] = [
            (ipaddress.ip_network(e.target, strict=False), e) for e in self.entries if e.kind in ("cidr", "ip")
        ]
        self._clouds = {e.target: e for e in self.entries if e.kind == "cloud_account"}

    @property
    def configured(self) -> bool:
        return bool(self.entries)

    def match_domain(self, name: str) -> ScopeEntry | None:
        base = name[2:] if name.startswith("*.") else name
        best: ScopeEntry | None = None
        for entry in self._domains:
            if (base == entry.target or base.endswith("." + entry.target)) and (
                best is None or len(entry.target) > len(best.target)
            ):
                best = entry
        return best

    def match_ip(self, address: str) -> ScopeEntry | None:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        best: ScopeEntry | None = None
        best_len = -1
        for network, entry in self._networks:
            if network.version == ip.version and ip in network and network.prefixlen > best_len:
                best, best_len = entry, network.prefixlen
        return best

    def match_cloud(self, provider: str | None, account: str | None) -> ScopeEntry | None:
        if not provider or not account:
            return None
        return self._clouds.get(f"{provider}:{account}")

    def match_address(self, address: str) -> ScopeEntry | None:
        """An IP address or a host name."""
        return self.match_ip(address) if is_ip(address) else self.match_domain(address)

    def summary(self, limit: int = 6) -> str:
        if not self.entries:
            return "none"
        shown = ", ".join(e.target for e in self.entries[:limit])
        return shown + (f" (+{len(self.entries) - limit} more)" if len(self.entries) > limit else "")


class ScopeStore:
    """Scope entries persisted per workspace in the key-value store."""

    def __init__(self, kv: KVRepository) -> None:
        self.kv = kv

    def entries(self) -> list[ScopeEntry]:
        items: list[ScopeEntry] = []
        for key, value in self.kv.items(SCOPE_NAMESPACE).items():
            try:
                items.append(ScopeEntry.model_validate(value))
            except ValidationError:
                log.warning("ignoring a damaged surface scope entry %r", key)
        return Scope(items).entries

    def scope(self) -> Scope:
        return Scope(self.entries())

    def get(self, target: str) -> ScopeEntry | None:
        raw = self.kv.get(SCOPE_NAMESPACE, target)
        if raw is None:
            return None
        try:
            return ScopeEntry.model_validate(raw)
        except ValidationError:
            return None

    def add(
        self,
        target: Any,
        kind: str | None = None,
        owner: Any = None,
        authorization: Any = None,
        *,
        replace: bool = False,
        now: datetime | None = None,
    ) -> tuple[ScopeEntry, str]:
        """Add (or with ``replace`` update) an entry. Returns the entry and added|replaced|unchanged."""
        normalized, chosen = normalize_target(target, kind)
        owner_text = clean_text(owner, "owner")
        authorization_text = clean_text(authorization, "authorization")
        existing = self.get(normalized)
        if existing is not None:
            if (
                existing.kind == chosen
                and existing.owner == owner_text
                and existing.authorization == authorization_text
            ):
                return existing, "unchanged"
            if not replace:
                raise ConflictError(
                    f"{normalized} is already in the authorized scope.",
                    reason=existing.describe(),
                    hint="Use --replace (API: replace=true) to update its owner and authorization.",
                )
        elif len(self.kv.items(SCOPE_NAMESPACE)) >= MAX_SCOPE_ENTRIES:
            raise ResourceLimitExceeded(f"The authorized scope is limited to {MAX_SCOPE_ENTRIES} entries.")
        entry = ScopeEntry(
            target=normalized,
            kind=chosen,
            owner=owner_text,
            authorization=authorization_text,
            added_at=now or utcnow(),
        )
        self.kv.set(SCOPE_NAMESPACE, normalized, entry.to_json_dict())
        return entry, "replaced" if existing is not None else "added"

    def resolve_key(self, target: str) -> str:
        try:
            return normalize_target(target)[0]
        except InvalidInputError:
            return target.strip().lower()

    def remove(self, target: str) -> ScopeEntry:
        key = self.resolve_key(target)
        existing = self.get(key)
        if existing is None:
            raise NotFoundError(
                f"{target.strip()[:200]!r} is not in the authorized scope.", suggestions=["raf surface scope list"]
            )
        self.kv.delete(SCOPE_NAMESPACE, key)
        return existing
