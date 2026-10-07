"""Normalized policy model shared by every policy format R$F understands.

A :class:`PolicySet` (one file / one revision) contains :class:`Policy` objects; each policy has
an evaluation strategy and ordered :class:`PolicyRule` entries:

* ``network`` policies (firewall-like) use **first-match** over (source, destination, ports);
* ``identity`` / ``service`` policies use **deny-overrides** over (principals, resources, actions).

Selectors are normalized strings:

* addresses: ``any``, ``cidr:10.20.0.0/16``, ``network:dev``, ``host:db-01``, ``ip:10.30.0.10``,
  ``service:postgres``
* principals: ``*``, ``user:alice``, ``identity:svc-deploy``, ``group:engineering``, ``role:developer``
* resources: ``*``, ``host:*`` (every host), ``cloud_resource:production`` (and what it contains)
* ports: ``any``, ``tcp/443``, ``tcp/1000-2000``, ``udp/53``, ``icmp``
* actions: ``*``, ``ssh``, ``deploy:*`` (prefix wildcard), ``admin``
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import Field

from raf.core.errors import InvalidInputError
from raf.core.ids import digest, object_id
from raf.core.objects.models import RafModel
from raf.core.ports import ANY, PortSet

Effect = Literal["allow", "deny"]
Domain = Literal["network", "identity", "service"]
Evaluation = Literal["first-match", "deny-overrides"]

MAX_RULES_PER_POLICY = 5000
_TYPED_RE = re.compile(r"^([a-z_][a-z0-9_-]*):(.+)$")


# --------------------------------------------------------------------------- selectors


def normalize_address(value: Any) -> str:
    """Normalize a network address selector."""
    text = str(value).strip()
    lowered = text.lower()
    if lowered in (ANY, "*", "all", "0.0.0.0/0", "::/0"):
        return ANY
    if lowered.startswith("cidr:"):
        text = text[5:]
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        network = None
    if network is not None:
        return f"cidr:{network.compressed}"
    match = _TYPED_RE.match(text)
    if match:
        otype, key = match.group(1).lower(), match.group(2)
        if otype == "zone":
            otype = "network"
        return object_id(otype, key)
    # bare names are network zones (firewall exports name zones, not objects)
    return object_id("network", text)


def normalize_principal(value: Any) -> str:
    text = str(value).strip()
    if text in ("*", ANY):
        return "*"
    match = _TYPED_RE.match(text)
    if match:
        return object_id(match.group(1).lower(), match.group(2))
    return object_id("user", text)


def normalize_resource(value: Any) -> str:
    text = str(value).strip()
    if text in ("*", ANY):
        return "*"
    match = _TYPED_RE.match(text)
    if match:
        otype, key = match.group(1).lower(), match.group(2).strip()
        if key == "*":
            return f"{otype}:*"
        return object_id(otype, key)
    raise InvalidInputError(f"Resource '{text}' must be typed (host:DB-01, service:git, cloud_resource:prod) or '*'.")


def normalize_action(value: Any) -> str:
    text = str(value).strip().lower()
    return "*" if text in ("*", ANY, "all") else text


def action_covers(a: str, b: str) -> bool:
    """True when action pattern ``a`` includes everything ``b`` does (``*`` / ``prefix*`` wildcards)."""
    if a == "*" or a == b:
        return True
    if a.endswith("*"):
        return b.startswith(a[:-1])
    return False


def action_matches(statement_action: str, requested: str | None) -> bool:
    if requested is None:
        return True
    return action_covers(statement_action, requested) or statement_action == "admin"


# --------------------------------------------------------------------------- policy objects


class PolicyRule(RafModel):
    id: str
    policy: str
    order: int
    effect: Effect
    sources: list[str] = Field(default_factory=lambda: [ANY])
    destinations: list[str] = Field(default_factory=lambda: [ANY])
    ports: list[str] = Field(default_factory=lambda: [ANY])
    actions: list[str] = Field(default_factory=lambda: ["*"])
    description: str = ""
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def ref(self) -> str:
        return f"{self.policy}:{self.id}"

    def port_set(self) -> PortSet:
        return PortSet.parse(self.ports)

    def signature(self) -> dict[str, Any]:
        return {
            "effect": self.effect,
            "sources": sorted(self.sources),
            "destinations": sorted(self.destinations),
            "ports": sorted(self.ports),
            "actions": sorted(self.actions),
            "enabled": self.enabled,
        }

    def summary(self, domain: str) -> str:
        src = ", ".join(self.sources)
        dst = ", ".join(self.destinations)
        if domain == "network":
            return f"{self.effect} {src} → {dst} ports {', '.join(self.ports)}"
        return f"{self.effect} {src} actions {', '.join(self.actions)} on {dst}"


class Policy(RafModel):
    id: str
    name: str
    domain: Domain
    evaluation: Evaluation
    default: Effect = "deny"
    revision: str | None = None
    description: str = ""
    source: str | None = None
    #: network policies: address selectors this policy governs (empty = every flow)
    scope: list[str] = Field(default_factory=list)
    rules: list[PolicyRule] = Field(default_factory=list)

    @property
    def object_id(self) -> str:
        return object_id("policy", self.id)

    def digest(self) -> str:
        payload = json.dumps(
            {
                "default": self.default,
                "evaluation": self.evaluation,
                "rules": [{"id": r.id, **r.signature()} for r in self.rules],
            },
            sort_keys=True,
        )
        return digest(payload, length=16)

    def rule(self, rule_id: str) -> PolicyRule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    def active_rules(self) -> list[PolicyRule]:
        return [r for r in sorted(self.rules, key=lambda r: r.order) if r.enabled]


class PolicySet(RafModel):
    name: str
    format: str
    revision: str | None = None
    source: str | None = None
    policies: list[Policy] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def policy(self, policy_id: str) -> Policy | None:
        return next((p for p in self.policies if p.id == policy_id or p.object_id == policy_id), None)


@dataclass(frozen=True, slots=True)
class FlowRequest:
    """A hypothetical flow or access request to evaluate."""

    subject: str
    target: str
    verb: str = "access"
    ports: tuple[str, ...] = ()
    action: str | None = None
    source_hosts: tuple[str, ...] = ()


def default_evaluation(domain: str) -> Evaluation:
    return "first-match" if domain == "network" else "deny-overrides"
