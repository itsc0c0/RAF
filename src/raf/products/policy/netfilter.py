"""Netfilter rule sets (iptables-save, nftables) -> normalized R$F network policies.

The parsers (:mod:`policy.iptables`, :mod:`policy.nftables`) read their syntax into
:class:`FilterRule` s per chain and name the *base chains*: the chains the kernel runs for the
``input``, ``forward`` and ``output`` hooks. This module flattens the chains into first-match
:class:`PolicyRule` s and builds the policies:

* A forward base chain (traffic the host routes) becomes ``<prefix>-forward``, scoped to the
  networks its rules name, so the chain's policy never denies flows elsewhere in the workspace.
  A forward chain without rules for new flows (a host that does not route) or naming no address
  is not imported.
* The input and output base chains of a table (traffic to and from the host itself) become
  ``<prefix>-host``, scoped to ``host:<name>``: input rules without a destination target the
  host, output rules without a source come from it, and each chain's policy closes its part as a
  final rule (metadata ``chain_policy``).
* Several base chains on one hook (nftables tables and priorities) become one policy each: a
  packet must pass all of them - a drop is final, an accept ends only its own chain - and that
  is how R$F combines policies (a flow is allowed only when every applicable policy allows it).
* A jump inlines the target chain with both rules' conditions; ``RETURN`` continues after the
  jump, and in a base chain the chain's policy decides. ``goto`` inlines the target too, but the
  packet does not come back: what the target leaves undecided gets the base chain's policy, or
  leaves the calling chain like a ``RETURN``.
* Address families: an ``ip6`` table (and ip6tables-save) sees only IPv6 packets, so its rules
  and chain policies apply to IPv6 addresses only (:data:`V6_ANY`) and its host policy lets other
  traffic pass (metadata ``pass``). ``ip`` and ``inet`` tables are applied to every flow: most
  inventories hold IPv4 addresses only.

Conditions a parser cannot express exactly arrive as ``unmodeled`` reasons: such rules are
imported disabled with the reasons in ``metadata.unmodeled``, never approximated away.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field

from raf.core.errors import InvalidInputError
from raf.core.ids import slugify
from raf.core.ports import ANY, PortSet
from raf.products.policy.model import MAX_RULES_PER_POLICY, Policy, PolicyRule, normalize_address

#: Verdicts that end the packet's way through the base chain.
TERMINAL = {"ACCEPT": "allow", "DROP": "deny", "REJECT": "deny"}
RETURN = "RETURN"
HOOKS = ("input", "forward", "output")
#: Every IPv6 address: what an IPv6-only rule or chain means by "any".
V6_ANY = "cidr:::/0"
MAX_DEPTH = 8
#: Rule visits while flattening: a chain is walked again for every jump to it, so nested jumps multiply.
MAX_STEPS = 20 * MAX_RULES_PER_POLICY


@dataclass
class FilterRule:
    """One rule of a chain, its conditions already in R$F terms."""

    chain: str  # key of the chain in FilterRuleset.rules
    position: int  # 1-based position in the chain (rule IDs)
    line: int | None = None
    handle: int | None = None
    part: str = ""  # one element of an nftables verdict map
    sources: list[str] = field(default_factory=lambda: [ANY])
    destinations: list[str] = field(default_factory=lambda: [ANY])
    ports: list[str] = field(default_factory=lambda: [ANY])
    family: str | None = None  # "ip6": IPv6 packets only, "ip": IPv4 only (a rule of an inet table)
    target: str | None = None  # ACCEPT, DROP, REJECT, RETURN, a chain key, another target; None: no verdict
    goto: bool = False
    verdict: str = ""  # the verdict as the rule set writes it (metadata)
    comment: str = ""
    unmodeled: list[str] = field(default_factory=list)
    skip: str | None = None  # why the rule decides nothing about new flows

    def conditional(self) -> bool:
        return (
            (self.sources, self.destinations, self.ports) != ([ANY], [ANY], [ANY])
            or self.family is not None
            or bool(self.unmodeled)
        )

    @property
    def where(self) -> str:
        return f"line {self.line}" if self.line is not None else f"rule {self.position}"


@dataclass
class BaseChain:
    """A chain the kernel runs for a hook."""

    key: str
    hook: str  # input | forward | output
    policy: str  # as the rule set writes it: ACCEPT/DROP (iptables), accept/drop (nftables)
    title: str  # in policy names and messages: "FORWARD", "forward"
    family: str = "inet"  # ip | ip6 | inet
    table: str = "filter"
    priority: int = 0

    @property
    def effect(self) -> str:
        return "allow" if self.policy.lower() == "accept" else "deny"


@dataclass
class FilterRuleset:
    """What a parser read: rules per chain and the base chains, in the order the kernel runs them."""

    tool: str  # iptables | ip6tables | nftables (policy descriptions)
    base: list[BaseChain]
    rules: dict[str, list[FilterRule]]
    names: dict[str, str]  # chain key -> its name in rule IDs
    labels: dict[str, str]  # chain key -> its name in messages and metadata
    regular: list[str] = field(default_factory=list)  # chains that run only when jumped to
    tables: dict[str, str] = field(default_factory=dict)  # chain key -> "inet filter" (nftables metadata)

    def label(self, key: str) -> str:
        return self.labels.get(key, key)


@dataclass
class _Budget:
    """Rule visits left for flattening one rule set (bounds the work of deeply nested jumps)."""

    left: int = MAX_STEPS

    def spend(self) -> None:
        self.left -= 1
        if self.left < 0:
            raise InvalidInputError(
                f"Flattening the user chains takes more than {MAX_STEPS} steps: the jumps nest too much.",
                hint="Split the rule set, or describe it as a raf-policy/1 document.",
            )


def build_policies(
    ruleset: FilterRuleset, *, prefix: str, host: str, source: str | None
) -> tuple[list[Policy], list[str]]:
    """The policies of a rule set (IDs start with ``prefix``; ``host`` names the machine) and warnings."""
    warnings: list[str] = []
    budget = _Budget()
    flat = {chain.key: _expand(ruleset, chain.key, budget=budget) for chain in ruleset.base}
    policies = [
        *_forward_policies(ruleset, flat, prefix, source, warnings),
        *_host_policies(ruleset, flat, prefix, host, source),
    ]
    for policy in policies:
        if len(policy.rules) > MAX_RULES_PER_POLICY:
            raise InvalidInputError(
                f"Policy '{policy.id}' would have {len(policy.rules)} rules (limit {MAX_RULES_PER_POLICY})."
            )
    reachable = _reachable(ruleset)
    unused = sorted(ruleset.label(key) for key in ruleset.regular if key not in reachable)
    if unused:
        listed = ", ".join(unused[:10]) + (f" and {len(unused) - 10} more" if len(unused) > 10 else "")
        verb = "is" if len(unused) == 1 else "are"
        bases = "INPUT, FORWARD or OUTPUT" if ruleset.tool != "nftables" else "an input, forward or output chain"
        warnings.append(f"chain(s) {listed} {verb} never jumped to from {bases}: not imported")
    disabled = sum(1 for policy in policies for rule in policy.rules if not rule.enabled)
    if disabled:
        warnings.append(
            f"{disabled} rule(s) use conditions the policy model cannot express exactly (interfaces, negation, "
            "source ports, match modules ...): imported disabled, reasons in metadata.unmodeled"
        )
    if not policies:
        warnings.append(
            "nothing to import: no rules for new flows on the input, forward or output hook, and only accept policies"
        )
    return policies, warnings


# --------------------------------------------------------------------------- flattening


def _expand(
    ruleset: FilterRuleset,
    key: str,
    *,
    budget: _Budget,
    depth: int = 0,
    prefix: str = "",
    stack: tuple[str, ...] = (),
) -> list[PolicyRule]:
    """The rules of chain ``key`` in first-match order, jumped-to chains inlined."""
    base = {chain.key: chain for chain in ruleset.base}
    out: list[PolicyRule] = []
    blocked: str | None = None  # a conditional RETURN came before: what follows is not reached by every packet
    for rule in ruleset.rules.get(key, []):
        budget.spend()
        part = f"-{rule.part}" if rule.part else ""
        rule_id = slugify(f"{prefix}{ruleset.names.get(key, key)}-{rule.position}{part}")
        if rule.skip is not None or not rule.target:
            continue
        target = rule.target
        reasons = [*rule.unmodeled, *([blocked] if blocked else [])]
        if target == RETURN:
            if key in base:  # the base chain's policy decides
                out.append(_policy_rule(ruleset, rule, rule_id, base[key].effect, reasons))
            elif not rule.conditional():
                break  # the rest of this chain is never reached
            else:
                blocked = f"follows a conditional RETURN in {ruleset.label(key)} ({rule.where})"
            continue
        if target in TERMINAL:
            out.append(_policy_rule(ruleset, rule, rule_id, TERMINAL[target], reasons))
            continue
        if target not in ruleset.rules or target in base:
            out.append(_policy_rule(ruleset, rule, rule_id, "deny", [*reasons, f"target {ruleset.label(target)}"]))
            continue
        loop = target == key or target in stack
        if depth >= MAX_DEPTH or loop:
            why = "jump loop" if loop else "jumps nested too deeply"
            out.append(_policy_rule(ruleset, rule, rule_id, "deny", [*reasons, f"{why} to {ruleset.label(target)}"]))
            continue
        inner = _expand(ruleset, target, budget=budget, depth=depth + 1, prefix=f"{rule_id}.", stack=(*stack, key))
        for sub in inner:
            combined = _combine(ruleset, rule, sub, reasons)
            if combined is not None:
                out.append(combined)
        if len(out) > MAX_RULES_PER_POLICY:
            raise InvalidInputError(f"Inlining user chains gives more than {MAX_RULES_PER_POLICY} rules.")
        if not rule.goto:
            continue
        # goto: the packet does not come back to this chain
        if not any(_decides_everything(sub) for sub in inner):
            if key in base:  # what the target leaves undecided gets the base chain's policy
                out.append(_goto_end(ruleset, rule, rule_id, base[key], target, reasons))
            elif rule.conditional():  # it leaves this chain like a RETURN
                blocked = f"follows a conditional goto in {ruleset.label(key)} ({rule.where})"
                continue
        if not rule.conditional():
            break
    return out


def _decides_everything(rule: PolicyRule) -> bool:
    return (
        rule.enabled
        and (rule.sources, rule.destinations, rule.ports) == ([ANY], [ANY], [ANY])
        and "family" not in rule.metadata
    )


def _metadata(ruleset: FilterRuleset, rule: FilterRule) -> dict[str, object]:
    metadata: dict[str, object] = {"chain": ruleset.label(rule.chain)}
    if rule.chain in ruleset.tables:
        metadata["table"] = ruleset.tables[rule.chain]
    if rule.line is not None:
        metadata["line"] = rule.line
    if rule.handle is not None:
        metadata["handle"] = rule.handle
    metadata["target"] = rule.verdict or rule.target
    if rule.family:
        metadata["family"] = rule.family
    return metadata


def _policy_rule(ruleset: FilterRuleset, rule: FilterRule, rule_id: str, effect: str, reasons: list[str]) -> PolicyRule:
    unmodeled = list(dict.fromkeys(reasons))
    metadata = _metadata(ruleset, rule)
    if unmodeled:
        metadata["unmodeled"] = unmodeled
    return PolicyRule(
        id=rule_id,
        policy="",
        order=0,
        effect="allow" if effect == "allow" else "deny",
        sources=rule.sources,
        destinations=rule.destinations,
        ports=rule.ports,
        description=rule.comment,
        enabled=not unmodeled,
        metadata=metadata,
    )


def _goto_end(
    ruleset: FilterRuleset, rule: FilterRule, rule_id: str, chain: BaseChain, target: str, reasons: list[str]
) -> PolicyRule:
    """Packets that the goto's target leaves undecided: the base chain's policy decides them."""
    end = _policy_rule(ruleset, rule, f"{rule_id}.end", chain.effect, reasons)
    return end.model_copy(
        update={
            "description": f"end of {ruleset.label(target)}, reached by goto: {chain.title} policy {chain.policy}",
            "metadata": {**end.metadata, "chain_policy": chain.policy},
        }
    )


def _combine(ruleset: FilterRuleset, jump: FilterRule, sub: PolicyRule, reasons: list[str]) -> PolicyRule | None:
    """``sub`` (a rule of the jumped-to chain) as reached through ``jump``: both rules' conditions."""
    family = sub.metadata.get("family")
    if jump.family and family and jump.family != family:
        return None  # IPv4 and IPv6 at once: no packet takes this path
    sources = _intersect(jump.sources, sub.sources)
    destinations = _intersect(jump.destinations, sub.destinations)
    ports = PortSet.parse(jump.ports).intersect(PortSet.parse(sub.ports)).labels()
    if not sources or not destinations or not ports:
        return None
    unmodeled = list(dict.fromkeys([*reasons, *sub.metadata.get("unmodeled", [])]))
    metadata = {**sub.metadata, "via": f"{ruleset.label(jump.chain)} {jump.where}"}
    if jump.family or family:
        metadata["family"] = jump.family or family
    if unmodeled:
        metadata["unmodeled"] = unmodeled
    return sub.model_copy(
        update={
            "sources": sources,
            "destinations": destinations,
            "ports": ports,
            "description": sub.description or jump.comment,
            "enabled": not unmodeled,
            "metadata": metadata,
        }
    )


def _intersect(a: list[str], b: list[str]) -> list[str]:
    if a == [ANY]:
        return list(b)
    if b == [ANY]:
        return list(a)
    result: set[str] = set()
    for x in a:
        for y in b:
            nx, ny = _network(x), _network(y)
            if nx is None or ny is None:
                if x == y:
                    result.add(x)
            elif nx.version == ny.version and nx.overlaps(ny):
                result.add(x if nx.prefixlen >= ny.prefixlen else y)
    return sorted(result)


def intersect_addresses(a: list[str], b: list[str]) -> list[str]:
    """The selectors both ``a`` and ``b`` match (CIDRs intersected; empty: nothing)."""
    return _intersect(a, b)


def _network(selector: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if not selector.startswith("cidr:"):
        return None
    return ipaddress.ip_network(selector[5:], strict=False)


def _whole(selector: str) -> bool:
    network = _network(selector)
    return network is not None and network.prefixlen == 0


def _reachable(ruleset: FilterRuleset) -> set[str]:
    seen: set[str] = set()
    todo = [r.target for chain in ruleset.base for r in ruleset.rules.get(chain.key, []) if r.target]
    while todo:
        target = todo.pop()
        if target in seen or target not in ruleset.rules:
            continue
        seen.add(target)
        todo.extend(r.target for r in ruleset.rules[target] if r.target)
    return seen


# --------------------------------------------------------------------------- policies


def _finish(rule: PolicyRule, chain: BaseChain, *, toward: str | None = None, away: str | None = None) -> PolicyRule:
    """Host defaults (input rules target the host, output rules come from it), then the address family."""
    sources, destinations = rule.sources, rule.destinations
    if toward and destinations == [ANY]:
        destinations = [toward]
    if away and sources == [ANY]:
        sources = [away]
    if chain.family == "ip6" or rule.metadata.get("family") == "ip6":
        sources = [V6_ANY] if sources == [ANY] else sources
        destinations = [V6_ANY] if destinations == [ANY] else destinations
    if (sources, destinations) == (rule.sources, rule.destinations):
        return rule
    return rule.model_copy(update={"sources": sources, "destinations": destinations})


def _forward_policies(
    ruleset: FilterRuleset, flat: dict[str, list[PolicyRule]], prefix: str, source: str | None, warnings: list[str]
) -> list[Policy]:
    chosen: list[tuple[BaseChain, list[PolicyRule], list[str]]] = []
    for chain in sorted((c for c in ruleset.base if c.hook == "forward"), key=lambda c: c.priority):
        rules = [_finish(r, chain) for r in flat[chain.key]]
        if not rules:
            if chain.effect != "allow":
                warnings.append(
                    f"{chain.title} has no rules for new flows (a host that does not route between networks): its "
                    f"{chain.policy} policy is not imported"
                )
            continue
        scope = sorted({s for r in rules for s in (*r.sources, *r.destinations) if s != ANY and not _whole(s)})
        if not scope:
            warnings.append(
                f"{chain.title} names no address (interface-based rules): not imported; describe its zones in a "
                "raf-policy/1 document instead"
            )
            continue
        chosen.append((chain, rules, scope))
    policies = []
    for chain, rules, scope in chosen:
        policy_id = f"{prefix}-forward"
        if len(chosen) > 1:
            policy_id += "-" + slugify(ruleset.names.get(chain.key, chain.key))
        policies.append(
            Policy(
                id=policy_id,
                name=f"{prefix} {chain.title}",
                domain="network",
                evaluation="first-match",
                default="allow" if chain.effect == "allow" else "deny",
                description=(
                    f"{ruleset.tool} {chain.title} chain (policy {chain.policy}), for flows from or to the networks "
                    "its rules name"
                ),
                source=source,
                scope=scope,
                rules=_numbered(rules, policy_id),
            )
        )
    return policies


def _host_policies(
    ruleset: FilterRuleset, flat: dict[str, list[PolicyRule]], prefix: str, name: str, source: str | None
) -> list[Policy]:
    host = normalize_address(f"host:{name}")
    hooks = {chain.hook for chain in ruleset.base}
    tables: dict[tuple[str, str], tuple[list[BaseChain], list[BaseChain]]] = {}
    for chain in ruleset.base:
        if chain.hook in ("input", "output"):
            sides = tables.setdefault((chain.family, chain.table), ([], []))
            sides[0 if chain.hook == "input" else 1].append(chain)
    pairs: list[tuple[str, str, int, BaseChain | None, BaseChain | None]] = []
    for (family, table), (inputs, outputs) in tables.items():
        inputs.sort(key=lambda c: c.priority)
        outputs.sort(key=lambda c: c.priority)
        for index in range(max(len(inputs), len(outputs))):
            incoming = inputs[index] if index < len(inputs) else None
            outgoing = outputs[index] if index < len(outputs) else None
            if all(c is None or (not flat[c.key] and c.effect == "allow") for c in (incoming, outgoing)):
                continue  # accepts everything: nothing to say about the host
            pairs.append((family, table, index, incoming, outgoing))
    policies = []
    for family, table, index, incoming, outgoing in pairs:
        if len(pairs) == 1:
            policy_id = f"{prefix}-host"
        else:
            policy_id = f"{prefix}-host-" + slugify(f"{family}-{table}" + (f"-{index + 1}" if index else ""))
        whole = [V6_ANY] if family == "ip6" else [ANY]
        rules: list[PolicyRule] = []
        if incoming is not None:
            rules += [_finish(r, incoming, toward=host) for r in flat[incoming.key]]
            rules.append(_closing("input-policy", incoming, whole, [host]))
        else:
            rules.append(_uncovered("input", "input" in hooks, [ANY], [host]))
        if outgoing is not None:
            rules += [_finish(r, outgoing, away=host) for r in flat[outgoing.key]]
            rules.append(_closing("output-policy", outgoing, [host], whole))
        else:
            rules.append(_uncovered("output", "output" in hooks, [host], [ANY]))
        if family == "ip6":
            rules.append(_passing("ipv4-pass", [ANY], [ANY], "IPv4 traffic: an IPv6 table does not see it"))
        titles = "/".join(c.title for c in (incoming, outgoing) if c is not None)
        parts = [f"{c.title} (policy {c.policy})" for c in (incoming, outgoing) if c is not None]
        policies.append(
            Policy(
                id=policy_id,
                name=f"{prefix} {titles}",
                domain="network",
                evaluation="first-match",
                default="deny",  # never reached: the chain policies (or pass rules) close every flow of the host
                description=f"{ruleset.tool} {' and '.join(parts)} of {host}",
                source=source,
                scope=[host],
                rules=_numbered(rules, policy_id),
            )
        )
    return policies


def _closing(rule_id: str, chain: BaseChain, sources: list[str], destinations: list[str]) -> PolicyRule:
    return PolicyRule(
        id=rule_id,
        policy="",
        order=0,
        effect="allow" if chain.effect == "allow" else "deny",
        sources=sources,
        destinations=destinations,
        ports=[ANY],
        description=f"{chain.title} chain policy {chain.policy}",
        metadata={"chain": chain.title, "chain_policy": chain.policy},
    )


def _uncovered(side: str, filtered: bool, sources: list[str], destinations: list[str]) -> PolicyRule:
    """The side of a host policy that has no chain in this table."""
    direction = "to" if side == "input" else "from"
    if filtered:  # another table's chain decides it
        return _passing(f"{side}-pass", sources, destinations, f"traffic {direction} the host: other tables decide it")
    return PolicyRule(
        id=f"{side}-unfiltered",
        policy="",
        order=0,
        effect="allow",
        sources=sources,
        destinations=destinations,
        ports=[ANY],
        description=f"no {side} chain: traffic {direction} the host is not filtered",
        metadata={"chain_policy": "none"},
    )


def _passing(rule_id: str, sources: list[str], destinations: list[str], description: str) -> PolicyRule:
    """A rule that leaves the decision to other policies (it is not a rule of the rule set)."""
    return PolicyRule(
        id=rule_id,
        policy="",
        order=0,
        effect="allow",
        sources=sources,
        destinations=destinations,
        ports=[ANY],
        description=description,
        metadata={"pass": True},
    )


def _numbered(rules: Iterable[PolicyRule], policy_id: str) -> list[PolicyRule]:
    """The rules in first-match order (``order``), with IDs unique within the policy."""
    out: list[PolicyRule] = []
    used: set[str] = set()
    for order, rule in enumerate(rules):
        rule_id, n = rule.id, 1
        while rule_id in used:
            n += 1
            rule_id = f"{rule.id}-{n}"
        used.add(rule_id)
        out.append(rule.model_copy(update={"order": order, "id": rule_id, "policy": policy_id}))
    return out


__all__ = [
    "HOOKS",
    "RETURN",
    "TERMINAL",
    "V6_ANY",
    "BaseChain",
    "FilterRule",
    "FilterRuleset",
    "build_policies",
    "intersect_addresses",
]
