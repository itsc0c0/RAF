"""``iptables-save`` / ``ip6tables-save`` output -> normalized R$F network policies.

Only the ``filter`` table decides what is allowed (``nat``, ``mangle``, ``raw`` and ``security`` are
reported and ignored). Rules become first-match :class:`PolicyRule` s with CIDR selectors:

* ``FORWARD`` (traffic the host routes) becomes ``<name>-forward``, scoped to the networks its rules
  name, so the chain's policy never denies flows elsewhere in the workspace. A FORWARD chain without
  rules (a host that does not route) or naming no address is not imported.
* ``INPUT`` and ``OUTPUT`` (traffic to and from the host itself) become ``<name>-host``, scoped to
  ``host:<name>``: INPUT rules without ``-d`` target the host, OUTPUT rules without ``-s`` come from
  it, and each chain's policy closes its part as a final rule.
* Jumps to user chains are inlined (conditions combined); ``RETURN`` ends a chain like the policy
  of a built-in one; ``LOG`` and other non-terminating targets do not decide anything.

What the model cannot express - negation, interfaces other than loopback, source ports, rate
limits, ipsets and other match modules, ``--goto`` - is never approximated silently: such a rule
is imported disabled with the reasons in ``metadata.unmodeled``, and the set's warnings count them.
Loopback rules and rules for established/related (return) traffic are left out: they decide
nothing about new flows between hosts. The input is untrusted text: it is tokenized like a shell
command line (never executed), bounded in size and rule count, and every value is normalized.
"""

from __future__ import annotations

import ipaddress
import shlex
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from raf.core.errors import InvalidInputError
from raf.core.ids import slugify
from raf.core.ports import ANY, PortSet
from raf.products.policy.model import MAX_RULES_PER_POLICY, Policy, PolicyRule, PolicySet, normalize_address

IPTABLES_SUFFIXES = (".rules", ".iptables", ".v4", ".v6")
_TERMINAL = {"ACCEPT": "allow", "DROP": "deny", "REJECT": "deny"}
#: Targets that let the packet continue: they decide nothing.
_NON_TERMINAL = {
    "LOG",
    "NFLOG",
    "ULOG",
    "AUDIT",
    "TRACE",
    "MARK",
    "CONNMARK",
    "SECMARK",
    "CONNSECMARK",
    "TCPMSS",
    "CLASSIFY",
    "DSCP",
    "TOS",
    "TTL",
    "HL",
    "ECN",
    "SET",
    "TEE",
    "IDLETIMER",
    "LED",
    "RATEEST",
    "HMARK",
    "CHECKSUM",
}
_BUILTIN = ("INPUT", "FORWARD", "OUTPUT")
_TABLES = {"filter", "nat", "mangle", "raw", "security"}
_PROTOCOLS = {
    "tcp": "tcp",
    "6": "tcp",
    "udp": "udp",
    "17": "udp",
    "icmp": "icmp",
    "1": "icmp",
    "ipv6-icmp": "icmp",
    "icmpv6": "icmp",
    "58": "icmp",
    "all": ANY,
    "0": ANY,
}
_ICMP_TYPES = {
    "any": None,
    "echo-reply": 0,
    "pong": 0,
    "destination-unreachable": 3,
    "redirect": 5,
    "echo-request": 8,
    "ping": 8,
    "time-exceeded": 11,
    "ttl-exceeded": 11,
    "parameter-problem": 12,
}
_ICMPV6_TYPES = {
    "any": None,
    "destination-unreachable": 1,
    "packet-too-big": 2,
    "time-exceeded": 3,
    "ttl-exceeded": 3,
    "parameter-problem": 4,
    "echo-request": 128,
    "ping": 128,
    "echo-reply": 129,
    "pong": 129,
    "router-solicitation": 133,
    "router-advertisement": 134,
    "neighbour-solicitation": 135,
    "neighbor-solicitation": 135,
    "neighbour-advertisement": 136,
    "neighbor-advertisement": 136,
    "redirect": 137,
}
#: Match modules whose options are understood (anything else is reported as unmodeled).
_MODULES = {"tcp", "udp", "icmp", "icmp6", "multiport", "comment", "conntrack", "state", "iprange"}
_MAX_DEPTH = 8
#: Rule visits while flattening: a chain is walked again for every jump to it, so nested jumps multiply.
_MAX_STEPS = 20 * MAX_RULES_PER_POLICY


@dataclass
class _Rule:
    """One ``-A`` line of the filter table."""

    chain: str
    line: int
    sources: list[str] = field(default_factory=lambda: [ANY])
    destinations: list[str] = field(default_factory=lambda: [ANY])
    ports: list[str] = field(default_factory=lambda: [ANY])
    target: str | None = None
    goto: bool = False
    comment: str = ""
    unmodeled: list[str] = field(default_factory=list)
    skip: str | None = None  # why the rule decides nothing about new flows

    def conditional(self) -> bool:
        return (self.sources, self.destinations, self.ports) != ([ANY], [ANY], [ANY]) or bool(self.unmodeled)


@dataclass
class _Budget:
    """Rule visits left for flattening one rule set (bounds the work of deeply nested jumps)."""

    left: int = _MAX_STEPS

    def spend(self) -> None:
        self.left -= 1
        if self.left < 0:
            raise InvalidInputError(
                f"Flattening the user chains takes more than {_MAX_STEPS} steps: the jumps nest too much.",
                hint="Split the rule set, or describe it as a raf-policy/1 document.",
            )


def looks_like_iptables(text: str) -> bool:
    """``iptables-save`` output: a ``*table`` line first, then chain or rule lines.

    Only the head is examined (sniffing reads the first 64 KiB, and a large rule set does not reach
    its ``COMMIT`` there); :func:`parse_iptables` checks that the filter table is complete.
    """
    lines = [line.strip() for line in text.splitlines()[:400]]
    content = [line for line in lines if line and not line.startswith("#")]
    return (
        bool(content)
        and content[0].startswith("*")
        and content[0][1:].strip().lower() in _TABLES
        and any(line.startswith((":", "-A ")) for line in content[1:])
    )


def parse_iptables(text: str, source: str | None, *, host: str | None = None) -> PolicySet:
    name = slugify(host or (Path(source).stem if source else "") or "iptables") or "iptables"
    warnings: list[str] = []
    chains, rules = _read_filter_table(text, warnings)
    policies: list[Policy] = []
    expanded: dict[str, list[PolicyRule]] = {}
    budget = _Budget()
    for chain in _BUILTIN:
        policy_id = f"{name}-{'forward' if chain == 'FORWARD' else 'host'}"
        expanded[chain] = _expand(chain, rules, chains, policy_id, budget=budget)
    forward = _forward_policy(name, chains, expanded["FORWARD"], source, warnings)
    if forward is not None:
        policies.append(forward)
    host_policy = _host_policy(name, chains, expanded["INPUT"], expanded["OUTPUT"], source)
    if host_policy is not None:
        policies.append(host_policy)
    for policy in policies:
        if len(policy.rules) > MAX_RULES_PER_POLICY:
            raise InvalidInputError(
                f"Policy '{policy.id}' would have {len(policy.rules)} rules (limit {MAX_RULES_PER_POLICY})."
            )
    unused = sorted(set(chains) - set(_BUILTIN) - _reachable(rules))
    if unused:
        listed = ", ".join(unused[:10]) + (f" and {len(unused) - 10} more" if len(unused) > 10 else "")
        verb = "is" if len(unused) == 1 else "are"
        warnings.append(f"chain(s) {listed} {verb} never jumped to from INPUT, FORWARD or OUTPUT: not imported")
    disabled = sum(1 for policy in policies for rule in policy.rules if not rule.enabled)
    if disabled:
        warnings.append(
            f"{disabled} rule(s) use conditions the policy model cannot express exactly (interfaces, negation, "
            "source ports, match modules ...): imported disabled, reasons in metadata.unmodeled"
        )
    if not policies:
        warnings.append("nothing to import: no rules in INPUT, FORWARD or OUTPUT and only ACCEPT policies")
    return PolicySet(name=name, format="iptables-save", source=source, policies=policies, warnings=warnings)


# --------------------------------------------------------------------------- reading


def _read_filter_table(text: str, warnings: list[str]) -> tuple[dict[str, str], dict[str, list[_Rule]]]:
    """Chain policies (``-`` for user chains) and rules of the filter table, in order."""
    if not looks_like_iptables(text):
        raise InvalidInputError(
            "Not iptables-save output.",
            hint="Expected '*filter', ':CHAIN POLICY [p:b]', '-A CHAIN ...' and 'COMMIT' lines (iptables-save).",
        )
    table: str | None = None
    ignored: set[str] = set()
    chains: dict[str, str] = {}
    rules: dict[str, list[_Rule]] = {}
    unparsed = count = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:].strip().lower()
            if table not in _TABLES:
                unparsed += 1  # its lines are skipped up to the next COMMIT, like those of other tables
            elif table != "filter":
                ignored.add(table)
            continue
        if line == "COMMIT":
            table = None
            continue
        if table != "filter":
            continue
        if line.startswith(":"):
            parts = line[1:].split()
            if parts:
                chains[parts[0]] = parts[1].upper() if len(parts) > 1 else "-"
                rules.setdefault(parts[0], [])
            continue
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            unparsed += 1
            continue
        if tokens and tokens[0].startswith("[") and tokens[0].endswith("]"):  # iptables-save -c counters
            tokens = tokens[1:]
        if len(tokens) < 2 or tokens[0] not in ("-A", "--append"):
            unparsed += 1
            continue
        count += 1
        if count > MAX_RULES_PER_POLICY:
            raise InvalidInputError(f"More than {MAX_RULES_PER_POLICY} rules in the filter table.")
        chain = tokens[1]
        rules.setdefault(chain, []).append(_parse_rule(chain, number, tokens[2:]))
    if table == "filter":
        raise InvalidInputError(
            "The filter table has no COMMIT line: the rule set looks truncated.",
            hint="iptables-restore would reject it too; save the rule set again (iptables-save > file).",
        )
    if ignored:
        warnings.append(f"table(s) {', '.join(sorted(ignored))} ignored: only the filter table decides access")
    if unparsed:
        warnings.append(f"{unparsed} line(s) of the filter table are not rules ('-A CHAIN ...') and were skipped")
    for chain in _BUILTIN:
        chains.setdefault(chain, "ACCEPT")
        rules.setdefault(chain, [])
    return chains, rules


def _parse_rule(chain: str, line: int, tokens: list[str]) -> _Rule:
    rule = _Rule(chain=chain, line=line)
    protocol = ANY
    dports: list[str] | None = None
    icmp_type: int | None = None
    module_known = True  # the options of an unknown match module are covered by its "match <name>" reason
    negate = False
    i = 0

    def value() -> str:
        nonlocal i
        i += 1
        return tokens[i] if i < len(tokens) else ""

    while i < len(tokens):
        arg = tokens[i]
        if arg == "!":
            negate = True
            i += 1
            continue
        if arg in ("-s", "--source", "--src", "-d", "--destination", "--dst"):
            selectors = _addresses(value())
            where = "source" if arg in ("-s", "--source", "--src") else "destination"
            if negate:
                rule.unmodeled.append(f"negated {where}")
            elif selectors is None:
                rule.unmodeled.append(f"{where} address not understood")
            else:
                setattr(rule, "sources" if where == "source" else "destinations", selectors)
        elif arg in ("-p", "--protocol"):
            name = value().lower()
            mapped = _PROTOCOLS.get(name)
            if negate or mapped is None:
                rule.unmodeled.append(f"protocol {'not ' if negate else ''}{name}")
            else:
                protocol = mapped
        elif arg in ("-i", "--in-interface", "-o", "--out-interface"):
            interface = value()
            if interface == "lo" and not negate:
                rule.skip = "loopback traffic"
            elif not (interface == "lo" and negate):  # "! -i lo": everything but loopback, i.e. no constraint here
                rule.unmodeled.append(f"interface {'not ' if negate else ''}{interface}")
        elif arg in ("-m", "--match"):
            module = value().lower()
            module_known = module in _MODULES
            if not module_known:
                rule.unmodeled.append(f"match {module}")
        elif arg in ("--dport", "--destination-port", "--dports", "--destination-ports"):
            ports = [p for p in value().split(",") if p]
            if negate:
                rule.unmodeled.append("negated destination port")
            else:
                dports = ports
        elif arg in ("--sport", "--source-port", "--sports", "--source-ports", "--ports"):
            value()
            rule.unmodeled.append("port in either direction" if arg == "--ports" else "source port")
        elif arg in ("--icmp-type", "--icmpv6-type"):
            text = value().lower()
            kind, code, _ = text.partition("/")  # a code ("3/3") narrows the type: the model has no codes
            names = _ICMPV6_TYPES if arg == "--icmpv6-type" else _ICMP_TYPES
            number = int(kind) if kind.isdigit() else names.get(kind, -1)
            if negate or code or number == -1 or (number is not None and number > 255):
                rule.unmodeled.append(f"icmp type {'not ' if negate else ''}{text}")
            else:
                icmp_type = number
        elif arg == "--comment":
            rule.comment = value()[:500]
        elif arg in ("--ctstate", "--state"):
            states = {s.strip().upper() for s in value().split(",") if s.strip()}
            if negate:
                rule.unmodeled.append("negated connection state")
            elif "NEW" in states:
                pass  # new flows match: the other states only add their return traffic
            elif states <= {"ESTABLISHED", "RELATED"}:
                rule.skip = "return traffic"
            elif states <= {"ESTABLISHED", "RELATED", "INVALID"}:
                rule.skip = f"state {','.join(sorted(states))}"
            else:  # DNAT, SNAT, UNTRACKED: new flows of one kind only
                rule.unmodeled.append(f"connection state {','.join(sorted(states))}")
        elif arg in ("--src-range", "--dst-range"):
            networks = _range(value())
            where = "sources" if arg == "--src-range" else "destinations"
            if negate or networks is None:
                rule.unmodeled.append(f"{'negated ' if negate else ''}address range")
            else:
                setattr(rule, where, networks)
        elif arg == "--syn":
            if negate:
                rule.unmodeled.append("not SYN")
        elif arg == "--tcp-flags":
            value()
            value()
            rule.unmodeled.append("tcp flags")
        elif arg in ("-f", "--fragment"):
            rule.unmodeled.append("fragments")
        elif arg in ("-j", "--jump", "-g", "--goto"):
            rule.target = value()
            rule.goto = arg in ("-g", "--goto")
        elif arg in ("-c", "--set-counters"):
            value()
            value()
        elif rule.target is None and module_known:
            # a condition the model does not know: approximating it away would widen the rule
            rule.unmodeled.append(f"option {arg[:40]}")
            if arg.startswith("-") and i + 1 < len(tokens) and not tokens[i + 1].startswith(("-", "!")):
                value()
        elif arg.startswith("-") and i + 1 < len(tokens) and not tokens[i + 1].startswith(("-", "!")):
            value()  # an option of the target, or of a match module reported above
        negate = False
        i += 1
    rule.ports = _port_labels(protocol, dports, icmp_type, rule)
    return rule


def _addresses(text: str) -> list[str] | None:
    selectors: list[str] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            return None
        selectors.append(normalize_address(part))
    return sorted(set(selectors)) or None


def _range(text: str) -> list[str] | None:
    low, _, high = text.partition("-")
    try:
        first, last = ipaddress.ip_address(low.strip()), ipaddress.ip_address(high.strip() or low.strip())
        networks = list(ipaddress.summarize_address_range(first, last))
    except (ValueError, TypeError):
        return None
    return sorted({normalize_address(str(n)) for n in networks})


def _port_labels(protocol: str, dports: list[str] | None, icmp_type: int | None, rule: _Rule) -> list[str]:
    """Canonical :class:`PortSet` labels (``tcp/22``, ``tcp/1000-2000``, ``udp/all``, ``icmp/8``)."""
    if protocol == "icmp":
        return [f"icmp/{icmp_type}" if icmp_type is not None else "icmp"]
    whole = PortSet.parse([protocol]).labels()
    if dports is None:
        return whole
    if protocol not in ("tcp", "udp"):
        rule.unmodeled.append("ports without tcp or udp")
        return [ANY]
    labels = []
    for port in dports:
        low, colon, high = port.partition(":")
        low = low or "0"  # ":1024" is 0-1024 and "1024:" is 1024-65535, as iptables reads them
        high = (high or "65535") if colon else low
        if not (low.isdigit() and high.isdigit()) or int(low) > int(high) or int(high) > 65535:
            rule.unmodeled.append(f"port {port}")
            return whole
        labels.append(f"{protocol}/{low}" if low == high else f"{protocol}/{low}-{high}")
    return PortSet.parse(labels).labels() or whole


# --------------------------------------------------------------------------- flattening


def _expand(
    chain: str,
    rules: dict[str, list[_Rule]],
    chains: dict[str, str],
    policy_id: str,
    *,
    budget: _Budget,
    depth: int = 0,
    prefix: str = "",
    stack: tuple[str, ...] = (),
) -> list[PolicyRule]:
    """The rules of ``chain`` in first-match order, user chains inlined."""
    out: list[PolicyRule] = []
    blocked: str | None = None  # a conditional RETURN came before: what follows is not reached by every packet
    for position, rule in enumerate(rules.get(chain, []), 1):
        budget.spend()
        rule_id = slugify(f"{prefix}{chain.lower()}-{position}")
        if rule.skip is not None:
            continue
        target = rule.target or ""
        reasons = list(rule.unmodeled)
        if blocked:
            reasons.append(blocked)
        if target in _NON_TERMINAL or not target:
            continue
        if target == "RETURN":
            if chain in _BUILTIN:
                effect = "allow" if chains.get(chain, "ACCEPT") == "ACCEPT" else "deny"  # the chain's policy decides
                out.append(_policy_rule(rule, rule_id, policy_id, effect, reasons))
            elif not rule.conditional():
                break  # the rest of this user chain is never reached
            else:
                blocked = f"follows a conditional RETURN in {chain} (line {rule.line})"
            continue
        if target in _TERMINAL:
            out.append(_policy_rule(rule, rule_id, policy_id, _TERMINAL[target], reasons))
            continue
        if target in rules and target not in _BUILTIN:
            loop = target == chain or target in stack
            if rule.goto or depth >= _MAX_DEPTH or loop:
                why = "--goto" if rule.goto else ("jump loop" if loop else "jumps nested too deeply")
                out.append(_policy_rule(rule, rule_id, policy_id, "deny", [*reasons, f"{why} to {target}"]))
                continue
            inner = _expand(
                target,
                rules,
                chains,
                policy_id,
                budget=budget,
                depth=depth + 1,
                prefix=f"{rule_id}.",
                stack=(*stack, chain),
            )
            for sub in inner:
                combined = _combine(rule, sub, reasons)
                if combined is not None:
                    out.append(combined)
            if len(out) > MAX_RULES_PER_POLICY:
                raise InvalidInputError(f"Inlining user chains gives more than {MAX_RULES_PER_POLICY} rules.")
            continue
        out.append(_policy_rule(rule, rule_id, policy_id, "deny", [*reasons, f"target {target}"]))
    return out


def _policy_rule(rule: _Rule, rule_id: str, policy_id: str, effect: str, reasons: list[str]) -> PolicyRule:
    unmodeled = list(dict.fromkeys(reasons))
    metadata: dict[str, object] = {"chain": rule.chain, "line": rule.line, "target": rule.target}
    if unmodeled:
        metadata["unmodeled"] = unmodeled
    return PolicyRule(
        id=rule_id,
        policy=policy_id,
        order=0,
        effect="allow" if effect == "allow" else "deny",
        sources=rule.sources,
        destinations=rule.destinations,
        ports=rule.ports,
        description=rule.comment,
        enabled=not unmodeled,
        metadata=metadata,
    )


def _combine(jump: _Rule, sub: PolicyRule, reasons: list[str]) -> PolicyRule | None:
    """``sub`` (a rule of the jumped-to chain) as reached through ``jump``: both rules' conditions."""
    sources = _intersect(jump.sources, sub.sources)
    destinations = _intersect(jump.destinations, sub.destinations)
    ports = PortSet.parse(jump.ports).intersect(PortSet.parse(sub.ports)).labels()
    if not sources or not destinations or not ports:
        return None  # no packet can take this path
    unmodeled = list(dict.fromkeys([*reasons, *sub.metadata.get("unmodeled", [])]))
    metadata = {**sub.metadata, "via": f"{jump.chain} line {jump.line}"}
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


def _network(selector: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if not selector.startswith("cidr:"):
        return None
    return ipaddress.ip_network(selector[5:], strict=False)


def _reachable(rules: dict[str, list[_Rule]]) -> set[str]:
    seen: set[str] = set()
    todo = [r.target for chain in _BUILTIN for r in rules.get(chain, []) if r.target]
    while todo:
        target = todo.pop()
        if target in seen or target not in rules:
            continue
        seen.add(target)
        todo.extend(r.target for r in rules[target] if r.target)
    return seen


# --------------------------------------------------------------------------- policies


def _forward_policy(
    name: str, chains: dict[str, str], rules: list[PolicyRule], source: str | None, warnings: list[str]
) -> Policy | None:
    policy = chains.get("FORWARD", "ACCEPT")
    if not rules:
        if policy != "ACCEPT":
            warnings.append(
                f"FORWARD has no rules for new flows (a host that does not route between networks): its {policy} "
                "policy is not imported"
            )
        return None
    scope = sorted({s for rule in rules for s in (*rule.sources, *rule.destinations) if s != ANY})
    if not scope:
        warnings.append(
            "FORWARD names no address (interface-based rules): not imported; describe its zones in a raf-policy/1 "
            "document instead"
        )
        return None
    return Policy(
        id=f"{name}-forward",
        name=f"{name} FORWARD",
        domain="network",
        evaluation="first-match",
        default="allow" if policy == "ACCEPT" else "deny",
        description=f"iptables FORWARD chain (policy {policy}), for flows from or to the networks its rules name",
        source=source,
        scope=scope,
        rules=_numbered(rules),
    )


def _host_policy(
    name: str, chains: dict[str, str], incoming: list[PolicyRule], outgoing: list[PolicyRule], source: str | None
) -> Policy | None:
    input_policy, output_policy = chains.get("INPUT", "ACCEPT"), chains.get("OUTPUT", "ACCEPT")
    if not incoming and not outgoing and input_policy == output_policy == "ACCEPT":
        return None
    host = normalize_address(f"host:{name}")
    policy_id = f"{name}-host"
    rules = [r.model_copy(update={"destinations": [host]}) if r.destinations == [ANY] else r for r in incoming]
    rules.append(_closing_rule(policy_id, "input-policy", input_policy, [ANY], [host], "INPUT"))
    rules += [r.model_copy(update={"sources": [host]}) if r.sources == [ANY] else r for r in outgoing]
    rules.append(_closing_rule(policy_id, "output-policy", output_policy, [host], [ANY], "OUTPUT"))
    return Policy(
        id=policy_id,
        name=f"{name} INPUT/OUTPUT",
        domain="network",
        evaluation="first-match",
        default="deny",  # never reached: the two chain-policy rules close every flow from or to the host
        description=f"iptables INPUT (policy {input_policy}) and OUTPUT (policy {output_policy}) of {host}",
        source=source,
        scope=[host],
        rules=_numbered(rules),
    )


def _closing_rule(
    policy_id: str, rule_id: str, chain_policy: str, sources: list[str], destinations: list[str], chain: str
) -> PolicyRule:
    return PolicyRule(
        id=rule_id,
        policy=policy_id,
        order=0,
        effect="allow" if chain_policy == "ACCEPT" else "deny",
        sources=sources,
        destinations=destinations,
        ports=[ANY],
        description=f"{chain} chain policy {chain_policy}",
        metadata={"chain": chain, "chain_policy": chain_policy},
    )


def _numbered(rules: Iterable[PolicyRule]) -> list[PolicyRule]:
    """The rules in first-match order (``order``), with IDs unique within the policy."""
    out: list[PolicyRule] = []
    used: set[str] = set()
    for order, rule in enumerate(rules):
        rule_id, n = rule.id, 1
        while rule_id in used:
            n += 1
            rule_id = f"{rule.id}-{n}"
        used.add(rule_id)
        out.append(rule.model_copy(update={"order": order, "id": rule_id}))
    return out


__all__ = ["IPTABLES_SUFFIXES", "looks_like_iptables", "parse_iptables"]
