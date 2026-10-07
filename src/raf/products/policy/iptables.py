"""``iptables-save`` / ``ip6tables-save`` output -> normalized R$F network policies.

Only the ``filter`` table decides what is allowed (``nat``, ``mangle``, ``raw`` and ``security`` are
reported and ignored). The chains become policies as :mod:`policy.netfilter` describes:
``FORWARD`` becomes ``<name>-forward`` (scoped to the networks its rules name), ``INPUT`` and
``OUTPUT`` become ``<name>-host`` (scoped to ``host:<name>``); user chains are inlined where they
are jumped to; ``LOG`` and other non-terminating targets decide nothing. ip6tables-save output
(recognized by its header, a ``.v6`` file or IPv6-only addresses) becomes ``<name>-ip6-forward``
and ``<name>-ip6-host`` and applies to IPv6 addresses only.

What the model cannot express - negation, interfaces other than loopback, source ports, rate
limits, ipsets and other match modules - is never approximated silently: such a rule is imported
disabled with the reasons in ``metadata.unmodeled``, and the set's warnings count them. Loopback
rules and rules for established/related (return) traffic are left out: they decide nothing about
new flows between hosts. The input is untrusted text: it is tokenized like a shell command line
(never executed), bounded in size and rule count, and every value is normalized.
"""

from __future__ import annotations

import ipaddress
import shlex
from pathlib import Path

from raf.core.errors import InvalidInputError
from raf.core.ids import slugify
from raf.core.ports import ANY, PortSet
from raf.products.policy.model import MAX_RULES_PER_POLICY, PolicySet, normalize_address
from raf.products.policy.netfilter import BaseChain, FilterRule, FilterRuleset, build_policies

IPTABLES_SUFFIXES = (".rules", ".iptables", ".v4", ".v6")
#: Suffixes a file name loses before it names the host ("rules.v4" -> "rules", "edge.nft.json" -> "edge").
NAME_SUFFIXES = (".json", ".txt", ".conf", ".nft", ".nftables", *IPTABLES_SUFFIXES)
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


def default_name(source: str | None, fallback: str) -> str:
    """The host a rule set file belongs to by default: its name without suffixes, as a slug."""
    name = Path(source).name if source else ""
    while name.lower().endswith(NAME_SUFFIXES):
        name = name[: name.rindex(".")]
    return slugify(name) if name.strip(" .-_") else fallback


def parse_iptables(text: str, source: str | None, *, host: str | None = None) -> PolicySet:
    name = slugify(host) if host and host.strip() else default_name(source, "iptables")
    warnings: list[str] = []
    chains, rules = _read_filter_table(text, warnings)
    family = _family(text, source, rules)
    base = [
        BaseChain(key=chain, hook=chain.lower(), policy=chains[chain], title=chain, family=family) for chain in _BUILTIN
    ]
    ruleset = FilterRuleset(
        tool="ip6tables" if family == "ip6" else "iptables",
        base=base,
        rules=rules,
        names={chain: chain.lower() for chain in rules},
        labels={chain: chain for chain in rules},
        regular=[chain for chain in chains if chain not in _BUILTIN],
    )
    prefix = f"{name}-ip6" if family == "ip6" else name
    policies, more = build_policies(ruleset, prefix=prefix, host=name, source=source)
    return PolicySet(
        name=name,
        format="ip6tables-save" if family == "ip6" else "iptables-save",
        source=source,
        policies=policies,
        warnings=[*warnings, *more],
    )


def _family(text: str, source: str | None, rules: dict[str, list[FilterRule]]) -> str:
    """``ip6`` for ip6tables-save output: its header, a ``.v6`` file, or IPv6 addresses only."""
    head = text[:4096]
    if "ip6tables-save" in head:
        return "ip6"
    if "iptables-save" in head:
        return "ip"
    if source and source.lower().endswith(".v6"):
        return "ip6"
    versions = {
        ipaddress.ip_network(selector[5:], strict=False).version
        for chain in rules.values()
        for rule in chain
        for selector in (*rule.sources, *rule.destinations)
        if selector.startswith("cidr:")
    }
    return "ip6" if versions == {6} else "ip"


# --------------------------------------------------------------------------- reading


def _read_filter_table(text: str, warnings: list[str]) -> tuple[dict[str, str], dict[str, list[FilterRule]]]:
    """Chain policies (``-`` for user chains) and rules of the filter table, in order."""
    if not looks_like_iptables(text):
        raise InvalidInputError(
            "Not iptables-save output.",
            hint="Expected '*filter', ':CHAIN POLICY [p:b]', '-A CHAIN ...' and 'COMMIT' lines (iptables-save).",
        )
    table: str | None = None
    ignored: set[str] = set()
    chains: dict[str, str] = {}
    rules: dict[str, list[FilterRule]] = {}
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
        chain_rules = rules.setdefault(chain, [])
        chain_rules.append(_parse_rule(chain, len(chain_rules) + 1, number, tokens[2:]))
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


def _parse_rule(chain: str, position: int, line: int, tokens: list[str]) -> FilterRule:
    rule = FilterRule(chain=chain, position=position, line=line)
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
            rule.verdict = value()
            rule.target = None if rule.verdict in _NON_TERMINAL else rule.verdict  # LOG & co. decide nothing
            rule.goto = arg in ("-g", "--goto")
        elif arg in ("-c", "--set-counters"):
            value()
            value()
        elif not rule.verdict and module_known:
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


def _port_labels(protocol: str, dports: list[str] | None, icmp_type: int | None, rule: FilterRule) -> list[str]:
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


__all__ = ["IPTABLES_SUFFIXES", "NAME_SUFFIXES", "default_name", "looks_like_iptables", "parse_iptables"]
