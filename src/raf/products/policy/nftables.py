"""nftables rule sets -> normalized R$F network policies.

Reads a ruleset as ``nft list ruleset`` prints it, as an nftables script (``/etc/nftables.conf``:
``flush ruleset``, ``define``, blocks, ``add``/``insert`` commands) or as ``nft -j list ruleset``
JSON. Tables of the ``ip``, ``ip6`` and ``inet`` families are read; their ``filter`` chains on
the ``input``, ``forward`` and ``output`` hooks become policies as :mod:`policy.netfilter`
describes (several base chains on one hook become one policy each: a packet must pass all of
them). Regular chains are inlined where they are jumped to (``jump``, ``goto``).

Understood exactly: ``ip``/``ip6`` addresses (prefixes, ranges, anonymous and named sets,
``define`` variables), ``tcp``/``udp``/``th`` destination ports (sets, ranges, ``!=``, ``<``,
service names), ``meta l4proto``/``ip protocol``/``ip6 nexthdr``, ICMP and ICMPv6 types,
``meta nfproto``, ``ct state``, loopback interfaces, verdict maps (``vmap``), ``counter``,
``log``, ``comment``. Anything else - other interfaces, negated addresses, source ports, rate
limits, dynamic sets, ``fib``, marks, concatenations - is never approximated away: the rule is
imported disabled with the reasons in ``metadata.unmodeled``. ``ct state established,related``
and loopback rules decide nothing about new flows between hosts and are left out. Chains of type
``nat`` or ``route``, ``filter`` chains on other hooks (``prerouting``, ``ingress`` ...) and
tables of other families are reported and ignored; ``include`` is never followed.

The text is untrusted: it is tokenized (never executed), bounded in size, tokens, ``define``
expansion, set sizes and rule count, and every value is normalized.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from raf.core.errors import InvalidInputError
from raf.core.ids import slugify
from raf.core.ports import ANY, PortSet
from raf.products.policy.iptables import default_name
from raf.products.policy.model import MAX_RULES_PER_POLICY, PolicySet, normalize_address
from raf.products.policy.netfilter import (
    HOOKS,
    RETURN,
    BaseChain,
    FilterRule,
    FilterRuleset,
    build_policies,
    intersect_addresses,
)

NFT_SUFFIXES = (".nft", ".nftables")
FAMILIES = ("ip", "ip6", "inet", "arp", "bridge", "netdev")
_IP_FAMILIES = ("ip", "ip6", "inet")
_PRIORITIES = {"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}
_MAX_TOKENS = 1_000_000
_MAX_DEFINE_TOKENS = 100_000
#: Elements of one set that a rule may use (a CIDR each); larger sets are reported, not modeled.
MAX_SET_ELEMENTS = 256
_MAX_STORED_ELEMENTS = 65_536
_VERDICTS = ("accept", "drop", "reject", "return", "continue", "jump", "goto", "queue")
_OPERATORS = {"==": "==", "eq": "==", "!=": "!=", "ne": "!=", "<": "<", "lt": "<", ">": ">", "gt": ">"}
_OPERATORS |= {"<=": "<=", "le": "<=", ">=": ">=", "ge": ">="}
_PROTOCOLS = {
    "tcp": "tcp",
    "6": "tcp",
    "udp": "udp",
    "17": "udp",
    "icmp": "icmp",
    "1": "icmp",
    "ipv6-icmp": "icmpv6",
    "icmpv6": "icmpv6",
    "58": "icmpv6",
}
_ICMP_TYPES = {
    "echo-reply": 0,
    "destination-unreachable": 3,
    "source-quench": 4,
    "redirect": 5,
    "echo-request": 8,
    "router-advertisement": 9,
    "router-solicitation": 10,
    "time-exceeded": 11,
    "parameter-problem": 12,
    "timestamp-request": 13,
    "timestamp-reply": 14,
    "info-request": 15,
    "info-reply": 16,
    "address-mask-request": 17,
    "address-mask-reply": 18,
}
_ICMPV6_TYPES = {
    "destination-unreachable": 1,
    "packet-too-big": 2,
    "time-exceeded": 3,
    "parameter-problem": 4,
    "echo-request": 128,
    "echo-reply": 129,
    "mld-listener-query": 130,
    "mld-listener-report": 131,
    "mld-listener-done": 132,
    "mld-listener-reduction": 132,
    "nd-router-solicit": 133,
    "nd-router-advert": 134,
    "nd-neighbor-solicit": 135,
    "nd-neighbor-advert": 136,
    "nd-redirect": 137,
    "router-renumbering": 138,
    "ind-neighbor-solicit": 141,
    "ind-neighbor-advert": 142,
    "mld2-listener-report": 143,
}
#: Service names nft accepts for ports (/etc/services), the common ones.
_SERVICES = {
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "http": 80,
    "www": 80,
    "kerberos": 88,
    "pop3": 110,
    "sunrpc": 111,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "netbios-ssn": 139,
    "imap": 143,
    "imap2": 143,
    "snmp": 161,
    "snmp-trap": 162,
    "bgp": 179,
    "ldap": 389,
    "https": 443,
    "microsoft-ds": 445,
    "isakmp": 500,
    "syslog": 514,
    "submission": 587,
    "ldaps": 636,
    "rsync": 873,
    "imaps": 993,
    "pop3s": 995,
    "openvpn": 1194,
    "ms-sql-s": 1433,
    "nfs": 2049,
    "mysql": 3306,
    "ms-wbt-server": 3389,
    "ipsec-nat-t": 4500,
    "sip": 5060,
    "xmpp-client": 5222,
    "postgresql": 5432,
    "redis": 6379,
    "http-alt": 8080,
    "webcache": 8080,
}
#: Statements that make a rule match fewer packets: the model has no equivalent.
_LIMITING = {"limit": "rate limit", "quota": "quota", "meter": "meter", "numgen": "numgen", "jhash": "hash"}
_NAT = ("snat", "dnat", "masquerade", "redirect", "tproxy", "dup", "fwd", "synproxy")
#: Selector heads whose second word is a field (``ip saddr``, ``meta mark``); the rest are opaque.
_HEADS = (
    "ip", "ip6", "tcp", "udp", "udplite", "th", "icmp", "icmpv6", "sctp", "dccp", "meta", "ct",
    "ether", "vlan", "arp", "rt", "ipsec", "socket", "osf", "exthdr", "frag", "hbh", "dst", "mh",
    "srh", "ah", "esp", "comp", "igmp", "gre", "geneve", "vxlan", "tunnel", "dccp",
)  # fmt: skip
_INTERFACES = ("iif", "iifname", "oif", "oifname")
#: Bare meta keys (``mark``, ``l4proto`` without ``meta``).
_META_KEYS = (
    "mark", "pkttype", "skuid", "skgid", "cgroup", "priority", "length", "nfproto", "l4proto",
    "iiftype", "oiftype", "rtclassid", "cpu", "nftrace", "ibrname", "obrname", "iifgroup", "oifgroup",
    "time", "day", "hour", "secpath", "iifkind", "oifkind", "broute", "sdif", "sdifname",
)  # fmt: skip
_KNOWN = {
    "ip saddr",
    "ip daddr",
    "ip protocol",
    "ip6 saddr",
    "ip6 daddr",
    "ip6 nexthdr",
    "tcp dport",
    "tcp sport",
    "udp dport",
    "udp sport",
    "udplite dport",
    "udplite sport",
    "th dport",
    "th sport",
    "icmp type",
    "icmpv6 type",
    "meta l4proto",
    "meta nfproto",
    "meta protocol",
    "ct state",
    *_INTERFACES,
}
_LOG_OPTIONS = ("prefix", "level", "group", "snaplen", "queue-threshold")
_LOG_FLAGS = ("tcp", "ip", "skuid", "ether", "all", "sequence", "options", ",")


# --------------------------------------------------------------------------- detection


_START_RE = re.compile(
    r"^(?:table\s+(?:(?:ip|ip6|inet|arp|bridge|netdev)\s+)?[\w.$-]+\s*\{|flush\s+ruleset\b|"
    r"(?:add|create|insert)\s+(?:table|chain|rule|set|map|element)\s|define\s+[\w-]+\s*=|include\s+\")"
)
_JSON_RE = re.compile(r'^\s*\{\s*"nftables"\s*:\s*\[')


def looks_like_nftables(text: str) -> bool:
    """An nftables ruleset or script: it starts like one (``table ... {``, ``flush ruleset``,
    ``add rule ...``, ``define``) and names a table or adds rules somewhere in its head."""
    head = text[:65536]
    lines = [line.strip() for line in head.splitlines()[:400]]
    content = [line for line in lines if line and not line.startswith("#")]
    if not content or not _START_RE.match(content[0]):
        return False
    return any(re.match(r"(?:table|add\s+(?:table|rule|chain))\s", line) for line in content)


def looks_like_nftables_json(text: str) -> bool:
    """``nft -j list ruleset`` output: an object whose ``nftables`` key holds a list."""
    return bool(_JSON_RE.match(text[:4096]))


def parse_nftables(text: str, source: str | None, *, host: str | None = None) -> PolicySet:
    """The policies of an nftables ruleset (text or JSON); ``host`` names the machine it runs on."""
    name = slugify(host) if host and host.strip() else default_name(source, "nftables")
    if looks_like_nftables_json(text):
        state, fmt = _read_json(text), "nftables-json"
    elif looks_like_nftables(text):
        state, fmt = _TextReader(text).read(), "nftables"
    else:
        raise InvalidInputError(
            "Not an nftables ruleset.",
            hint="Expected 'nft list ruleset' output ('table inet filter { ... }'), an nftables script or "
            "'nft -j list ruleset' JSON.",
        )
    ruleset, warnings = _ruleset(state)
    policies, more = build_policies(ruleset, prefix=name, host=name, source=source)
    warnings = [*state.warnings, *warnings, *more]
    return PolicySet(name=name, format=fmt, source=source, policies=policies, warnings=warnings)


# --------------------------------------------------------------------------- what was read


@dataclass
class _Match:
    selector: str
    op: str
    values: list[str]


@dataclass
class _Verdict:
    kind: str | None = None  # accept drop reject return continue jump goto queue; None: no verdict
    target: str | None = None

    def text(self) -> str:
        return f"{self.kind} {self.target}" if self.target else (self.kind or "")


@dataclass
class _Rule:
    """One rule as written: matches, statements the model cannot express, the verdict."""

    line: int | None = None
    handle: int | None = None
    matches: list[_Match] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    verdict: _Verdict = field(default_factory=_Verdict)
    vmap: tuple[str, list[tuple[str, _Verdict]] | str] | None = None  # selector, elements or "@map"
    comment: str = ""


@dataclass
class _Chain:
    family: str
    table: str
    name: str
    order: int
    type: str | None = None
    hook: str | None = None
    priority: int = 0
    policy: str = "accept"
    rules: list[_Rule] = field(default_factory=list)


@dataclass
class _Set:
    type: str = ""
    flags: set[str] = field(default_factory=set)
    elements: list[str] = field(default_factory=list)
    verdicts: list[tuple[str, _Verdict]] = field(default_factory=list)  # maps: key -> verdict
    concat: bool = False
    is_map: bool = False


@dataclass
class _State:
    tables: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    chains: dict[tuple[str, str, str], _Chain] = field(default_factory=dict)
    sets: dict[tuple[str, str, str], _Set] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    rules: int = 0
    unparsed: list[str] = field(default_factory=list)

    def table(self, family: str, name: str) -> dict[str, Any]:
        return self.tables.setdefault((family, name), {"dormant": False})

    def chain(self, family: str, table: str, name: str) -> _Chain:
        self.table(family, table)
        key = (family, table, name)
        if key not in self.chains:
            self.chains[key] = _Chain(family, table, name, order=len(self.chains))
        return self.chains[key]

    def set(self, family: str, table: str, name: str) -> _Set:
        self.table(family, table)
        return self.sets.setdefault((family, table, name), _Set())

    def add_rule(self, chain: _Chain, rule: _Rule, *, insert: bool = False) -> None:
        self.rules += 1
        if self.rules > MAX_RULES_PER_POLICY:
            raise InvalidInputError(f"More than {MAX_RULES_PER_POLICY} rules in the ruleset.")
        if insert:
            chain.rules.insert(0, rule)
        else:
            chain.rules.append(rule)

    def reset(self) -> None:
        self.tables.clear()
        self.chains.clear()
        self.sets.clear()

    def skipped(self, what: str) -> None:
        self.unparsed.append(what)


# --------------------------------------------------------------------------- text


@dataclass(frozen=True, slots=True)
class _Tok:
    kind: str  # word | str | punct | nl
    text: str
    line: int


_TOKEN_RE = re.compile(
    r"(?P<cont>\\[ \t]*\r?\n)|(?P<nl>\r?\n)|(?P<ws>[ \t\r\f\v]+)|(?P<comment>#[^\n]*)"
    r'|(?P<str>"[^"\n]*")|(?P<punct>[{};,])|(?P<word>[^\s{};,"#\\]+)|(?P<bad>.)'
)


def _tokenize(text: str) -> list[_Tok]:
    tokens: list[_Tok] = []
    line = 1
    for match in _TOKEN_RE.finditer(text):
        kind, value = match.lastgroup or "bad", match.group()
        if kind == "cont":
            line += 1
        elif kind == "nl":
            tokens.append(_Tok("nl", "\n", line))
            line += 1
        elif kind == "str":
            tokens.append(_Tok("str", value[1:-1], line))
        elif kind in ("punct", "word", "bad"):
            tokens.append(_Tok("punct" if kind == "punct" else "word", value, line))
        if len(tokens) > _MAX_TOKENS:
            raise InvalidInputError(f"The ruleset has more than {_MAX_TOKENS:,} tokens.")
    return tokens


def _is(tok: _Tok | None, text: str) -> bool:
    return tok is not None and tok.kind in ("punct", "word") and tok.text == text


def _statements(tokens: list[_Tok]) -> list[list[_Tok]]:
    """Statements separated by newlines or ``;`` outside braces (a block or a set is one statement)."""
    out: list[list[_Tok]] = []
    current: list[_Tok] = []
    depth = 0
    for tok in tokens:
        if _is(tok, "{"):
            depth += 1
        elif _is(tok, "}"):
            depth -= 1
            if depth < 0:
                raise InvalidInputError(f"Unbalanced '}}' on line {tok.line} of the ruleset.")
        elif depth == 0 and (tok.kind == "nl" or _is(tok, ";")):
            if current:
                out.append(current)
                current = []
            continue
        current.append(tok)
    if depth:
        raise InvalidInputError("Unbalanced '{' in the ruleset: it looks truncated.")
    if current:
        out.append(current)
    return out


def _block(stmt: list[_Tok]) -> tuple[list[_Tok], list[_Tok] | None, list[_Tok]]:
    """Header, the tokens between the first ``{`` and its ``}``, and what follows the block."""
    for start, tok in enumerate(stmt):
        if _is(tok, "{"):
            depth = 0
            for end in range(start, len(stmt)):
                if _is(stmt[end], "{"):
                    depth += 1
                elif _is(stmt[end], "}"):
                    depth -= 1
                    if depth == 0:
                        return stmt[:start], stmt[start + 1 : end], stmt[end + 1 :]
    return stmt, None, []


def _words(tokens: list[_Tok]) -> list[str]:
    return [t.text for t in tokens if t.kind != "nl"]


class _TextReader:
    def __init__(self, text: str) -> None:
        self.text = text
        self.state = _State()
        self.defines: dict[str, list[_Tok]] = {}
        self.substituted = 0

    def read(self) -> _State:
        for stmt in _statements(_tokenize(self.text)):
            self._top(stmt)
        if self.state.unparsed:
            first = ", ".join(self.state.unparsed[:3])
            self.state.warnings.append(
                f"{len(self.state.unparsed)} statement(s) not understood and skipped (first: {first})"
            )
        return self.state

    # -- variables ---------------------------------------------------------------

    def _substitute(self, stmt: list[_Tok]) -> list[_Tok]:
        if not any(t.kind == "word" and t.text.startswith("$") for t in stmt):
            return stmt
        out: list[_Tok] = []
        for tok in stmt:
            if tok.kind == "word" and tok.text.startswith("$") and tok.text[1:] in self.defines:
                value = self.defines[tok.text[1:]]
                self.substituted += len(value)
                if self.substituted > _MAX_TOKENS:
                    raise InvalidInputError("Expanding the ruleset's variables gives too many tokens.")
                out += value
            else:
                out.append(tok)
        return out

    def _define(self, stmt: list[_Tok]) -> None:
        stmt = [t for t in stmt if t.kind != "nl"]
        if len(stmt) < 4 or not _is(stmt[2], "="):
            self.state.skipped(f"line {stmt[0].line} define")
            return
        value = self._substitute(stmt[3:])
        if len(value) > _MAX_DEFINE_TOKENS:
            raise InvalidInputError(f"Variable {stmt[1].text} is too large.")
        self.defines[stmt[1].text] = value

    # -- statements ----------------------------------------------------------------

    def _top(self, stmt: list[_Tok]) -> None:
        head = stmt[0].text if stmt[0].kind == "word" else ""
        if head in ("define", "redefine"):
            self._define(stmt)
        elif head == "undefine":
            if len(stmt) > 1:
                self.defines.pop(stmt[1].text, None)
        elif head == "include":
            target = stmt[1].text if len(stmt) > 1 else ""
            self.state.warnings.append(f"include {target!r} not followed: only the given file is read")
        elif head == "flush":
            self._flush(_words(self._substitute(stmt))[1:], stmt[0].line)
        elif head in ("add", "create"):
            self._command(self._substitute(stmt[1:]), insert=False)
        elif head == "insert":
            self._command(self._substitute(stmt[1:]), insert=True)
        elif head in ("delete", "destroy"):
            self._delete(_words(self._substitute(stmt))[1:], stmt[0].line)
        elif head in ("table", "chain", "set", "map", "rule", "element"):
            self._command(self._substitute(stmt), insert=False)
        else:
            self.state.skipped(f"line {stmt[0].line} {head or stmt[0].text!r}")

    @staticmethod
    def _family(words: list[_Tok]) -> tuple[str, list[_Tok]]:
        if len(words) > 1 and words[0].kind == "word" and words[0].text in FAMILIES and not _is(words[1], "{"):
            return words[0].text, words[1:]
        return "ip", words

    def _command(self, tokens: list[_Tok], *, insert: bool) -> None:
        if not tokens:
            return
        kind, rest = tokens[0].text, tokens[1:]
        line = tokens[0].line
        header, body, trailing = _block(rest)
        family, header = self._family(header)
        names = [t.text for t in header if t.kind != "nl"]
        if kind == "table" and names:
            self.state.table(family, names[0])
            if body is not None:
                self._table_body(family, names[0], body)
        elif kind == "chain" and len(names) >= 2:
            chain = self.state.chain(family, names[0], names[1])
            if body is not None:
                self._chain_body(chain, body)
        elif kind in ("set", "map") and len(names) >= 2 and body is not None:
            self._set_body(self.state.set(family, names[0], names[1]), body, is_map=kind == "map")
        elif kind == "element" and len(names) >= 2 and body is not None:
            target = self.state.set(family, names[0], names[1])
            self._elements(target, body)
        elif kind == "rule" and len(rest) >= 2:
            family, rest = self._family(rest)
            if len(rest) < 2:
                self.state.skipped(f"line {line} rule")
                return
            table, chain_name, statement = rest[0].text, rest[1].text, rest[2:]
            if statement and statement[0].text in ("position", "index", "handle"):
                self.state.skipped(f"line {line} rule at a position")
                return
            chain = self.state.chain(family, table, chain_name)
            self.state.add_rule(chain, self._rule(statement, family, table), insert=insert)
            return
        else:
            self.state.skipped(f"line {line} {kind}")
            return
        if any(t.kind != "nl" for t in trailing):
            for stmt in _statements(trailing):
                self._top(stmt)

    def _flush(self, words: list[str], line: int) -> None:
        if words[:1] == ["ruleset"]:
            self.state.reset()
            return
        if words[:1] in (["table"], ["chain"]):
            family, rest = (words[1], words[2:]) if len(words) > 2 and words[1] in FAMILIES else ("ip", words[1:])
            for key, chain in self.state.chains.items():
                if key[:2] == (family, rest[0] if rest else "") and (words[0] == "table" or rest[1:2] == [key[2]]):
                    chain.rules.clear()
            return
        self.state.skipped(f"line {line} flush {' '.join(words[:1])}")

    def _delete(self, words: list[str], line: int) -> None:
        if words[:1] in (["table"], ["chain"]):
            family, rest = (words[1], words[2:]) if len(words) > 2 and words[1] in FAMILIES else ("ip", words[1:])
            for key in list(self.state.chains):
                if key[:2] == (family, rest[0] if rest else "") and (words[0] == "table" or rest[1:2] == [key[2]]):
                    del self.state.chains[key]
            if words[0] == "table":
                self.state.tables.pop((family, rest[0] if rest else ""), None)
            return
        self.state.skipped(f"line {line} delete {' '.join(words[:1])}")

    def _table_body(self, family: str, table: str, body: list[_Tok]) -> None:
        for stmt in _statements(body):
            stmt = self._substitute(stmt)
            head = stmt[0].text if stmt[0].kind == "word" else ""
            header, inner, _ = _block(stmt)
            names = [t.text for t in header[1:] if t.kind != "nl"]
            if head == "chain" and names:
                chain = self.state.chain(family, table, names[0])
                if inner is not None:
                    self._chain_body(chain, inner)
            elif head in ("set", "map") and names and inner is not None:
                self._set_body(self.state.set(family, table, names[0]), inner, is_map=head == "map")
            elif head == "flags":
                if "dormant" in _words(stmt):
                    self.state.table(family, table)["dormant"] = True
            elif head in ("comment", "flowtable", "counter", "quota", "limit", "ct", "secmark", "synproxy", "tunnel"):
                continue  # named objects: nothing that decides access
            else:
                self.state.skipped(f"line {stmt[0].line} {head or stmt[0].text!r}")

    def _chain_body(self, chain: _Chain, body: list[_Tok]) -> None:
        for stmt in _statements(body):
            stmt = self._substitute(stmt)
            head = stmt[0].text if stmt[0].kind == "word" else ""
            if head == "type":
                self._chain_type(chain, _words(stmt))
            elif head == "policy" and len(stmt) > 1:
                chain.policy = stmt[1].text.lower()
            elif head in ("comment", "devices", "device"):
                continue
            else:
                self.state.add_rule(chain, self._rule(stmt, chain.family, chain.table))

    @staticmethod
    def _chain_type(chain: _Chain, words: list[str]) -> None:
        chain.type = words[1] if len(words) > 1 else None
        if "hook" in words and words.index("hook") + 1 < len(words):
            chain.hook = words[words.index("hook") + 1]
        if "priority" in words:
            chain.priority = _priority(" ".join(words[words.index("priority") + 1 :]))

    def _set_body(self, target: _Set, body: list[_Tok], *, is_map: bool) -> None:
        target.is_map = is_map
        for stmt in _statements(body):
            stmt = self._substitute(stmt)
            head = stmt[0].text if stmt[0].kind == "word" else ""
            words = _words(stmt)
            if head in ("type", "typeof"):
                target.type = " ".join(words[1:])
                target.concat = target.concat or " . " in f" {target.type} "
            elif head == "flags":
                target.flags |= {w for w in words[1:] if w != ","}
            elif head == "timeout":
                target.flags.add("timeout")
            elif head == "elements":
                _, inner, _ = _block(stmt)
                if inner is not None:
                    self._elements(target, inner)

    def _elements(self, target: _Set, tokens: list[_Tok]) -> None:
        for element in _split(tokens):
            words = [t.text for t in element if t.kind != "nl"]
            if not words:
                continue
            if target.is_map or ":" in words:
                if ":" in words:
                    colon = words.index(":")
                    target.verdicts.append((" ".join(words[:colon]), _verdict_words(words[colon + 1 :])))
                continue
            if "." in words:
                target.concat = True
            target.elements.append(words[0])
            if len(target.elements) > _MAX_STORED_ELEMENTS:
                raise InvalidInputError(f"A set holds more than {_MAX_STORED_ELEMENTS:,} elements.")

    # -- rules -----------------------------------------------------------------------

    def _rule(self, tokens: list[_Tok], family: str, table: str) -> _Rule:
        rule = _Rule(line=tokens[0].line if tokens else None)
        toks = [t for t in tokens if t.kind != "nl"]
        n = len(toks)
        i = 0
        while i < n:
            tok = toks[i]
            word = tok.text.lower() if tok.kind == "word" else None
            if word is None:
                rule.reasons.append(f"unexpected {tok.text[:40]!r}")
                i += 1
            elif word in _VERDICTS:
                rule.verdict, i = _text_verdict(toks, i)
            elif word == "comment":
                rule.comment = toks[i + 1].text[:500] if i + 1 < n else ""
                i += 2
            elif word == "counter":
                i = _skip_counter(toks, i + 1)
            elif word == "log":
                i = _skip_log(toks, i + 1)
            elif word in _LIMITING:
                rule.reasons.append(_LIMITING[word])
                i = _skip_opaque(toks, i + 1)
            elif word in ("add", "update", "delete") and i + 1 < n and toks[i + 1].text.startswith("@"):
                rule.reasons.append("set update")
                i = _skip_opaque(toks, i + 2)
            elif word == "notrack":
                i += 1
            elif word in _NAT:
                rule.reasons.append(f"{word} statement")
                i = _skip_opaque(toks, i + 1)
            elif word == "fib":
                rule.reasons.append("match fib")
                i = _skip_opaque(toks, i + 1, stop_at_heads=False)
            else:
                i = self._match(rule, toks, i)
        return rule

    def _match(self, rule: _Rule, toks: list[_Tok], i: int) -> int:
        selector, i = _selector(toks, i)
        if selector is None:
            rule.reasons.append(f"match {toks[i].text[:40]}")
            return _skip_opaque(toks, i + 1)
        if i < len(toks) and _is(toks[i], "set"):  # an assignment such as "meta mark set 1": decides nothing
            return _skip_value(toks, i + 1)
        if i < len(toks) and _is(toks[i], "vmap"):
            i += 1
            if i < len(toks) and toks[i].text.startswith("@"):
                rule.vmap = (selector, toks[i].text)
                return i + 1
            elements, i = _brace_group(toks, i)
            entries: list[tuple[str, _Verdict]] = []
            for element in elements:
                words = [t.text for t in element]
                if ":" not in words:
                    rule.reasons.append("verdict map element not understood")
                    continue
                colon = words.index(":")
                entries.append((" ".join(words[:colon]), _verdict_words(words[colon + 1 :])))
            rule.vmap = (selector, entries)
            return i
        if selector not in _KNOWN:
            rule.reasons.append(f"match {selector}")
            return _skip_opaque(toks, i)
        op = "=="
        if i < len(toks) and toks[i].kind == "word" and toks[i].text in _OPERATORS:
            op = _OPERATORS[toks[i].text]
            i += 1
        values, i = _values(toks, i)
        rule.matches.append(_Match(selector, op, values))
        return i


def _priority(text: str) -> int:
    match = re.fullmatch(r"\s*([a-z]+)?\s*(?:([+-])?\s*(\d+))?\s*", text)
    if not match:
        return 0
    base = _PRIORITIES.get(match.group(1) or "", 0)
    offset = int(match.group(3) or 0) * (-1 if match.group(2) == "-" else 1)
    return base + offset if match.group(1) else offset


def _split(tokens: list[_Tok]) -> Iterator[list[_Tok]]:
    """Elements of a ``{ a, b, c }`` body: split at commas outside nested braces."""
    current: list[_Tok] = []
    depth = 0
    for tok in tokens:
        if _is(tok, "{"):
            depth += 1
        elif _is(tok, "}"):
            depth -= 1
        elif depth == 0 and _is(tok, ","):
            yield current
            current = []
            continue
        if tok.kind != "nl":
            current.append(tok)
    yield current


def _brace_group(toks: list[_Tok], i: int) -> tuple[list[list[_Tok]], int]:
    """The elements of the ``{ ... }`` at ``i`` and the index after its ``}``."""
    if i >= len(toks) or not _is(toks[i], "{"):
        return [], i
    depth = 0
    for end in range(i, len(toks)):
        if _is(toks[end], "{"):
            depth += 1
        elif _is(toks[end], "}"):
            depth -= 1
            if depth == 0:
                return [e for e in _split(toks[i + 1 : end]) if e], end + 1
    return [], len(toks)


def _values(toks: list[_Tok], i: int) -> tuple[list[str], int]:
    if i >= len(toks):
        return [], i
    if _is(toks[i], "{"):
        elements, i = _brace_group(toks, i)
        return [" ".join(t.text for t in element) for element in elements], i
    values = [toks[i].text]
    i += 1
    while i + 1 < len(toks) and _is(toks[i], ","):
        values.append(toks[i + 1].text)
        i += 2
    return values, i


def _selector(toks: list[_Tok], i: int) -> tuple[str | None, int]:
    word = toks[i].text.lower() if toks[i].kind == "word" else ""
    if word in _INTERFACES:
        return word, i + 1
    if word in _META_KEYS:
        return f"meta {word}", i + 1
    if word in _HEADS:
        nxt = toks[i + 1].text.lower() if i + 1 < len(toks) and toks[i + 1].kind == "word" else ""
        if not nxt or nxt in _OPERATORS or nxt in _VERDICTS:
            return word, i + 1
        if word == "meta" and nxt in _INTERFACES:
            return nxt, i + 2
        return f"{word} {nxt}", i + 2
    return None, i


def _skip_counter(toks: list[_Tok], i: int) -> int:
    if i < len(toks) and _is(toks[i], "packets"):
        return i + 4  # packets N bytes N
    if i < len(toks) and _is(toks[i], "name"):
        return i + 2
    return i


def _skip_log(toks: list[_Tok], i: int) -> int:
    while i < len(toks):
        if toks[i].text in _LOG_OPTIONS:
            i += 2
        elif _is(toks[i], "flags"):
            i += 1
            while i < len(toks) and toks[i].text in _LOG_FLAGS:
                i += 1
        else:
            break
    return i


def _skip_value(toks: list[_Tok], i: int) -> int:
    if i < len(toks) and _is(toks[i], "{"):
        return _brace_group(toks, i)[1]
    return i + 1


def _skip_opaque(toks: list[_Tok], i: int, *, stop_at_heads: bool = True) -> int:
    """Past a construct the model has no equivalent for: up to the verdict, a comment or the next match."""
    while i < len(toks):
        tok = toks[i]
        word = tok.text.lower() if tok.kind == "word" else ""
        if word in _VERDICTS or word == "comment":
            return i
        if stop_at_heads and (word in _HEADS or word in _INTERFACES or word in ("counter", "log")):
            return i
        i = _brace_group(toks, i)[1] if _is(tok, "{") else i + 1
    return i


def _text_verdict(toks: list[_Tok], i: int) -> tuple[_Verdict, int]:
    word = toks[i].text.lower()
    if word in ("jump", "goto"):
        return _Verdict(word, toks[i + 1].text if i + 1 < len(toks) else None), i + 2
    i += 1
    if word in ("reject", "queue"):  # their arguments (reject with tcp reset, queue num 1) decide nothing more
        while i < len(toks) and not _is(toks[i], "comment"):
            i += 1
    return _Verdict(word), i


def _verdict_words(words: list[str]) -> _Verdict:
    if not words:
        return _Verdict()
    kind = words[0].lower()
    if kind in ("jump", "goto"):
        return _Verdict(kind, words[1] if len(words) > 1 else None)
    return _Verdict(kind if kind in _VERDICTS else f"? {kind}")


# --------------------------------------------------------------------------- JSON


def _read_json(text: str) -> _State:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(f"nftables JSON is not valid: {exc.msg} (line {exc.lineno})") from exc
    except RecursionError as exc:
        raise InvalidInputError("nftables JSON nesting is too deep.") from exc
    items = data.get("nftables") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise InvalidInputError('nftables JSON must be an object with an "nftables" list.')
    state = _State()
    for item in items:
        if not isinstance(item, dict) or len(item) != 1:
            state.skipped("an entry that is not a one-key object")
            continue
        ((kind, value),) = item.items()
        if not isinstance(value, dict):
            if kind == "metainfo":
                continue
            state.skipped(f"{kind} entry")
            continue
        family, table = str(value.get("family", "ip")), str(value.get("table", ""))
        if kind == "metainfo":
            continue
        if kind == "table":
            entry = state.table(family, str(value.get("name", "")))
            entry["dormant"] = "dormant" in _flags(value.get("flags"))
        elif kind == "chain":
            chain = state.chain(family, table, str(value.get("name", "")))
            chain.type = value.get("type")
            chain.hook = value.get("hook")
            prio = value.get("prio", 0)
            chain.priority = prio if isinstance(prio, int) else _priority(str(prio))
            chain.policy = str(value.get("policy", "accept")).lower()
        elif kind == "rule":
            chain = state.chain(family, table, str(value.get("chain", "")))
            rule = _json_rule(value.get("expr"))
            rule.handle = value.get("handle") if isinstance(value.get("handle"), int) else None
            rule.comment = str(value.get("comment", ""))[:500]
            state.add_rule(chain, rule)
        elif kind in ("set", "map"):
            target = state.set(family, table, str(value.get("name", "")))
            target.is_map = kind == "map"
            target.type = value["type"] if isinstance(value.get("type"), str) else "concat"
            target.concat = not isinstance(value.get("type"), str)
            target.flags |= _flags(value.get("flags"))
            _json_elements(target, value.get("elem"))
        elif kind == "element":
            _json_elements(state.set(family, table, str(value.get("name", ""))), value.get("elem"))
        elif kind in ("flowtable", "counter", "quota", "ct helper", "ct timeout", "ct expectation", "limit"):
            continue
        else:
            state.skipped(f"{kind} entry")
    if state.unparsed:
        state.warnings.append(f"{len(state.unparsed)} JSON entries not understood and skipped ({state.unparsed[0]})")
    return state


def _flags(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(v) for v in value}
    return set()


def _json_elements(target: _Set, elements: Any) -> None:
    if not isinstance(elements, list):
        return
    for element in elements:
        if target.is_map and isinstance(element, list) and len(element) == 2:
            keys = _json_values(element[0])
            verdict = _json_verdict(element[1])
            if keys and verdict is not None:
                target.verdicts.append((keys[0], verdict))
            continue
        values = _json_values(element)
        if values is None:
            target.concat = True
            continue
        target.elements += values
        if len(target.elements) > _MAX_STORED_ELEMENTS:
            raise InvalidInputError(f"A set holds more than {_MAX_STORED_ELEMENTS:,} elements.")


def _json_values(value: Any) -> list[str] | None:
    """The values of a JSON right-hand side (None: a form the model has no equivalent for)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (str, int)):
        return [str(value)]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            items = _json_values(item)
            if items is None:
                return None
            out += items
        return out
    if isinstance(value, dict) and len(value) == 1:
        ((kind, inner),) = value.items()
        if kind == "prefix" and isinstance(inner, dict):
            return [f"{inner.get('addr')}/{inner.get('len')}"]
        if kind == "range" and isinstance(inner, list) and len(inner) == 2:
            return [f"{inner[0]}-{inner[1]}"]
        if kind == "set":
            return _json_values(inner if isinstance(inner, list) else [inner])
        if kind == "elem" and isinstance(inner, dict):
            return _json_values(inner.get("val"))
    return None


def _json_selector(left: Any) -> tuple[str | None, str]:
    """The selector of a JSON left-hand side, or None with what it is for the reason."""
    if not isinstance(left, dict) or len(left) != 1:
        return None, "expression"
    ((kind, inner),) = left.items()
    if not isinstance(inner, dict):
        return None, str(kind)
    if kind == "payload" and "protocol" in inner and "field" in inner:
        return f"{inner['protocol']} {inner['field']}", ""
    if kind == "meta" and "key" in inner:
        key = str(inner["key"])
        return (key if key in _INTERFACES else f"meta {key}"), ""
    if kind == "ct" and "key" in inner and "dir" not in inner:
        return f"ct {inner['key']}", ""
    return None, str(kind)


def _json_verdict(value: Any) -> _Verdict | None:
    if not isinstance(value, dict) or len(value) != 1:
        return None
    ((kind, inner),) = value.items()
    if kind in ("jump", "goto"):
        return _Verdict(kind, str(inner.get("target")) if isinstance(inner, dict) else None)
    if kind in _VERDICTS:
        return _Verdict(kind)
    return None


def _json_rule(expressions: Any) -> _Rule:
    rule = _Rule()
    if not isinstance(expressions, list):
        rule.reasons.append("rule without expressions")
        return rule
    for statement in expressions:
        if not isinstance(statement, dict) or len(statement) != 1:
            rule.reasons.append("statement not understood")
            continue
        ((kind, value),) = statement.items()
        verdict = _json_verdict(statement)
        if verdict is not None:
            rule.verdict = verdict
        elif kind == "match" and isinstance(value, dict):
            selector, what = _json_selector(value.get("left"))
            op = {"in": "=="}.get(str(value.get("op", "==")), str(value.get("op", "==")))
            values = _json_values(value.get("right"))
            if selector is None or selector not in _KNOWN:
                rule.reasons.append(f"match {selector or what}")
            elif values is None or op not in _OPERATORS.values():
                rule.reasons.append(f"match {selector} {op} (value not understood)")
            else:
                rule.matches.append(_Match(selector, op, values))
        elif kind == "vmap" and isinstance(value, dict):
            selector, what = _json_selector(value.get("key"))
            data = value.get("data")
            if selector is None:
                rule.reasons.append(f"verdict map on {what}")
            elif isinstance(data, str) and data.startswith("@"):
                rule.vmap = (selector, data)
            else:
                entries: list[tuple[str, _Verdict]] = []
                pairs = data.get("set") if isinstance(data, dict) else None
                for pair in pairs if isinstance(pairs, list) else []:
                    keys = _json_values(pair[0]) if isinstance(pair, list) and len(pair) == 2 else None
                    target = _json_verdict(pair[1]) if keys else None
                    if keys and target is not None:
                        entries += [(key, target) for key in keys]
                    else:
                        rule.reasons.append("verdict map element not understood")
                rule.vmap = (selector, entries)
        elif kind in ("counter", "log", "mangle", "notrack", "ct helper", "ct timeout", "ct expectation"):
            continue  # statements that decide nothing
        elif kind in _LIMITING:
            rule.reasons.append(_LIMITING[kind])
        elif kind == "set":
            rule.reasons.append("set update")
        elif kind in _NAT:
            rule.reasons.append(f"{kind} statement")
        elif kind == "xt":
            rule.reasons.append("xtables extension")
        else:
            rule.reasons.append(f"statement {kind}")
    return rule


# --------------------------------------------------------------------------- policies


def _ruleset(state: _State) -> tuple[FilterRuleset, list[str]]:
    warnings: list[str] = []
    modeled: list[_Chain] = []
    ignored_types: set[str] = set()
    for (family, table), entry in state.tables.items():
        if family not in _IP_FAMILIES:
            warnings.append(
                f"table {family} {table} ignored: only ip, ip6 and inet tables filter IP traffic between hosts"
            )
        elif entry.get("dormant"):
            warnings.append(f"table {family} {table} ignored: it is dormant")
    for chain in state.chains.values():
        if chain.family not in _IP_FAMILIES or state.tables.get((chain.family, chain.table), {}).get("dormant"):
            continue
        if chain.hook is None:
            modeled.append(chain)  # a regular chain: runs only when jumped to
        elif chain.type != "filter":
            ignored_types.add(chain.type or "?")
        elif chain.hook not in HOOKS:
            if chain.rules or chain.policy != "accept":
                warnings.append(
                    f"filter chain {chain.family} {chain.table} {chain.name} on hook {chain.hook} is not modeled: "
                    f"its {len(chain.rules)} rule(s) and {chain.policy} policy are ignored"
                )
        else:
            modeled.append(chain)
    if ignored_types:
        warnings.append(f"chains of type {', '.join(sorted(ignored_types))} ignored: they do not filter")
    names, labels = _chain_names(modeled)
    keys = {(c.family, c.table, c.name): _key(c) for c in modeled}
    rules: dict[str, list[FilterRule]] = {}
    for chain in modeled:
        key = _key(chain)
        rules[key] = [
            converted
            for position, rule in enumerate(chain.rules, 1)
            for converted in _convert(state, chain, rule, position, keys)
        ]
    base = [
        BaseChain(
            key=_key(chain),
            hook=chain.hook,
            policy=chain.policy,
            title=labels[_key(chain)],
            family=chain.family,
            table=chain.table,
            priority=chain.priority,
        )
        for chain in sorted(modeled, key=lambda c: (c.priority, c.order))
        if chain.hook is not None
    ]
    ruleset = FilterRuleset(
        tool="nftables",
        base=base,
        rules=rules,
        names=names,
        labels=labels,
        regular=[_key(c) for c in modeled if c.hook is None],
        tables={_key(c): f"{c.family} {c.table}" for c in modeled},
    )
    return ruleset, warnings


def _key(chain: _Chain) -> str:
    return f"{chain.family} {chain.table} {chain.name}"


def _chain_names(chains: list[_Chain]) -> tuple[dict[str, str], dict[str, str]]:
    """Chain names in rule IDs and messages: the chain's name, qualified only where it is ambiguous."""
    count_name: dict[str, int] = {}
    count_table: dict[tuple[str, str], int] = {}
    for chain in chains:
        count_name[chain.name] = count_name.get(chain.name, 0) + 1
        count_table[(chain.table, chain.name)] = count_table.get((chain.table, chain.name), 0) + 1
    names, labels = {}, {}
    for chain in chains:
        if count_name[chain.name] == 1:
            parts = [chain.name]
        elif count_table[(chain.table, chain.name)] == 1:
            parts = [chain.table, chain.name]
        else:
            parts = [chain.family, chain.table, chain.name]
        names[_key(chain)] = slugify("-".join(parts))
        labels[_key(chain)] = " ".join(parts)
    return names, labels


def _convert(
    state: _State, chain: _Chain, rule: _Rule, position: int, keys: dict[tuple[str, str, str], str]
) -> list[FilterRule]:
    """The rule as :class:`FilterRule` s: one, or one per element of its verdict map."""
    if rule.vmap is None:
        return [_filter_rule(state, chain, rule, position, rule.matches, rule.verdict, "", keys)]
    selector, entries = rule.vmap
    if isinstance(entries, str):  # a named map
        named = state.sets.get((chain.family, chain.table, entries[1:]))
        if named is None or not named.verdicts or named.concat:
            broken = _Rule(rule.line, rule.handle, rule.matches, [*rule.reasons, f"verdict map {entries}"])
            broken.verdict, broken.comment = _Verdict("drop"), rule.comment
            return [_filter_rule(state, chain, broken, position, rule.matches, broken.verdict, "", keys)]
        entries = named.verdicts
    out = []
    for n, (key, verdict) in enumerate(entries, 1):
        matches = [*rule.matches, _Match(selector, "==", [key])]
        out.append(_filter_rule(state, chain, rule, position, matches, verdict, f"v{n}", keys))
    return out


def _filter_rule(
    state: _State,
    chain: _Chain,
    rule: _Rule,
    position: int,
    matches: list[_Match],
    verdict: _Verdict,
    part: str,
    keys: dict[tuple[str, str, str], str],
) -> FilterRule:
    conditions = _Conditions(chain.family)
    for match in matches:
        values = _resolve(state, chain, match)
        if isinstance(values, str):
            conditions.reasons.append(values)
        else:
            conditions.apply(match.selector, match.op, values)
    out = FilterRule(
        chain=_key(chain),
        position=position,
        line=rule.line,
        handle=rule.handle,
        part=part,
        comment=rule.comment,
        verdict=verdict.text(),
    )
    out.sources, out.destinations = conditions.sources, conditions.destinations
    out.family = conditions.family()
    out.unmodeled = list(dict.fromkeys([*conditions.reasons, *rule.reasons]))
    ports = conditions.ports.labels()
    out.ports = ports or [ANY]
    out.skip = conditions.skip or (None if ports else "matches no packet (protocols and ports)")
    kind = verdict.kind
    if kind in ("accept", "drop", "reject"):
        out.target = kind.upper()
    elif kind == "return":
        out.target = RETURN
    elif kind in ("jump", "goto") and verdict.target:
        out.target = keys.get((chain.family, chain.table, verdict.target), f"undefined chain {verdict.target}")
        out.goto = kind == "goto"
    elif kind == "queue":
        out.target = "queue"
    elif kind and kind != "continue":
        out.target = kind
    return out


def _resolve(state: _State, chain: _Chain, match: _Match) -> list[str] | str:
    """The match's values with named sets resolved, or why they cannot be (a reason)."""
    out: list[str] = []
    for value in match.values:
        if not value.startswith("@"):
            out.append(value)
            continue
        named = state.sets.get((chain.family, chain.table, value[1:]))
        if named is None:
            return f"unknown set {value}"
        if named.concat:
            return f"concatenated set {value}"
        if named.flags & {"dynamic", "timeout"}:
            return f"dynamic set {value} (filled at run time)"
        out += named.elements
    if len(out) > MAX_SET_ELEMENTS:
        return f"{match.selector} set of {len(out)} elements (more than {MAX_SET_ELEMENTS})"
    return out


class _Conditions:
    """What a rule's matches allow, in R$F terms."""

    def __init__(self, table_family: str) -> None:
        self.table_family = table_family
        self.sources: list[str] = [ANY]
        self.destinations: list[str] = [ANY]
        self.ports = PortSet.everything()
        self.families = {"ip", "ip6"} if table_family == "inet" else {table_family}
        self.reasons: list[str] = []
        self.skip: str | None = None

    def family(self) -> str | None:
        if self.table_family != "inet" or len(self.families) != 1:
            return None
        return next(iter(self.families))

    def _restrict(self, families: set[str]) -> None:
        self.families &= families
        if not self.families:
            self.skip = "matches no packet (IPv4 and IPv6 at once)"

    def apply(self, selector: str, op: str, values: list[str]) -> None:
        head, _, field_name = selector.partition(" ")
        if selector in ("ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr"):
            self._address("source" if field_name == "saddr" else "destination", 4 if head == "ip" else 6, op, values)
        elif selector in ("tcp dport", "udp dport", "th dport"):
            self._ports(("tcp", "udp") if head == "th" else (head,), op, values)
        elif selector in ("tcp sport", "udp sport", "th sport", "udplite sport"):
            self.reasons.append("source port")
        elif selector == "udplite dport":
            self.reasons.append("protocol udplite")
        elif selector in ("meta l4proto", "ip protocol", "ip6 nexthdr"):
            if head in ("ip", "ip6"):
                self._restrict({head})
            self._protocols(op, values)
        elif selector in ("icmp type", "icmpv6 type"):
            self._icmp(head == "icmpv6", op, values)
        elif selector == "ct state":
            self._ct_state(op, values)
        elif selector in _INTERFACES:
            self._interface(selector, op, values)
        elif selector in ("meta nfproto", "meta protocol"):
            self._nfproto(op, values)
        else:
            self.reasons.append(f"match {selector}")

    def _address(self, side: str, version: int, op: str, values: list[str]) -> None:
        self._restrict({"ip" if version == 4 else "ip6"})
        if op != "==":
            self.reasons.append(f"negated {side}" if op == "!=" else f"{side} address {op}")
            return
        selectors: list[str] = []
        for value in values:
            networks = _networks(value, version)
            if networks is None:
                self.reasons.append(f"{side} address {value[:60]} not understood")
                return
            selectors += networks
        selectors = sorted(set(selectors)) or [ANY]
        current = self.sources if side == "source" else self.destinations
        merged = selectors if current == [ANY] else intersect_addresses(current, selectors)
        if not merged:
            self.skip = "matches no packet (addresses)"
            return
        if side == "source":
            self.sources = merged
        else:
            self.destinations = merged

    def _ports(self, protocols: tuple[str, ...], op: str, values: list[str]) -> None:
        spans: list[tuple[int, int]] = []
        for value in values:
            span = _port_span(value)
            if span is None:
                self.reasons.append(f"port {value[:40]}")
                return
            spans.append(span)
        whole = PortSet.parse(list(protocols))
        if op in ("<", ">", "<=", ">="):
            if len(spans) != 1:
                self.reasons.append(f"port {op} {', '.join(values)}")
                return
            low, high = spans[0][0], spans[0][1]
            spans = [{"<": (0, low - 1), "<=": (0, high), ">": (high + 1, 65535), ">=": (low, 65535)}[op]]
            spans = [(lo, hi) for lo, hi in spans if lo <= hi]
            op = "=="
        chosen = PortSet.parse([f"{p}/{lo}-{hi}" for p in protocols for lo, hi in spans]) if spans else PortSet.empty()
        self.ports = self.ports.intersect(chosen if op == "==" else whole.subtract(chosen))

    def _protocols(self, op: str, values: list[str]) -> None:
        names = [_PROTOCOLS.get(v.lower()) for v in values]
        modeled = {n for n in names if n}
        if op not in ("==", "!="):
            self.reasons.append(f"protocol {op} {', '.join(values)}")
            return
        if op == "==" and not modeled:
            self.reasons.append(f"protocol {', '.join(values)}")
            return
        chosen = PortSet.parse(sorted({"icmp" if n == "icmpv6" else n for n in modeled}))
        if op == "==":
            self.ports = self.ports.intersect(chosen)
            if modeled == {"icmpv6"}:
                self._restrict({"ip6"})
            elif modeled == {"icmp"}:
                self._restrict({"ip"})
        else:
            self.ports = self.ports.subtract(chosen)

    def _icmp(self, v6: bool, op: str, values: list[str]) -> None:
        self._restrict({"ip6" if v6 else "ip"})
        names = _ICMPV6_TYPES if v6 else _ICMP_TYPES
        types: list[int] = []
        for value in values:
            number = int(value) if value.isdigit() else names.get(value.lower(), -1)
            if not 0 <= number <= 255:
                self.reasons.append(f"icmp type {value[:40]}")
                return
            types.append(number)
        chosen = PortSet.parse([f"icmp/{t}" for t in types])
        if op == "==":
            self.ports = self.ports.intersect(chosen)
        elif op == "!=":
            self.ports = self.ports.intersect(PortSet.parse(["icmp"]).subtract(chosen))
        else:
            self.reasons.append(f"icmp type {op} {', '.join(values)}")

    def _ct_state(self, op: str, values: list[str]) -> None:
        states = {v.strip().lower() for v in values if v.strip()}
        if op != "==":
            self.reasons.append("negated connection state")
        elif "new" in states:
            pass  # new flows match: the other states only add their return traffic
        elif states <= {"established", "related"}:
            self.skip = "return traffic"
        elif states <= {"established", "related", "invalid"}:
            self.skip = f"state {','.join(sorted(states))}"
        else:  # untracked: new flows of one kind only
            self.reasons.append(f"connection state {','.join(sorted(states))}")

    def _interface(self, selector: str, op: str, values: list[str]) -> None:
        if values == ["lo"] and op == "==":
            self.skip = "loopback traffic"
        elif values == ["lo"] and op == "!=":
            pass  # everything but loopback: no constraint between hosts
        else:
            self.reasons.append(f"interface {'not ' if op == '!=' else ''}{', '.join(values)[:60]}")

    def _nfproto(self, op: str, values: list[str]) -> None:
        mapping = {"ipv4": "ip", "ip": "ip", "ipv6": "ip6", "ip6": "ip6"}
        families = {mapping[v.lower()] for v in values if v.lower() in mapping}
        if len(families) != len(values) or op not in ("==", "!="):
            self.reasons.append(f"protocol family {op} {', '.join(values)}")
            return
        self._restrict(families if op == "==" else {"ip", "ip6"} - families)


def _networks(value: str, version: int) -> list[str] | None:
    try:
        if "-" in value and "/" not in value:
            low, _, high = value.partition("-")
            first, last = ipaddress.ip_address(low.strip()), ipaddress.ip_address(high.strip())
            if first.version != version or last.version != version:
                return None
            return [normalize_address(str(n)) for n in ipaddress.summarize_address_range(first, last)]
        network = ipaddress.ip_network(value.strip(), strict=False)
    except (ValueError, TypeError):
        return None
    if network.version != version:
        return None
    return [normalize_address(str(network))]


def _port_span(value: str) -> tuple[int, int] | None:
    text = value.strip().lower()
    low, dash, high = text.partition("-")
    if dash and low.isdigit() and high.isdigit():
        span = (int(low), int(high))
    elif text.isdigit():
        span = (int(text), int(text))
    elif text in _SERVICES:
        span = (_SERVICES[text], _SERVICES[text])
    else:
        return None
    return span if span[0] <= span[1] <= 65535 else None


__all__ = [
    "MAX_SET_ELEMENTS",
    "NFT_SUFFIXES",
    "looks_like_nftables",
    "looks_like_nftables_json",
    "parse_nftables",
]
