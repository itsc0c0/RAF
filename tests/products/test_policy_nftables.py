"""Policy: nftables rulesets (nft list ruleset, nftables scripts, nft -j JSON) -> network policies."""

from __future__ import annotations

import json
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError
from raf.core.ports import PortSet
from raf.products.policy.engine import PolicyWorld, evaluate_network
from raf.products.policy.formats import load_policy_file, parse_policy_text, sniff_policy
from raf.products.policy.model import Policy, PolicyRule, PolicySet
from tests.conftest import FIXTURES

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

POLICIES = FIXTURES / "policies"


def _parse(text: str, name: str = "fw.nft") -> PolicySet:
    return parse_policy_text(text, source=name, suffix=Path(name).suffix)


def _policy(policy_set: PolicySet, policy_id: str) -> Policy:
    found = next((p for p in policy_set.policies if p.id == policy_id), None)
    assert found is not None, [p.id for p in policy_set.policies]
    return found


def _rules(policy: Policy) -> dict[str, PolicyRule]:
    return {r.id: r for r in policy.rules}


def _table(*rules: str, hook: str = "forward", policy: str = "drop", extra: str = "") -> str:
    body = "\n".join(f"\t\t{rule}" for rule in rules)
    header = f"type filter hook {hook} priority filter; policy {policy};"
    return f"table inet filter {{\n{extra}\tchain {hook} {{\n\t\t{header}\n{body}\n\t}}\n}}\n"


def _shape(policy_set: PolicySet) -> list[tuple[Any, ...]]:
    out: list[tuple[Any, ...]] = []
    for policy in policy_set.policies:
        out.append((policy.id, policy.default, tuple(policy.scope)))
        for r in policy.rules:
            closing = "chain_policy" in r.metadata  # "INPUT chain policy DROP" / "input chain policy drop"
            addresses = (tuple(r.sources), tuple(r.destinations))
            out.append((r.id, r.effect, *addresses, tuple(r.ports), r.enabled, "" if closing else r.description))
    return out


def test_the_router_reads_the_same_in_iptables_nftables_and_nft_json() -> None:
    names = ("raven-edge.rules", "raven-edge.nft", "raven-edge.nft.json")
    sets = [load_policy_file(POLICIES / name) for name in names]
    assert [s.format for s in sets] == ["iptables-save", "nftables", "nftables-json"]
    assert {s.name for s in sets} == {"raven-edge"}  # "raven-edge.nft.json" names the host too
    assert _shape(sets[1]) == _shape(sets[0]) and _shape(sets[2]) == _shape(sets[0])
    assert sets[1].warnings == sets[2].warnings == ["chains of type nat ignored: they do not filter"]
    deploy = _rules(_policy(sets[1], "raven-edge-forward"))["forward-6.raven-deploy-1"]
    assert deploy.metadata["via"] == "forward line 23" and deploy.metadata["table"] == "inet filter"
    from_json = _rules(_policy(sets[2], "raven-edge-forward"))["forward-6.raven-deploy-1"]
    assert from_json.metadata["via"] == "forward rule 6"


def test_the_analysis_is_the_same_for_every_format(raven: RafContext) -> None:
    from raf.products.policy.service import PolicyService

    findings = {}
    for name in ("raven-edge.rules", "raven-edge.nft", "raven-edge.nft.json"):
        _, analysis = PolicyService(raven).check(POLICIES / name, host="VPN-01")
        findings[name] = sorted((f.rule_id, f.severity.value, *f.metadata["rules"]) for f in analysis.findings)
    assert findings["raven-edge.nft"] == findings["raven-edge.rules"] == findings["raven-edge.nft.json"]
    assert ("shadowed-rule", "HIGH", "forward-12", "forward-6.raven-deploy-1") in findings["raven-edge.nft"]


def test_scripts_with_variables_sets_and_verdict_maps() -> None:
    text = """#!/usr/sbin/nft -f
flush ruleset

define LAN = { 10.10.0.0/16, 10.20.0.0/16 }
define WEB = 10.40.0.5

table inet filter {
\tset admins {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = { 10.10.5.0/24,
\t\t\t     10.10.6.1-10.10.6.2 }
\t}

\tmap by_port {
\t\ttype inet_service : verdict
\t\telements = { 25 : drop, 587 : accept }
\t}

\tchain forward {
\t\ttype filter hook forward priority 0; policy drop;
\t\tct state { established, related } accept
\t\tip saddr $LAN ip daddr $WEB tcp dport { http, https } accept comment "staff to the web server"
\t\tip saddr @admins ip daddr 10.30.0.0/16 tcp dport ssh accept
\t\tip saddr $LAN ip daddr 10.30.0.0/16 tcp dport vmap { 5432 : drop, 8443 : accept }
\t\tip daddr 10.60.0.0/16 tcp dport vmap @by_port
\t\tip daddr 10.70.0.0/16 meta l4proto { tcp, udp } th dport 53 accept
\t\tip daddr 10.80.0.0/16 tcp dport < 1024 accept
\t\tip daddr 10.81.0.0/16 tcp dport != 22 drop
\t\tip daddr 10.82.0.0/16 tcp dport 1000-2000 accept
\t\tip daddr 10.83.0.0/16 icmp type { echo-request, destination-unreachable } accept
\t\tip6 daddr 2001:db8::/32 icmpv6 type echo-request accept
\t\tmeta nfproto ipv6 tcp dport 443 accept
\t}
}
"""
    assert sniff_policy(text.encode(), ".conf") >= 0.95
    policy_set = _parse(text, "nftables.conf")
    assert (policy_set.name, policy_set.format, policy_set.warnings) == ("nftables", "nftables", [])
    rules = _rules(_policy(policy_set, "nftables-forward"))
    shape = {rid: (r.effect, r.sources, r.destinations, r.ports) for rid, r in rules.items()}
    lan = ["cidr:10.10.0.0/16", "cidr:10.20.0.0/16"]
    admins = ["cidr:10.10.5.0/24", "cidr:10.10.6.1/32", "cidr:10.10.6.2/32"]
    assert shape == {
        "forward-2": ("allow", lan, ["cidr:10.40.0.5/32"], ["tcp/80", "tcp/443"]),
        "forward-3": ("allow", admins, ["cidr:10.30.0.0/16"], ["tcp/22"]),
        "forward-4-v1": ("deny", lan, ["cidr:10.30.0.0/16"], ["tcp/5432"]),
        "forward-4-v2": ("allow", lan, ["cidr:10.30.0.0/16"], ["tcp/8443"]),
        "forward-5-v1": ("deny", ["any"], ["cidr:10.60.0.0/16"], ["tcp/25"]),
        "forward-5-v2": ("allow", ["any"], ["cidr:10.60.0.0/16"], ["tcp/587"]),
        "forward-6": ("allow", ["any"], ["cidr:10.70.0.0/16"], ["tcp/53", "udp/53"]),
        "forward-7": ("allow", ["any"], ["cidr:10.80.0.0/16"], ["tcp/0-1023"]),
        "forward-8": ("deny", ["any"], ["cidr:10.81.0.0/16"], ["tcp/0-21", "tcp/23-65535"]),
        "forward-9": ("allow", ["any"], ["cidr:10.82.0.0/16"], ["tcp/1000-2000"]),
        "forward-10": ("allow", ["any"], ["cidr:10.83.0.0/16"], ["icmp/3", "icmp/8"]),
        "forward-11": ("allow", ["cidr:::/0"], ["cidr:2001:db8::/32"], ["icmp/128"]),
        "forward-12": ("allow", ["cidr:::/0"], ["cidr:::/0"], ["tcp/443"]),  # IPv6 only
    }
    assert rules["forward-2"].description == "staff to the web server"
    assert all(r.enabled for r in rules.values())


def test_what_the_model_cannot_express_is_imported_disabled() -> None:
    policy_set = _parse(
        _table(
            "ip saddr != 10.0.0.0/8 ip daddr 10.1.0.0/16 accept",
            'iifname "eth0" oifname "eth1" ip daddr 10.1.0.0/16 accept',
            "ip daddr 10.1.0.0/16 tcp sport 1024-65535 tcp dport 22 accept",
            "ip daddr 10.1.0.0/16 limit rate 10/second accept",
            "ip daddr 10.1.0.0/16 ip saddr @banned drop",
            "ip daddr 10.1.0.0/16 ip saddr @pairs accept",
            "ip daddr 10.1.0.0/16 ip saddr @nothere accept",
            "ip daddr 10.1.0.0/16 fib saddr . iif oif missing drop",
            "ip daddr 10.1.0.0/16 tcp flags & (fin|syn|rst|ack) == syn accept",
            "ip daddr 10.1.0.0/16 meta mark 0x1 accept",
            "ip daddr 10.1.0.0/16 ct state untracked accept",
            "ip daddr 10.1.0.0/16 queue num 1",
            "ip daddr 10.1.0.0/16 jump nowhere",
            "ip daddr 10.1.0.0/16 meta l4proto gre accept",
            "ip daddr 10.1.0.0/16 icmp code 3 accept",
            "ip daddr 10.1.0.0/16 add @seen { ip saddr } accept",
            extra="\tset banned {\n\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t}\n"
            "\tset pairs {\n\t\ttype ipv4_addr . inet_service\n\t\telements = { 10.9.0.1 . 22 }\n\t}\n",
        )
    )
    rules = _policy(policy_set, "fw-forward").rules
    assert {r.id: r.metadata.get("unmodeled") for r in rules} == {
        "forward-1": ["negated source"],
        "forward-2": ["interface eth0", "interface eth1"],
        "forward-3": ["source port"],
        "forward-4": ["rate limit"],
        "forward-5": ["dynamic set @banned (filled at run time)"],
        "forward-6": ["concatenated set @pairs"],
        "forward-7": ["unknown set @nothere"],
        "forward-8": ["match fib"],
        "forward-9": ["match tcp flags"],
        "forward-10": ["match meta mark"],
        "forward-11": ["connection state untracked"],
        "forward-12": ["target queue"],
        "forward-13": ["target undefined chain nowhere"],
        "forward-14": ["protocol gre"],
        "forward-15": ["match icmp code"],
        "forward-16": ["set update"],
    }
    assert not any(r.enabled for r in rules)
    assert any("16 rule(s) use conditions the policy model cannot express" in w for w in policy_set.warnings)


def test_rules_for_return_traffic_loopback_and_logging_decide_nothing() -> None:
    policy_set = _parse(
        _table(
            "ct state vmap { established : accept, related : accept, invalid : drop }",
            "ct state established,related counter accept",
            'iif "lo" accept',
            'iifname != "lo" ip saddr 10.0.0.0/8 ip daddr 10.1.0.0/16 accept',
            'log prefix "fw: " level info flags all counter',
            "ip saddr 10.0.0.0/8 ip daddr 10.2.0.0/16 continue",
            "ip saddr 10.0.0.0/8 ip daddr 10.3.0.0/16 ct state new,established accept",
            "ip saddr 10.0.0.0/8 ip saddr 192.168.0.0/16 accept",
            "meta l4proto udp tcp dport 22 accept",
        )
    )
    rules = _policy(policy_set, "fw-forward").rules
    # the last two can never match: two disjoint source networks, udp and a tcp port
    assert [(r.id, r.destinations) for r in rules] == [
        ("forward-4", ["cidr:10.1.0.0/16"]),
        ("forward-7", ["cidr:10.3.0.0/16"]),
    ]


def test_jump_goto_and_return() -> None:
    policy_set = _parse(
        "table inet filter {\n"
        "\tchain forward {\n"
        "\t\ttype filter hook forward priority filter; policy drop;\n"
        "\t\tip saddr 10.0.0.0/8 jump corp\n"
        "\t\tip saddr 10.2.0.0/16 goto web\n"
        "\t\tip daddr 10.9.0.0/16 return\n"
        "\t\tip saddr 10.0.0.0/8 ip daddr 10.8.0.0/16 accept\n"
        "\t}\n"
        "\tchain corp {\n"
        "\t\tip saddr 10.1.0.0/16 ip daddr 10.5.0.0/16 tcp dport 22 accept\n"
        "\t\tip daddr 10.6.0.0/16 return\n"
        "\t\tip daddr 10.7.0.0/16 drop\n"
        "\t}\n"
        "\tchain web {\n"
        "\t\tip daddr 10.9.0.0/16 tcp dport 443 accept\n"
        "\t}\n"
        "\tchain unused {\n"
        "\t\taccept\n"
        "\t}\n"
        "}\n"
    )
    rules = _rules(_policy(policy_set, "fw-forward"))
    assert [(r.id, r.effect, r.enabled) for r in rules.values()] == [
        ("forward-1.corp-1", "allow", True),
        ("forward-1.corp-3", "deny", False),  # after a conditional return in corp
        ("forward-2.web-1", "allow", True),
        ("forward-2.end", "deny", True),  # what web leaves undecided gets forward's policy
        ("forward-3", "deny", True),  # return in a base chain: its policy decides
        ("forward-4", "allow", True),
    ]
    assert rules["forward-1.corp-3"].metadata["unmodeled"] == ["follows a conditional RETURN in corp (line 11)"]
    assert rules["forward-2.end"].description == "end of web, reached by goto: forward policy drop"
    unused = "chain(s) unused is never jumped to from an input, forward or output chain: not imported"
    assert unused in policy_set.warnings


def test_several_tables_hooks_and_families() -> None:
    text = """table ip filter {
\tchain FORWARD {
\t\ttype filter hook forward priority filter; policy drop;
\t\tip saddr 10.0.0.0/8 ip daddr 10.1.0.0/16 accept
\t}
\tchain INPUT {
\t\ttype filter hook input priority filter; policy drop;
\t\ttcp dport 22 accept
\t}
}
table ip6 filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy drop;
\t\ttcp dport 443 accept
\t}
}
table inet firewalld {
\tchain filter_FORWARD {
\t\ttype filter hook forward priority filter + 10; policy accept;
\t\tip daddr 10.1.2.0/24 drop
\t}
\tchain raw_PREROUTING {
\t\ttype filter hook prerouting priority raw; policy accept;
\t\tip saddr 192.0.2.0/24 drop
\t}
}
table bridge br {
\tchain forward {
\t\ttype filter hook forward priority 0; policy drop;
\t}
}
table inet old {
\tflags dormant
\tchain input {
\t\ttype filter hook input priority 0; policy drop;
\t}
}
"""
    policy_set = _parse(text, "edge.nft")
    assert [p.id for p in policy_set.policies] == [
        "edge-forward-forward",  # priority filter (0) runs first
        "edge-forward-filter_forward",  # then filter + 10; chain names keep their underscores
        "edge-host-ip-filter",
        "edge-host-ip6-filter",
    ]
    assert policy_set.warnings[:3] == [
        "table bridge br ignored: only ip, ip6 and inet tables filter IP traffic between hosts",
        "table inet old ignored: it is dormant",
        "filter chain inet firewalld raw_PREROUTING on hook prerouting is not modeled: its 1 rule(s) and accept "
        "policy are ignored",
    ]
    v4, v6 = _policy(policy_set, "edge-host-ip-filter"), _policy(policy_set, "edge-host-ip6-filter")
    assert [(r.id, r.sources, r.destinations, r.ports) for r in v4.rules] == [
        ("ip-filter-input-1", ["any"], ["host:edge"], ["tcp/22"]),
        ("input-policy", ["any"], ["host:edge"], ["any"]),
        ("output-unfiltered", ["host:edge"], ["any"], ["any"]),  # no output chain anywhere
    ]
    assert [(r.id, r.sources, r.destinations) for r in v6.rules] == [
        ("ip6-filter-input-1", ["cidr:::/0"], ["host:edge"]),
        ("input-policy", ["cidr:::/0"], ["host:edge"]),
        ("output-unfiltered", ["host:edge"], ["any"]),
        ("ipv4-pass", ["any"], ["any"]),
    ]

    # a packet must pass every base chain of its hook: one accept is not enough
    world = PolicyWorld([], [])

    def verdicts(src: str, dst: str, port: str) -> list[tuple[str, str]]:
        found = evaluate_network(world, policy_set.policies, src, dst, PortSet.parse([port]))
        return [(v.policy, v.decision) for v in found]

    assert verdicts("ip:10.9.0.1", "ip:10.1.2.3", "tcp/80") == [
        ("edge-forward-forward", "allow"),
        ("edge-forward-filter_forward", "deny"),
    ]
    # firewalld's chain names only 10.1.2.0/24: elsewhere it does not apply (and would accept)
    assert verdicts("ip:10.9.0.1", "ip:10.1.5.3", "tcp/80") == [("edge-forward-forward", "allow")]


def test_scripts_with_commands() -> None:
    text = """add table inet fw
add chain inet fw input { type filter hook input priority 0; policy drop; }
add set inet fw admins { type ipv4_addr; }
add element inet fw admins { 10.10.0.5, 10.10.0.6 }
add rule inet fw input ip saddr @admins tcp dport 22 accept
add rule inet fw input tcp dport 80 accept
insert rule inet fw input ip saddr 10.66.0.0/16 drop
add rule inet fw input position 3 tcp dport 25 accept
include "/etc/nftables.d/*.nft"
add chain inet fw scratch
add rule inet fw scratch accept
delete chain inet fw scratch
"""
    policy_set = _parse(text, "host-7.nft")
    host = _policy(policy_set, "host-7-host")
    assert [(r.id, r.effect, r.sources, r.ports) for r in host.rules[:3]] == [
        ("input-1", "deny", ["cidr:10.66.0.0/16"], ["any"]),  # inserted at the top
        ("input-2", "allow", ["cidr:10.10.0.5/32", "cidr:10.10.0.6/32"], ["tcp/22"]),
        ("input-3", "allow", ["any"], ["tcp/80"]),
    ]
    assert "include '/etc/nftables.d/*.nft' not followed: only the given file is read" in policy_set.warnings
    skipped = [w for w in policy_set.warnings if w.startswith("1 statement(s) not understood")]
    assert len(skipped) == 1 and "rule at a position" in skipped[0]


def test_json_specifics() -> None:
    def match(left: dict[str, Any], right: Any, op: str = "==") -> dict[str, Any]:
        return {"match": {"op": op, "left": left, "right": right}}

    def entry(kind: str, **fields: Any) -> dict[str, Any]:
        return {kind: {"family": "inet", "table": "f", **fields}}

    def rule(*expr: Any, **fields: Any) -> dict[str, Any]:
        return entry("rule", chain="fwd", expr=list(expr), **fields)

    daddr = {"payload": {"protocol": "ip", "field": "daddr"}}
    nets = [{"prefix": {"addr": "10.1.0.0", "len": 16}}, {"range": ["10.2.0.1", "10.2.0.2"]}]
    verdicts = [[22, {"accept": None}], [23, {"drop": None}]]
    tcp_dport = {"payload": {"protocol": "tcp", "field": "dport"}}
    doc = {
        "nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {"table": {"family": "inet", "name": "f"}},
            entry("chain", name="fwd", type="filter", hook="forward", prio=0, policy="drop"),
            entry("map", name="svc", type="inet_service", map="verdict", elem=verdicts),
            entry("set", name="nets", type="ipv4_addr", flags=["interval"], elem=nets),
            rule(match(daddr, "@nets"), {"vmap": {"key": tcp_dport, "data": "@svc"}}, handle=7),
            rule(
                match(daddr, {"prefix": {"addr": "10.3.0.0", "len": 16}}),
                {"xt": {"type": "match", "name": "recent"}},
                {"accept": None},
                comment="xt",
            ),
            rule(match({"fib": {"result": "type", "flags": ["daddr"]}}, "local"), {"drop": None}),
            rule(
                match(daddr, {"set": ["10.4.0.1", "10.4.0.2"]}),
                match({"payload": {"protocol": "udp", "field": "dport"}}, {"range": [5000, 5010]}),
                {"counter": None},
                {"reject": {"type": "icmpx", "expr": "admin-prohibited"}},
            ),
            entry("flowtable", name="ft"),
            {"something": {"family": "inet"}},
        ]
    }
    policy_set = _parse(json.dumps(doc), "dump.json")
    assert (policy_set.name, policy_set.format) == ("dump", "nftables-json")
    rules = _rules(_policy(policy_set, "dump-forward"))
    networks = ["cidr:10.1.0.0/16", "cidr:10.2.0.1/32", "cidr:10.2.0.2/32"]
    assert [(r.id, r.effect, r.destinations, r.ports, r.metadata.get("unmodeled")) for r in rules.values()] == [
        ("fwd-1-v1", "allow", networks, ["tcp/22"], None),
        ("fwd-1-v2", "deny", networks, ["tcp/23"], None),
        ("fwd-2", "allow", ["cidr:10.3.0.0/16"], ["any"], ["xtables extension"]),
        ("fwd-3", "deny", ["any"], ["any"], ["match fib"]),
        ("fwd-4", "deny", ["cidr:10.4.0.1/32", "cidr:10.4.0.2/32"], ["udp/5000-5010"], None),
    ]
    assert rules["fwd-1-v1"].metadata["handle"] == 7 and rules["fwd-2"].description == "xt"
    assert policy_set.warnings[0] == "1 JSON entries not understood and skipped (something entry)"
    with pytest.raises(InvalidInputError, match="nftables JSON is not valid"):
        _parse('{"nftables": [ {', "dump.json")
    with pytest.raises(InvalidInputError, match="Not an nftables ruleset"):
        _parse("hello world\n", "fw.nft")


def test_detection_names_and_limits() -> None:
    text = (POLICIES / "raven-edge.nft").read_text()
    for suffix in (".nft", ".conf", ".txt", ""):
        assert sniff_policy(text.encode(), suffix) >= 0.95
    assert sniff_policy((POLICIES / "raven-edge.nft.json").read_bytes(), ".json") >= 0.95
    assert sniff_policy(b"table of contents {\n", ".txt") == 0.0
    assert _parse(text, "edge-router.conf").name == "edge-router"
    assert parse_policy_text(text, source="x.nft", suffix=".nft", host="VPN-01").name == "vpn-01"
    many = _table(*[f"ip daddr 10.1.{n // 250}.{n % 250} accept" for n in range(5001)])
    with pytest.raises(InvalidInputError, match="More than 5000 rules"):
        _parse(many)
    with pytest.raises(InvalidInputError, match="Unbalanced"):
        _parse(_table("ip daddr 10.1.0.0/16 accept").removesuffix("}\n"))
    elements = ", ".join(f"10.2.{n // 250}.{n % 250}" for n in range(300))
    big = _parse(_table(f"ip daddr {{ {elements} }} accept", "ip daddr 10.9.0.0/16 accept"))
    assert _policy(big, "fw-forward").rules[0].metadata["unmodeled"] == ["ip daddr set of 300 elements (more than 256)"]
    bomb = "define A = { " + ", ".join(["10.0.0.1"] * 2000) + " }\n"
    bomb += "define B = { " + ", ".join(["$A"] * 30) + " }\n" + _table("ip daddr $B accept")
    with pytest.raises(InvalidInputError, match="Variable B is too large"):
        _parse(bomb)


@pytest.fixture
def api(raven_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)})) as client:
        yield client


def test_cli_api_and_import(raven_home: Path, cli: Any, api: Any) -> None:
    checked = cli("policy", "check", str(POLICIES / "raven-edge.nft"), "--host", "VPN-01", "--json")
    assert checked.exit_code == 0, checked.stderr
    data = checked.json()
    assert data["sets"][0]["format"] == "nftables"
    assert {f["rule_id"] for f in data["analysis"]["findings"]} >= {"shadowed-rule", "overly-broad-rule"}
    document = (POLICIES / "raven-edge.nft.json").read_text()
    for fmt in ("nftables", "json"):  # nft -j output is recognized whichever format is named
        response = api.post("/api/v1/policy/check", json={"document": document, "format": fmt, "host": "VPN-01"})
        assert response.status_code == 200, response.text
        assert [p["id"] for p in response.json()["set"]["policies"]] == ["vpn-01-forward", "vpn-01-host"]
    imported = cli("import", str(POLICIES / "raven-edge.nft.json"), "--json")
    assert imported.exit_code == 0, imported.stderr
    listed = cli("policy", "list", "--json")
    assert {"raven-edge-forward", "raven-edge-host"} <= {p["id"] for p in listed.json()["policies"]}
