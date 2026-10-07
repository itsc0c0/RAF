"""Policy: iptables-save rule sets -> network policies (fixtures/policies/raven-edge.rules and synthetic sets)."""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError
from raf.core.ports import PortSet
from raf.data import raven
from raf.products.policy.formats import parse_policy_text, sniff_policy
from raf.products.policy.model import Policy, PolicyRule, PolicySet
from tests.conftest import FIXTURES

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

ROUTER = FIXTURES / "policies" / "raven-edge.rules"


def _filter(*rules: str, chains: str = ":INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]") -> str:
    return "*filter\n" + chains + "\n" + "\n".join(rules) + "\nCOMMIT\n"


def _parse(text: str, name: str = "fw.rules") -> PolicySet:
    return parse_policy_text(text, source=name, suffix=Path(name).suffix)


def _policy(policy_set: PolicySet, suffix: str) -> Policy:
    found = next((p for p in policy_set.policies if p.id.endswith(suffix)), None)
    assert found is not None, [p.id for p in policy_set.policies]
    return found


def _rule(policy: Policy, rule_id: str) -> PolicyRule:
    found = policy.rule(rule_id)
    assert found is not None, [r.id for r in policy.rules]
    return found


def test_the_raven_router_rule_set() -> None:
    policy_set = _parse(ROUTER.read_text(), ROUTER.name)
    assert (policy_set.name, policy_set.format) == ("raven-edge", "iptables-save")
    assert policy_set.warnings == ["table(s) nat ignored: only the filter table decides access"]
    forward = _policy(policy_set, "-forward")
    assert (forward.default, forward.evaluation) == ("deny", "first-match")
    assert "cidr:10.30.0.0/16" in forward.scope and "any" not in forward.scope
    # FIREWALL_RULES in order (r10 split by protocol), the deployment chain inlined where it is jumped to;
    # the connection-tracking rule and the LOG rule decide nothing about new flows
    described = [(r.description.split(":")[0], r.effect, r.ports) for r in forward.rules]
    expected = []
    for rule in raven.FIREWALL_RULES:
        effect = "allow" if rule["action"] == "allow" else "deny"
        if rule["id"] == "r10-internet-to-dmz":
            expected += [(rule["id"], effect, ["tcp/443"]), (rule["id"], effect, ["udp/1194"])]
        else:
            expected.append((rule["id"], effect, PortSet.parse(rule["ports"]).labels()))
    assert described == expected
    deploy = _rule(forward, "forward-6.raven-deploy-1")
    assert (deploy.sources, deploy.destinations) == (["cidr:10.20.0.0/16"], ["cidr:10.30.0.0/16"])
    assert deploy.ports == ["any"]
    assert deploy.metadata["via"] == "FORWARD line 25" and deploy.metadata["chain"] == "RAVEN-DEPLOY"
    assert _rule(forward, "forward-12").destinations == ["cidr:10.30.0.10/32"]  # DB-01
    host = _policy(policy_set, "-host")
    assert host.scope == ["host:raven-edge"]
    assert [(r.id, r.effect, r.sources, r.destinations, r.ports) for r in host.rules] == [
        ("input-3", "allow", ["cidr:10.10.0.0/16"], ["host:raven-edge"], ["tcp/22"]),
        ("input-4", "allow", ["any"], ["host:raven-edge"], ["icmp/8"]),
        ("input-policy", "deny", ["any"], ["host:raven-edge"], ["any"]),
        ("output-policy", "allow", ["host:raven-edge"], ["any"], ["any"]),
    ]
    assert all(r.enabled for p in policy_set.policies for r in p.rules)


def test_the_analysis_finds_the_shadowed_database_rule(raven: RafContext) -> None:
    from raf.products.policy.service import PolicyService

    sets, analysis = PolicyService(raven).check(ROUTER, host="VPN-01")
    assert [p.id for p in sets[0].policies] == ["vpn-01-forward", "vpn-01-host"]
    found = {(f.rule_id, *f.metadata["rules"]): f for f in analysis.findings}
    # r40 jumps to a chain that accepts everything, so the database protection r85 never applies
    shadowed = found["shadowed-rule", "forward-12", "forward-6.raven-deploy-1"]
    assert shadowed.severity.value == "HIGH" and "r85-deny-dev-to-prod-db" in shadowed.description
    assert "r40-dev-to-prod" in found["overly-broad-rule", "forward-6.raven-deploy-1"].description
    assert ("redundant-rule", "forward-13", "forward-5") in found  # r90 duplicates r30
    # the chain policies that close INPUT and OUTPUT conflict with nothing; every reference is known
    assert not any(
        "input-policy" in rules or "output-policy" in rules for kind, *rules in found if kind != "overly-broad-rule"
    )
    assert not any(kind in ("default-allow", "stale-reference") for kind, *_ in found)


def test_what_the_model_cannot_express_is_imported_disabled_with_the_reason() -> None:
    policy_set = _parse(
        _filter(
            "-A FORWARD ! -s 10.0.0.0/8 -d 10.1.0.0/16 -j ACCEPT",
            "-A FORWARD -i eth0 -o eth1 -d 10.1.0.0/16 -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -p tcp --sport 1024:65535 --dport 22 -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -m limit --limit 5/min -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -m set --match-set blocked src -j DROP",
            "-A FORWARD -d 10.1.0.0/16 -p tcp --tcp-flags SYN,ACK SYN -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -j NFQUEUE --queue-num 1",
            "-A FORWARD -d 10.1.0.0/16 -g SIDE",
            "-A SIDE -j ACCEPT",
            chains=":INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:SIDE - [0:0]",
        )
    )
    forward = _policy(policy_set, "-forward")
    reasons = {r.id: r.metadata.get("unmodeled") for r in forward.rules}
    assert reasons == {
        "forward-1": ["negated source"],
        "forward-2": ["interface eth0", "interface eth1"],
        "forward-3": ["source port"],
        "forward-4": ["match limit"],
        "forward-5": ["match set"],
        "forward-6": ["tcp flags"],
        "forward-7": ["target NFQUEUE"],
        "forward-8": ["--goto to SIDE"],
    }
    assert not any(r.enabled for r in forward.rules)
    assert any("8 rule(s) use conditions the policy model cannot express" in w for w in policy_set.warnings)


def test_unknown_conditions_are_never_dropped_silently() -> None:
    policy_set = _parse(
        _filter(
            "-A FORWARD -d 10.1.0.0/16 -p tcp -m tcp --tcp-option 5 -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -m conntrack --ctorigdst 10.9.0.1 -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -m conntrack --ctstate DNAT -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 stray -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -p icmp -m icmp --icmp-type 3/3 -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -p icmp -m icmp --icmp-type 300 -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -p tcp -m tcp --dport 2000:1000 -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -p tcp -m tcp --dport 70000 -j ACCEPT",
            "-A FORWARD -c 10 200 -s 10.0.0.0/8 -d 10.1.0.0/16 -p tcp -m tcp --dport :1024 -j ACCEPT",
            "-A FORWARD -s 10.0.0.0/8 -d 10.1.0.0/16 -p udp -m udp --dport 1024: -j REJECT --reject-with tcp-reset",
            "-A FORWARD -s 2001:db8::/32 -p ipv6-icmp -m icmp6 --icmpv6-type echo-request -j ACCEPT",
            "-A FORWARD -s 10.0.0.0/8 -j SET --add-set seen src",
        )
    )
    rules = {r.id: r for r in _policy(policy_set, "-forward").rules}
    assert {rule_id: rules[rule_id].metadata.get("unmodeled") for rule_id in rules if not rules[rule_id].enabled} == {
        "forward-1": ["option --tcp-option"],
        "forward-2": ["option --ctorigdst"],
        "forward-3": ["connection state DNAT"],
        "forward-4": ["option stray"],
        "forward-5": ["icmp type 3/3"],
        "forward-6": ["icmp type 300"],
        "forward-7": ["port 2000:1000"],
        "forward-8": ["port 70000"],
    }
    assert rules["forward-9"].ports == ["tcp/0-1024"]  # "-c" sets counters: not a condition
    assert (rules["forward-10"].effect, rules["forward-10"].ports) == ("deny", ["udp/1024-65535"])
    assert rules["forward-11"].ports == ["icmp/128"]  # ICMPv6 names have their own numbers
    assert "forward-12" not in rules  # SET adds to an ipset and lets the packet continue


def test_rules_that_decide_nothing_about_new_flows_are_left_out() -> None:
    policy_set = _parse(
        _filter(
            "-A FORWARD -i lo -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m state --state INVALID -j DROP",
            "-A FORWARD -m conntrack --ctstate INVALID,ESTABLISHED -j DROP",
            '-A FORWARD -j LOG --log-prefix "fw: "',
            "-A FORWARD -s 10.0.0.0/8 -d 10.1.0.0/16 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
            "-A FORWARD ! -i lo -s 10.0.0.0/8 -d 10.2.0.0/16 -j ACCEPT",
        )
    )
    assert [r.id for r in _policy(policy_set, "-forward").rules] == ["forward-6", "forward-7"]
    assert all(r.enabled for r in _policy(policy_set, "-forward").rules)


def test_user_chains_are_inlined_with_both_rules_conditions() -> None:
    policy_set = _parse(
        _filter(
            "-A FORWARD -s 10.0.0.0/8 -p tcp -j CORP",
            "-A FORWARD -d 10.9.0.0/16 -j RETURN",
            "-A FORWARD -s 10.0.0.0/8 -j LOOP",
            "-A CORP -s 10.1.0.0/16 -d 10.5.0.0/16 -p tcp --dport 22 -j ACCEPT",
            "-A CORP -s 192.168.0.0/16 -d 10.5.0.0/16 -j ACCEPT",
            "-A CORP -d 10.5.0.0/16 -p udp --dport 53 -j ACCEPT",
            "-A CORP -d 10.6.0.0/16 -p tcp --dport 443 -j RETURN",
            "-A CORP -d 10.0.0.0/8 -j DROP",
            "-A CORP -j RETURN",
            "-A CORP -d 10.7.0.0/16 -j ACCEPT",
            "-A LOOP -d 10.8.0.0/16 -j LOOP",
            "-A UNUSED -j ACCEPT",
            chains=":INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:CORP - [0:0]\n:LOOP - [0:0]\n"
            ":UNUSED - [0:0]",
        )
    )
    forward = _policy(policy_set, "-forward")
    rules = {r.id: r for r in forward.rules}
    ssh = rules["forward-1.corp-1"]  # 10.1/16 within the jump's 10/8; tcp/22 within the jump's tcp
    assert (ssh.sources, ssh.destinations, ssh.ports, ssh.enabled) == (
        ["cidr:10.1.0.0/16"],
        ["cidr:10.5.0.0/16"],
        ["tcp/22"],
        True,
    )
    assert "forward-1.corp-2" not in rules  # 192.168/16 is outside the jump's 10/8
    assert "forward-1.corp-3" not in rules  # udp cannot pass the jump's tcp
    blocked = rules["forward-1.corp-5"]  # after a conditional RETURN: not every packet gets here
    assert not blocked.enabled and blocked.metadata["unmodeled"] == ["follows a conditional RETURN in CORP (line 14)"]
    assert "forward-1.corp-7" not in rules  # after an unconditional RETURN: never reached
    assert (rules["forward-2"].effect, rules["forward-2"].enabled) == ("deny", True)  # RETURN in FORWARD: its policy
    loop = rules["forward-3.loop-1"]
    assert not loop.enabled and loop.metadata["unmodeled"] == ["jump loop to LOOP"]
    assert "chain(s) UNUSED is never jumped to from INPUT, FORWARD or OUTPUT: not imported" in policy_set.warnings


def test_ports_protocols_and_addresses() -> None:
    policy_set = _parse(
        _filter(
            "[3:180] -A FORWARD -s 10.0.0.0/8 -d 10.1.0.0/16 -p tcp -m tcp --dport 1000:2000 -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -p tcp -m multiport --dports 22,80,8000:8080 -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -p icmp -m icmp --icmp-type echo-request -j ACCEPT",
            "-A FORWARD -d 10.1.0.0/16 -p udp -j ACCEPT",
            "-A FORWARD -m iprange --src-range 10.0.0.1-10.0.0.6 -d 10.1.0.0/16 -j ACCEPT",
            "-A FORWARD -s 2001:db8::/32 -d 2001:db8:1::/48 -p ipv6-icmp -j ACCEPT",
            '-A FORWARD -d 10.1.0.0/16 -p 47 -m comment --comment "GRE \\"tunnel\\"" -j ACCEPT',
        )
    )
    rules = {r.id: r for r in _policy(policy_set, "-forward").rules}
    assert rules["forward-1"].ports == ["tcp/1000-2000"]
    assert rules["forward-2"].ports == ["tcp/22", "tcp/80", "tcp/8000-8080"]
    assert rules["forward-3"].ports == ["icmp/8"]
    assert rules["forward-4"].ports == ["udp/all"]
    assert rules["forward-5"].sources == [f"cidr:10.0.0.{n}" for n in ("1/32", "2/31", "4/31", "6/32")]
    assert (rules["forward-6"].sources, rules["forward-6"].ports) == (["cidr:2001:db8::/32"], ["icmp"])
    gre = rules["forward-7"]
    assert not gre.enabled and gre.metadata["unmodeled"] == ["protocol 47"] and gre.description == 'GRE "tunnel"'


def test_forward_is_only_imported_for_a_router_that_names_networks() -> None:
    chains = ":INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]"
    server = _parse(_filter("-A INPUT -p tcp --dport 443 -j ACCEPT", chains=chains), "web-01.rules")
    assert [p.id for p in server.policies] == ["web-01-host"]  # a FORWARD DROP must not deny the whole workspace
    assert any(
        "FORWARD has no rules for new flows" in w and "DROP policy is not imported" in w for w in server.warnings
    )
    interfaces = _parse(_filter("-A FORWARD -i eth0 -o eth1 -j ACCEPT"))
    assert not any(p.id.endswith("-forward") for p in interfaces.policies)
    assert any("FORWARD names no address" in w for w in interfaces.warnings)
    open_router = _parse(
        _filter("-A FORWARD -s 10.0.0.0/8 -d 10.9.0.0/16 -j DROP", chains=":FORWARD ACCEPT [0:0]"), "r.rules"
    )
    assert _policy(open_router, "-forward").default == "allow"
    nothing = _parse(_filter())
    assert nothing.policies == [] and any("nothing to import" in w for w in nothing.warnings)


def test_detection_limits_and_errors() -> None:
    text = ROUTER.read_text()
    for suffix in (".rules", ".txt", ".v4", ""):
        assert sniff_policy(text.encode(), suffix) >= 0.95
    assert _parse(text, "router-backup.txt").format == "iptables-save"  # recognized by content, any name
    assert sniff_policy(b'{"format": "raf-policy/1"}', ".json") > sniff_policy(b"*filter\n", ".json")
    with pytest.raises(InvalidInputError, match="Not iptables-save output"):
        _parse("hello\n", "fw.rules")
    with pytest.raises(InvalidInputError, match="Not iptables-save output"):
        _parse("*emphasis*\n:not a chain\nCOMMIT\n", "notes.rules")
    # a large rule set is recognized from its head, but must be complete and within the limits
    large = _filter(*[f"-A FORWARD -s 10.0.0.0/8 -d 10.1.{n // 250}.{n % 250}/32 -j ACCEPT" for n in range(4000)])
    assert sniff_policy(large.encode(), ".txt") >= 0.95 and len(_policy(_parse(large), "-forward").rules) == 4000
    with pytest.raises(InvalidInputError, match="no COMMIT line"):
        _parse(large.removesuffix("COMMIT\n"))
    too_many = _filter(*["-A FORWARD -s 10.0.0.0/8 -d 10.1.0.0/16 -j ACCEPT"] * 5001)
    with pytest.raises(InvalidInputError, match="More than 5000 rules"):
        _parse(too_many)
    broken = _parse(_filter('-A FORWARD -s 10.0.0.0/8 -d 10.1.0.0/16 -m comment --comment "open -j ACCEPT'))
    assert any("not rules" in w for w in broken.warnings)
    # declarations are cheap to repeat: they must not make the parse slow or the warnings long
    many = _parse("*filter\n" + "".join(f":C{n} - [0:0]\n" for n in range(50_000)) + "*bogus\n-A X\nCOMMIT\n")
    assert many.warnings[0].startswith("1 line(s)") and "and 49990 more" in many.warnings[1]
    assert len(many.warnings[1]) < 300


def test_flattening_is_bounded() -> None:
    # every level jumps ten times to the next: walking it all would visit a million rules
    levels = [f"L{n}" for n in range(1, 6)]
    chains = ":INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n" + "".join(
        f":{c} - [0:0]\n" for c in levels
    )
    nested = [
        f"-A {caller} -s 10.0.0.0/8 -j {callee}" for caller, callee in zip(["FORWARD", *levels], levels, strict=False)
    ]
    leaf = [f"-A {levels[-1]} -j LOG"]
    with pytest.raises(InvalidInputError, match="takes more than 100000 steps"):
        _parse(_filter(*[rule for rule in nested for _ in range(10)], *leaf * 10, chains=chains.rstrip("\n")))
    # inlining one chain at four places: each policy stays within the rule limit
    big = [f"-A BIG -s 10.1.{n // 250}.{n % 250}/32 -j ACCEPT" for n in range(1500)]
    jumps = ["-A INPUT -s 10.0.0.0/8 -j BIG"] * 2 + ["-A OUTPUT -d 10.0.0.0/8 -j BIG"] * 2
    host_chains = ":INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:BIG - [0:0]"
    with pytest.raises(InvalidInputError, match="would have 6002 rules"):
        _parse(_filter(*jumps, *big, chains=host_chains))


@pytest.fixture
def api(raven_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)})) as client:
        yield client


def test_cli_and_api(raven_home: Path, cli: Any, api: Any) -> None:
    checked = cli("policy", "check", str(ROUTER), "--host", "VPN-01", "--json")
    assert checked.exit_code == 0, checked.stderr
    data = checked.json()
    assert data["sets"][0]["format"] == "iptables-save"
    assert {f["rule_id"] for f in data["analysis"]["findings"]} >= {"shadowed-rule", "overly-broad-rule"}
    response = api.post(
        "/api/v1/policy/check", json={"document": ROUTER.read_text(), "format": "iptables", "host": "VPN-01"}
    )
    assert response.status_code == 200, response.text
    assert [p["id"] for p in response.json()["set"]["policies"]] == ["vpn-01-forward", "vpn-01-host"]
    imported = cli("policy", "import", str(ROUTER), "--json")
    assert imported.exit_code == 0, imported.stderr
    created = {p["object_id"] for p in imported.json()["policies"]}
    assert created == {"policy:raven-edge-forward", "policy:raven-edge-host"}
