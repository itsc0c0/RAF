# R$F Policy

R$F Policy normalizes network/firewall rules and access policies into one model, finds conflicts,
shadowed, redundant and overly broad rules, compares revisions, and evaluates hypothetical flows
and access requests - always returning the **policy chain that caused the decision**.

Status: **BETA** · category: exposure · command: `raf policy` · API: `/api/v1/policy`

## Commands

```text
raf policy check FILE|DIR [--principal P] [--host NAME]    normalize + analyze, nothing stored
raf policy import FILE|DIR [--principal P] [--host NAME]   store policies in the workspace graph
raf policy analyze [FILE|DIR] [--no-save]           analyze stored policies, record findings
raf policy list | show POLICY
raf policy can SUBJECT VERB TARGET [--port P] [--from HOST]
raf policy diff BEFORE [AFTER=current]              files, directories, current or snapshot names
```

`raf import` and `raf analyze` also recognize policy files (parser `raf-policy`).

## Formats (auto-detected)

* **raf-policy/1** (JSON or YAML):

  ```json
  {"format": "raf-policy/1", "name": "raven-policies", "revision": "2026-10-01",
   "policies": [
     {"id": "raven-fw", "domain": "network", "default": "deny", "rules": [
       {"id": "r40-dev-to-prod", "action": "allow", "source": "network:DEV",
        "destination": "network:PROD", "ports": ["any"], "description": "..."}]},
     {"id": "raven-access", "domain": "identity", "default": "deny", "statements": [
       {"id": "break-glass", "effect": "allow", "principals": ["role:break-glass"],
        "actions": ["*"], "resources": ["*"]}]}]}
  ```

  Network policies may declare `scope` (address selectors they govern; default: every flow).
* **AWS-IAM-style JSON** (`Version`/`Statement`): `Effect`, `Action`, `Resource`, `Principal`;
  `NotAction`/`NotResource` are skipped with a warning; `Condition` is recorded but not evaluated.
  Without a `Principal`, pass `--principal`.
* **CSV firewall exports**: headers such as `id, action, source, destination, protocol, port,
  description, enabled, policy`; bare zone names become `network:<name>`; the default action is
  assumed to be deny (stated as a warning).
* **iptables-save / ip6tables-save** output (`.rules`, `.iptables`, `.v4`, `.v6`, or any file whose
  content is recognized): only the `filter` table decides access (`nat`, `mangle`, `raw` and
  `security` are reported and ignored). A rule set becomes up to two first-match network policies,
  named after the file or `--host NAME`:

  | iptables | R$F |
  |---|---|
  | `FORWARD` (traffic the host routes) | `<name>-forward`, scoped to the networks its rules name; default = the chain policy. Not imported when FORWARD has no rules for new flows (a host that does not route) or names no address (interface-only rules), so a server's `FORWARD DROP` never denies the rest of the workspace |
  | `INPUT`, `OUTPUT` (traffic to and from the host) | `<name>-host`, scoped to `host:<name>`: INPUT rules without `-d` target the host, OUTPUT rules without `-s` come from it, and each chain policy closes its part as a final rule (`input-policy`, `output-policy`) |
  | `-j ACCEPT`; `-j DROP`, `-j REJECT` | allow; deny |
  | jump to a user chain | inlined with both rules' conditions combined (rule `forward-6.raven-deploy-1` is rule 1 of `RAVEN-DEPLOY` reached through FORWARD rule 6); after `RETURN` the calling chain continues, and in a built-in chain the chain policy decides |
  | `-g` (goto) a user chain | inlined too, but the packet does not come back: what the target leaves undecided gets the built-in chain's policy (rule `forward-2.end`) |
  | `LOG`, `NFLOG`, `MARK`, `SET` and other non-terminating targets | nothing: the packet continues |
  | loopback rules (`-i lo`), `--ctstate ESTABLISHED,RELATED`, `INVALID` | left out: they decide nothing about new flows between hosts |

  Rule descriptions come from `-m comment`; metadata keeps each rule's chain, line and target.
  Conditions the model cannot express exactly - negation, interfaces other than loopback, source
  ports, ICMP codes, connection states such as `DNAT`, match modules other than tcp, udp, icmp,
  multiport, comment, conntrack/state and iprange, options it does not know, jump loops, rules
  after a conditional `RETURN` - are never approximated away: such a rule is imported **disabled**
  with the reasons in `metadata.unmodeled`, and the set's warnings count them. ip6tables-save
  output (its header, a `.v6` file, or IPv6 addresses only) becomes `<name>-ip6-forward` and
  `<name>-ip6-host` and applies to IPv6 addresses only. `raf policy check
  fixtures/policies/raven-edge.rules` shows the Raven router's rules: the jump of r40 to
  `RAVEN-DEPLOY` accepts every port from DEV to PROD, so r85, the database protection, can never
  apply.
* **nftables** rulesets (`.nft`, `.nftables`, or any file whose content is recognized, such as
  `/etc/nftables.conf`): `nft list ruleset` output, nftables scripts (`flush ruleset`, `define`,
  `include` (reported, never followed), blocks, `add`/`insert`/`delete` commands) and
  `nft -j list ruleset` JSON. Tables of the `ip`, `ip6` and `inet` families are read; `filter`
  chains on the `input`, `forward` and `output` hooks become policies the same way as iptables
  chains (`<name>-forward`, `<name>-host`), regular chains are inlined where they are `jump`ed or
  `goto`ed to, `return` behaves like `RETURN`.

  | nftables | R$F |
  |---|---|
  | several base chains on one hook (tables, priorities: iptables-nft, firewalld, Docker, Kubernetes) | one policy each, `<name>-forward-<chain>`, `<name>-host-<family>-<table>`: a packet must pass all of them (a drop is final, an accept ends only its own chain), which is how R$F combines policies |
  | `ip`/`ip6 saddr`/`daddr`: addresses, prefixes, ranges, `{ anonymous sets }`, `@named` sets, `$variables` | CIDR selectors; sets of more than 256 elements are reported, not modeled |
  | `tcp`/`udp`/`th dport`: numbers, ranges, sets, service names, `!=`, `<`, `>=` ... | exact port sets (`tcp dport != 22` is tcp/0-21 and tcp/23-65535) |
  | `meta l4proto`, `ip protocol`, `ip6 nexthdr`, `icmp`/`icmpv6 type`, `meta nfproto` | protocols, ICMP types; IPv6-only rules (an `ip6` table, `meta nfproto ipv6`, `icmpv6`) apply to IPv6 addresses only |
  | `ct state vmap { ... }`, `tcp dport vmap @map` | one rule per element (`input-1-v1`, `input-1-v2`) |
  | `counter`, `log`, `continue`, assignments (`meta mark set ...`) | nothing: the packet continues |
  | `ct state established,related`, `invalid`; `iif lo` | left out: they decide nothing about new flows between hosts |
  | `nat` and `route` chains; `filter` chains on `prerouting`, `postrouting`, `ingress`, `egress`; `arp`, `bridge`, `netdev` tables; dormant tables | reported and ignored |

  Negated addresses, interfaces other than loopback, source ports, `limit`, `quota`, dynamic or
  concatenated sets, `fib`, `tcp flags`, marks, `queue`, set updates and other statements the model
  cannot express make the rule **disabled** with the reasons in `metadata.unmodeled`.
  `fixtures/policies/raven-edge.nft` and `raven-edge.nft.json` hold the Raven router's ruleset; they
  import to exactly the policies and findings of `raven-edge.rules`.

Selectors: `any`, CIDRs (`10.20.0.0/16`), typed objects (`network:DEV`, `host:DB-01`,
`service:postgres`, `group:engineering`, `role:developer`), `type:*` and glob patterns for
resources; ports `any`, `tcp/443`, `tcp/1000-2000`, `udp/53`, `tcp/all` (a whole protocol), `icmp`,
`icmp/8` or service names (`ssh`, `https`, `postgres` ...); actions `*`, exact names, or prefix
wildcards (`deploy:*`).

Policy files are untrusted input: safe loaders only (YAML anchors/aliases are refused), 5 MB and
5,000-rule limits, scalar selectors only; nothing is executed. iptables rules are split into words
like a shell command line but never run; nftables text is tokenized (at most 1,000,000 tokens,
`define` values of at most 100,000) and JSON is read with a safe loader; flattening user chains is
bounded (100,000 rule visits), and every resulting policy keeps the 5,000-rule limit.

## Semantics

* **Network** policies: first match wins, evaluated over **port sets** - each matching rule decides
  the still-undecided part of the requested ports, so one evaluation explains every port, and
  rules that would have matched but were pre-empted are listed.
* **Zone semantics**: `network:INTERNET` (`0.0.0.0/0`) means addresses not inside a more specific
  known network, so an Internet rule never silently covers CORP. Hosts belong to the zones they are
  `MEMBER_OF` (else the most specific network containing their IP). Use a CIDR (`10.0.0.0/8`) to
  express supernets.
* **Identity** policies: deny-overrides (explicit deny > allow > default deny). Principals match
  through group membership (transitive) and held roles; resources match through containment
  (`cloud_resource:production` contains `host:DB-01`, which runs `service:postgres`).

## `raf policy can`

```text
raf policy can alice access DB-01      → DENY (raven-fw r99-default-deny; no access statement)
                                         Indirect: WS-01 → DEV-01 (tcp/22, r30) → DB-01 (any, r40)
raf policy can DEV-01 reach DB-01 --port tcp/5432
                                       → ALLOW (r40-dev-to-prod); r85-deny-dev-to-prod-db would
                                         deny tcp/5432 but is pre-empted (first match wins)
raf policy can frank admin production  → ALLOW (raven-access break-glass via operations)
```

Verbs: `access` (any port/action), `reach`/`connect` (network only), port verbs (`ssh`, `rdp`,
`https`, `postgres` ...) and access-policy actions (`admin`, `deploy:release`, `read` ...). For users,
the network source is their own device (`OWNS`), otherwise hosts they have sessions on; `--from`
overrides it. When the direct flow is denied, R$F looks for **indirect** paths through hosts the
subject can log into.

## Revisions

`raf policy diff fixtures/policies/raven-policies-2026-09.json current` classifies every change as
`access-expanded`, `access-reduced` or `changed` (by comparing rule coverage) and lists findings
introduced or resolved by the new revision - e.g. widening r40 to `any` made the database deny rule
r85 unreachable.

## Findings

`overly-broad-rule`, `shadowed-rule`, `redundant-rule`, `conflicting-rules`, `stale-reference`,
`default-allow` - see [risk-model.md](../risk-model.md#policy-findings-raf-policy-analyze).
