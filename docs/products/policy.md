# R$F Policy

R$F Policy normalizes network/firewall rules and access policies into one model, finds conflicts,
shadowed, redundant and overly broad rules, compares revisions, and evaluates hypothetical flows
and access requests - always returning the **policy chain that caused the decision**.

Status: **BETA** · category: exposure · command: `raf policy` · API: `/api/v1/policy`

## Commands

```text
raf policy check FILE|DIR [--principal P]           normalize + analyze, nothing stored
raf policy import FILE|DIR [--principal P]          store policies in the workspace graph
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

Selectors: `any`, CIDRs (`10.20.0.0/16`), typed objects (`network:DEV`, `host:DB-01`,
`service:postgres`, `group:engineering`, `role:developer`), `type:*` and glob patterns for
resources; ports `any`, `tcp/443`, `tcp/1000-2000`, `udp/53`, `icmp` or service names (`ssh`,
`https`, `postgres` ...); actions `*`, exact names, or prefix wildcards (`deploy:*`).

Policy files are untrusted input: safe loaders only (YAML anchors/aliases are refused), 5 MB and
5,000-rule limits, scalar selectors only; nothing is executed.

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
