# R$F risk model (raf-risk/1.0)

R$F never emits an unexplained number. Every score is the **clamped sum of named factors**
(0..100); each factor carries a rule id, a human label, a direction (`+` raises risk, `-` lowers it),
its points and the object IDs it is based on. The same rules are used by the CLI, the API, the web
UI, findings and Oracle, so a score can always be traced back to objects, relationships, policies
and events.

| Score | Level |
|---|---|
| 0 - 24 | LOW |
| 25 - 49 | MEDIUM |
| 50 - 74 | HIGH |
| 75 - 100 | CRITICAL |

Implementation: `raf.core.risk.model` (methodology), `raf.core.objects.semantics` (traversal rules),
`raf.core.graph.propagation` (path search), `raf.core.risk.exposure` (asset exposure).

## Traversal semantics

Blast, IAM paths, Exposure and Ghost all propagate over the same relationship semantics. A hop has a
**mode** and a **factor** (multiplied into the path confidence together with the relationship's own
confidence: `factor × (0.5 + 0.5 × relationship.confidence)`).

* `control` - acting with the privileges of / owning the next object
* `reach` - network reachability only; it never grants control by itself and continues only through
  network structure (zones, addresses, services on a reachable host)
* `trust` - identities of one realm are accepted in another

| Relationship | Forward | Reverse |
|---|---|---|
| `LOGGED_INTO` user→host | control 0.8 (the credentials work there) | control 0.5 (a session on the host can be captured) |
| `ADMIN_OF` | control 1.0 | - |
| `MEMBER_OF` principal→group | control 1.0 (inherits access) | - |
| `MEMBER_OF` host↔network | reach 1.0 | reach 1.0 |
| `HAS_ROLE`, `HAS_PERMISSION`, `CAN_ASSUME`, `HAS_IDENTITY` | control 1.0 | - |
| `CAN_ACCESS` | control 0.9 | - |
| `USES` host→identity | control 0.8 (credentials present on the host) | - |
| `RUNS` host→service | control 0.9; in reach mode: reach 1.0 | control 0.4 (service → its host) |
| `DEPLOYS_TO` | control 0.9 | - |
| `CONTAINS` environment/compute | control 0.9 | - |
| `CONTAINS` host/dir→file, `CONTAINS_SECRET`, `AUTHENTICATES_AS` | control 1.0 / 0.9 / 1.0 | - |
| `TRUSTS` A→B | - | trust 0.8 (B's identities are accepted by A) |
| `OWNS` principal→asset | control 0.6 | - |
| `CAN_REACH` | reach 0.9 | - |
| `CONNECTED_TO` host/ip | reach 0.6 | - |
| `HAS_ADDRESS` | reach 1.0 | reach 1.0 |

Additional rules:

* **Vulnerability upgrade** - a *reached* asset affected by a vulnerability with CVSS ≥ 7 or a known
  exploit can be upgraded from reach to control with factor `0.6 × min(score, 10) / 10`. The hop
  names the vulnerability. (Blast enables this; IAM paths do not.)
* **Disabled identities** (`metadata.disabled = true`) cannot be taken over.
* **Search** - best-first search keeping, per (object, mode), the Pareto front of (confidence, depth):
  a state is discarded only if another reached the same object in the same mode with at least the
  same confidence *and* no greater depth. A shorter, weaker path is therefore never hidden by a
  longer, stronger one that cannot be extended within the depth limit.
* **Time** - with `--at`, only relationships valid at that time are traversed (`valid_from`/`first_seen`
  ≤ t < `valid_to`).

## Blast radius (`raf blast`)

Assets are hosts, services, cloud resources, containers, networks and projects. *Controllable*
means reached in control/trust mode; *critical* means criticality high or critical.

| Rule | Points | When |
|---|---|---|
| `blast.critical-control` | +25 each (max 50) | critical-criticality assets controllable |
| `blast.high-control` | +10 each (max 30) | high-criticality assets controllable |
| `blast.critical-reach` | +5 each (max 15) | high/critical assets only network-reachable (no control path) |
| `blast.privileged-paths` | +10 each (max 20) | control of critical assets through privileged roles/identities or admin rights |
| `blast.controllable` | +1 each (max 20) | any controllable asset |
| `blast.exploitable` | +5 | propagation relies on an exploitable vulnerability |
| `blast.mfa` | -10 | the subject is protected by MFA |
| `blast.disabled` | -30 | the subject account is disabled |

The *primary path* is the path to the most critical controllable asset (then highest confidence,
then fewest hops). Every hop states why it is traversable.

## Asset exposure (`raf exposure`)

Exposure is **not** a CVSS sort. For every host, service, cloud resource and container:

| Rule | Points | Meaning |
|---|---|---|
| `exposure.criticality` | +25 critical, +15 high, +5 medium | business criticality |
| `exposure.internet-direct` | +20 | reachable from an external zone in one network hop, or flagged internet-facing |
| `exposure.internet-indirect` | +8 | reachable from the Internet only through other zones |
| `exposure.workstation-reach` | +2 per workstation (max 10) | network-reachable from user workstations (the other common entry point) |
| `exposure.vulnerability` | +2 × highest CVSS (max 20); **halved** when no entry point reaches the asset | vulnerabilities on the asset or on services it runs |
| `exposure.more-vulnerabilities` | +2 each further vulnerability (max 6; halved when unreachable) | |
| `exposure.exploit` | +8 (+4 when unreachable) | a public exploit is available |
| `exposure.controllers` | +3 per user (max 15) | users with a control path to the asset |
| `exposure.credential-path` | +5 | control is obtainable through exposed credentials (stored secrets, credential files, captured sessions) |
| `exposure.privileged-credentials` | +10 per identity (max 15) | credentials of privileged identities stored on the asset |
| `exposure.secrets` | +5 each (max 10) | secrets stored on the asset |
| `exposure.stepping-stone` | +8 per asset (max 15) | control paths from the asset to *other* critical assets |
| `exposure.isolated` | **-15** | no entry point (Internet zone or workstation) can reach the asset |

Entry points are external network zones (`0.0.0.0/0`, zone `external`/`internet`) and user
workstations (hosts owned by users or with role `workstation`). Large workspaces are bounded:
at most 200 workstation entry points and 300 principals are evaluated; the report says when it
sampled.

Example (Raven Industries): `VPN-01` (internet-facing, high criticality, CVSS 9.8 with exploit on its
VPN service) is CRITICAL, while `LAB-01` (CVSS 9.1 with exploit, but in the isolated lab zone that no
entry point reaches) is LOW: the vulnerability counts half and isolation subtracts 15 points.

Assets scoring HIGH or CRITICAL become findings (`exposure / asset-exposure`) whose explanation is
the factor list; re-running auto-resolves findings that no longer apply.

## IAM findings (`raf iam analyze`)

| Rule | Severity | Detects |
|---|---|---|
| `excessive-privilege` | HIGH (wildcard role or ≥5 assets) / MEDIUM | entitled control over ≥3 high/critical assets, or a wildcard role |
| `dormant-privileged` | MEDIUM | privileged identity without activity for `iam.dormant_days` (default 90), measured against the newest event in the workspace (reproducible) |
| `inherited-privilege` | HIGH (wildcard) / MEDIUM | privileged role obtained only through nested groups (≥2 group hops) |
| `broad-role` | HIGH (wildcard) / MEDIUM | privileged role that is wildcard or held by ≥ `iam.broad_role_threshold` principals |
| `credential-exposure-path` | HIGH (credential file on disk) / MEDIUM | credentials of a privileged identity on a host others can log into or access |
| `risky-trust` | MEDIUM | transitive (≥2 hops) or external trust relationships |
| `privileged-without-mfa` | MEDIUM | privileged human/admin identity with MFA recorded as disabled |

## Policy findings (`raf policy analyze`)

| Rule | Severity | Detects |
|---|---|---|
| `overly-broad-rule` | HIGH / MEDIUM / LOW | any→any; external source with every port; every port towards a high/critical destination (HIGH); every port (MEDIUM); >1024 ports (LOW); identity: all actions on all resources, wildcard/admin for every principal (HIGH), wildcard on a critical resource or privileged actions on every resource (MEDIUM) |
| `shadowed-rule` | HIGH (a deny that never applies) / MEDIUM | first-match: fully covered by an earlier rule with the opposite effect; deny-overrides: an allow fully covered by a deny |
| `redundant-rule` | LOW | fully covered by another rule with the same effect |
| `conflicting-rules` | LOW | partial overlap with opposite effects (outcome depends on order) |
| `stale-reference` | LOW | references objects that are not in the workspace |
| `default-allow` | MEDIUM | the policy's default action is allow |

Generalization (a broad rule after a specific exception) is the normal exception pattern and is not
reported.
