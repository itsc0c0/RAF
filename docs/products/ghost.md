# R$F Ghost

R$F Ghost creates security digital twins: **MODEL → SIMULATE → COMPARE**. A model is an
in-memory copy of a security state on which you try changes - remove an access path, add
segmentation, disable an identity, patch a vulnerability - and then measure what changed.
Nothing ever touches a real environment; there are no connectors that apply changes.

Status: **BETA** · category: synthetic environments · command: `raf ghost` · API: `/api/v1/ghost`

## Commands

```text
raf ghost create NAME [--from current|SNAPSHOT] [-d TEXT]   freeze a state as a model
raf ghost clone SOURCE NAME                                  copy a model (or 'current' / a snapshot)
raf ghost modify NAME [operations...] [--op 'OP ARG']... [--undo]
raf ghost operations                                         list the what-if operations
raf ghost simulate NAME|current                              exposure, attack paths, top risks
raf ghost compare A B                                        BASELINE / EXPERIMENT / CHANGE
raf ghost list | show NAME | delete NAME
```

`raf snapshot create after --source ghost:NAME` persists a model as a snapshot, so `raf diff`
works between real and hypothetical states.

## How models work

* **Base**: `create`/`clone current` captures the workspace in a frozen snapshot
  (`ghost-<name>-base`, content-addressed and shared with other snapshots); models built on a
  snapshot reference it. The base never changes, so a model stays reproducible while the workspace
  moves on.
* **Operations** are computed against the model's current state and stored with their explicit
  **effects** (relationships removed/added, objects added, metadata replaced) and an explanation.
  Replaying a model applies the stored effects in order - exact and fast. `--undo` drops the last one.
* **Findings** are carried over from the base when a model is turned into a state for `raf diff`;
  analyzers are not re-run inside models. `raf ghost compare` recomputes exposure instead.

## Operations

| Operation | Argument | Effect |
|---|---|---|
| `remove-access` | `A:B` | cut **every** control path from A to B with a minimum-cost set of relationship removals (Edmonds-Karp max-flow/min-cut over the control traversals; costs: credential exposure 1 - `USES`, `CONTAINS_SECRET`, `AUTHENTICATES_AS`, `LOGGED_INTO` - access grants 3, memberships 4, structural facts 50) |
| `remove-relationship` | `rel:ID` or `'SRC TYPE DST'` | remove one relationship |
| `add-segmentation` | `SRC_ZONE:DST_ZONE` | remove the zone reachability and insert a deny rule in the network policy model |
| `disable-identity` | user or identity | the account is disabled (cannot be taken over) |
| `change-role` / `add-role` / `remove-role` | `PRINCIPAL:OLD:NEW` / `PRINCIPAL:ROLE` | edit directly held roles (inherited roles are changed on the group) |
| `remove-exposure` | host or service | remove direct Internet reachability; if the host's zone is Internet-facing, the host moves to a `<zone>-internal` segment that keeps every other reachability |
| `patch-vuln` | `VULN[:ASSET]` | the vulnerability no longer affects the asset(s) |
| `isolate` | host | remove every network relationship of the host |
| `disable-rule` | `POLICY:RULE` | disable a rule in the policy model and remove reachability derived from it |
| `deny-flow` | `SRC:DST[:PORTS]` | insert a deny rule at the top of the network policy model and remove or trim the matching reachability |

References are resolved against the **model** (names, aliases, typed IDs such as `group:operations`).
Operations validate their preconditions and fail with a clear message, e.g. removing a role that is
only inherited, or cutting access where no path exists.

Example on the Raven demo:

```text
$ raf ghost clone current hardened
$ raf ghost modify hardened --remove-access alice:production
 1. remove-access alice:production → cut 3 relationship(s) so that alice no longer controls production
      remove .env CONTAINS_SECRET DEPLOY_TOKEN (credential exposure) ...
      remove DEV-01 USES svc-deploy (credential exposure) ...
      remove dave LOGGED_INTO DEV-01 (credential exposure): whoever controls DEV-01 may capture dave's session
```

The third removal is the kind of insight Ghost is for: `dave` inherits break-glass through a nested
group, so his session on DEV-01 is a second route to production.

## Compare metrics

Computed by `raf.core.risk.exposure` on each state (see [risk-model.md](../risk-model.md)):

| Metric | Meaning |
|---|---|
| `attack_paths` | (entry point, high/critical asset) pairs that are connected (network reach from external zones/workstations, or control from users) |
| `critical_paths` | pairs where a *critical* asset can be controlled (a user's control path, or network reach upgraded through an exploitable vulnerability) |
| `reachable_assets` | assets reachable or controllable from any entry point |
| `entry_points` | external zones + user workstations + users |
| `exposed_critical_assets` | high/critical assets with exposure HIGH or CRITICAL |

`compare` also lists assets whose exposure changed and, per user, the high/critical assets they
can control before and after (`lost` / `gained`).

## API

`GET /ghost/models`, `POST /ghost/models {name, base}`, `GET /ghost/models/{name}`,
`POST /ghost/models/{name}/clone {name}`, `POST /ghost/models/{name}/ops {op, arg}`,
`POST /ghost/models/{name}/undo`, `GET /ghost/models/{name}/simulate`, `DELETE /ghost/models/{name}`,
`GET /ghost/compare?a=&b=` (`{a, b, delta, assets, users, a_metrics, b_metrics}`), `GET /ghost/operations`.

## Limitations

* Network reachability is modeled at zone level (`CAN_REACH` between networks); per-port effects are
  reflected in the policy model and in trimmed `ports` metadata, not in propagation.
* Large workspaces: compare runs one propagation per entry point and principal (bounded, see the
  exposure model).
