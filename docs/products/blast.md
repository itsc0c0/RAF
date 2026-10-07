# R$F Blast

R$F Blast estimates the impact of a **hypothetical** compromise: given an object assumed
compromised (user, identity, host, service ...), it propagates over the shared graph with the
documented traversal semantics and reports what could be controlled or merely reached, how, and an
explainable risk level. Nothing is executed against any system - this is analysis of recorded
relationships.

Status: **BETA** · category: exposure · command: `raf blast` · API: `GET /api/v1/blast/{ref}`

## Usage

```text
raf blast REF [--max-depth N] [--min-confidence C] [--at TIME] [--all]
```

* `REF` - any object reference (`alice`, `USER-17`, `WS-04`, `svc-deploy`, `@last`)
* `--max-depth` (default `blast.max_depth` = 8) and `--min-confidence` (default `blast.min_confidence` = 0.2)
* `--at` - use the graph as it was at that time (relationships valid then)
* `--all` - list every reached object

Output: reachable/controllable/critical asset counts, privilege paths, the **primary path** (to the
most critical controllable asset) with a "why" for each hop, the risk factors and a table of
critical assets. `--json` emits `raf.blast/v1`.

```text
$ raf blast alice
Primary path
alice → MEMBER_OF engineering → HAS_ROLE developer → CAN_ACCESS DEV-01 → USES svc-deploy
      → MEMBER_OF deployers → HAS_ROLE prod-deployer → CAN_ACCESS ci-cd → DEPLOYS_TO production
Risk  CRITICAL (100/100)
```

## Model

See [risk-model.md](../risk-model.md): control vs reach vs trust modes, confidence factors,
vulnerability upgrades, disabled identities, Pareto-front search, and the blast factor table.
Network reachability alone never counts as control; it is reported separately
(`blast.critical-reach`).

## Limitations

* Results are only as complete as the imported relationships; missing data means missing paths.
* Port-level policy decisions are not part of propagation (`CAN_REACH` edges carry ports as
  explanation). Use `raf policy can` for port-precise flow decisions.
