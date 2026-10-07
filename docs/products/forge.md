# R$F Forge

R$F Forge generates realistic but synthetic security telemetry - authentication, DNS, HTTP,
process, file, identity and cloud-audit events - and modeled scenarios. Every record carries
`synthetic: true` and the `forge` tag; scenarios describe suspicious behavior purely as events
(no payloads, no real credentials, `.example` domains and documentation IP ranges only).

Status: **BETA** · category: synthetic environments · command: `raf forge` · API: `/api/v1/forge`

## Commands

```text
raf forge auth|dns|web|process|file|identity|cloud [--count N] [--seed S] [--start T] [--hours H]
                                                   [--noise 0..1] [--population P] [-o FILE [--ingest]]
raf forge scenario NAME [--seed S] [--start DAY] [--population P] [-o FILE [--ingest]]
raf forge list
```

* `--count` up to 1,000,000 (the API allows 100,000 per request).
* `--start`/`--hours`: the time window (default: the day after the newest event in the workspace,
  24 hours) - the chosen window is printed so a run can be reproduced exactly with the same seed.
* `--noise`: share of unusual-but-benign records (failed logons from documentation addresses, rare
  NXDOMAIN names, 4xx/5xx responses, sensitive file paths, policy changes ...).
* `--population`: `auto` (default: the workspace's users, workstations, servers and identities if
  present, so generated events connect to the existing graph), `workspace`, `raven` or `generic`.
* By default results are imported into the workspace (`synthetic` source, a job you can inspect);
  `-o FILE` writes R$F native JSONL instead (`--ingest` to do both).

## Scenarios

| Scenario | Models |
|---|---|
| `suspicious-access` | password failures then an off-hours VPN login from a documentation address, first-time logon to the most critical server, bulk file read, DNS to `files.exfil-test.example` and a large outbound transfer to `198.51.100.23`, plus a synthetic alert |
| `credential-risk` | a token written to a developer's file (value modeled and redacted) **with a credential-placement relationship**, the service account used from that workstation, a new access key, and a password-spray pattern against an admin account |
| `lateral-movement` | a workstation session followed by remote logons across hosts with an admin identity |

Each scenario creates an incident `SIM-<SCENARIO>-<SEED>`, so `raf timeline`, `raf replay`,
`raf trace` and `raf blast` work on it. Because `credential-risk` adds a `USES` relationship from the
workstation to the service identity, `raf iam analyze` and `raf exposure` pick up the new credential
exposure path.

## Determinism

Generators and scenarios are seeded (`random.Random` with the seed and the generator/scenario
name); the same population, window, count, noise and seed produce identical records, including
event IDs, so re-importing is idempotent.
