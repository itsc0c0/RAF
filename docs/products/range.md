# R$F Range

R$F Range creates synthetic organizations for cybersecurity training and testing: users,
identities, workstations, servers, services, networks, groups, roles, reachability rules, synthetic
vulnerabilities and routine background activity. Everything is fictional (`.example` domains,
documentation IP ranges), marked synthetic, and deterministic for a configuration and seed.

Status: **BETA** · category: synthetic environments · command: `raf range` · API: `/api/v1/range`

Range is a **lightweight simulation**: no virtual machines or containers. The organization is
written into the current workspace as ordinary security objects, so every product (Graph, Blast,
IAM, Exposure, Ghost, Timeline ...) works on it. Activity is generated in *simulated time*.

## Commands

```text
raf range create NAME [--preset P] [--seed N] [--config FILE] [options]
raf range start NAME [--hours 24]        generate routine activity for the next period (status: running)
raf range tick NAME [--hours 24]         advance a running range
raf range stop NAME                      stop generating (data stays)
raf range reset NAME [--yes]             remove what the range generated, recreate its inventory (same seed)
raf range destroy NAME [--yes]           remove what the range generated and forget the range
raf range status [NAME] | list | presets
```

Options for generic organizations: `--employees`, `--workstations`, `--servers`, `--departments a,b`,
`--services dns,web,...`, `--mfa-rate 0.8`, `--segmentation/--no-segmentation`, `--event-rate`,
`--vulnerabilities`, `--start` (simulated start, default `2026-10-05T00:00Z`).

Without `--seed` (or `seed` in `POST /range/ranges`), `raf range create` uses the
`range.default_seed` setting (42 unless configured: `raf config set range.default_seed 7`); the seed
must be between 0 and 2^31. The seed is stored with the range, so `reset` regenerates the same data.

`create`, `status NAME`, `start`, `tick`, `stop` and `reset` remember the range as `@range`, and
every command that takes `NAME` also takes `@range` (or `@last`): `raf range tick @range --hours 8`.

## Presets

| Preset | Organization |
|---|---|
| `raven` | Raven Industries - the demo organization (its inventory and routine working days; seeds vary the activity) |
| `acme` | the specification's example: 30 employees, 20 workstations, 5 servers, engineering/finance/hr/operations, dns/web/database/git |
| `small-office` | 10 employees, flat network (no segmentation), dns/mail/file, low MFA adoption |
| `enterprise` | 200 employees, 25 servers, nine departments, every catalog service |

`raf range create raven` picks the `raven` preset by name; any other name defaults to `acme`.

### Configuration file

```yaml
name: acme
employees: 30
workstations: 20
servers: 5
departments: [engineering, finance, hr, operations]
services: [dns, web, database, git]          # dns directory web database git mail file ci vpn backup monitoring
admins: 2
event_rate: 12                               # events per active user-hour
vulnerabilities: 3
security controls:
  mfa: 0.8                                   # share of users with MFA
  segmentation: true                         # false = flat internal network ("any" between zones)
  edr: true
```

Unknown keys are rejected; files are limited to 256 KB and parsed with safe loaders.

## What gets generated

* **Inventory**: users (with departments, titles, MFA), admin identities for operations staff,
  service identities whose credentials sit on their servers, groups per department, roles
  (service access, `server-admin`), networks (`INTERNET`, `<ORG>-CORP`, `<ORG>-SERVERS`, `<ORG>-DMZ`),
  hosts and services, reachability rules derived from the services and the segmentation control,
  and synthetic vulnerabilities (`SIM-<ORG>-...`).
* **Activity** (per simulated hour): logons (with occasional failures), process starts, DNS, web
  requests, service access with network connections, logoffs, and scheduled service-account jobs.

## Lifecycle and data ownership

Every write is an ingestion job recorded in the range state. `reset` and `destroy` remove exactly
what those jobs wrote: an object, relationship or event is deleted only when *all* of its provenance
comes from the range; objects that other imports also contributed (for example `user:alice` from an
HR export) are kept. Both ask for confirmation (`--yes` in scripts).

## API

`GET /range/presets`, `GET /range/ranges`, `POST /range/ranges {name, preset?, seed?, config?, start?}`,
`GET /range/ranges/{name}`, `POST /range/ranges/{name}/start|tick {hours}`, `POST .../stop`,
`POST .../reset`, `DELETE /range/ranges/{name}`.

## Limitations

* No live services or traffic; activity is generated as events in simulated time (use R$F Lab for
  isolated containers).
* `start`/`tick` generate a period synchronously; nothing runs in the background.
