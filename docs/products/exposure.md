# R$F Exposure

R$F Exposure combines assets, services, vulnerabilities, identities, relationships and criticality
into a contextual exposure model. It is deliberately **not** a CVSS sort: an Internet-facing,
critical asset with privileged relationships matters more than an isolated low-value test host with
a higher CVSS. Every score is a list of named factors with points and evidence.

Status: **BETA** · category: exposure · command: `raf exposure` · API: `/api/v1/exposure`

## Commands

```text
raf exposure [--min-level L] [--type T] [--limit N] [--no-save]   rank assets, record HIGH/CRITICAL findings
raf exposure show ASSET                                            explain one asset factor by factor
```

`raf exposure show` lists the score factors, vulnerabilities, entry points (Internet zones and user
workstations) with the network path from each, principals that can obtain control (and whether the
path is privileged or uses exposed credentials), and the critical assets this asset is a stepping
stone to.

## Model

Factor table and methodology: [risk-model.md](../risk-model.md#asset-exposure-raf-exposure).
The model lives in `raf.core.risk.exposure` and works on any graph state, which is how Ghost
compares exposure between a baseline and a what-if model.

On the Raven demo, `VPN-01` ranks first (direct Internet exposure, CVSS 9.8 with exploit, high
criticality) and `LAB-01` ranks last despite CVSS 9.1 with an exploit, because no entry point can
reach the isolated lab zone.

## API

| Method | Path | Result |
|---|---|---|
| GET | `/exposure?limit=&min_level=&type=` | `{items: [{object, score, level, factors, entry_points, vulnerabilities, controllers, ...}], total, metrics, by_level}` (read-only) |
| GET | `/exposure/{ref}` | one explained assessment |
| POST | `/exposure/analyze` | recompute and record findings |
