# R$F IAM

R$F IAM analyzes identity and access relationships - users, identities, groups, roles,
permissions, resources, trusts and sessions - and reports defensively useful issues. It is
read-only: it never modifies any external identity system.

Status: **BETA** · category: exposure · command: `raf iam` · API: `/api/v1/iam`

## Commands

```text
raf iam analyze [--no-save] [--min-severity S] [--limit N]   run all analyzers, record findings
raf iam show PRINCIPAL [--limit N]                           effective access of a principal
raf iam path SOURCE TARGET [--max-depth N] [--paths N]       how SOURCE could obtain control of TARGET
```

### Two graph views

* **Grant graph** (`MEMBER_OF`, `HAS_ROLE`, `HAS_PERMISSION`, `CAN_ACCESS`, `ADMIN_OF`, `CAN_ASSUME`,
  `HAS_IDENTITY`, `CONTAINS`, `DEPLOYS_TO`): what a principal is *entitled* to - `raf iam show`.
* **Access graph** (grants plus `USES`, `LOGGED_INTO`, `CONTAINS_SECRET`, `AUTHENTICATES_AS`, `TRUSTS`,
  `RUNS`, `OWNS`): how a principal *could* obtain something, including credential exposure -
  `raf iam path`. The best path is shown first; alternatives are found by removing one relationship
  of the best path at a time (a simplified Yen's algorithm).

### Analyzers

`excessive-privilege`, `dormant-privileged`, `inherited-privilege`, `broad-role`,
`credential-exposure-path`, `risky-trust`, `privileged-without-mfa` - thresholds and severities are
documented in [risk-model.md](../risk-model.md#iam-findings-raf-iam-analyze). Settings:
`iam.dormant_days` (90), `iam.broad_role_threshold` (10).

Re-running `analyze` is idempotent; findings that no longer apply are auto-resolved.

On the Raven demo: break-glass is a broad wildcard role, `dave` inherits it through the nested
group `oncall-support → operations`, `old-admin` is dormant and has no MFA, and the deploy token of
`svc-deploy` in `/opt/deploy/.env` on DEV-01 gives every developer an unexpected path to production.

## API

| Method | Path | Result |
|---|---|---|
| GET | `/iam/analyze` | dry run: `{summary, findings, ...}` |
| POST | `/iam/analyze?persist=true` | run and record findings |
| GET | `/iam/path?source=&target=&max_depth=&limit=` | `{source, target, paths: [{confidence, hops: [{source, target, relationship_type, why, ...}]}]}` |
| GET | `/iam/principals/{ref}` | effective access |
