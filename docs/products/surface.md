# R$F Surface

R$F Surface models an organization's **authorized external attack surface**: its domains and the
names below them, the addresses they resolve to, the services listening there, the certificates
those services present, its cloud assets, and who owns each of them. It works from **imported
inventories** (CMDB and IPAM exports, DNS zone exports, certificate inventories, cloud asset lists)
and an **authorized scope** the operator declares, correlates everything in the shared graph and
produces explainable findings.

Status: **BETA** · category: exposure · command: `raf surface` · API: `/api/v1/surface`

## No scanning

R$F Surface never touches the network: no DNS resolution, no port scanning, no HTTP requests, no
certificate retrieval, no WHOIS lookups. Everything it knows comes from the files (or API bodies)
you import and the scope you declare; discovery belongs to authorized tools whose output you
import. A finding therefore means "according to the imported data" - a dangling DNS record, for
example, is judged from the records and inventory you supplied, so confirm it before acting.

## Quick start (Raven Industries)

```text
raf demo load                  # also imports the Raven inventory, applies its scope and analyzes it
raf surface show
raf surface findings
```

`raf demo load` imports `fixtures/surface/raven-surface.json`, the synthetic inventory of the demo
organization, with `--apply-scope` semantics, then runs `raf surface analyze`. To do the same by
hand in another workspace:

```text
raf surface scope add raven.example --owner "IT operations" --authorization SEC-2026-031
raf surface import fixtures/surface/raven-surface.json --apply-scope
raf surface analyze
```

`raf surface sample FILE` writes the same document; `scripts/generate_fixtures.py --check` and a
test keep the fixture in sync with the generator. `raf analyze FILE` also recognizes inventories
(it imports and analyzes, but never changes the scope).

## Commands

```text
raf surface [show] [--at TIME] [--expiring-days N]     summary and the domain → address → service/certificate tree
raf surface scope add TARGET [--kind K] [--owner O] [--authorization REF] [--replace]
raf surface scope list
raf surface scope remove TARGET                         asks for confirmation (--yes in scripts)
raf surface import FILE [--apply-scope] [--format json|jsonl|yaml|csv] [--source-name NAME]
raf surface analyze [--at TIME] [--expiring-days 30] [--no-save] [--limit N]
raf surface assets [--kind K] [--in-scope | --out-of-scope] [--all] [--limit N]
raf surface findings [--rule R] [--min-severity S] [--status open|resolved|...|all]
raf surface sample OUTPUT                               write the Raven sample inventory
```

All commands accept the global flags (`--json`, `--quiet`, `--workspace` ...). JSON documents carry a
schema id: `raf.surface.summary/v1`, `raf.surface.scope/v1`, `raf.surface.scope.entry/v1`,
`raf.surface.import/v1`, `raf.surface.analysis/v1`, `raf.surface.assets/v1`,
`raf.surface.findings/v1`, `raf.surface.sample/v1`. Findings are ordinary R$F findings (product
`surface`): `raf findings --product surface`, `raf finding show ID`, `raf finding ack ID` work as for
every product.

`raf import FILE` also recognizes surface inventories (parser `raf-surface/1.0`, detected by the
`raf-surface/1` marker, or a CSV header with a `kind` column holding surface record kinds) and writes
the same objects and relationships as `raf surface import`. It never changes the authorized scope:
a `scope` section is reported as a warning.

## Authorized scope

The scope is stored per workspace (key-value namespace `surface.scope`). Each entry has a `target`,
a `kind`, an optional `owner` (who is accountable for the entry), an `authorization` reference
(free text such as a ticket) and `added_at`.

| Kind | Example | Covers |
|---|---|---|
| `domain` | `raven.example` | the name and every name below it (`www.raven.example`, `a.b.raven.example`), never `notraven.example` |
| `cidr` | `198.51.100.0/28` | every address in the range; host bits are cleared (`198.51.100.7/28` → `198.51.100.0/28`); prefixes broader than /8 (IPv4) or /32 (IPv6) are refused |
| `ip` | `198.51.100.20` | exactly that address (IPv4 or IPv6) |
| `cloud_account` | `examplecloud:raven-prod` | cloud assets recorded with that provider and account |

The kind is inferred when `--kind` is omitted (`/` → cidr, an address → ip, `provider:account` →
cloud_account, otherwise domain). Wildcards are refused (a domain entry already covers its
subdomains). The most specific entry wins when several cover an asset. Adding an existing target
with other details is a conflict unless `--replace` is given; adding it with the same details is a
no-op. Every change is written to the audit log.

How assets are judged:

* a **name** is in scope when a domain entry covers it, or when it is the endpoint of an in-scope
  cloud asset (a load balancer's provider host name);
* an **address** when a cidr/ip entry covers it (or it is the address of an in-scope cloud asset);
* a **service** through its endpoint; a **cloud asset** through its account (or its endpoint/address);
* a **certificate** when it is presented at an in-scope endpoint or names an in-scope host.

Assets outside the scope are recorded and shown, but **never treated as owned**: ownership,
certificate, DNS and exposure rules do not judge them; `out-of-scope-asset` reports them instead.
Without any scope entry nothing is treated as owned and analysis produces no findings (it says so).

Scope only changes through an explicit operator action: `raf surface scope add/remove`, the API,
or `raf surface import FILE --apply-scope` after reviewing the file's `scope` section (entries that
conflict with existing ones are reported and the existing entry is kept).

## Inventory format (`raf-surface/1`)

A JSON or YAML document with an optional header, an optional `scope` section and records - either a
flat `records` list with a `kind` per record, or per-kind sections (`domains`, `dns`, `ips`,
`services`, `certificates`, `cloud_assets`, `owners`). A plain JSON list of records is accepted too.

```json
{
  "format": "raf-surface/1",
  "organization": "Raven Industries",
  "as_of": "2026-10-07T00:00:00Z",
  "scope": [
    {"target": "raven.example", "kind": "domain", "owner": "IT operations", "authorization": "SEC-2026-031"},
    {"target": "198.51.100.0/28", "kind": "cidr", "owner": "IT operations", "authorization": "SEC-2026-031"}
  ],
  "records": [
    {"kind": "domain", "name": "raven.example", "owner": "IT operations", "registrar": "example-registrar",
     "expires": "2027-08-14T00:00:00Z"},
    {"kind": "dns", "name": "vpn.raven.example", "type": "A", "value": "198.51.100.10", "ttl": 300},
    {"kind": "dns", "name": "git.raven.example", "type": "A", "value": "10.20.0.11", "view": "internal"},
    {"kind": "ip", "address": "198.51.100.10", "owner": "IT operations", "host": "VPN-01", "asn": "AS64500"},
    {"kind": "service", "name": "vpn", "ip": "198.51.100.10", "port": 443, "protocol": "tcp",
     "product": "Raven VPN appliance 7.1", "internet_facing": true, "server": "VPN-01", "role": "remote-access"},
    {"kind": "certificate", "subject_cn": "vpn01-mgmt.raven.example", "sans": ["vpn01-mgmt.raven.example"],
     "not_after": "2027-01-10T00:00:00Z", "fingerprint_sha256": "7b2a...", "presented_by": ["198.51.100.10:443"]},
    {"kind": "cloud_asset", "provider": "examplecloud", "account": "raven-prod", "type": "bucket",
     "name": "raven-public-assets", "public": true, "classification": "public", "owner": "Platform"},
    {"kind": "owner", "owner": "Platform", "asset": "domain:shop.raven.example"}
  ]
}
```

**JSON Lines**: one record per line; an optional first line without `kind` is the header
(`{"format": "raf-surface/1", "scope": [...]}`). **CSV**: a header row with a `kind` column and
one column per field; list fields (`sans`, `presented_by`, `tags`) are separated by `;`, `,`, `|`
or spaces. **YAML** is read with a safe loader that also refuses aliases; quote values YAML would
otherwise convert (for example hexadecimal serials).

| Kind | Fields (aliases) |
|---|---|
| `domain` | **name** (domain, fqdn), owner, registrar, expires, status (active, decommissioned), criticality, notes, tags |
| `dns` | **name**, **type** (A, AAAA, CNAME, MX, NS, TXT), **value**, ttl, view (external - default - or internal), priority (MX; `10 mx.example` also works), status (active, removed), removed_at |
| `ip` | **address** (ip), owner, provider, asn, host (server: the host holding the address), status, criticality, notes, tags |
| `service` | **ip** or **host** (the endpoint; a host name with dots), **port**, protocol (tcp, udp), product, name, internet_facing, server (the host running it, such as VPN-01), owner, criticality, role (for example bastion, remote-access), status, notes, tags |
| `certificate` | subject_cn (cn, subject - `CN=...` is parsed), sans, issuer, serial, not_before, not_after, **fingerprint_sha256** (or issuer + serial), presented_by (`198.51.100.10:443`, `[2001:db8::1]:443`, `host.example:443`; port 443 by default; `/udp` suffix), self_signed, owner, status (active, removed), notes |
| `cloud_asset` | **provider**, account, **type** (bucket, container, load_balancer, vm ...), **name**, public, owner, region, endpoint (host name or URL), address, classification, criticality, resource_id, status, notes, tags |
| `owner` | **owner**, **asset** (`domain:NAME`, `ip:ADDRESS`, `service:NAME` or `service:ADDRESS:PORT/PROTO`, `host:NAME`, `certificate:SHA256`, `cloud_asset:NAME` (same file) or `cloud_asset:provider/account/type/name`), asset_kind, contact, status (active, removed), removed_at |

Owners are teams or organizations by default; `user:NAME` and `group:NAME` make the owner a
principal (an `OWNS` edge from a principal is a control path for Blast and Exposure). An asset's
`status` (`decommissioned`) is only changed by records that state it. A `removed` DNS or owner
record, or a `removed` certificate (no longer presented),
**ends** the relationship (`valid_to`) instead of deleting it, so the analysis stops using it and
the history stays queryable.

## How records map to the object model

| Record | Objects and relationships |
|---|---|
| domain | `domain:<name>` (+ `<owner> OWNS domain`) |
| dns A / AAAA | `domain:<name> RESOLVES_TO ip:<address>` (metadata `record_type`, `view`, `ttl`) |
| dns CNAME | `domain:<name> RESOLVES_TO domain:<target>` |
| dns MX / NS | `domain:<name> RELATED_TO domain:<target>` (metadata `record_type`, `priority`) |
| dns TXT | `metadata.txt` of the name (the values of the latest import, at most 20) |
| every name | `domain:<child> PART_OF domain:<closest ancestor named in the same inventory>` |
| ip | `ip:<address>` (+ `host:<server> HAS_ADDRESS ip`) |
| service | `service:<name or address:port/proto> LISTENS_ON port:<address>:<port>`, `port HAS_ADDRESS ip/domain`, `host:<server> RUNS service` |
| certificate | `certificate:<sha256> ISSUED_FOR domain:<cn/san>` (up to 100 names; wildcards stay in metadata), `port:<endpoint> PRESENTS certificate` |
| cloud_asset | `cloud_resource:<provider>/<account>/<type>/<name> HAS_ADDRESS domain:<endpoint> / ip:<address>` |
| owner | `organization:<owner>` (or `user:` / `group:`) `OWNS <asset>` |

Subdomains point to their parent with **`PART_OF`** (child → parent), not `CONTAINS`: containment
has traversal semantics in Blast/Exposure and in policy resource matching, while a DNS name being
below another says nothing about control. Views compute the hierarchy from the names themselves, so
inventories imported separately still nest correctly.

Every object Surface writes carries `metadata.surface.sources` (how surface data saw it: `inventory`,
`dns`, `dns-target`, `certificate`, `endpoint`, `owner`; it accumulates across imports) and the
`surface` tag; relationships carry `metadata.surface = true` and `last_seen` (the document's `as_of`,
else the import time). Imports run as `import` jobs through the core ingestion pipeline: provenance,
rejection quarantine and `raf import report <job>` work as for any import. Names already in the
workspace are reused: in the Raven demo, `service:vpn`, `host:VPN-01` and `domain:www.raven.example`
are the same objects the rest of R$F already knows.

**Assets and references.** Assets are what the organization's data declares: names with inventory
or DNS records, service and cloud endpoints, inventoried addresses, services, certificates and cloud
assets. Names seen only as DNS answers or in certificates, and addresses seen only as DNS answers,
are references: shown in the tree and with `raf surface assets --all`, never judged on their own.

**Ownership** is the inventory's `owner` field or an `OWNS` relationship. Addresses inherit the
owner of the host (or cloud asset) that holds them, services the owner of the host running them,
certificates the owner of the service or cloud asset presenting them, endpoint names the owner of
their cloud asset. Names do not inherit from their parent domain: the zone owner is not
necessarily accountable for what a record points at.

## Rules

Every finding starts at a baseline severity and moves one level per named factor; each step is an
`explanation` entry (`+` raises, `-` lowers), so a finding always states why it has its severity.
The reference time for certificates is `--at`, else the newest event in the workspace, else now.

| Rule | Fires when | Baseline | Raised by | Lowered by | Range |
|---|---|---|---|---|---|
| `out-of-scope-asset` | the organization's data references an asset no scope entry covers (related names, endpoints and services fold into one finding) | LOW | the asset inventory lists it as the organization's | - | LOW-MEDIUM |
| `unowned-asset` | an in-scope inventory asset (name, address, service, cloud asset) has no owner, recorded or inherited | LOW | internet-facing; criticality high/critical (of the asset or its host) | - | LOW-HIGH |
| `expired-certificate` | an in-scope certificate's `not_after` is before the reference time | MEDIUM if presented, else LOW | presented at an internet-facing endpoint; presenting service high/critical | - | LOW-HIGH |
| `expiring-certificate` | ... within `--expiring-days` (default 30) | LOW | internet-facing endpoint; less than 7 days left; high/critical service | - | LOW-HIGH |
| `certificate-name-mismatch` | an endpoint presents certificates whose CN/SANs (wildcards per RFC 6125) do not cover an in-scope name that resolves to it (TLS name ports such as 443/8443/993, or a host-name endpoint) | LOW | internet-facing; the service is remote access/SSO or high/critical | - | LOW-HIGH |
| `dangling-dns` | an external CNAME of an in-scope name leads to a decommissioned target, or to a name with no inventory record and no A/AAAA/CNAME record (chains followed); an A/AAAA record points to a decommissioned address, or to an address outside the scope that is not in the inventory | HIGH when the target is outside the scope (claimable: subdomain takeover), MEDIUM inside | criticality of the name | - | MEDIUM-CRITICAL |
| `exposed-sensitive-service` | an internet-facing in-scope service is remote administration, remote desktop, a database, file sharing ... (ports 22, 23, 135, 139, 161, 445, 623, 1433, 1521, 2049, 2375/2376, 3306, 3389, 5432, 5900, 5984, 5985/5986, 6379, 9042, 9200, 11211, 27017, or the product name, such as OpenSSH, Terminal Services, PostgreSQL, Redis) | per service: SSH, FTP, SNMP MEDIUM; RDP, VNC, Telnet, SMB, databases HIGH; Docker API (2375) CRITICAL | criticality high/critical (service or host); no accountable owner | role `bastion` (a deliberately exposed, hardened entry point) | LOW-CRITICAL |
| `public-cloud-storage` | an in-scope bucket/container/storage account/file share is `public` | MEDIUM | sensitive classification (confidential, restricted, internal, pii ...); criticality high/critical; a name suggesting non-public content (backup, dump, logs ...) | classification `public` | LOW-CRITICAL |
| `shadow-asset` | an in-scope name has external A/AAAA/CNAME records but no inventory record (and is not the endpoint of an inventoried service or cloud asset); names whose records are dangling are reported as `dangling-dns` only | LOW | it resolves to an in-scope address that is not in the inventory either (an unknown system) | it resolves to a known address (informational) | LOW-MEDIUM |
| `internal-address-in-dns` | an external-view A/AAAA record of an in-scope name points to an internal address (RFC 1918, CGNAT, loopback, link-local, ULA ...) | LOW | the address belongs to a high/critical host | - | LOW-MEDIUM |

Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) are treated as
public addresses (R$F demos use them as such). Finding IDs are stable (`raf.core.ids.finding_id`
over the rule and its subject), so re-analysis updates findings instead of duplicating them, keeps
analyst decisions (acknowledged, false positive, suppressed), and auto-resolves open findings whose
condition no longer holds - an owner was recorded, a record was removed, the scope changed, a
certificate was renewed.

### On the Raven fixture

With the fixture's scope and the demo loaded (reference time 2026-10-07T01:06:00Z, the newest event):

| Finding | Severity | Why |
|---|---|---|
| Internet-facing RDP on 198.51.100.12:3389 (JUMP-01) | CRITICAL | RDP baseline HIGH; criticality high; no owner |
| No accountable owner: Microsoft Terminal Services on 198.51.100.12:3389 | HIGH | internet-facing; criticality high |
| Certificate name mismatch at 198.51.100.10:443 (vpn.raven.example) | HIGH | internet-facing; remote-access service; self-signed appliance certificate |
| Expired certificate: shop.raven.example (2026-09-30) | HIGH | presented on the internet-facing web service |
| Certificate expires in 21 days: api.raven.example | MEDIUM | presented by the public load balancer |
| Dangling DNS record: legacy-ftp.raven.example CNAME ftp-old.raven.example | MEDIUM | target decommissioned (FTP-OLD), inside the scope |
| Shadow asset: staging.raven.example | MEDIUM | resolves to 198.51.100.13, in Raven's range but in no inventory |
| Internal address in external DNS: dc01.raven.example → 10.10.0.5 | MEDIUM | the address belongs to DC-01 (domain controller, critical) |
| Outside the authorized scope: raven-launch.example (+ www) | MEDIUM | agency-run microsite claimed by Marketing |
| Internet-facing SSH on 198.51.100.11:22 | LOW | SSH baseline MEDIUM; role bastion |
| Public cloud storage: raven-public-assets | LOW | classified public |
| Shadow asset: jump.raven.example | LOW | resolves to an inventoried address (JUMP-01) |
| No accountable owner: domain ci.raven.example | LOW | - |

## Views

`raf surface show` prints the scope, asset counts per kind, in/out of scope, internet-facing assets,
owners, open findings by severity, the **domain tree** (domain → subdomains → DNS records → addresses
and their hosts → services and certificates, with cloud assets behind CNAMEs and certificate states
at the reference time), addresses without a name, cloud assets, assets outside the scope and the top
findings. `raf surface assets` lists assets with their scope entry, owner (and where it is inherited
from; claimed owners of out-of-scope assets are shown as claims), a one-line summary and their open
findings.

## API

| Method | Path | Description |
|---|---|---|
| GET | `/surface/summary?at=&expiring_days=` | the summary (same document as `raf surface show --json`) |
| GET | `/surface/assets?kind=&scope=in\|out\|all&references=&limit=&offset=` | `{items, total, limit, offset}` |
| GET | `/surface/scope` | `{items, total}` |
| POST | `/surface/scope` `{target, kind?, owner?, authorization?, replace?}` | 201 `{entry, result: added\|replaced\|unchanged}`; 409 on conflict |
| DELETE | `/surface/scope/{target}` | `{entry, result: removed}` (CIDR targets contain `/`, which the path accepts) |
| POST | `/surface/import?apply_scope=&format=&source_name=` | body: a raf-surface/1 document or a JSON list of records (also `format=jsonl\|yaml\|csv`); returns the import result |
| POST | `/surface/analyze?at=&expiring_days=&persist=` | the analysis with all findings |
| GET | `/surface/findings?rule=&min_severity=&status=open\|...\|all&limit=&offset=` | `{items, total, limit, offset}` |

Imports reach the API only as request bodies: no route accepts a server-side path. Bodies above
20 MB are refused with 413 (before they are buffered when `Content-Length` says so).

## Untrusted input

Inventories are untrusted. Surface reads them with safe parsers only (`json`, `csv`, a YAML safe
loader that refuses aliases and arbitrary tags), limits documents to 20 MB, 50,000 records, 1 MB per
JSON Lines line, 64 fields per record, 500 certificate names and 100 entries per other list field,
and refuses nesting deep enough to exhaust the parser. Text is stripped of control characters,
terminal escape sequences, zero-width and bidi-override characters and bounded in length; names,
addresses, ports, fingerprints, timestamps and booleans are validated. A broken document is refused
with a readable reason; a broken record is rejected with its locator (`records[12]`, `line 7`) and
reason, quarantined with the job, and the rest of the file is imported. Nothing is executed,
resolved or fetched.

## Limitations

* Judgments are only as good as the imported data: R$F cannot see records, services or certificates
  that are not in an inventory (TLS endpoints with SNI may present more certificates than recorded).
* There is no public-suffix list: a domain scope entry covers names by label suffix, and Surface
  cannot tell a registrable domain from a public suffix such as `co.uk` (only single-label scopes are
  refused).
* Domain registration expiry (`expires`) is recorded and shown, but there is no expiry rule for it
  yet; WHOIS and RDAP data are not imported.
* Owners and records accumulate across imports: an owner change adds an `OWNS` relationship (end the
  old one with an `owner` record with status `removed`), and an asset's status is only changed by
  records that state it. TXT values are replaced by the latest import that has any for the name.
