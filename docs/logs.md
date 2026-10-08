# Mixed and multi-source logs

Real log collections rarely hold one format: a SIEM export, a `journalctl` dump, a case folder
concatenated by an analyst, a Kubernetes node's container logs - lines from web servers, cloud
audit trails, identity providers, databases, EDR agents and applications follow each other in one
file. R$F's **multilog** parser reads such files line by line: every line is framed and decoded on
its own, so a file can mix any of the formats below. Nothing about the file has to be declared.

```text
$ raf analyze fixtures/logs/raven-multisource.log

R$F ANALYZE  raven-multisource.log
────────────────────────────────────────
Detected: Multi-source log: multilog parser (score 0.95); 9 source(s) in the first lines: nginx, app,
bind9, postgres, cloudtrail, idp, k8s-audit, netflow, edr

Running:
  ✓ Ingest (Multi-source log) 2,560 of 2,560 records accepted (multilog/1.0 + raf-native/1.0); 15 source(s):
    nginx 677, app 512, bind9 266, cloudtrail 235, idp 233, k8s-audit 231, postgres 162, netflow 143 and 7 more
  ✓ Timeline                 2,560 events indexed, 2026-10-06T21:00:02.152000Z → 2026-10-06T22:00:00.354000Z
  ✓ Graph                    526 objects and 586 relationships created; 75 objects and 158 relationships updated
  ✓ Detections               9 detection(s) (2 critical, 3 high, 2 medium, 2 low) over 2,560 events;
    2 explained (approved changes, tickets, scheduled jobs); suspected incident CASE-125236
  ...
```

The fixture is synthetic (`scripts/generate_fixtures.py`, `src/raf/data/multisource.py`): one hour of
Raven Industries activity with an attack chain buried in routine traffic and decoys. What the
detections make of it is described in [Timeline detections](products/timeline.md#detections).

## When it is used

`raf analyze`, `raf import` and `raf evidence import` pick the parser with the best sniff score over
the first 64 KiB. Multilog surveys up to 80 lines and scores:

| What the lines look like | Score | Effect |
|---|---|---|
| timestamped, from two or more sources or decoders | 0.95 | multilog wins |
| one structured format the other parsers do not know (a DNS server log, PostgreSQL, CEF, auditd ...) | 0.6 | wins over the generic `text` parser |
| timestamped free text | 0.55 | wins over `text` (multilog also extracts addresses, accounts and URLs) |
| plain syslog of `sshd`, `sudo`, `su`, `systemd-logind`, `cron`, `kernel` | 0.5 | the `syslog` parser (0.88) keeps it |
| JSON objects only | 0 | the `jsonl` parser keeps it (its normalizers choose by content) |

`--format multilog` forces it.

## Framing

Each line is split into timestamp, source tag, host, process ID, level and payload:

| Framing | Example |
|---|---|
| tagged | `2026-10-07T19:00:00.059Z nginx[edge-01] 10.24.11.25 - - "GET / HTTP/1.1" ...` (tag `nginx`, host `edge-01`) |
| ISO syslog | `2026-10-07T19:00:00Z web-01 sshd[123]: Accepted publickey ...` |
| RFC 3164 / RFC 5424 | `<34>Oct  7 19:00:00 web-01 sshd[9]: ...`, `<165>1 2026-10-07T19:00:00Z host app 77 ID47 [sd@1 a="b"] msg` |
| level | `2026-10-07 19:00:00,123 INFO [main] App - started`, `[2026-10-07 19:00:00] ERROR: boom` |
| epoch | `1696700000.123  45 10.0.0.1 TCP_MISS/200 ...` (Squid) |
| bare | JSON objects, CEF, access logs and others that carry their own timestamp |

Timestamps: ISO 8601 (`T` or space, comma or dot fractions, `Z`, offsets, ` UTC`), `YYYY/MM/DD`,
RFC 3164 (the year comes from the file's modification time, with a warning, unless the line has
one), epoch seconds or milliseconds, and the formats documented in [the object model](object-model.md).
Naive times use `ingest.default_timezone`.

**Continuations.** A line without a timestamp of its own continues the record before it (stack
traces, wrapped messages, pretty-printed JSON): it is appended to that record's message (at most 500
lines or 64 KiB) and the record's locator becomes `lines N-M`. A line without a timestamp that
continues nothing is rejected with its reason, as every rejected record is.

**Headers.** `#Fields:` (W3C extended log format: IIS and others) and Zeek `#fields` lines name the
columns of the lines that follow; other `#` lines are comments.

## Formats

Payloads are decoded in this order: JSON objects (also wrapped by Docker `{"log": ...}` lines or CRI
`stdout F ...` lines, or after a short prefix), CEF and LEEF, Windows events as XML, text formats
(those the line's tag hints at first), key=value records, free text.

| Family | Recognized by | Event types |
|---|---|---|
| AWS CloudTrail | `eventName` + `eventSource` | `cloud.api`, `auth.login`/`auth.failure` (console), `iam.*` (grants, groups, credentials, users) |
| Kubernetes audit | `kind: Event` with `auditID` / `verb` + `objectRef` | `cloud.api` (`platform: kubernetes`, verb, resource, namespace, name, status) |
| GCP audit, Azure activity | `protoPayload.methodName`; `operationName` + `caller` | `cloud.api` |
| Azure AD sign-ins, Okta | `userPrincipalName` + `status`; `eventType` + `actor` + `outcome` | `auth.*` with sessions |
| Identity providers | sign-in words in the event type (or an `idp`/`sso`/`vpn` tag) and an actor | `auth.login`, `auth.failure`, `auth.mfa`, `auth.logout` with the session |
| Windows / Sysmon | `EventID` with `Computer`/`EventData`/`winlog` (JSON, key=value or XML) | 41 Security, System and PowerShell event IDs (4624/4625 logons, 4688 processes, 4720-4757 accounts and groups, 4768-4776 Kerberos/NTLM, 1102 log cleared, 7045 services ...) and Sysmon 1/3/5/11/22/23 ... |
| Suricata EVE, Zeek | `event_type` + `src_ip`/`dest_ip`; `uid` + `id.orig_h` (JSON or TSV) | `alert`, `dns.query`, `http.request`, `tls.handshake`, `network.flow` |
| Elastic Common Schema | `@timestamp` + `ecs` / `event.category` | as the ECS normalizer |
| EDR / process telemetry | a command line or image | `process.start`, `network.connection`, `file.*`, `dns.query` |
| Flows | source and destination addresses plus bytes, ports or a decision | `network.flow` |
| Change records | a ticket (`CHG-...`) with a window, status or approval | `change.record` (the window becomes `window_start`/`window_end`) |
| Application JSON / logfmt | a level or service with an event or message | `service.access` (a person used a service), `file.read`/`file.create`/`file.delete` (downloads, exports, deletions), `auth.*`, `log.<event>` |
| DNS, HTTP, database records | query + answer fields; method + path + status; statement + database | `dns.query`, `http.request`, `db.query` |
| Web access logs | NCSA common/combined, with or without their own time, vhost prefix and key=value tail (`rt=`, `rid=`, `upstream=`) | `http.request` |
| nginx error log | `PID#TID: *CID message, client: ..., request: "..."` | `http.request` (failed) or `log.web_error` |
| BIND, dnsmasq | `client IP#PORT: query: NAME IN TYPE`; `query[A] NAME from IP` | `dns.query` (BIND's `(ADDRESS)` is the address the query arrived on: the logging server `HAS_ADDRESS` it) |
| PostgreSQL | `user=... db=... LEVEL:` prefixes or `[pid] user@db LEVEL:` | `db.query` (duration, verb, tables, risky statements), `auth.login`/`auth.failure`/`auth.logout` |
| Linux audit | `type=... msg=audit(EPOCH:SERIAL):` | `auth.*`, `process.start` (EXECVE, decoded arguments), `auth.privilege` (sudo), `iam.*` |
| Cisco ASA / FTD | `%ASA-SEV-ID:` | `network.connection` (deny/built), `network.flow` (teardown), `auth.*` |
| Squid | epoch + `CODE/STATUS` | `http.request` |
| AWS VPC flow logs | default version 2 format | `network.flow` |
| S3 server access logs | the standard space-separated format, or key=value with `bucket` and `op` | `file.read`/`file.create`/`file.delete`, `cloud.api` (listings) |
| CEF, LEEF | `CEF:0|...`, `LEEF:1.0|...` / `LEEF:2.0|...` (after a syslog prefix too) | `alert`, `auth.*`, `http.request`, `network.connection` |
| syslog daemons | `sshd`, `sudo`, `su`, `systemd-logind`, `cron`, kernel firewall lines (`SRC= DST=`) | as the syslog parser |
| anything else | free text | `auth.failure`/`auth.login` from their usual wording, `network.connection` for denials, else `log.message`; addresses, e-mail accounts, user names and URLs become involved objects |

Fields that no decoder maps are kept as event attributes (bounded), so nothing a line says is lost;
the raw line is kept as the event's raw excerpt (`ingest.store_raw`).

## What becomes objects

Decoders state the role every object plays in an event, which is what Graph, Trace, Lens and the
detections work with:

| Object | From |
|---|---|
| users, identities, roles | actors (`user@domain` and `DOMAIN\user` are normalized; an assumed AWS role is its role, the session name an attribute; Kubernetes service accounts and database roles are identities) |
| sessions | identity-provider session IDs (`session:<app>|<id>`), linked to every event of the session |
| secrets | the access key a cloud call was signed with (`secret`, role `credential`): its name is redacted (`AKIA****MPLE`) and its key is a SHA-256 fingerprint; credential fingerprints logged by jobs |
| files | S3 objects (`s3://bucket/key`), downloaded or exported artifacts and the entries of their manifests (`CONTAINS`) |
| hosts, IPs, domains, URLs, services | reporters, clients, servers, upstreams, databases (`database@host`) |

Relationships follow from events ([object model](object-model.md#relationships)); in addition a
credential `AUTHENTICATES_AS` the identity that used it and the source address `USES` it, a bucket
`CONTAINS` the objects read from it, and an identity `READ` them.

## Redaction

Values of credential-like fields (`password`, `token`, `secret`, `api_key`, `Authorization`,
`cookie` ...) are stored redacted; secret-looking substrings of messages, URLs, query strings and SQL
statements are masked (bearer tokens, `password=...`, private keys, access key IDs, literal
passwords in `ALTER USER ... PASSWORD '...'`). The raw excerpt of the line is evidence and is kept
as received (bounded by `ingest.raw_max_bytes`; `ingest.store_raw false` keeps none).

## Importing again

Events are identified by source content and line, so importing a file again creates no duplicates.
When the same file was imported before with another parser - for example as plain text, before
multilog existed - its events are **re-read**: the new parse replaces their content and involved
objects, keeps their identity, import job and incident links, and the import report counts them
(`12,448 re-read with the current parser`). The analysis scope then includes the job that first
imported them.

## Limits

* Lines longer than `ingest.max_record_kb` are rejected; JSON nesting is limited to 64 levels,
  key=value records to 256 pairs, attributes kept per event to 64.
* A source tag is a hint: decoders validate their own format, and a line whose tag is unknown is
  still decoded by content.
* Free-text extraction is pattern based; it does not infer meaning beyond the wording it lists.
* Formats that need multi-line structure (XML documents spanning lines, multi-line JSON exports)
  are folded into one record's message rather than decoded field by field; export them as one object
  per line.
