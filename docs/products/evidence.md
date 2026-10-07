# R$F Evidence

R$F Evidence is the DFIR case-management foundation: cases, evidence items with SHA-256 hashes,
read-only storage, a hash-chained chain of custody, verification, and parsing that always works on
the stored copy so every derived fact points back to the artifact it came from.

Status: **BETA** · category: specialized analysis · command: `raf evidence` · API: `/api/v1/evidence`

## Commands

```text
raf evidence case create NAME [--title T] [--description D] [--incident REF]
raf evidence case list | case show NAME
raf evidence import PATH --case NAME [--no-parse] [--note TEXT] [--derived-from ITEM] [--synthetic]
raf evidence list [--case NAME]
raf evidence show ITEM                      metadata + full chain of custody
raf evidence verify [ITEM...] [--case NAME] re-hash stored copies, check every custody chain (exit 5 on failure)
raf evidence note ITEM TEXT
raf evidence export ITEM --output PATH      copy out a verified item (recorded in custody)
```

A case named like an existing incident (`INC-001`) is linked to it automatically; `--incident`
links any incident explicitly.

## What every item records

| Field | Meaning |
|---|---|
| `id` | `ev-0001` ... (graph object `evidence:ev-0001`) |
| `case` | owning case |
| `source` | absolute path of the original artifact |
| `imported_at` | import time (UTC) |
| `sha256`, `size` | hash and size of the original, computed while copying |
| `type`, `media_type` | detected format (`syslog`, `jsonl`, `csv`, `pcap`, `text`, `binary` ...) and media type |
| `stored` | location of the read-only copy: `evidence/<sha[:2]>/<sha><ext>` in the workspace |
| `notes` | analyst notes |
| `derived_from` | the item this artifact was derived from (also a `DERIVED_FROM` relationship) |
| `status`, `parser`, `events`, `job` | parsing outcome and the import job |
| `custody` | chain of custody (below) |

## Integrity rules

* **Originals are never modified or moved.** Files are copied into the store while the SHA-256 is
  computed; the copy keeps the original modification time and is made read-only. Identical
  content is stored once (content addressing); each import is still its own item.
* **Chain of custody.** Every action is an entry `{seq, at, action, actor, details, prev_hash, hash}`
  with `hash = sha256(prev_hash + entry)`, starting from a zero genesis hash. Actions: `acquired`
  (source, hash, size, original mtime), `stored`, `derived`, `parsed` (parser, job, counts),
  `linked` (incident and window), `verified` (result), `note`, `exported`. Editing or reordering any
  entry breaks the chain and `verify` reports it. Imports, verifications and exports are also written
  to the workspace audit log (itself hash-chained).
* **Derived data references its source.** Parsing reads the stored copy; events carry
  `raw_reference = evidence:<item>#<record>`, objects and relationships carry the item in their
  provenance, and derived artifacts use `--derived-from`.
* **Incident linking is bounded by time.** Parsed events are linked to the case's incident only when
  they fall inside the incident window (`start`..`end`); context lines from the same file stay
  unlinked.
* Symbolic links are not followed; file size is limited by `ingest.max_file_mb`; at most 10,000 files
  per import. Files without a parser (free-text notes, binaries) are stored and hashed but not parsed.
* Export refuses items that fail verification and never overwrites an existing file.

## API

| Method | Path | Result |
|---|---|---|
| GET | `/evidence/cases` | `{items: [case + item_count]}` |
| POST | `/evidence/cases` `{name, title?, description?, incident?}` | the case |
| GET | `/evidence/cases/{case}` | case + `items` |
| POST | `/evidence/cases/{case}/items` (multipart `file`, `note?`, `parse?`) | import one uploaded artifact (size-limited by `api.max_upload_mb`) |
| POST | `/evidence/cases/{case}/verify` `{items?}` | `{verified, items: [{id, name, ok, expected, actual, reason, custody_ok}]}` |
| GET | `/evidence/items?case=` · `/evidence/items/{id}` | items with custody chains |
| POST | `/evidence/items/{id}/notes` `{text}` | add a note |

## Demo

`raf demo load` creates case `INC-001` linked to the incident and imports the analyst notes, the
syslog excerpt, EDR process events, the proxy log and the packet capture
(`raven-inc001.pcap`, parsed by R$F Protocol).

## Limitations

* No disk-image or memory-image parsers; such artifacts are stored and hashed only.
* The chain of custody proves internal consistency; it is not signed with an external key.
