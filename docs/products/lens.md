# R$F Lens

R$F Lens is the general security data workbench. It opens any scope of the shared store and
answers, in one view: which events match, how they are distributed over time and by field, which
kinds of objects are involved, which objects are involved most, which findings relate to them,
how the subject is connected - and where to go next (Graph, Timeline, Trace, Evidence, Exposure).

Status: **BETA** · category: specialized analysis · command: `raf lens` · API: `GET /api/v1/lens/query`
· web: Investigate · depends on: Timeline (same query engine and filter language)

## Usage

```text
raf lens [SCOPE] [--filter EXPR] [--source TEXT] [--from T] [--to T] [--group-by FIELD]
                 [--limit N] [--buckets N]
```

Scopes: nothing (the workspace), any object (`10.30.0.5`, `APP-01`, `alice`), an incident
(`INC-001`), an analysis (`analysis-3`), a job, or an evidence item (`evidence:ev-0005` - the events
parsed from that artifact). `--source` narrows to data from one source, for example an imported
packet capture (`--source raven-inc001.pcap`). Filters use the shared filter language
(`type=auth.* outcome=failure actor=alice`, see `raf help filters`). Group by `category`,
`event_type`, `actor`, `target`, `severity`, `source` or `outcome`.

## Output

| Section | Content |
|---|---|
| Events, window, activity | total, first/last timestamps, a histogram over the window |
| Groups | counts by the chosen field |
| Involves | object types involved in the matching events |
| Most involved | up to 25 objects with event counts and criticality (the scope itself excluded) |
| Relationships | for an object scope: relationship types and directions (graph drill-down) |
| Related findings | open/acknowledged findings on the scope and its most involved objects |
| Events | the first page (cursor-paginated through the API) |
| Pivots | per top object: `raf graph`, `raf timeline`, `raf trace`, `raf evidence list --object`, and `raf exposure show` for assets |

Example: `raf lens 10.30.0.5` shows APP-01's address talking to DB-01 and resolving
`portal.raven.example`, the outbound TLS flow to `198.51.100.23` from the packet capture, and the
exposure findings of the hosts involved.

## API

`GET /lens/query?ref=&filter=&source=&start=&end=&group_by=&buckets=&limit=&cursor=` returns
`{scope, filters, total, first, last, items, names, next_cursor, group_by, groups, histogram, involved:
[{type, count}], top_objects: [{id, name, type, count, criticality}], findings, relationships, pivots}`.

## Limitations

* The most-involved ranking considers the 2,000 most involved objects of the scope.
* Lens reads what is in the workspace; to explore a capture or log that is not imported yet, import
  it (`raf import`, `raf evidence import`) or inspect it with `raf protocol inspect`.
