# Developing R$F plugins

A plugin is an R$F product that lives outside the R$F package: a directory with a manifest
(`raf-plugin.yaml`) and Python code. Once installed and trusted it can add **CLI commands**, an
**HTTP API router** and **ingestion parsers**, all working on the shared object model of the current
workspace. Built-in products use the same manifest model and the same SDK
([development.md](development.md#adding-a-product)); this guide is for code that is not part of the
R$F repository.

Everything below was checked against R$F 0.1.0 (plugin API version 1) with the example plugin at the
end of this document, installed into a scratch `RAF_HOME` with the Raven demo loaded.

## What a plugin can contribute

| Contribution | Manifest | Behavior |
|---|---|---|
| CLI commands | `cli`, `commands` | loaded lazily when invoked; listed in the **Plugins** panel of `raf --help` |
| API routes | `api` | mounted at `/api/v1/<plugin name>` when `raf serve` starts |
| Ingestion parsers | `parsers` | used by `raf import`, `raf analyze` and `raf evidence import` (detection or `--format NAME`) |

There is no hook for anything else: web workbench views (the workbench only links to its own
routes), object pivots (the pivot lists are fixed), snapshot state providers, and analyzers (the
`analyzers` and `entrypoint` manifest fields are validated but never loaded). R$F does not install
a plugin's Python dependencies: a plugin runs in R$F's environment and can import only what is
installed there. There is no remote registry; `raf install` takes local directories.

## Directory layout

```text
asset-notes/                    the plugin directory (any name)
├── raf-plugin.yaml             manifest
├── README.md                   optional; referenced by `docs`
└── asset_notes/                a Python package with a unique name
    ├── __init__.py
    ├── service.py              logic shared by CLI and API
    ├── cli.py                  Typer app        -> cli: asset_notes.cli:app
    ├── api.py                  FastAPI router   -> api: asset_notes.api:router
    └── parser.py               Parser subclass  -> parsers: [asset_notes.parser:AssetNotesParser]
```

* `raf install` copies the directory to `RAF_HOME/plugins/<name>/` (without `__pycache__`, `*.pyc`
  and `.git`). R$F loads the plugin from that copy, never from the source directory.
* When a plugin attribute is loaded, the installed directory is inserted at the front of `sys.path`
  and `module.path:attribute` is imported. Plugins share one interpreter with R$F and with each
  other: give the package a name nothing else uses (`asset_notes`, not `cli` or `utils`). Two
  plugins with the same top-level package collide (the first one imported wins), and a top-level
  module in the plugin directory can shadow an installed library of the same name.
* Symbolic links anywhere in the directory are refused at installation
  (*"Plugin contains a symlink (data.txt); refusing to install."*, `raf.security_violation`, exit 5).

## The manifest

`raf-plugin.yaml` is read with a safe YAML loader and validated as a `ProductManifest`
(`raf.core.plugins.manifest`). Unknown fields are rejected.

| Field | Required | Default (plugins) | Rules and effect |
|---|---|---|---|
| `name` | yes | | 2-41 characters: a lower-case letter, then lower-case letters, digits or `-` (`^[a-z][a-z0-9-]{1,40}$`); must not be a built-in product name. It is also the API prefix `/api/v1/<name>` and the directory under `RAF_HOME/plugins` |
| `display_name` | no | `name` with `-` replaced by spaces, title-cased (`multi-cmd` -> `Multi Cmd`) | shown by `raf products`, `raf product info` and as the OpenAPI tag. Error messages use the name instead (*"R$F Asset-Notes is not available."*) |
| `version` | yes | | a **string**: quote values YAML reads as numbers (`'1.0'`, `'2'`; `0.1.0` is already a string) |
| `api_version` | no | `1` | must equal the plugin API version of this R$F (`raf version` prints `plugin_api 1`) |
| `status` | no | `EXPERIMENTAL` | `STABLE`, `BETA`, `ALPHA` or `EXPERIMENTAL`: the maturity you declare |
| `description` | yes | | one line, shown by `raf products` and `raf product info` |
| `category` | no | `analysis` | free text, present in the JSON of `raf product info` and `GET /api/v1/products`; plugin commands always appear in the **Plugins** help panel whatever the category |
| `depends_on` | no | `[]` | product names (built-in or plugins); see [Dependencies](#dependencies) |
| `commands` | no | `[]` | top-level command names, all mapped to the same `cli` object; when empty, the command is the plugin `name` |
| `cli` | no | | `module.path:attribute` of a Typer app (a plain Click command also works) |
| `api` | no | | `module.path:attribute` of a FastAPI `APIRouter` |
| `parsers` | no | `[]` | `module.path:Class` of `Parser` subclasses |
| `analyzers` | no | `[]` | validated as import paths; **not used** |
| `permissions` | no | `[]` | names from the list below, stored sorted and de-duplicated; **declarative only**, see [What trust means](#what-trust-means) |
| `entrypoint` | no | | validated as an import path; **not used** |
| `optional` | no | `false` | shown as "(optional)" next to the status in `raf products`; no other effect |
| `builtin` | no | `false` | plugins may not set it to `true` (*"Plugins cannot declare themselves built-in."*) |
| `docs` | no | | free text (a path or URL) shown as "Docs" by `raf product info` |
| `ui` | no | `{}` | `{"route": ..., "nav": ...}`. The workbench's Products page shows an Open button for `route` only when it is one of the workbench's own routes and the product is available; `nav` is not used |

Permission names: `read.objects`, `write.objects`, `write.relationships`, `read.events`,
`write.events`, `read.findings`, `write.findings`, `read.evidence`, `run.jobs`, `register.parsers`,
`network.outbound`.

An invalid manifest fails the installation with every problem listed. For this manifest:

```yaml
name: bad-plugin
version: 1
api_version: 2
description: Broken manifest example
permissions: [read.objects, read.everything]
cli: bad_plugin.cli
```

```text
$ raf install ./bad-plugin

R$F: Invalid plugin manifest bad-plugin/raf-plugin.yaml.

Reason:
  version: Input should be a valid string; api_version: Value error, unsupported plugin api_version 2 (this R$F supports 1); cli: Value error, expected 'module.path:attribute'; permissions: Value error, unknown permissions: read.everything
```

An unknown field is reported as `author: Extra inputs are not permitted`, a built-in name as
*"'timeline' is a built-in product name."* (all exit 4).

### Product statuses

`status` is the maturity the author declares. `raf products`, `raf product info`, `raf plugin list`
and `GET /api/v1/products` show a display status: `DISABLED` when the product is disabled (an
installed, untrusted plugin is disabled), `UNAVAILABLE` when a dependency is not available,
otherwise the maturity. The JSON carries both: `status` (display status) and `maturity`.

### Dependencies

A product is available only when every product in its `depends_on` is installed, enabled (and
trusted, for plugins) and itself available. The example plugin depends on `graph`:

```text
$ raf product disable graph
Disabled Graph.
warning: these products depend on it and are now unavailable: asset-notes

$ raf notes

R$F: R$F Asset-Notes is not available.

Reason:
  requires 'graph', which is unavailable

Try:
  raf product enable asset-notes
  raf products
```

The command exits 4 and the API router is not mounted. A dependency that is not installed at all
gives the same result. Dependency cycles are rejected, but `raf install` stores the plugin before it
checks for cycles: a plugin that depends on itself (or closes a cycle) stays installed, and every
later command that loads the registry fails with *"Product dependency cycle"*, `raf uninstall`
included. Recover by deleting `RAF_HOME/plugins/<name>/` and its entry under `plugins` in
`RAF_HOME/registry.json`.

**Imports are not checked for plugins.** For built-in code the layering core -> data/sdk ->
products -> analysis -> apps, and the rule that a product imports another product only if it lists
it in `depends_on`, are enforced by `tests/unit/test_architecture.py`, which parses every module
under `src/raf` in the test suite (and CI). Nothing enforces them at runtime and the test never sees
installed plugins. Follow the same rules anyway: import `raf.core`, `raf.data` and `raf.sdk`, other
products only when declared in `depends_on`, never `raf.analysis` or `raf.apps`.

## Install, trust, verify, uninstall

```text
raf install ./asset-notes          copy into RAF_HOME/plugins/asset-notes (disabled, untrusted)
raf plugin list                    installed plugins: version, trusted, status, permissions
raf plugin trust asset-notes       record the SHA-256 of the installed files and enable (confirmation)
raf plugin verify asset-notes      compare the installed files with the trusted hash
raf product disable asset-notes    disable or enable like any product
raf uninstall asset-notes          remove the directory and the registry entry (confirmation)
```

```text
$ raf install ./asset-notes
Installed plugin asset-notes 0.1.0 (disabled, untrusted).
warning: plugins run code in-process. Review it, then trust it explicitly.
Permissions         read.objects, write.objects

Next:
  raf plugin trust asset-notes

$ raf notes

R$F: R$F Asset-Notes is not available.

Reason:
  product 'asset-notes' is disabled

Try:
  raf product enable asset-notes
  raf products

$ raf product enable asset-notes

R$F: Plugin 'asset-notes' is not trusted yet.

Try:
  raf plugin trust asset-notes

$ raf plugin trust asset-notes
Trust plugin 'asset-notes'? It will run with your privileges.
  Requested permissions: read.objects, write.objects
Type 'yes' to continue: yes
Trusted and enabled asset-notes.

$ raf plugin verify asset-notes
asset-notes: files match the trusted hash.

$ raf plugin list
PLUGIN       VERSION  TRUSTED  STATUS        PERMISSIONS
asset-notes  0.1.0    yes      EXPERIMENTAL  read.objects, write.objects
```

* The not-available message suggests `raf product enable`, but for a new plugin `raf plugin trust`
  is the step that enables it; `raf product enable` refuses untrusted plugins (exit 4).
* `raf plugin trust` and `raf uninstall` ask for confirmation; without a terminal they need `--yes`
  (`raf --yes plugin trust asset-notes`), otherwise they fail with `raf.confirmation_required`.
* Installing a name that is already installed is refused (`raf.conflict`, exit 4). A source that
  does not exist on disk is handed to the remote registry, which is not configured: *"No remote
  product registry is configured."* (exit 6). A path without `raf-plugin.yaml` is *"not an R$F plugin
  directory"* (exit 4).
* State changes are written to the audit log: `plugin.install`, `plugin.trust`, `plugin.uninstall`,
  `product.enable`, `product.disable`.
* State lives in `RAF_HOME/registry.json` (`source` is the path as given to `raf install`):

```json
{
  "disabled": [],
  "plugins": {
    "asset-notes": {
      "enabled": true,
      "installed_at": "2026-10-07T14:05:58.573290Z",
      "sha256": "d6e60ad91fd6e318b5abb8a00b673539de912f473a7b20758fc64bab31999548",
      "source": "asset-notes",
      "trusted": true,
      "trusted_at": "2026-10-07T14:06:01.622592Z",
      "version": "0.1.0"
    }
  }
}
```

### What trust means

* The **trust hash** is a SHA-256 over the relative path and the content of every regular file in
  the installed directory except `__pycache__` directories, data files included. Installation
  records a hash too, but `raf plugin trust` replaces it with the hash of the files at that moment:
  whatever is in `RAF_HOME/plugins/<name>/` when you trust it is what you trust. Review that copy.
* Every time R$F loads something from the plugin (a CLI command, the API router, a parser) it hashes
  the directory again and refuses to import anything when the hash differs:

  ```text
  $ raf notes

  R$F: Plugin 'asset-notes' is not trusted or was modified after it was trusted.

  Review the plugin, then run: raf plugin trust asset-notes
  ```

  (exit 5). `raf serve` skips the router with a logged warning; imports print a warning
  (*"parser asset_notes.parser:AssetNotesParser from asset-notes unavailable: ..."*) and detect the
  file without the plugin's parser. The hash covers content only, so restoring the original files
  restores trust; keeping a change requires `raf plugin trust` again.
* A modified plugin also breaks `raf --help` and `raf help` (exit 5), because building the help
  loads every product command, while `raf products` and `raf plugin list` keep showing it as
  available. `raf plugin verify` reports the change as a warning but exits 0: check `unchanged` in
  `raf --json plugin verify NAME`.
* The hash does not cover `__pycache__`, and Python loads cached bytecode from there when its header
  matches the source file: a replaced `.pyc` runs while `raf plugin verify` still reports a match.
  Anyone who can write to the plugin directory can also edit `registry.json`; protect `RAF_HOME`
  itself.
* A trusted plugin whose module fails to import with anything other than `ImportError` or
  `AttributeError` (a `SyntaxError`, an exception raised at import time) is not contained:
  `raf --help` ends with an internal error (exit 1), `raf serve` does not start, and a broken parser
  module makes every import fail (*"Internal error while running the job."*). `raf product disable
  NAME` and `raf uninstall NAME` still work. Run your tests before trusting a new version.
* **Trust is the only boundary.** A trusted plugin runs in the R$F process with your privileges and
  can read and write everything R$F can. The declared `permissions` are validated against the list
  above and shown by `raf install`, `raf plugin trust` and `raf plugin list`, but **nothing enforces
  them**. The "SDK facade (`raf.sdk.PluginContext`)" that code comments and `raf help plugins`
  mention does not exist.
* A plugin command name is not checked against built-in product commands: a trusted plugin that
  declares `commands: [timeline]` replaces `raf timeline`. Platform commands (`status`, `show`,
  `import`, `help`, ...) cannot be replaced: they are looked up first.

## CLI commands (`raf.sdk.cli`)

The manifest's `cli` points to a Typer app. With one command the app is the top-level command
(`raf notes`); with several it becomes a group (`raf notes list`, `raf notes set`) whose help line in
`raf --help` comes from `typer.Typer(help="...")`. Every name in `commands` maps to the same app. A
plain Click command also works, but when it is listed under several names `raf --help` shows the
last name for each entry. Global flags (`--json`, `--quiet`, `-w`, ...) are removed from the command
line before your command is parsed, wherever the user typed them, and are available in `rt.STATE`.

| Function | Purpose |
|---|---|
| `rt.ctx()` | the `RafContext` of the selected workspace, opened once per invocation: `settings`, `store` (`objects`, `relationships`, `events`, `findings`, `incidents`, `provenance`, `analyses`, `kv`, `counters`), `audit`, `jobs`, `refs`, `resolve(ref, types=..., accept=("object",))`, `workspace`, `home`, `registry` |
| `rt.output(schema, data, render)` | with `--json` print `{"schema": schema, ...data}`, otherwise call `render()`; a payload that is not a mapping becomes `items`. Name schemas after the plugin (`asset-notes.notes/v1`) |
| `rt.emit_json(schema, data)` | print the JSON document directly |
| `rt.header(title, subtitle=None)` | section header (hidden with `--quiet`) |
| `rt.kv_block(rows, width=20)`, `rt.table(columns, rows, title=None)` | key/value lines and tables; cell values are escaped for the terminal |
| `rt.next_steps(commands, title="Next")` | suggested commands, de-duplicated (never executed; hidden with `--quiet`) |
| `rt.note(text)`, `rt.warn(text)`, `rt.success(text)` | dim note on stderr (hidden with `--quiet`); `warning: ...` on stderr; green line on stdout (hidden with `--quiet`) |
| `rt.confirm(prompt, details=())` | confirmation for destructive actions: passes with `--yes`, asks for `yes` on a terminal, otherwise raises `ConfirmationRequired` (exit 4) |
| `rt.console()`, `rt.err_console()` | the Rich consoles for stdout and stderr; they escape control sequences in every text segment. Do not use `print()` |
| `rt.sev_text(sev)`, `rt.conf_text(conf)`, `rt.ts_text(dt)`, `rt.ref_text(id, name=None)`, `rt.render_chain(steps)` | formatting helpers used by the built-in products |
| `rt.parse_time_option(value, anchor=None, window=None)` | parse `--at` / `--from` / `--to` values ([time values](cli.md#time-values)) |
| `rt.STATE` | `json`, `quiet`, `no_color`, `debug`, `yes`, `workspace`, `argv` |

`rt.console().print("...")` interprets Rich markup in plain strings, so `[example]` in data would
disappear: print data as `rich.text.Text` objects or through `rt.table` and `rt.kv_block`, as the
built-in products do.

Conventions of the built-in products, which plugins should follow:

* resolve user input with `ctx.resolve(ref)` (or `raf.core.query.scope.resolve_scope` for scopes) so
  IDs, names, aliases and `@last` work, and print each of `resolved.notes` with `rt.note`;
* remember what the user looked at with `ctx.refs.remember(kind, id)`, `kind` being one of `object`,
  `incident`, `analysis`, `snapshot`, `job`, `case`, `ghost`, `range`, `lab` (anything else raises
  `ValueError`);
* record state changes in the audit log: `ctx.audit.record("asset-notes.set", affected=[...],
  details={...})`;
* run long or data-writing work as a job with `ctx.jobs.run_inline(kind, title, params, fn)`; `fn(jc)`
  may call `jc.progress(fraction, message)` and `jc.check_cancelled()`. `run_inline` returns the
  `Job` and does not raise when `fn` fails: the job is `FAILED` with `job.error`, so check
  `job.status`;
* raise `RafError` subclasses for expected failures (see [Errors](#errors)).

## API routes (`raf.sdk.api`)

The manifest's `api` points to a FastAPI `APIRouter`; R$F mounts it at `/api/v1/<plugin name>` with
the display name as OpenAPI tag (`/api/v1/openapi.json`, `/api/docs`). Declare a parameter
`ctx: Ctx` to receive the context of the workspace the request addresses (`?workspace=NAME` or the
`X-RAF-Workspace` header, else the current workspace). The server keeps one long-lived context per
workspace and shares it between requests: never close it.

* `RafError` exceptions become `{"error": {"code", "message", ...}}` with the error's HTTP status;
  request validation errors become 422 `raf.invalid_request`; other HTTP errors
  `raf.http_<status>`; anything else 500 `raf.internal`.
* The server's protections apply to plugin routes: loopback binding by default, the Host header
  check (403), a bearer token for non-loopback binding, the request size limit `api.max_upload_mb`
  (200), security headers.
* Routers are mounted when the server starts and never unmounted: restart `raf serve` after
  trusting, enabling, disabling or updating a plugin. A product disabled while the server runs
  (with `raf product disable` or `POST /api/v1/products/{name}/disable`) keeps answering on its
  routes until the restart.
* Accept uploaded content rather than server-side paths, so that API clients cannot make R$F read
  arbitrary files.

## Parsers

A parser turns a file into raw records; a normalizer turns records into objects, relationships,
events, incidents and findings. Plugins contribute parsers (`raf.core.ingestion.base.Parser`):

| Member | Meaning |
|---|---|
| `name` (class attribute) | the format name for `--format`. A parser with an existing name replaces it, including built-in ones (`csv`, `jsonl`, ...) for every import |
| `version` | default `"1.0"`; the label `name/version` is recorded on events and provenance records |
| `description`, `extensions` | informational; use `extensions` in your own `sniff` |
| `normalizer` | `raf-native` (default), `ecs`, `cloudtrail`, `tabular`, `generic-json`, or `auto` (the normalizer whose `score` is highest over the first 25 records; `generic-json` when none fits) |
| `sniff(path, head) -> float` (classmethod) | confidence 0..1 that the file is yours; `head` is the first 64 KiB |
| `records(stream, ctx) -> Iterator[RawRecord]` | stream records from the binary file with bounded memory |

Detection asks every parser and takes the highest score; below 0.2 the file is unknown, ties go to
the parser registered first (built-ins before plugins), and an exception in `sniff` counts as 0. The
built-in CSV parser returns 0.9 for any consistently delimited `.csv` file, JSON Lines up to 0.95,
Surface inventories 0.96-0.98 and packet captures 1.0, so return more than the generic parsers (the
example returns 0.99) only for content you recognize, and 0.0 otherwise.

`RawRecord(data, locator, raw=None, normalizer=None, parser_label=None)` carries one record: `data`
(a dict for the native normalizer); a `locator` such as `line 12`, recorded in provenance and used
to derive event IDs, so keep it stable; the raw text (an excerpt is stored with each event while
`ingest.store_raw` is on, up to `ingest.raw_max_bytes`); and optionally a normalizer or label for
this record only. For a record you cannot read, yield `RawRecord.rejected(locator, message, raw)`:
it is counted as rejected, quarantined with its reason and the first 4,096 characters of the raw
text in `workspaces/<workspace>/rejects/<job>.jsonl` (`raf import report JOB`), and the import
continues.

Raising from `records()` stops the file. A single-file import job fails: `raf import` reports the
job's error message and hint as `raf.ingestion` (exit 1) whatever the exception class, and an
exception that is not a `RafError` becomes *"Internal error while running the job."*. Records
already written stay and nothing is rolled back: the pipeline reads the first 25 records before
processing anything, then writes every `ingest.batch_size` (2,000) records. In a directory import a
`RafError` skips that file (counted under `Files ... skipped`) and the other files are imported; any
other exception fails the whole import. The base class documents `RecordRejected` as the exception
for unrecoverable framing problems.

`ParseContext` gives the parser `source` (`name`, `path`, `sha256`, `size`, `evidence_id`,
`synthetic`, `incident`, `default_host`), `default_tz`, `reference_time`, `max_record_bytes`
(`ingest.max_record_kb`), `raw_max_bytes`, `store_raw`, `user_strip_domain`, `options`, `warnings`
(strings appended there are counted and sampled in the import report) and `excerpt(raw)`. Read
lines with `raf.core.security.files.iter_lines(stream, ctx.max_record_bytes)`: it yields
`Line(number, text, size)`, with `text` set to `None` for a line longer than the limit (the rest of
that line is skipped, never loaded), decodes UTF-8 with replacement and drops a leading BOM.

With the `raf-native` normalizer, yield records in the native format: events
`{"timestamp", "event_type", "actor", "action", "target", "outcome", "host", "severity",
"confidence", "message", "attributes", "objects", "relationships", "incident", "synthetic", "id"}`,
objects `{"kind": "object", "type", "name", "key", "metadata", "tags", ...}`, relationships
`{"kind": "relationship", "source", "type", "target", ...}`, incidents `{"kind": "incident", "name",
"title", "severity", "status", ...}` and findings `{"kind": "finding", "title", "severity",
"confidence", "affected", ...}`. The pipeline derives IDs, resolves bare names against existing
objects, builds relationships from events and records provenance (source name and SHA-256,
locator, parser label, job, evidence item); see the [object model](object-model.md#events).

Files larger than `ingest.max_file_mb` are refused before any parser runs, and in a directory
import every file is detected separately. The parsers of all available products are collected for
each import, so a plugin's parser is used as soon as the plugin is trusted.

## Provenance

Data that enters through a parser gets provenance automatically. Code that writes objects,
relationships or events in any other way (a command, an API route, an analysis you run yourself)
should go through the ingestion pipeline inside a job: that gives deterministic IDs, the merge
rules, provenance records carrying the job and source, and job and audit visibility.

```python
from typing import Any

from raf.core.context.app import RafContext
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions
from raf.core.jobs.manager import Job, JobContext


def set_note(ctx: RafContext, host: str, owner: str, note: str) -> Job:
    record = {"kind": "object", "type": "host", "name": host,
              "metadata": {"owner": owner, "analyst_note": note}}

    def work(jc: JobContext) -> dict[str, Any]:
        report = IngestionPipeline(ctx, job=jc).ingest_records(
            [record], source_name="asset-notes:cli", options=IngestOptions(), label="asset-notes/1.0"
        )
        return report.to_json_dict()

    job = ctx.jobs.run_inline("asset-notes", f"Note on {host}", {"host": host}, work)
    ctx.audit.record("asset-notes.set", affected=[host], details={"job": job.id})
    return job
```

After `set_note(ctx, "WS-03", "Facilities", "kiosk, no local admin")`:

```text
$ raf show WS-03
...
Provenance (10 of 41)
  ...
  asset-notes:cli  record record 0  parser asset-notes/1.0  observed -
  ...

$ raf audit --operation asset-notes
#   TIME                         ACTOR  OPERATION        RESULT   AFFECTED
21  2026-10-07T14:09:52.599882Z  root   asset-notes.set  success  WS-03
```

and `raf jobs` lists `job-7  asset-notes  COMPLETED ... Note on WS-03`. Pass
`IngestOptions(synthetic=True)` for generated data.

**Findings** carry their own justification instead of provenance rows: a deterministic ID
(`raf.core.ids.finding_id(product, rule, subject)`), independent `severity` and `confidence`,
`affected_objects`, `evidence` references and an `explanation`. Store them with
`ctx.store.findings.upsert(findings)` (analyst statuses such as FALSE_POSITIVE survive re-runs) and
resolve the ones a re-run no longer produces with
`ctx.store.findings.resolve_absent(product, rule_ids, present_ids)`:

```python
from raf.core.ids import finding_id
from raf.core.objects.models import EvidenceRef, Finding
from raf.core.objects.types import Severity
from raf.core.timeutil import utcnow


def record_findings(ctx: RafContext) -> tuple[int, int]:
    now = utcnow()
    findings = []
    for host in ctx.store.objects.list(types=["host"], limit=10_000):
        if host.metadata.get("criticality") == "critical" and not host.metadata.get("analyst_note"):
            findings.append(Finding(
                id=finding_id("asset-notes", "undocumented-critical-host", host.id),
                title=f"Critical host without an analyst note: {host.name}",
                description=f"{host.name} is critical but has no analyst note.",
                severity=Severity.MEDIUM, confidence=0.9,
                product="asset-notes", rule_id="undocumented-critical-host",
                affected_objects=[host.id],
                evidence=[EvidenceRef(kind="object", id=host.id, note="criticality critical, no analyst note")],
                recommendation="Record a note (raf import hosts.notes.csv).",
                explanation=[{"label": "criticality critical", "sign": "+", "points": 1}],
                created_at=now, updated_at=now,
            ))
    stats = ctx.store.findings.upsert(findings)
    resolved = ctx.store.findings.resolve_absent("asset-notes", ["undocumented-critical-host"], [f.id for f in findings])
    return stats.created + stats.updated, resolved
```

On the Raven demo after the import in the [example](#example-asset-notes) (DB-01 has a note), the
first run returns `(1, 0)`: one finding for DC-01, the other critical host. After a note for DC-01
is recorded, the next run returns `(0, 1)` and the finding is RESOLVED:

```text
$ raf findings --product asset-notes --status RESOLVED
SEVERITY  CONFIDENCE   PRODUCT      TITLE                           ID
MEDIUM    HIGH (0.90)  asset-notes  Critical host without an        finding:asset-notes:undocumented
                                    analyst note: DC-01             -critical-host:252bcfea3e42
```

## Errors

Raise `raf.core.errors.RafError` subclasses. The CLI renders them (or a `raf.error/v1` document with
`--json`) and exits with their code; the API answers with their HTTP status; a job records them as
its error. Other exceptions are reported as internal errors (CLI: *"R$F hit an internal error"*,
exit 1; API: 500 `raf.internal`).

| Class | `code` | Exit | HTTP | Use for |
|---|---|---|---|---|
| `RafError` | `raf.error` | 1 | 400 | base class |
| `NotFoundError` | `raf.not_found` | 3 | 404 | unknown object, item, name |
| `AmbiguousReferenceError(reference, candidates)` | `raf.ambiguous_reference` | 4 | 409 | several matches |
| `InvalidInputError` | `raf.invalid_input` | 4 | 422 | bad arguments or data |
| `ConflictError` | `raf.conflict` | 4 | 409 | already exists, wrong state |
| `ConfigError` | `raf.config` | 4 | 422 | bad configuration |
| `WorkspaceError` | `raf.workspace` | 4 | 409 | workspace state |
| `ProductDisabledError` | `raf.product_disabled` | 4 | 409 | a needed product is unavailable |
| `ConfirmationRequired` | `raf.confirmation_required` | 4 | 428 | raised by `rt.confirm` |
| `StorageError` | `raf.storage` | 1 | 500 | storage failures |
| `IngestionError` | `raf.ingestion` | 1 | 422 | an import that cannot proceed |
| `SecurityViolation` | `raf.security_violation` | 5 | 400 | unsafe input (path traversal, symbolic links) |
| `ResourceLimitExceeded` | `raf.resource_limit` | 5 | 400 | size and count limits |
| `PermissionDeniedError` | `raf.permission_denied` | 5 | 403 | |
| `IntegrityError` | `raf.integrity` | 5 | 409 | hash or chain mismatch |
| `DependencyUnavailableError` | `raf.dependency_unavailable` | 6 | 503 | missing external tool or service |
| `OperationCancelled` | `raf.cancelled` | 130 | 409 | raised by `jc.check_cancelled()` |

`RecordRejected` (`raf.core.ingestion.base`, code `raf.record_rejected`) is an `InvalidInputError`.
Every error takes `message` plus the keyword arguments `reason=`, `hint=`, `suggestions=[commands]`
and `details={...}`:

```python
raise NotFoundError("No note for 'WS-09'.", hint="Notes come from *.notes.csv files.",
                    suggestions=["raf import hosts.notes.csv"])
```

A subclass can set its own `code`, `exit_code` and `http_status` class attributes.

## Testing a plugin

Test against a throw-away `RAF_HOME`, install and trust the plugin through the real CLI, and call
the CLI in-process. The CLI caches the registry per process, so clear those caches between
invocations, and drop the plugin's modules from `sys.modules` between tests. Use FastAPI's
`TestClient` with a loopback base URL; the API rejects other Host headers. With the tests in a
directory next to the plugin directory, this file passes against the example plugin
(`.venv/bin/python -m pytest -q asset-notes-tests`, run with R$F's interpreter: 4 passed):

```python
"""Tests for the asset-notes example plugin."""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[1] / "asset-notes"


def raf(*args: str) -> tuple[int, str, str]:
    """Run the raf CLI in-process; returns (exit code, stdout, stderr)."""
    from raf.apps.cli import registry as cli_registry
    from raf.apps.cli.main import run

    cli_registry.build_registry.cache_clear()  # the CLI caches the registry per process
    cli_registry.load_product_command.cache_clear()
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with redirect_stdout(out), redirect_stderr(err):
        try:
            run(list(args))
        except SystemExit as exc:
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("RAF_HOME", str(tmp_path / "rafhome"))
    monkeypatch.delenv("RAF_WORKSPACE", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    for name in [m for m in sys.modules if m == "asset_notes" or m.startswith("asset_notes.")]:
        del sys.modules[name]  # each test imports the plugin from its own RAF_HOME
    return tmp_path / "rafhome"


def test_untrusted_plugin_is_not_loaded(home: Path) -> None:
    assert raf("install", str(PLUGIN))[0] == 0
    code, out, _ = raf("--json", "notes")
    assert code == 4
    assert json.loads(out)["error"]["code"] == "raf.product_disabled"


def test_notes_from_imported_csv(home: Path, tmp_path: Path) -> None:
    assert raf("install", str(PLUGIN))[0] == 0
    assert raf("--yes", "plugin", "trust", "asset-notes")[0] == 0
    notes = tmp_path / "hosts.notes.csv"
    notes.write_text("host,owner,note\nWS-02,Finance IT,reimaged\n,nobody,no host\n", encoding="utf-8")
    code, out, _ = raf("--json", "import", str(notes))
    report = json.loads(out)
    assert code == 0 and report["format"] == "asset-notes"
    assert (report["accepted"], report["rejected"]) == (1, 1)
    code, out, _ = raf("--json", "notes", "WS-02")
    doc = json.loads(out)
    assert code == 0 and doc["schema"] == "asset-notes.notes/v1"
    assert doc["items"] == [
        {"id": "host:ws-02", "name": "WS-02", "owner": "Finance IT", "note": "reimaged", "criticality": None}
    ]


def test_api_route(home: Path) -> None:
    from fastapi.testclient import TestClient

    from raf.apps.api.app import create_app

    raf("install", str(PLUGIN))
    raf("--yes", "plugin", "trust", "asset-notes")
    client = TestClient(create_app(serve_ui=False), base_url="http://127.0.0.1")
    response = client.get("/api/v1/asset-notes/notes")
    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}


def test_tampering_is_detected(home: Path) -> None:
    raf("install", str(PLUGIN))
    raf("--yes", "plugin", "trust", "asset-notes")
    (home / "plugins" / "asset-notes" / "asset_notes" / "service.py").write_text("raise SystemExit\n")
    code, out, _ = raf("--json", "plugin", "verify", "asset-notes")
    assert json.loads(out)["unchanged"] is False
    code, out, _ = raf("--json", "notes")
    assert code == 5 and json.loads(out)["error"]["code"] == "raf.security_violation"
```

Parsers can also be tested without installing anything:

```python
from raf.core.context.app import open_context
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions
from raf.core.ingestion.registry import ParserRegistry

ctx = open_context()                       # uses RAF_HOME / RAF_WORKSPACE
registry = ParserRegistry.default()
registry.register_parser(AssetNotesParser)
report = IngestionPipeline(ctx, registry).ingest_file(path, IngestOptions(format="asset-notes"))
# report.accepted == 2, report.rejected == 1 for the hosts.notes.csv below
ctx.close()
```

Inside the R$F repository, `tests/conftest.py` provides the `raf_home`, `ctx` and `cli` fixtures used
by the built-in products.

## Example: Asset Notes

A complete plugin that imports analyst notes on hosts from `*.notes.csv` files, shows them with
`raf notes`, and serves them at `GET /api/v1/asset-notes/notes`. The files below are exactly the
ones that were installed and tested.

`raf-plugin.yaml`:

```yaml
# R$F plugin manifest (YAML, loaded with a safe loader)
name: asset-notes
display_name: Asset Notes
version: 0.1.0
api_version: 1
status: EXPERIMENTAL
description: Analyst notes on hosts, imported from *.notes.csv files
category: analysis
depends_on: [graph]
commands: [notes]
cli: asset_notes.cli:app
api: asset_notes.api:router
parsers: [asset_notes.parser:AssetNotesParser]
permissions: [read.objects, write.objects]
docs: README.md
```

`asset_notes/__init__.py`:

```python
"""Asset Notes: an example R$F plugin."""
```

`asset_notes/service.py`:

```python
"""Business logic shared by the CLI command and the API route."""

from __future__ import annotations

from typing import Any

from raf.core.context.app import RafContext


def notes(ctx: RafContext, ref: str | None = None) -> dict[str, Any]:
    """Hosts that carry an analyst note (or the note of one resolved object)."""
    if ref:
        obj = ctx.resolve(ref).obj
        objects = [obj] if obj is not None else []
    else:
        objects = [o for o in ctx.store.objects.list(types=["host"], limit=1000) if o.metadata.get("analyst_note")]
    items = [
        {
            "id": o.id,
            "name": o.name,
            "owner": o.metadata.get("owner"),
            "note": o.metadata.get("analyst_note"),
            "criticality": o.metadata.get("criticality"),
        }
        for o in objects
    ]
    return {"items": items, "total": len(items)}
```

`asset_notes/cli.py`:

```python
"""``raf notes``: show analyst notes on hosts."""

from __future__ import annotations

import typer

from asset_notes.service import notes
from raf.sdk import cli as rt

app = typer.Typer(add_completion=False)


@app.command("notes", help="Show analyst notes on hosts (from *.notes.csv imports).")
def notes_cmd(ref: str = typer.Argument(None, help="One object (WS-02, host:db-01, @last).")) -> None:
    ctx = rt.ctx()
    data = notes(ctx, ref)
    if ref and data["items"]:
        ctx.refs.remember("object", data["items"][0]["id"])

    def render() -> None:
        rt.header("ASSET NOTES")
        if not data["items"]:
            rt.console().print("No notes yet.")
            rt.next_steps(["raf import hosts.notes.csv"])
            return
        rt.table(
            ["HOST", "OWNER", "CRITICALITY", "NOTE"],
            [(i["name"], i["owner"] or "-", i["criticality"] or "-", i["note"] or "-") for i in data["items"]],
        )
        rt.next_steps([f"raf graph {data['items'][0]['id']}", f"raf exposure show {data['items'][0]['id']}"])

    rt.output("asset-notes.notes/v1", data, render)
```

`asset_notes/api.py`:

```python
"""Asset Notes API routes (mounted at /api/v1/asset-notes)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from asset_notes.service import notes
from raf.sdk.api import Ctx

router = APIRouter()


@router.get("/notes")
def list_notes(ctx: Ctx, ref: str | None = None) -> dict[str, Any]:
    return notes(ctx, ref)
```

`asset_notes/parser.py`:

```python
"""Parser for ``*.notes.csv`` files: a ``host,owner,note`` header, then one host per line."""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path
from typing import IO, ClassVar

from raf.core.ingestion.base import ParseContext, Parser, RawRecord
from raf.core.security.files import iter_lines

HEADER = ["host", "owner", "note"]


class AssetNotesParser(Parser):
    name: ClassVar[str] = "asset-notes"
    version: ClassVar[str] = "1.0"
    description: ClassVar[str] = "Analyst notes on hosts (host,owner,note CSV)"
    extensions: ClassVar[tuple[str, ...]] = (".notes.csv",)
    normalizer: ClassVar[str] = "raf-native"  # records below are R$F native object records

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        first_line = head.split(b"\n", 1)[0].strip().lower()
        if path.name.lower().endswith(cls.extensions) and first_line == b"host,owner,note":
            return 0.99
        return 0.0

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        header_seen = False
        for line in iter_lines(stream, ctx.max_record_bytes):  # bounded: never reads a huge line into memory
            locator = f"line {line.number}"
            if line.text is None:
                yield RawRecord.rejected(locator, f"Line longer than {ctx.max_record_bytes} bytes.")
                continue
            if not line.text.strip():
                continue
            values = next(csv.reader([line.text]))
            if not header_seen:
                header_seen = True
                if [v.strip().lower() for v in values] != HEADER:
                    yield RawRecord.rejected(locator, "Expected the header host,owner,note.", line.text)
                    return
                continue
            row = dict(zip(HEADER, (v.strip() for v in values), strict=False))
            if not row.get("host"):
                yield RawRecord.rejected(locator, "Missing 'host'.", line.text)
                continue
            yield RawRecord(
                {
                    "kind": "object",
                    "type": "host",
                    "name": row["host"],
                    "metadata": {"owner": row.get("owner", ""), "analyst_note": row.get("note", "")},
                },
                locator,
                line.text,
            )
```

`README.md` is one line of text. Using the plugin on the Raven demo (`raf demo load`), after
installing and trusting it as shown above:

```text
$ cat hosts.notes.csv
host,owner,note
WS-02,Finance IT,"Bob's workstation; reimaged after INC-001"
DB-01,DBA team,Customer database - restore tested 2026-09
,nobody,missing host

$ raf import hosts.notes.csv

R$F IMPORT  hosts.notes.csv
────────────────────────────────────────
Format         asset-notes (asset-notes/1.0, raf-native/1.0)
Processed      3
Accepted       2
Rejected       1
Objects        0 created, 2 updated
Relationships  0 created, 0 updated
Events         0 created
SHA-256        a8320169dadf69a9b7b8abbbcdb0514ce652861d54293f58f75e1254a43f8a62
Duration       0.01 s

R$F could not parse record line 4.
Reason:
  Missing 'host'.
The remaining 2 records were imported.
Run:
  raf import report job-5
for details.

Next:
  raf incidents
  raf objects --type host
  raf findings

$ raf notes

ASSET NOTES
────────────────────────────────────────
HOST   OWNER       CRITICALITY  NOTE
DB-01  DBA team    critical     Customer database - restore tested 2026-09
WS-02  Finance IT  medium       Bob's workstation; reimaged after INC-001

Next:
  raf graph host:db-01
  raf exposure show host:db-01

$ raf --json notes WS-02
{
  "schema": "asset-notes.notes/v1",
  "items": [
    {
      "id": "host:ws-02",
      "name": "WS-02",
      "owner": "Finance IT",
      "note": "Bob's workstation; reimaged after INC-001",
      "criticality": "medium"
    }
  ],
  "total": 1
}

$ raf serve --port 8799 --no-ui &
$ curl -s 'http://127.0.0.1:8799/api/v1/asset-notes/notes?ref=DB-01'
{"items":[{"id":"host:db-01","name":"DB-01","owner":"DBA team","note":"Customer database - restore tested 2026-09","criticality":"critical"}],"total":1}
$ curl -s 'http://127.0.0.1:8799/api/v1/asset-notes/notes?ref=nosuchhost'
{"error":{"code":"raf.not_found","message":"No object named 'nosuchhost' exists in this workspace.","hint":"Import data first (raf analyze <file>) or load the demo (raf demo load).","suggestions":["raf search nosuchhost"]}}
```

The two hosts were updated, not created: the parser's records merge into the existing `host:db-01`
and `host:ws-02` objects (their `criticality` comes from the demo inventory). The rejected line is
in `raf import report job-5`. `raf analyze hosts.notes.csv` picks the plugin's parser as well
(*"Detected: asset-notes: asset-notes parser (score 0.99)"*), and `raf --help` lists the command:

```text
╭─ Plugins ──────────────────────────────────────────────────────────────────╮
│ notes       Show analyst notes on hosts (from *.notes.csv imports).         │
╰────────────────────────────────────────────────────────────────────────────╯
```

## Limitations

* Permissions are declared and displayed, never enforced; a trusted plugin has the full privileges
  of the R$F process.
* The trust hash skips `__pycache__`, which Python reads cached bytecode from.
* A broken or modified trusted plugin can break `raf --help` (and, if it fails at import, `raf
  serve` and every import) instead of being shown as unavailable.
* Plugin commands can replace built-in product commands without a warning.
* A dependency cycle introduced by `raf install` leaves the registry unusable until it is repaired
  by hand.
* `analyzers` and `entrypoint` are accepted but unused; there are no hooks for web views, pivots or
  snapshot state providers; Python dependencies are not installed; no remote registry.
