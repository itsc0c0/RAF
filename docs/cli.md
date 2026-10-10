# R$F command line (`raf`)

`raf` is the command-line interface of R$F (Typer + Rich). Every command works on one workspace (the
current one unless `-w NAME` is given), uses the same services as the HTTP API, and can print a
stable JSON document instead of the human view. Product commands are loaded lazily from the product
registry: a disabled or broken product shows up as unavailable instead of breaking `raf`.

```text
raf [GLOBAL FLAGS] COMMAND [SUBCOMMAND] [ARGUMENTS] [OPTIONS]
raf COMMAND --help            (or -h)
raf help COMMAND [SUBCOMMAND] | raf help TOPIC
```

Help topics (`raf help TOPIC`): `objects`, `relationships`, `query` (the filter language; `filters`
is the same topic), `refs` (context references), `exit-codes`, `plugins`.

## Global flags

| Flag | Effect |
|---|---|
| `--json` | print one JSON document on stdout (see [Output](#output-conventions)); disables colors, progress bars and the interactive shell |
| `--quiet`, `-q` | only essential output: no headers, notes, success messages or next-step suggestions (tables and data are still printed; `raf diff` lists only HIGH changes, `raf timeline` hides the histogram) |
| `--no-color` | no colors (also `NO_COLOR` in the environment, or `raf config set core.color false`) |
| `--debug` | full tracebacks for errors and debug-level logs on the console (whatever `core.log_level` says) |
| `--yes`, `-y` | confirm destructive operations (delete, uninstall, trust, reset ...) without a prompt (`raf config set core.confirm_destructive false` does this for every command) |
| `--workspace NAME`, `-w NAME`, `--workspace=NAME` | run this command in another workspace |
| `--version` | print `R$F 0.2.0` and exit; only directly after `raf` (`raf version` shows every version identifier) |

Global flags are accepted **anywhere** on the command line (`raf graph alice --json -w verify` is the
same as `raf --json -w verify graph alice`); they are removed before the command is parsed. Arguments
after `--` are passed through unchanged (`raf lab exec NAME -- ls -la`).

### Environment

| Variable | Effect |
|---|---|
| `RAF_HOME` | R$F home directory (default `~/.raf`): `config.toml`, `registry.json`, `plugins/`, `logs/`, `workspaces/` |
| `RAF_WORKSPACE` | the current workspace, overriding `raf workspace use` |
| `RAF_<SECTION>_<KEY>` | a configuration value, e.g. `RAF_GRAPH_MAX_NODES=900` (`raf config keys` lists every variable); it overrides the configuration files |
| `RAF_CORE_LOG_LEVEL` | console log level: the `core.log_level` setting (`DEBUG`, `INFO`, `WARNING`, `ERROR`), applied from start-up |
| `RAF_ORACLE_API_KEY`, `RAF_API_TOKEN` | secrets (never read from configuration files) |
| `RAF_OS_BIN` | path of the `raf-os` binary used by `raf tui` |
| `NO_COLOR` | disable colors |
| `COLUMNS` | output width when stdout is not a terminal (default 160) |

### Interactive shell

`raf` without arguments, on an interactive terminal (stdin and stdout are terminals) and without
`--json`, prints the status banner and opens a `raf > ` prompt:

* each line is split like a shell command line (quotes work) and run as a command; the `raf` prefix
  is optional;
* global flags work per line; `-w`, `--no-color` and `--debug` given when starting the shell apply to
  every line;
* `exit`, `quit`, `:q` or Ctrl+D leave the shell, `clear` clears the screen; history is kept in
  `RAF_HOME/shell_history` (1,000 lines) when readline is available.

Without a terminal (scripts, pipes) or with `--json`, `raf` alone runs `raf status`.

## Output conventions

* **Human output** goes to stdout: headers, key/value blocks, tables, trees. Notes (for example how a
  reference was resolved: `@last -> analysis-1`), warnings, prompts and progress bars go to stderr.
  Text that comes from imported data is printed with control characters, escape sequences and
  bidirectional overrides escaped (`\x1b`).
* **Closed pipes.** When the reader of the output goes away (`raf timeline workspace | head`), `raf`
  stops writing and exits quietly with status 0, like `rg`; a command that had already failed keeps
  its own exit status.
* **Next steps.** Many commands end with `Next:`, `Explore:` or `Try:` and a list of commands
  (`raf replay INC-001`, `raf trace user:alice`). They are suggestions only; R$F never runs them.
* **JSON.** With `--json` a command prints exactly one document: `{"schema": "raf.<name>/v1", ...}`.
  Payloads that are lists are wrapped as `{"schema": ..., "items": [...]}`. Timestamps are ISO 8601
  UTC with `Z`; models include computed fields such as `confidence_level`. The schema ID of each
  command is listed in the [command reference](#command-reference).
* **Errors.** Expected failures are structured errors. Human form (stderr):

  ```text
  R$F: 'git' matches more than one object.

  Reason:
    Name resolution found multiple candidates: file:dev-01|/usr/bin/git, file:ws-03|/usr/bin/git, ...

  Use a full object ID (for example 'host:ws-04') or a type-qualified reference.
  ```

  With `--json` the error is a `raf.error/v1` document on stdout:

  ```json
  {"schema": "raf.error/v1",
   "error": {"code": "raf.ambiguous_reference", "message": "'git' matches more than one object.",
             "reason": "Name resolution found multiple candidates: ...",
             "hint": "Use a full object ID (for example 'host:ws-04') or a type-qualified reference.",
             "details": {"candidates": ["file:dev-01|/usr/bin/git", "..."]}}}
  ```

  `reason`, `hint`, `suggestions` (commands to try) and `details` are present when they apply.
  A failed import job is reported the same way: `raf --json import` prints only the `raf.error/v1`
  document (code `raf.ingestion`, exit 1), with the failed job - including the job's own error - in
  `details.job` and `raf job show JOB` in `suggestions`.
  Command-line mistakes have the code `raf.usage`. An unexpected exception prints *"R$F hit an
  internal error. This is a bug in R$F, not in your data."* (JSON code `raf.internal` with `type`
  and `detail`), is logged with its traceback to `RAF_HOME/logs/raf.log` (unless `core.log_file` is
  `false`), and exits with 1; `--debug` prints the traceback.
* **Confirmations.** Destructive commands print what they will do and ask for `yes`. Without a
  terminal they fail with `raf.confirmation_required` (exit 4) unless `--yes` is given or
  `core.confirm_destructive` is `false`.

## Exit codes

| Code | Meaning | Error codes |
|---|---|---|
| 0 | success (also when the reader of the output went away, as with `raf ... \| head`) | |
| 1 | general failure | `raf.error`, `raf.storage`, `raf.ingestion`, `raf.internal`, Lab backend errors; `raf analyze` when the analysis failed |
| 2 | usage error (unknown command or option, missing argument, value out of range) | `raf.usage` |
| 3 | not found | `raf.not_found` |
| 4 | invalid input, conflict, ambiguous reference, unavailable product, confirmation required | `raf.invalid_input` (incl. `raf.invalid_timestamp`, `raf.record_rejected`), `raf.ambiguous_reference`, `raf.conflict`, `raf.config`, `raf.workspace`, `raf.product_disabled`, `raf.confirmation_required` |
| 5 | security violation or failed integrity check | `raf.security_violation`, `raf.resource_limit`, `raf.permission_denied`, `raf.integrity`; also `raf evidence verify`, `raf audit verify`, `raf bundle verify` and `raf plugin verify` when verification fails, and the commands of a plugin whose files changed after trust |
| 6 | a required external dependency is unavailable (Docker/Podman, OS keyring, AI provider) | `raf.dependency_unavailable`, Oracle provider errors |
| 124 | `raf lab exec`: the command timed out | `raf.lab.command_failed` |
| 130 | cancelled or interrupted (Ctrl+C, aborted prompt, cancelled job) | `raf.cancelled` |

`raf lab exec` otherwise exits with the status of the command it ran. `raf plugin verify` exits 5
when the plugin's files changed after trust, 4 when it is not trusted and 3 when it is not
installed.

## References

### Objects

Wherever a command takes an object, it accepts:

* a full ID `<type>:<key>`; the key is normalized as on import, so `host:WS-02` finds `host:ws-02`
  ([object model](object-model.md#identifiers));
* a name or an alias (`metadata.aliases`), without regard to case: `alice`, `WS-02`, `production`;
* where it makes sense, other IDs: `event:...` and `finding:...` (`raf show`), `analysis-N` and
  `job-N` (scopes), an evidence case name (resolves to its incident), an evidence item ID
  (`ev-0005` is `evidence:ev-0005`);
* a [context reference](#context-references) such as `@last`.

When a name matches objects of several types, the first type in this order wins and a note names the
alternatives: incident, user, host, identity, service, group, role, network, cloud_resource,
container, domain, ip, project, package, vulnerability, policy, organization, permission, process,
file, directory, url, certificate, secret, session, connection, port, dependency, alert, evidence.
An evidence item ID competes with names the same way: if an object is also *named* `ev-0005`, that
object wins and the note names `evidence:ev-0005`.
Several matches of the winning type are an error (`raf.ambiguous_reference`, exit 4) listing the
candidates. An unknown name fails with `raf.not_found` (exit 3) and similar IDs as a hint.

### Scopes

Graph, Timeline, Replay and Lens take a **scope**: nothing or `workspace` / `all` / `@workspace`
(the whole workspace; Replay requires the word), one reference (object, incident, `analysis-N`,
`job-N`, context reference), or `TYPE NAME` (`host WS-02`, `user alice`), where `TYPE` is any
object type as `raf objects --type` takes it: a canonical type (`raf help objects`), an alias
(`hostname`, `account`, `ipaddress`, `ip_address`, `fqdn`, `cloudresource`, `vuln`, `cve`, `proc`,
`dir`, `cert`, `net`) or a plugin type `x-<name>`; case does not matter. Lens also accepts an
evidence item (`ev-0005` or `evidence:ev-0005`): the events parsed from it. Events, findings and
snapshots are not scopes: `raf timeline event:...` fails with `raf.invalid_input` (exit 4) and
suggests `raf show event:...` (`raf snapshot show NAME` for a snapshot).

### Context references

Commands remember what they produced or showed, per workspace (the last 30 entries), and later
commands refer to it with `@` tokens:

| Token | Refers to | Remembered by |
|---|---|---|
| `@last` | the most recent remembered entity of a kind the command accepts | any of the below |
| `@object` | most recent object | `raf show`, scopes on an object (`graph`, `timeline`, `replay`, `lens`), `graph neighbors`, `trace`, `blast`, `iam show`, `exposure show`, `oracle ask`, `evidence import`, `vault scan`, `dependency scan`, `raf demo load` (alice) |
| `@incident` | most recent incident | incident scopes, `raf show INC-...`, `raf import` / `forge scenario` that created one, `raf demo load` |
| `@analysis` | most recent analysis | `raf analyze`, analysis scopes |
| `@snapshot` | most recent snapshot | `raf snapshot create` |
| `@job` | most recent job | `raf import`, `raf job show`, `forge`, `surface import` |
| `@case` | most recent evidence case | `raf evidence case create`, `raf evidence import` |
| `@lab` | most recent lab | `raf lab create`, `start`, `exec`, `shell` |
| `@range` | most recent range | `raf range create`, `status NAME`, `start`, `tick`, `stop`, `reset` |
| `@ghost` | most recent Ghost model | `raf ghost create`, `clone`, `modify`, `show` |
| `@workspace` | the current workspace | (always available) |

What a command accepts decides what `@last` means, and an `@<kind>` token of a kind the command does
not accept is an error (`raf show @lab`: *"@lab refers to a lab, which this command does not
accept."*, exit 4) rather than a name looked up in the wrong place. Scopes (`graph`, `timeline`,
`replay`, `lens`) accept objects, incidents, cases, analyses and jobs; object arguments (`show`,
`trace`, `blast`, `iam show`, `graph path`, ...) accept objects, incidents and cases (a case stands
for its incident); state arguments (`raf diff`) accept snapshots; lab commands accept labs and range
commands (`raf range status @range`) ranges, and Ghost commands (`raf ghost show @ghost`,
`raf ghost compare current @ghost`) Ghost models. `@workspace` is the whole workspace for scopes and
the current state for `raf diff`.
`@selection` exists only in the web UI.

## Time values

Options such as `--from`, `--to` and `--at` accept:

| Form | Example |
|---|---|
| ISO 8601 (`T` or space, `Z` or offset, fractions) | `2026-10-06T23:04:41Z`, `2026-10-06 23:04:41+02:00` |
| date only | `2026-10-06` (00:00 UTC) |
| epoch seconds, milliseconds, microseconds or nanoseconds | `1791327881` (= 2026-10-06T23:04:41Z) |
| RFC 2822 | `Tue, 06 Oct 2026 23:04:41 +0000` |
| `now` | |
| time of day | `23:04`, `23:04:41` |
| offset | `+15m`, `-2h`, `+1d`, `+30s`, `+250ms`, `+1w` |

A time of day is placed on the date of the command's anchor (Timeline: the scope's first event;
Replay: the replay window, preferring the occurrence inside it; Protocol: the capture), and offsets
are added to the anchor. Commands without an anchor (`graph --at`, `blast --at`, `lens --from/--to`)
place a time of day on the current UTC date and reject offsets. Values must lie between 1990 and
2200. API parameters take full timestamps only.

## Filter language

`raf timeline --filter`, `raf lens --filter` and the API parameter `filter` (`/timeline`,
`/timeline/export`, `/lens/query`) select events with a small query language (`raf help query`, or
`raf help filters`):

```text
type:auth.* outcome:failure actor:bob severity>=medium confidence>=0.6 time>=2026-10-06T22:00:00Z "vpn"
```

| Term | Selects events ... |
|---|---|
| `type:auth.login` | of this type; `type:auth.*` or `type:auth` = the type and every `auth.<action>` |
| `category:network` | of this category |
| `actor:alice` | whose actor is this object (name, ID, alias or `@` reference) |
| `target:WS-01` | whose target is this object |
| `object:host:dev-01` | that involve this object in any role (on an object scope: that involve both) |
| `severity>=medium`, `severity>medium`, `severity<=low`, `severity<high` | at or above / above / at or below / below this severity (`severity:` and `severity=` mean "at or above") |
| `confidence>=0.6`, `confidence<0.8`, `confidence:high` | whose confidence is in range: a number in 0..1, a percentage (`60`) or LOW/MEDIUM/HIGH (0.3/0.6/0.9); `confidence:` means "at least" |
| `outcome:failure` | with this outcome (`success`, `failure`, `unknown`, or as imported) |
| `source:auth.log` | whose source name contains this text |
| `time>=T`, `time>T`, `time<=T`, `time<T` | at or after, after, at or before, before a full timestamp |
| `after:T`, `before:T` | the same as `time>=T` and `time<=T` |
| `incident:INC-001` | linked to this incident |
| `job:job-4` | imported by this job (a job ID or `@job`) |
| `synthetic:true` | marked synthetic (`true`, `1`, `yes`) or not (`false`, `0`, `no`) |
| words and `"quoted phrases"` | containing every one of them (case-insensitive) in the message, event type, actor ID, target ID or raw record |

Rules:

* Terms are separated by spaces; quoting follows shell rules (`'...'`, `"..."`, `\`).
* `key:value` and `key=value` are the same. An unquoted token that looks like `word:...`,
  `word=...` or `word>=...` with a word that is not a key is an error that lists the keys
  (`Unknown filter key 'foo'`, exit 4), except URLs (`https://...`). Keys are lower case.
* A token that starts with a quote is always free text, so quote text that contains `:` or `=`:
  `'"error: disk full"'`, `'"user=alice"'`.
* Only `severity`, `confidence` and `time` compare (`>=`, `>`, `<=`, `<`); a comparison on any
  other key is an error, and so is `time:` (use a comparison).
* Free-text terms must all match: `exfil upload` selects events containing both words, `"exfil
  upload"` the phrase. They also combine with the API's `q` parameter (AND).
* Terms combine with AND. Repeated `type:`, `category:`, `object:` and `job:` terms are alternatives
  (OR). Repeated `severity` and time terms keep the strictest bound. Repeating `actor:`, `target:`,
  `outcome:` or `synthetic:` with different values selects nothing (an event has one actor, one
  outcome ...); for `incident:` and `source:` see below.
* **Filters only narrow.** Terms apply to what the command already selected - its scope and its
  options (`--from`/`--to`, `--type`, `--category`, `--severity`, Lens `--source`, the API's `q`) -
  and never widen it: `raf timeline job-1 --filter job:job-2` selects nothing, `type:auth.login`
  with `--type auth` selects logins, and for times the stricter bound wins (`--from 22:00` with
  `after:` an earlier moment keeps 22:00); `object:` on a scope that is another object selects the
  events that involve both (`raf timeline user alice --filter object:DEV-01`). A combination the
  event store cannot select is rejected with an explanation (exit 4) instead of being approximated:
  two different incidents, and two `source:` texts of which neither contains the other.
* References in `actor:`, `target:`, `object:` and `incident:` are resolved like any reference; an
  unknown name is an error (exit 3), and so is an event, finding or snapshot ID (exit 4).
* Values are bound as query parameters; nothing is ever interpolated into SQL.

## Command reference

Commands are grouped as in `raf --help`. Product pages describe options and output in detail.
"Schema" is the `schema` of the `--json` document.

### Platform

| Command | What it does | Example |
|---|---|---|
| `raf version` | R$F, API, bundle format, plugin API, object model and event schema versions (`raf.version/v1`) | `raf version` |
| `raf status` | platform and database state, workspace, data counts, open findings by severity, Oracle provider (`raf.status/v1`) | `raf status --json` |
| `raf help [COMMAND...]` / `raf help TOPIC` | help for a command path, or a topic | `raf help replay`, `raf help query` |
| `raf products` | every product with status (STABLE, BETA, ALPHA, EXPERIMENTAL, DISABLED, UNAVAILABLE) and description (`raf.products/v1`) | `raf products` |
| `raf product info NAME` | manifest, status, maturity, source, commands, dependencies and dependents (`raf.product/v1`) | `raf product info lens` |
| `raf product enable NAME` / `disable NAME` | enable or disable a product; disabling also makes its dependents unavailable (audited). A running `raf serve` answers 503 on the product's routes from the next request, and serves them again once it is re-enabled | `raf product disable lab` |
| `raf install PATH` | install a plugin from a local directory, disabled and untrusted (`raf.plugin/v1`) | `raf install ./asset-notes` |
| `raf uninstall NAME` | remove an installed plugin (confirmation) | `raf --yes uninstall asset-notes` |
| `raf plugin list` | installed plugins with version, trust, status and permissions (`raf.plugins/v1`) | `raf plugin list` |
| `raf plugin trust NAME` | record the SHA-256 of the plugin's files and enable it (confirmation) | `raf --yes plugin trust asset-notes` |
| `raf plugin verify NAME` | check that a trusted plugin's files still match (`raf.plugin.verify/v1`, `unchanged`); exit 5 when the files changed | `raf plugin verify asset-notes` |
| `raf serve [--host H] [--port P] [--no-ui] [--allow-host NAME]...` | run the HTTP API (`/api/v1`) and the web workbench; loopback by default, a non-loopback address requires a bearer token (`RAF_API_TOKEN`, or one is generated and shown once); see [api.md](api.md) | `raf serve --port 8765` |
| `raf tui [-p PAGE] [--param TEXT] [--dump PAGE [--width 100]] [--no-boot] [--no-mouse]` | R$F OS, a full-screen terminal panel: runs the `raf-os` binary (built from `tui/` with Rust; found via `RAF_OS_BIN`, `tui/target/release`, `tui/target/debug`, the virtualenv or `PATH`) against an API started for the session on a random loopback port with a one-time token. Pages: home, timeline, trace, iam, blast, exposure, policy, ghost, graph, oracle, findings, evidence; `--dump` prints one page as plain text. Needs an interactive terminal unless `--dump` is given (exit 4), has no `--json` output (exit 4), and exits 6 while the binary is not built | `raf tui --dump blast` |
| `raf demo load` | load Raven Industries: inventory, a working day of events, INC-001, its evidence case, policies, IAM and exposure analysis, the Surface inventory (`raf.demo/v1`) | `raf demo load` |

Plugin management is described in [plugin-development.md](plugin-development.md).

### Data

| Command | What it does | Example |
|---|---|---|
| `raf search QUERY [-t TYPE]... [--limit 25]` | ranked object search (exact name or ID, alias, prefix, substring) plus findings whose title or ID matches (no findings with `--type`) (`raf.search/v1`) | `raf search dev` |
| `raf show REF [-t TYPE]` | object inspector: type, source, first/last seen, confidence, metadata, relationships (25 shown), event activity, findings, provenance, pivots; also events (`event:...`) and findings (`finding:...`) (`raf.object/v1`, `raf.event/v1`, `raf.finding/v1`) | `raf show WS-02` |
| `raf objects [-t TYPE]... [--tag TAG] [--filter TEXT] [--limit 50] [--offset 0]` | list objects ordered by name; `--filter` is a substring of name or ID (`raf.objects/v1`; `total` is null with `--tag`) | `raf objects --type host --limit 3` |
| `raf findings [-s SEVERITY] [--product P] [--status S]... [--object REF] [--limit 50]` | findings of all products, highest severity and confidence first; default statuses OPEN and ACKNOWLEDGED (`raf.findings/v1`) | `raf findings --severity high` |
| `raf finding show ID` | one finding with explanation, affected objects, evidence and recommendation (`raf.finding/v1`) | `raf finding show finding:exposure:asset-exposure:20fdde4a71fb` |
| `raf finding ack\|resolve\|false-positive\|reopen ID [--note TEXT]` | set the status (ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE, OPEN); recorded in `metadata.status_history` and the audit log | `raf finding ack finding:... --note "triaged"` |
| `raf incidents` | incidents with severity, status, event count and window (`raf.incidents/v1`) | `raf incidents` |
| `raf jobs [--status S] [--limit 20]` | recent jobs (QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED) with progress and duration (`raf.jobs/v1`) | `raf jobs --status failed` |
| `raf job show JOB` / `raf job cancel JOB` | a job's status, result and error; request cancellation of a queued or running job (`raf.job/v1`) | `raf job show job-1` |
| `raf import PATH [-f FORMAT] [--incident NAME] [--host HOST] [--source-name NAME] [--timezone TZ] [--synthetic]` | import a file or a directory as a job, with provenance; malformed records are rejected individually; `Format` shows the parser of a file, or for a directory the formats of its files (`directory (syslog, jsonl, csv)`); a failed job is a `raf.error/v1` (exit 1) (`raf.import/v1`) | `raf import fixtures/evidence/auth.log --host DEV-01` |
| `raf import report JOB` | the rejected records of an earlier import (up to 500, raw text truncated) (`raf.import.report/v1`) | `raf import report job-5` |
| `raf analyze TARGET [-f FORMAT] [--incident NAME] [--source-name NAME] [--synthetic] [--no-correlate]` | detect the input type and run the matching pipeline; records `analysis-N`; `raf analyze analysis-N` shows a recorded one (`raf.analysis/v1`); see [analyze.md](analyze.md) | `raf analyze fixtures/pcap/raven-inc001.pcap` |
| `raf analyses [--limit 20]` | earlier analyses, newest first (`raf.analyses/v1`) | `raf analyses` |
| `raf detect [SCOPE] [--dry-run]` | the [Timeline detections](products/timeline.md#detections) over a scope (default: the workspace): findings, activity explained by changes, tickets or scheduled jobs, and suspected incidents (`raf.detections/v1`); `--dry-run` stores nothing | `raf detect analysis-1` |
| `raf audit [--limit 30] [--operation PREFIX]` | R$F's own hash-chained audit log (`raf.audit/v1`) | `raf audit --operation graph` |
| `raf audit verify` | recompute the audit hash chain; exit 5 when it is broken (`raf.audit.verify/v1`) | `raf audit verify` |

`raf import --format` names a parser: `jsonl`, `json`, `csv`, `syslog`, `access-log`, `multilog`
([mixed and multi-source logs](logs.md)), `text`,
`raf-policy` (Policy), `pcap` (Protocol), `raf-surface` (Surface), parsers of trusted plugins, and
`filesystem` (directories only: a file-metadata timeline instead of parsing each file; files and
directories become objects on the `--host` host (default `local`) linked by `CONTAINS`, with size,
mode, owner IDs and a SHA-256 for regular files up to 64 MiB; modification times become
`file.modify` events with confidence 0.6; symbolic links are recorded but not followed; more than
200,000 entries fail with `raf.resource_limit`).

### Workspace

| Command | What it does | Example |
|---|---|---|
| `raf workspace create NAME [-d TEXT] [--use]` | create a workspace (names: 1-63 lower-case letters, digits, `-`, `_`) (`raf.workspace/v1`) | `raf workspace create cliref --use` |
| `raf workspace use NAME` | make a workspace current (stored in `RAF_HOME/state.json`) | `raf workspace use default` |
| `raf workspace list` | workspaces; `*` marks the current one (`raf.workspaces/v1`) | `raf workspace list` |
| `raf workspace info [NAME]` | path, size and data counts (`raf.workspace.info/v1`) | `raf workspace info verify` |
| `raf workspace delete NAME` | delete a workspace and all its data (confirmation; refused while `RAF_WORKSPACE` selects it) | `raf --yes workspace delete scratch` |
| `raf workspace export NAME OUTPUT` | back up data, cases, evidence files, snapshots and the audit log into a `.raf` bundle (`raf.workspace.export/v1`) | `raf workspace export default backup.raf` |
| `raf workspace import PATH --name NAME` | restore a backup into a new workspace (validated before anything is written) (`raf.workspace.import/v1`) | `raf workspace import backup.raf --name restored` |
| `raf config list` | every key with its effective value and origin layer; secrets shown as set / not set (`raf.config/v1`) | `raf config list` |
| `raf config get KEY` | one effective value and its origin (`raf.config.value/v1`) | `raf config get graph.max_nodes` |
| `raf config set KEY VALUE [--scope global\|workspace]` | write a value to the global (default) or workspace `config.toml`; values are type-checked; secrets are refused | `raf config set graph.max_nodes 800 --scope workspace` |
| `raf config unset KEY [--scope global\|workspace]` | remove a value from a layer (`raf.config.unset/v1`) | `raf config unset graph.max_nodes --scope workspace` |
| `raf config path` | configuration file locations and the `RAF_` prefix (`raf.config.paths/v1`) | `raf config path` |
| `raf config keys` | every key with type, default and environment variable (`raf.config.keys/v1`) | `raf config keys` |
| `raf secret set KEY` / `delete KEY` | store (prompted, not echoed) or remove a secret in the OS keyring (`raf.secret/v1`) | `raf secret set oracle.api_key` |
| `raf secret status` | where each secret comes from: `env`, `keyring` or `not set` (`raf.secrets/v1`) | `raf secret status` |
| `raf bundle verify PATH` | check a bundle's structure, limits and every member's SHA-256; exit 5 on problems (`raf.bundle.verify/v1`) | `raf bundle verify inc.raf` |
| `raf bundle import PATH` | merge a bundle's objects, relationships, events, findings and evidence into the workspace (`raf.bundle.import/v1`) | `raf bundle import inc.raf` |

#### Configuration

Precedence: defaults < global `config.toml` < workspace `config.toml` (of `-w NAME` or the current
workspace) < `RAF_*` environment variables < command-line flags. The keys are listed by
`raf config keys`. Keys that change how `raf` itself behaves:

| Key (default) | Effect |
|---|---|
| `core.log_level` (`WARNING`) | minimum level of the console log on stderr (`DEBUG`, `INFO`, `WARNING`, `ERROR`); read when `raf` starts, so it applies to the whole command; `--debug` shows everything |
| `core.log_file` (`true`) | write structured JSON logs (INFO and above) to `RAF_HOME/logs/raf.log`; `false` writes no log file, and internal errors then are not logged anywhere (run with `--debug`) |
| `core.color` (`true`) | colors in terminal output (`--no-color` and `NO_COLOR` also turn them off) |
| `core.confirm_destructive` (`true`) | ask before destructive operations; `false` confirms them as `--yes` does, also without a terminal |
| `range.default_seed` (`42`) | seed of `raf range create` (and `POST /range/ranges`) without `--seed`; see [Range](products/range.md) |
| `evidence.max_item_mb` (`4096`) | largest evidence item; see [Evidence](products/evidence.md) |

A configuration file `raf` cannot read, or an invalid value (also in a `RAF_*` variable), fails every
command that opens a workspace with `raf.config` (exit 4); the logging settings then fall back to
their defaults.

### Investigate

| Command | What it does | Example |
|---|---|---|
| `raf snapshot create NAME [--source current\|ghost:MODEL] [-d TEXT]` | capture the security state (objects, relationships, findings) with structural sharing (`raf.snapshot/v1`) | `raf snapshot create before` |
| `raf snapshot list` / `show NAME` / `delete NAME` | snapshots; details; delete (confirmation) (`raf.snapshots/v1`, `raf.snapshot/v1`, `raf.snapshot.delete/v1`) | `raf snapshot list` |
| `raf graph [SCOPE] [--depth N] [--rel T]... [--node-type T]... [--direction D] [--at T] [--max-nodes N] [-o FILE] [--format F]` | the relationship graph of a scope (`raf.graph/v1`); [Graph](products/graph.md) | `raf graph alice --at 2026-10-06T08:00:00Z` |
| `raf graph neighbors OBJECT` | depth-1 neighborhood (`raf.graph/v1`) | `raf graph neighbors WS-02 --direction out` |
| `raf graph path FROM TO [--directed]` | shortest connection between two objects (`raf.graph.path/v1`) | `raf graph path alice DB-01` |
| `raf graph export [SCOPE] --format json\|cytoscape\|graphml\|dot\|csv [-o FILE]` | export a view (`raf.graph.export/v1` with `--output`) | `raf graph export INC-001 --format graphml -o inc.graphml` |
| `raf graph stats` | counts by type and the most connected objects (`raf.graph.stats/v1`) | `raf graph stats` |
| `raf timeline [SCOPE] [--from T] [--to T] [--type T]... [--category C]... [--severity S] [--filter EXPR] [--group-by F] [--limit 50] [--reverse] [--cursor C] [--export FILE --format F]` | events of a scope on one time axis, grouped, with a histogram, paginated and exportable (`raf.timeline/v1`, `raf.timeline.export/v1`); [Timeline](products/timeline.md) | `raf timeline user alice --filter 'type=auth.*'` |
| `raf trace OBJECT [--direction both\|back\|forward] [--depth 3]` | how an object became involved and what it did, observed vs. correlated links (`raf.trace/v1`); [Trace](products/trace.md) | `raf trace svc-deploy --direction back` |
| `raf replay SCOPE [--at T \| --from T --to T \| --play --speed X] [--no-context] [--limit 80]` | deterministic reconstruction: sequence, state at a moment, changes in a window, playback (`raf.replay/v1`, `raf.replay.state/v1`, `raf.replay.window/v1`); [Replay](products/replay.md) | `raf replay INC-001 --at 23:04:41` |
| `raf diff A B [--only CATEGORY] [--limit 60]` | compare two states with categorized, explained importance (`raf.diff/v1`); [Diff](products/diff.md) | `raf diff before after` |

### Exposure

| Command | What it does | Example |
|---|---|---|
| `raf blast REF [--max-depth N] [--min-confidence C] [--at T] [--all]` | blast radius of a hypothetical compromise with explained paths and risk (`raf.blast/v1`); [Blast](products/blast.md) | `raf blast alice` |
| `raf iam analyze [--no-save] [--min-severity S] [--limit 30]` | run the IAM analyzers and record findings (`raf.iam.analysis/v1`); [IAM](products/iam.md) | `raf iam analyze --no-save` |
| `raf iam show REF [--limit 40]` | effective access of a principal (`raf.iam.access/v1`) | `raf iam show sarah` |
| `raf iam path SOURCE TARGET [--max-depth 10] [--paths 3]` | how a principal could obtain control of a target (`raf.iam.paths/v1`) | `raf iam path alice production` |
| `raf policy check PATH [--principal P] [--host NAME] [--limit 40]` | normalize and analyze policy files without storing them (`raf.policy.check/v1`): raf-policy/1, IAM JSON, CSV exports, iptables-save, nftables (text or `nft -j` JSON; `--host` names the host whose rules they are); [Policy](products/policy.md) | `raf policy check fixtures/policies/raven-edge.rules` |
| `raf policy import PATH [--principal P] [--host NAME]` | store policies in the workspace graph (`raf.policy.import/v1`) | `raf policy import fixtures/policies/raven-fw-export.csv` |
| `raf policy list` / `show POLICY` | stored policies; one policy with its normalized rules (`raf.policy.list/v1`, `raf.policy/v1`) | `raf policy show raven-fw` |
| `raf policy analyze [PATH] [--no-save] [--limit 40]` | analyze stored policies (or a path) and record findings (`raf.policy.analysis/v1`) | `raf policy analyze --no-save` |
| `raf policy can SUBJECT VERB TARGET [-p PORT]... [--from HOST]...` | evaluate a hypothetical flow or access and show the deciding policy chain (`raf.policy.evaluation/v1`) | `raf policy can DEV-01 reach DB-01 --port tcp/5432` |
| `raf policy diff BEFORE [AFTER]` | compare policy revisions: files, `current` (default AFTER) or snapshots (`raf.policy.diff/v1`) | `raf policy diff fixtures/policies/raven-policies-2026-09.json current` |
| `raf exposure [--min-level L] [--type T] [--limit 25] [--no-save]` | rank assets by explainable exposure and record HIGH/CRITICAL findings (`raf.exposure/v1`); [Exposure](products/exposure.md) | `raf exposure --limit 5` |
| `raf exposure show REF` | one asset's exposure factor by factor (`raf.exposure.asset/v1`) | `raf exposure show VPN-01` |
| `raf surface show [--at T] [--expiring-days 30]` | external surface summary: scope, assets, domain tree, top findings (`raf.surface.summary/v1`); [Surface](products/surface.md) | `raf surface show` |
| `raf surface import PATH [--apply-scope] [-f FORMAT] [--source-name NAME]` | import a surface inventory (`raf.surface.import/v1`) | `raf surface import raven-surface.json` |
| `raf surface analyze [--at T] [--expiring-days 30] [--no-save] [--limit 25]` | run the surface rules and record findings (`raf.surface.analysis/v1`) | `raf surface analyze` |
| `raf surface assets [-k KIND] [--in-scope\|--out-of-scope] [--all] [--limit 200]` | surface assets with scope and ownership (`raf.surface.assets/v1`) | `raf surface assets --kind domain` |
| `raf surface findings [--rule R] [--min-severity S] [--status open] [--limit 50]` | surface findings (`raf.surface.findings/v1`) | `raf surface findings` |
| `raf surface sample OUTPUT` | write the synthetic Raven inventory (`raf.surface.sample/v1`) | `raf surface sample raven-surface.json` |
| `raf surface scope add TARGET [--kind K] [--owner O] [--authorization REF] [--replace]` / `list` / `remove TARGET` | the authorized scope (domains, CIDRs, IPs, cloud accounts) (`raf.surface.scope.entry/v1`, `raf.surface.scope/v1`) | `raf surface scope add raven.example --owner "IT operations" --authorization SEC-2026-031` |

### Synthetic environments

| Command | What it does | Example |
|---|---|---|
| `raf ghost create NAME [--from current\|SNAPSHOT] [-d TEXT]` / `clone SOURCE NAME` | create or copy a what-if model (`raf.ghost.model/v1`); [Ghost](products/ghost.md) | `raf ghost clone current hardened` |
| `raf ghost modify NAME [--remove-access A:B] [--isolate HOST] ... [--op 'OP ARG']... [--undo]` | apply what-if operations to a model (`raf.ghost.modify/v1`) | `raf ghost modify hardened --remove-access alice:production` |
| `raf ghost operations` / `list` / `show NAME` | supported operations; models; one model with its operation log (`raf.ghost.operations/v1`, `raf.ghost.list/v1`, `raf.ghost.model/v1`) | `raf ghost show hardened` |
| `raf ghost simulate NAME\|current [--limit 10]` | exposure and attack paths inside a model (`raf.ghost.simulate/v1`) | `raf ghost simulate hardened` |
| `raf ghost compare A B` | compare models, `current` or snapshots (`raf.ghost.compare/v1`) | `raf ghost compare current hardened` |
| `raf ghost delete NAME` | delete a model and its unused base snapshot (`raf.ghost.delete/v1`) | `raf --yes ghost delete hardened` |
| `raf range create NAME [--preset P] [--seed N] [--config FILE] [--employees N] [--workstations N] [--servers N] [--departments A,B] [--services A,B] [--mfa-rate R] [--segmentation\|--no-segmentation] [--event-rate N] [--vulnerabilities N] [--start T]` | create a synthetic organization in the workspace; without `--seed` the `range.default_seed` setting (42) (`raf.range.run/v1`); commands that take `NAME` also take `@range`; [Range](products/range.md) | `raf range create acme --seed 7 --employees 12` |
| `raf range start\|tick NAME [--hours 24]` | generate routine activity for the next simulated period (`raf.range.run/v1`) | `raf range start acme --hours 4` |
| `raf range stop NAME` / `reset NAME` / `destroy NAME` | stop generating; remove what the range wrote and recreate its inventory; remove it and forget the range (reset and destroy ask for confirmation) | `raf --yes range destroy acme` |
| `raf range status [NAME]` / `list` / `presets` | ranges with live counts; presets (`raf.range.status/v1`, `raf.range.list/v1`, `raf.range.presets/v1`) | `raf range presets` |
| `raf forge auth\|dns\|web\|process\|file\|identity\|cloud [-n 1000] [--seed 42] [--start T] [--hours 24] [--noise 0.05] [--population auto] [-o FILE [--ingest]]` | synthetic telemetry, imported or written as JSONL (`raf.forge/v1`); [Forge](products/forge.md) | `raf forge dns --count 50 --seed 3 -o dns.jsonl` |
| `raf forge scenario NAME [--seed 42] [--start DAY] [--population P] [-o FILE [--ingest]]` | modeled scenarios `suspicious-access`, `credential-risk`, `lateral-movement` (creates `SIM-<SCENARIO>-<SEED>`) (`raf.forge/v1`) | `raf forge scenario credential-risk --seed 5` |
| `raf forge list` | generators and scenarios (`raf.forge.catalog/v1`) | `raf forge list` |
| `raf lab create NAME [--image I] [--mount PATH]... [--allow-outbound] [--memory M] [--cpus C] [--root] [-d TEXT] [--backend B]` | define an isolated container lab (no container yet) (`raf.lab/v1`); [Lab](products/lab.md) | `raf lab create proto-test --mount fixtures/pcap` |
| `raf lab list` / `status [NAME] [--backend B]` | labs as recorded; backend availability and live state (`raf.lab.list/v1`, `raf.lab.status/v1`) | `raf lab status` |
| `raf lab start NAME` / `stop NAME` / `destroy NAME [--forget]` | create and start, stop, remove a lab's container (destroy asks for confirmation) (`raf.lab/v1`, `raf.lab.destroy/v1`) | `raf lab start proto-test` |
| `raf lab shell NAME` | interactive `/bin/sh` in a running lab (needs a terminal) | `raf lab shell proto-test` |
| `raf lab exec NAME [--timeout 60] [--max-output-kb 1024] [--raw] -- CMD [ARGS...]` | run one command (no shell), output captured; exits with the command's status, 124 on timeout (`raf.lab.exec/v1`) | `raf lab exec proto-test -- ls /lab/input` |

Lab needs a running Docker or Podman daemon for `start`, `stop`, `shell` and `exec`; without one
they fail with exit 6.

### Specialized analysis

| Command | What it does | Example |
|---|---|---|
| `raf protocol inspect PATH [-p PROTO] [--host IP] [--port N] [--flow N] [--from T] [--to T] [--limit 25] [--max-packets N]` | capture summary: protocols, flows, DNS names, TLS server names, HTTP hosts, warnings (`raf.protocol.inspect/v1`); [Protocol](products/protocol.md) | `raf protocol inspect fixtures/pcap/raven-inc001.pcap` |
| `raf protocol packet PATH NUMBER` | every decoded layer and field of one packet, explained (`raf.protocol.packet/v1`) | `raf protocol packet fixtures/pcap/raven-inc001.pcap 7` |
| `raf protocol flows PATH [--sort id\|bytes\|packets\|duration] [--limit 100]` | bidirectional flows with client/server inference (`raf.protocol.flows/v1`) | `raf protocol flows fixtures/pcap/raven-inc001.pcap --sort bytes` |
| `raf protocol generate OUTPUT [--scenario raven-inc001\|benign\|malformed] [--seed 1]` | write a deterministic synthetic capture (`raf.protocol.generate/v1`) | `raf protocol generate benign.pcap --scenario benign --seed 2` |
| `raf vault scan PATH [--allowlist FILE] [--host NAME] [--no-store] [--show-suppressed]` | find committed secrets; values are never printed or stored (`raf.vault.scan/v1`); [Vault](products/vault.md) | `raf vault scan ./raven-shop --host DEV-01` |
| `raf vault findings [--status OPEN\|...\|all] [--severity S] [--limit 100]` / `secrets [--all] [--limit 100]` / `rules` | stored findings, secret objects (redacted), detection rules (`raf.vault.findings/v1`, `raf.vault.secrets/v1`, `raf.vault.rules/v1`) | `raf vault rules` |
| `raf vault allowlist add [FINGERPRINT] --reason TEXT [--rule R] [--path GLOB]` / `list` | the workspace allowlist (`raf.vault.allowlist.add/v1`, `raf.vault.allowlist/v1`) | `raf vault allowlist list` |
| `raf dependency scan PATH [--name N] [--no-check]` | inventory manifests and lockfiles (`raf.dependency.scan/v1`); [Dependency](products/dependency.md) | `raf dependency scan ./raven-shop --name shop` |
| `raf dependency check [PROJECT]` / `projects` / `vulnerable [--all]` | match against imported advisories; projects; affected packages (`raf.dependency.check/v1`, `raf.dependency.projects/v1`, `raf.dependency.vulnerable/v1`) | `raf dependency check shop` |
| `raf dependency advisories import PATH` / `advisories list` | offline OSV advisories (`raf.dependency.advisories.import/v1`, `raf.dependency.advisories/v1`) | `raf dependency advisories import fixtures/advisories/raven-osv.json` |
| `raf dependency sbom import FILE [--name N] [--no-check]` / `sbom export PROJECT -o FILE` | CycloneDX / SPDX import, CycloneDX 1.5 export (`raf.dependency.sbom.import/v1`, `raf.dependency.sbom.export/v1`) | `raf dependency sbom export shop -o shop.cdx.json` |
| `raf dependency sample PATH [--upgraded]` | write the fictional raven-shop project (`raf.dependency.sample/v1`) | `raf dependency sample ./raven-shop` |
| `raf evidence case create NAME [--title T] [-d TEXT] [--incident REF]` / `case list` / `case show NAME` | evidence cases (`raf.evidence.case/v1`, `raf.evidence.cases/v1`); [Evidence](products/evidence.md) | `raf evidence case create INC-042` |
| `raf evidence import PATH --case NAME [--parse\|--no-parse] [--note TEXT] [--derived-from ITEM] [--synthetic]` | hash, store read-only, record custody, parse; files above `evidence.max_item_mb` are refused (`raf.evidence.import/v1`) | `raf evidence import fixtures/evidence/auth.log --case INC-042` |
| `raf evidence list [--case NAME] [--object REF]` / `show ITEM` | items; one item with its chain of custody (`raf.evidence.list/v1`, `raf.evidence.item/v1`) | `raf evidence list --object DEV-01` |
| `raf evidence verify [ITEM...] [--case NAME]` | re-hash stored copies and check custody chains; exit 5 on failure (`raf.evidence.verify/v1`) | `raf evidence verify --case INC-042` |
| `raf evidence note ITEM TEXT` / `export ITEM -o PATH` | add a custody-recorded note; copy out a verified item (`raf.evidence.item/v1`, `raf.evidence.export/v1`) | `raf evidence export ev-0001 -o auth-copy.log` |
| `raf lens [SCOPE] [-f EXPR] [--source TEXT] [--from T] [--to T] [--group-by event_type] [--limit 20] [--buckets 48]` | the data workbench: events, groups, histogram, involved objects, findings, pivots (`raf.lens/v1`); [Lens](products/lens.md) | `raf lens INC-001 --group-by actor` |

### AI reasoning

| Command | What it does | Example |
|---|---|---|
| `raf oracle ask QUESTION... [--facts]` | answer from workspace data with cited R$F IDs (`raf.oracle.answer/v1`); [Oracle](products/oracle.md) | `raf oracle ask "Who can control DB-01?"` |
| `raf oracle status` | provider, readiness, model settings (never the key) (`raf.oracle.status/v1`) | `raf oracle status` |

### Plugins

Commands contributed by trusted plugins appear in this panel of `raf --help` (for example `notes`
from the example plugin in [plugin-development.md](plugin-development.md)).
