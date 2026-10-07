# R$F Dependency

Dependency and SBOM analysis: inventory what a project declares and what is actually
resolved, put it in the shared security graph, import and export SBOMs, and match
packages against advisories you provide, entirely offline.

Status: **BETA**. Category: specialized analysis. Product id: `dependency`.

## Commands

```bash
raf dependency scan PATH [--name PROJECT] [--no-check]   # manifests + lockfiles -> project graph
raf dependency check [PROJECT]                           # match against imported advisories
raf dependency advisories import PATH                    # OSV JSON: object, list, {"vulns": [...]}, or a directory
raf dependency advisories list
raf dependency sbom import FILE [--name PROJECT] [--no-check]   # CycloneDX JSON or SPDX 2.x JSON
raf dependency sbom export PROJECT --output FILE         # CycloneDX 1.5 JSON
raf dependency projects
raf dependency vulnerable [--all]                        # affected packages and their advisories
raf dependency sample DIR [--upgraded]                   # write the fictional raven-shop demo project
```

`PROJECT` accepts a project name or ID (`project:/home/analyst/raven-shop`). All commands support
`--json` (`raf.dependency.scan/v1`, `raf.dependency.check/v1`, `raf.dependency.advisories.import/v1`,
`raf.dependency.advisories/v1`, `raf.dependency.sbom.import/v1`, `raf.dependency.sbom.export/v1`,
`raf.dependency.projects/v1`, `raf.dependency.vulnerable/v1`, `raf.dependency.sample/v1`).
Scans, checks and imports run as jobs and are audited.

### Demo (synthetic data)

```bash
raf dependency sample /tmp/raven-shop
raf dependency advisories import fixtures/advisories/raven-osv.json
raf dependency scan /tmp/raven-shop --name raven-shop
```

```
raven-shop
├── npm/raven-icons ~1.0.2 → 1.0.4
├── npm/raven-logger ^3.1.0 (dev) → 3.1.0
├── npm/raven-ui-kit ^2.2.0 → 2.2.0  [RAFSIM-2026-0102]
│   ├── raven-core-js 1.1.3
│   └── raven-icons 1.1.0
├── pypi/raven-auth ==1.2.0 → 1.2.0  [RAFSIM-2026-0101]
├── pypi/raven-common ==3.1.0 → 3.1.0
├── pypi/raven-lint ==0.4.0 (dev) → 0.4.0
└── pypi/raven-telemetry >=0.9 → (unresolved)  [RAFSIM-2026-0103]

SEV       CONFIDENCE     ADVISORY          PACKAGE               VERSION               FIXED
CRITICAL  HIGH (0.90)    RAFSIM-2026-0101  pypi/raven-auth       1.2.0                 1.4.2
HIGH      HIGH (0.90)    RAFSIM-2026-0102  npm/raven-ui-kit      2.2.0                 2.3.1
MEDIUM    MEDIUM (0.55)  RAFSIM-2026-0103  pypi/raven-telemetry  '>=0.9' (unresolved)  -
```

`raf dependency sample /tmp/raven-shop --upgraded` rewrites the project with fixed versions; the next
scan resolves the three findings. Every package and advisory in the demo is fictional (advisory ids
`RAFSIM-…`, summaries prefixed `(synthetic)`).

## Supported files

| File | Ecosystem | Provides |
|---|---|---|
| `requirements*.txt`, `*-requirements.txt`, `requirements/*.txt` | pypi | declared constraints (comments, `\` continuations, extras, `==` pins, ranges; markers, `--hash` and index options ignored; `-r` includes followed **only inside the scan root**, never through symlinks or URLs; `-c` constraints and `-e` editables not resolved) |
| `pyproject.toml` | pypi | PEP 621 `dependencies` (runtime) and `optional-dependencies` (optional), PEP 735 `dependency-groups` (dev), Poetry `tool.poetry.dependencies` / `dev-dependencies` / `group.<name>.dependencies` (bare Poetry versions are exact pins; path/git/url dependencies are not resolved) |
| `poetry.lock` | pypi | resolved versions, scopes (`category`/`groups`/`optional`), package edges |
| `Pipfile.lock` | pypi | resolved versions (`default` runtime, `develop` dev) |
| `package.json` | npm | `dependencies`, `devDependencies`, `optionalDependencies` (`npm:` aliases resolved to the real package; peer dependencies are not declarations) |
| `package-lock.json`, `npm-shrinkwrap.json` | npm | v2/v3 `packages` (nested `node_modules` resolved like Node; `dev`/`optional` flags; root dependencies = direct; workspace links skipped) and v1 `dependencies` trees |
| `yarn.lock` | npm | v1 entries (descriptor → version, dependency edges); Yarn Berry lockfiles are read as YAML (best effort) |
| `go.mod` | go | `require` lines and blocks (`// indirect` = transitive); `replace`/`exclude` are reported, not applied |
| `Cargo.toml` | cargo | `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` (dev), target-specific and workspace tables, renamed packages, optional dependencies |
| `Cargo.lock` | cargo | registry/git packages and edges; workspace members define direct dependencies |
| `Gemfile.lock` | rubygems | `GEM` specs (platform suffixes stripped), edges, `DEPENDENCIES` (direct gems and constraints) |
| `composer.lock` | packagist | `packages` (runtime) and `packages-dev` (dev), `require` edges (platform requirements ignored), `v` prefixes stripped |

Discovery walks the directory without following symlinks and skips `.git`, `node_modules`,
`.venv`, `vendor`, caches and virtualenvs. Files are read as untrusted input: size-limited
(`ingest.max_json_document_mb`), never executed, malformed entries become warnings, unreadable
files are listed under `skipped`.

## Names, versions and ranges

* **Names**: PyPI names use PEP 503 normalization (`Raven_Auth.Core` → `raven-auth-core`); other
  ecosystems compare lowercase. Package URLs follow the purl spec (`pkg:pypi/raven-auth@1.2.0`,
  `pkg:npm/%40raven/ui@2.0.0`, `pkg:golang/…`, `pkg:cargo/…`, `pkg:gem/…`, `pkg:composer/…`).
* **Versions**: PyPI uses a PEP 440 subset (epochs, trailing zeros ignored, `a`/`b`/`rc` and their
  spellings, `.post`, `.dev` before pre-releases, local versions ignored). npm, Cargo and Go use
  SemVer 2.0 (`v` prefix, pre-release precedence, build metadata ignored; Go pseudo-versions are
  pre-releases). RubyGems, Packagist, other ecosystems, and versions the primary scheme cannot
  parse use a generic comparator: numeric runs compare numerically, pre-release words
  (dev < alpha < beta < milestone < rc/pre < other words) sort before the release, post-release
  words (`post`, `patch`, `p`, `pl`, `rev`) after it.
* **Constraints** are interpreted as unions of intervals: PEP 440 (`~=`, `==1.2.*`, comparators) plus
  Poetry `^`/`~`; npm (`^`, `~`, x-ranges, hyphen ranges, `||`, partial comparators); Cargo (bare =
  caret); RubyGems `~>`; Composer `^`, `~`, `||`, hyphen ranges, wildcards; exact Go versions. Tags
  (`latest`), URLs, paths and branches (`dev-main`) cannot be interpreted. `!=` exclusions and
  pre-release opt-in rules are ignored (a slight over-approximation, only used for MEDIUM matches).

## Resolution model

* Every declared constraint is a **Dependency** (one per project, ecosystem and name; all
  declarations kept in `metadata.declarations` with manifest path and line).
* A dependency **resolves to** the lockfile versions of the same name — preferring entries the
  lockfile marks as direct and versions its constraint accepts — and to the version of an exact pin.
* Every resolved version is a **Package**; direct when a declaration resolves to it or the lockfile
  says so. Packages without a scope inherit it from their parents (runtime > optional > dev);
  unknown scopes are treated as runtime.
* Line numbers for TOML/JSON manifests are best effort (the formats carry no positions).

## Advisories and checks

`raf dependency advisories import` reads OSV documents from local files only — no network access.
Each advisory becomes a **Vulnerability** object (name = advisory id, tags `advisory`, `osv`;
metadata: summary, details, aliases (resolvable: `raf show RAVEN-SEC-0101`), severity and CVSS,
references, published/modified, normalized `affected` entries). Invalid documents are rejected
individually with a reason; withdrawn advisories are kept but never matched.

Matching (`raf dependency check`, and automatically after `scan`/`sbom import` when advisories exist):

* `affected[].package.{ecosystem,name}` is compared with normalized names.
* An exact version is affected when it is listed in `versions`, or when the OSV evaluation of a
  `SEMVER`/`ECOSYSTEM` range includes it: events are sorted by version (`introduced: "0"` first),
  `introduced` opens a range, `fixed` and `limit` close it exclusively, `last_affected` inclusively.
  `GIT` ranges are skipped (commit graphs are not evaluated).
* **`vulnerable-package`** (confidence **HIGH, 0.90**): the installed version is exact (lockfile,
  exact pin or SBOM). Creates `VULNERABILITY AFFECTS PACKAGE`.
* **`vulnerable-constraint`** (confidence **MEDIUM, 0.55**): a declared dependency without a
  resolved version whose constraint permits at least one affected version. Creates
  `VULNERABILITY AFFECTS DEPENDENCY`.
* **Severity** (independent of confidence): the highest CVSS v3.x base score computed from
  `severity[].score` vectors (or numeric scores) mapped to CRITICAL ≥ 9.0, HIGH ≥ 7.0, MEDIUM ≥ 4.0,
  LOW > 0; otherwise `database_specific.severity` (LOW/MODERATE/HIGH/CRITICAL); otherwise MEDIUM
  (recorded as `severity_source: default`). CVSS v4 and v2 vectors are not scored.
* Findings explain themselves (`explanation` factors summing to the confidence, evidence pointing to
  the vulnerability, package/dependency and project objects) and recommend the fixed version.
* Re-checking resolves findings that are no longer produced — scoped to the checked projects — and
  ends `AFFECTS` relationships that no longer hold.

## Data model

| Kind | ID / key | Content |
|---|---|---|
| Project | `project:<resolved path>` (scan) or `project:<name>` (SBOM import) | name, `metadata.path`, `source` (`scan`/`sbom`), `manifests`, `ecosystems`, `last_scan`; tag `dependency` |
| Dependency | `dependency:<project key>\|<ecosystem>/<name>` | constraint, scope (runtime/dev/optional), manifest, line, declarations, resolved versions |
| Package | `package:<ecosystem>/<name>@<version>` | ecosystem, name, version, purl (shared by all projects) |
| Vulnerability | `vulnerability:<advisory id>` | see above |
| `PROJECT DECLARES DEPENDENCY` | | scope |
| `DEPENDENCY RESOLVES_TO PACKAGE` | | `via`: `lockfile` or `pin` |
| `PROJECT DEPENDS_ON PACKAGE` | | every resolved package of the project; `metadata.direct`, `scope` |
| `PACKAGE DEPENDS_ON PACKAGE` | | lockfile / SBOM graph; `metadata.sources` = projects that asserted the edge |
| `VULNERABILITY AFFECTS PACKAGE` / `DEPENDENCY` | | `basis` (`exact`/`constraint`), reason, fixed versions |
| Finding | `finding:dependency:vulnerable-package:<digest(project\|package\|advisory)>`, `finding:dependency:vulnerable-constraint:<digest(dependency\|advisory)>` | product `dependency` |

All writes carry provenance (manifest path and line, parser `dependency/<kind>`, job id). IDs are
deterministic, so re-scanning creates no duplicates; relationships of a project that disappear from
its manifests are ended (`valid_to`) rather than deleted, and removed dependencies get `valid_to`.
A relationship that reappears later is reactivated. When a scan is incomplete (a manifest could not
be parsed, or the file limit was reached) nothing is ended: the previous state is kept and the scan
reports an `incomplete scan` warning, so a corrupted lockfile never resolves findings by accident.

## SBOM

* **Import**: CycloneDX JSON (`components`, nested components, `dependencies`; scope
  `required`/`optional`/`excluded` → runtime/optional/dev) and SPDX 2.x JSON (`packages` with purl
  external references, `DEPENDS_ON`, `*_DEPENDENCY_OF` relationships, `DESCRIBES`/`documentDescribes`
  root). Ecosystem, name and version come from the purl; packages without one are `generic`.
  Components without a version are skipped with a warning. When the SBOM does not state the root's
  dependencies, packages without a parent are treated as direct. SPDX 3 JSON-LD is not supported.
* **Export**: CycloneDX 1.5 JSON with `metadata.component` (the project), one `library` component
  per package (purl as `bom-ref`, scope, `raf:ecosystem`/`raf:direct` properties) and the
  dependency graph (root → direct packages, package → package edges asserted for this project).
  Export → import reproduces the same packages, direct flags, scopes and edges.

## API

| Method | Path | Description |
|---|---|---|
| GET | `/dependency/projects` | `{items: [{id, name, path, source, ecosystems, dependencies, packages, direct, open_findings, last_scan}], total}` |
| GET | `/dependency/projects/{ref}/graph` | `{project, packages: [{id, ecosystem, name, version, direct, scope, vulnerabilities}], edges: [{source, target, type: DEPENDS_ON}]}` (`{ref}` accepts names and IDs containing `/`) |
| GET | `/dependency/vulnerable?include_unused=` | `{items: [{package, advisories: [{id, summary, severity, cvss, aliases, fixed, reason, since}], projects}], total}` |
| GET | `/dependency/advisories` | imported advisories |

**Scanning and imports are CLI-only by design.** They read paths on the machine running R$F; the API
never accepts a server path and only exposes stored results.

## Limits

* No network: advisories must be imported from files (for example an OSV database export), and
  package registries are never queried, so unpinned constraints without a lockfile can only be
  matched at MEDIUM confidence.
* Only the listed manifest formats are parsed (no `setup.py`/`setup.cfg`, `Pipfile`, `Gemfile`,
  `composer.json`, `go.sum`, Maven/Gradle/NuGet manifests); environment markers and platform
  conditions are ignored.
* Package-to-package edges are shared facts about package versions; they are tagged with the
  projects that asserted them and are not ended when one project stops using a package.
* Version and range semantics are a documented subset of each ecosystem's rules (see above).
