# Developing R$F

## Setup

```bash
./scripts/bootstrap            # .venv (uv sync, or venv + pip), web build when npm is available
./scripts/bootstrap --check    # also lint, type-check and test
source .venv/bin/activate
```

Python 3.12+ (tested with 3.12). Node.js 20.19+ for `web/`. Docker or Podman only for manual Lab
experiments (no test needs them).

Use a throw-away home while developing so your real data is never touched:

```bash
export RAF_HOME=$(mktemp -d)
raf demo load
```

## Checks (what CI runs)

```bash
ruff check src tests scripts
ruff format --check src tests scripts
mypy                                  # strict, configured in pyproject.toml
pytest -q                             # ~520 tests, about a minute and a half
cd web && npm run typecheck && npm run lint && npm run format:check && npm run test && npm run build
cd web && npm run test:e2e            # browser end-to-end suite (needs the build and .venv/bin/raf)
```

`.github/workflows/ci.yml` runs four jobs on every push and pull request: Python (lint, format,
mypy, pytest, demo smoke test), web (typecheck, lint, format, tests, build), e2e (the Playwright suite
in Chromium against `raf serve`) and the R$F OS terminal panel (fmt, clippy, tests, build, `raf tui
--dump` of every page).

The end-to-end suite starts its own servers with private demo workspaces on 127.0.0.1 (see
[web-ui.md](web-ui.md#end-to-end-tests-webe2e)). Locally it uses the Chromium Playwright 1.56.1
downloads (`npx playwright install chromium` once, or `PLAYWRIGHT_BROWSERS_PATH` pointing to an
existing installation) and `../.venv/bin/raf` (set `RAF_BIN` for another one).

## Tests

| Directory | What |
|---|---|
| `tests/unit` | core: model, IDs, storage and migrations (the migrated schema must equal `schema.py`), ingestion, query, config, policy engine, propagation and risk, **architecture rules** |
| `tests/products` | one module per product: service behavior, CLI and API |
| `tests/api`, `tests/cli` | platform routes and commands, error handling, security middleware |
| `tests/integration` | `raf analyze` pipelines and **the end-to-end signature workflow** (`test_end_to_end.py`) |
| `tests/security` | hostile input end to end (terminal escape sequences, …) |

Fixtures: `raven` is a session-cached copy of a workspace with the demo loaded (copied per test);
`ctx` is an empty workspace; `cli(...)` runs the real CLI in-process and returns exit code, stdout
and stderr (`.json()` parses `--json` output). Tests never use the network or external services;
the model provider is tested with an `httpx.MockTransport`, the container runtime with fakes.

Mark long tests with `@pytest.mark.slow`; `docker` is reserved for tests that need a real daemon
(none in the default suite).

## Fixtures

Everything in `fixtures/` is generated deterministically from `src/raf/data/raven.py` (and the
Protocol product's synthetic capture builder):

```bash
python scripts/generate_fixtures.py          # regenerate
python scripts/generate_fixtures.py --check  # what the test suite runs
```

Change the generator, not the files. All names use `.example` domains and RFC 5737 addresses;
secrets in fixtures are synthetic and non-functional.

## Conventions

* **Layers** (`tests/unit/test_architecture.py`): core → data/sdk → products → analysis → apps; a
  product imports another product only if its manifest lists it in `depends_on`.
* **Domain logic lives in services** (`raf.products.<name>.service`, `raf.analysis.*`); CLI commands
  and API routes parse input, call the service and render.
* **CLI output** goes through `raf.sdk.cli`: `rt.output(schema, data, render)` emits JSON with a
  `schema` id under `--json` and calls `render()` otherwise; use `rt.table`, `rt.kv_block`,
  `rt.header`, `rt.next_steps` (suggestions are never executed), `rt.confirm` for destructive
  actions. The console escapes control sequences in data automatically; never print with `print()`.
* **Errors** are `RafError` subclasses (`raf.core.errors`) with `message`, `reason`, `hint`,
  `suggestions`; they map to exit codes and HTTP statuses. Never let raw tracebacks reach users.
* **Determinism**: IDs from `raf.core.ids`; seeded `random.Random` for synthetic data; sort before
  output; no wall-clock time in analysis results except `generated_at`.
* **Provenance**: data written outside the ingestion pipeline must still record provenance (source,
  parser/product, job).
* **Typing**: `mypy --strict`, no untyped defs; pydantic models derive from `RafModel`.
* **Style**: ruff (line length 120), formatted with `ruff format`.
* **Docs**: a feature counts as implemented when its documentation describes the actual behavior;
  update `docs/products/<name>.md`, `docs/api.md` and `docs/cli.md` with the code.

## Database migrations

Schema changes go into `src/raf/core/storage/schema.py` **and** a new Alembic revision in
`src/raf/core/storage/migrations/versions/` (update `SCHEMA_HEAD` in `database.py`). Workspaces are
migrated automatically when opened. `test_migrated_database_matches_the_schema` fails if the two
disagree.

## Adding a product

1. `src/raf/products/<name>/` with `manifest.py` (`MANIFEST = ProductManifest(...)`), `service.py`,
   `cli.py` (a Typer app, referenced by `cli="raf.products.<name>.cli:app"`), `api.py` (an
   `APIRouter` using `ctx: Ctx` from `raf.sdk.api`).
2. Add the name to `BUILTIN_PRODUCTS` in `src/raf/products/catalog.py`.
3. Tests in `tests/products/test_<name>.py`, docs in `docs/products/<name>.md`, rows in
   `docs/api.md` and `docs/cli.md`.
4. Choose an honest status (EXPERIMENTAL / ALPHA / BETA); see
   [implementation-status.md](implementation-status.md).

Plugins follow the same contract outside the repository: [plugin-development.md](plugin-development.md).

## Running the API and the workbench

```bash
raf serve                      # API + built UI on http://127.0.0.1:8765
cd web && npm run dev          # Vite dev server on :5173, proxies /api to :8765
```

## Logging and debugging

`--debug` prints full tracebacks and debug logs; logs are also written to `$RAF_HOME/logs/raf.log`
(secrets redacted). `RAF_CORE_LOG_LEVEL` sets the console level. Long operations are jobs:
`raf jobs`, `raf job show <id>`.
