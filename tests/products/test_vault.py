"""R$F Vault: detection, redaction, safety, persistence and leak checks.

Every fake secret is built at runtime (never a literal) so no real-looking
credential exists in the repository.
"""

from __future__ import annotations

import base64
import json
import os
import random
import sqlite3
import stat
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from raf.core.ids import object_id
from raf.core.objects.types import FindingStatus
from raf.core.security.redaction import redact_secret
from raf.products.vault.allowlist import load_allowlist
from raf.products.vault.detectors import FileKind, LineView, detect_line, is_placeholder, is_secret_key
from raf.products.vault.keys import KEY_FILE
from raf.products.vault.scanner import classify, scan_text
from raf.products.vault.service import VaultService

_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _rand(n: int, seed: int, alphabet: str = _ALNUM) -> str:
    rnd = random.Random(seed)
    return "".join(rnd.choice(alphabet) for _ in range(n))


def _b64url(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def fake_secrets() -> dict[str, str]:
    body = [_rand(64, 100 + i, _ALNUM + "+/") for i in range(6)]
    return {
        "aws_id": "AKIA" + "Z" * 12 + "Q7X2",
        "aws_secret": _rand(20, 1) + "/" + _rand(19, 2),
        "github": "ghp_" + "a1" * 18,
        "gitlab": "glpat-" + _rand(20, 3),
        "slack": "xox" + "b-" + "1234567890-" + _rand(24, 4),
        "stripe": "sk_" + "live_" + _rand(24, 5),
        "openai": "sk-" + "proj-" + _rand(40, 6),
        "google": "AIza" + _rand(35, 7),
        "jwt": _b64url({"alg": "HS256", "typ": "JWT"}) + "." + _b64url({"sub": "raven"}) + "." + _rand(43, 8),
        "db_password": "Rv" + _rand(14, 9),
        "url_password": "Pg" + _rand(14, 10),
        "inline": "Lg" + _rand(18, 11),
        "allowlisted": "AIza" + _rand(35, 12),
        "binary_token": "ghp_" + _rand(36, 13),
        "outside": "ghp_" + _rand(36, 14),
        "pem_body": "\n".join(body),
        "pem_line": body[2],
    }


@pytest.fixture
def secrets() -> dict[str, str]:
    return fake_secrets()


def make_repo(base: Path, s: dict[str, str]) -> Path:
    repo = base / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "keys").mkdir()
    (repo / "assets").mkdir()
    (repo / "tests" / "fixtures").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".env").write_text(
        "# local settings\n"
        f"AWS_ACCESS_KEY_ID={s['aws_id']}\n"
        f"aws_secret_access_key={s['aws_secret']}\n"
        f"DB_PASSWORD={s['db_password']}\n"
        "ADMIN_PASSWORD=changeme\n"
        "API_TOKEN=${API_TOKEN}\n"
        f"LEGACY_PASSWORD={s['inline']}  # raf:allow rotated in 2025\n",
        encoding="utf-8",
    )
    (repo / "config.yaml").write_text(
        "database:\n"
        f"  url: postgres://app:{s['url_password']}@db.raven.internal:5432/app\n"
        '  password: "<password>"\n'
        "slack:\n"
        f"  token: {s['slack']}\n",
        encoding="utf-8",
    )
    (repo / "src" / "app.py").write_text(
        f'GITHUB_TOKEN = "{s["github"]}"\n'
        f'STRIPE_KEY = "{s["stripe"]}"\n'
        'password = os.environ["APP_PASSWORD"]\n'
        f'client = Client(api_key="{s["openai"]}")\n'
        f'HEADERS = {{"Authorization": "Bearer {s["jwt"]}"}}\n'
        f"maps = '{s['google']}'\n"
        f"glab = '{s['gitlab']}'\n",
        encoding="utf-8",
    )
    begin, end = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"
    (repo / "keys" / "deploy.pem").write_text(f"{begin}\n{s['pem_body']}\n{end}\n", encoding="utf-8")
    (repo / "tests" / "fixtures" / "maps.txt").write_text(f"key={s['allowlisted']}\n", encoding="utf-8")
    (repo / "assets" / "logo.png").write_bytes(b"\x89PNG\x00\x00" + s["binary_token"].encode() + b"\x00")
    (repo / ".git" / "config").write_text(f"token = {s['github']}\n", encoding="utf-8")
    outside = base / "outside"
    outside.mkdir()
    (outside / "creds.env").write_text(f"GITHUB_TOKEN={s['outside']}\n", encoding="utf-8")
    (repo / "linked-creds.env").symlink_to(outside / "creds.env")
    (repo / "linked-dir").symlink_to(outside, target_is_directory=True)
    return repo


@pytest.fixture
def repo(tmp_path: Path, secrets: dict[str, str]) -> Path:
    return make_repo(tmp_path, secrets)


def _locations(results: list[dict[str, Any]]) -> set[tuple[str, int, str]]:
    return {(r["path"], r["line"], r["rule"]) for r in results}


EXPECTED = {
    (".env", 2, "aws-access-key-id"),
    (".env", 3, "aws-secret-access-key"),
    (".env", 4, "password-assignment"),
    ("config.yaml", 2, "url-credentials"),
    ("config.yaml", 5, "slack-token"),
    ("src/app.py", 1, "github-token"),
    ("src/app.py", 2, "stripe-key"),
    ("src/app.py", 4, "openai-style"),
    ("src/app.py", 5, "jwt"),
    ("src/app.py", 6, "google-api-key"),
    ("src/app.py", 7, "gitlab-token"),
    ("keys/deploy.pem", 1, "private-key"),
    ("tests/fixtures/maps.txt", 1, "google-api-key"),
}


# --------------------------------------------------------------------------- leak checks


def _secret_values(s: dict[str, str]) -> list[str]:
    return [v for k, v in s.items() if k != "pem_body"] + s["pem_body"].split("\n")


def _assert_no_leak(texts: list[str], s: dict[str, str]) -> None:
    for text in texts:
        for value in _secret_values(s):
            assert value not in text, "a secret value leaked into output"


def _iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            yield path


def _assert_no_leak_in_home(raf_home: Path, s: dict[str, str], control: str) -> None:
    found_control = False
    for path in _iter_files(raf_home):
        data = path.read_bytes()
        found_control = found_control or control.encode() in data
        for value in _secret_values(s):
            assert value.encode() not in data, f"a secret value leaked into {path.relative_to(raf_home)}"
    assert found_control, "positive control (a stored fingerprint) not found: the file scan is not effective"


def _db_text_rows(db_path: Path) -> Iterator[tuple[str, str]]:
    with sqlite3.connect(db_path) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            columns = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
            for row in conn.execute(f'SELECT * FROM "{table}"'):
                for column, value in zip(columns, row, strict=True):
                    if isinstance(value, str | bytes):
                        yield f"{table}.{column}", value if isinstance(value, str) else value.decode("utf-8", "replace")


def _assert_no_leak_in_db(raf_home: Path, s: dict[str, str], control: str) -> None:
    db_path = raf_home / "workspaces" / "default" / "raf.db"
    seen_tables: set[str] = set()
    control_tables: set[str] = set()
    for where, text in _db_text_rows(db_path):
        seen_tables.add(where.split(".")[0])
        if control in text:
            control_tables.add(where.split(".")[0])
        for value in _secret_values(s):
            assert value not in text, f"a secret value leaked into {where}"
    assert {"objects", "findings"} <= control_tables  # positive control: fingerprints are stored
    assert {"objects", "findings", "provenance", "relationships", "jobs", "audit_log"} <= seen_tables


# --------------------------------------------------------------------------- CLI end to end


def test_scan_detects_redacts_and_never_leaks(cli: Any, raf_home: Path, repo: Path, secrets: dict[str, str]) -> None:
    human = cli("vault", "scan", str(repo))
    assert human.exit_code == 0, human.stderr
    assert "R$F VAULT SCAN" in human.stdout and "github-token" in human.stdout
    result = cli("vault", "scan", str(repo), "--json", "--show-suppressed")
    assert result.exit_code == 0, result.stderr
    data = result.json()
    assert data["schema"] == "raf.vault.scan/v1" and data["stored"] is True
    assert _locations(data["results"]) == EXPECTED
    # placeholders, the binary file, .git and symlinks produce nothing
    assert not any(r["line"] in (5, 6) and r["path"] == ".env" for r in data["results"])
    skipped = {(s["path"], s["reason"]) for s in data["skipped"]}
    assert ("assets/logo.png", "binary") in skipped
    assert ("linked-creds.env", "symlink (not followed)") in skipped
    assert ("linked-dir", "symlinked directory (not followed)") in skipped
    assert not any(r["path"].startswith((".git", "linked")) for r in data["results"])
    # inline suppression is counted and listed only on request
    assert data["suppressed_count"] == 1
    assert _locations(data["suppressed"]) == {(".env", 7, "password-assignment")}
    assert data["suppressed"][0]["suppressed_by"] == "inline marker"
    without_run = cli("vault", "scan", str(repo), "--json")
    without = without_run.json()
    assert without["suppressed_count"] == 1 and without["suppressed"] == []
    # redaction and fingerprints
    by_rule = {r["rule"]: r for r in data["results"] if r["path"] != "tests/fixtures/maps.txt"}
    assert by_rule["github-token"]["redacted"] == redact_secret(secrets["github"]) == "ghp****a1a1"
    assert by_rule["aws-access-key-id"]["redacted"] == "AKI****Q7X2"
    for r in data["results"]:
        assert "****" in r["redacted"] or set(r["redacted"]) == {"*"}
        assert len(r["fingerprint"]) == 32 and int(r["fingerprint"], 16) >= 0
    assert by_rule["private-key"]["severity"] == "CRITICAL" and by_rule["private-key"]["line"] == 1
    assert by_rule["password-assignment"]["severity"] == "MEDIUM"
    assert by_rule["github-token"]["confidence"] > by_rule["password-assignment"]["confidence"]
    # nothing leaks: CLI output, JSON, every DB row, every file in RAF_HOME (db, logs, key, allowlist)
    listing = cli("vault", "findings", "--status", "all")
    listing_json = cli("vault", "findings", "--json")
    secrets_out = cli("vault", "secrets", "--all", "--json")
    texts = [human.stdout, human.stderr, result.stdout, result.stderr, listing.stdout, listing_json.stdout]
    _assert_no_leak([*texts, secrets_out.stdout, without_run.stdout], secrets)
    assert (raf_home / "logs" / "raf.log").exists()
    control = by_rule["github-token"]["fingerprint"]
    _assert_no_leak_in_db(raf_home, secrets, control)
    _assert_no_leak_in_home(raf_home, secrets, control)


def test_scan_persists_objects_relationships_findings(
    cli: Any, ctx: RafContext, repo: Path, secrets: dict[str, str]
) -> None:
    data = cli("vault", "scan", str(repo), "--json").json()
    env_path = str(repo.resolve() / ".env")
    file_id = object_id("file", f"local|{env_path}")
    file_obj = ctx.store.objects.require(file_id)
    assert file_obj.name == ".env" and file_obj.metadata["path"] == env_path and file_obj.metadata["host"] == "local"
    secret_id = object_id("secret", f"local|{env_path}|2|aws-access-key-id")
    secret = ctx.store.objects.require(secret_id)
    assert {"rule", "redacted", "fingerprint", "path", "line"} <= set(secret.metadata)
    assert secret.metadata["line"] == 2 and "value" not in secret.metadata
    rels = ctx.store.relationships.list(types=["CONTAINS_SECRET"], source=file_id)
    assert secret_id in {r.target_object for r in rels}
    findings = {f.rule_id: f for f in ctx.store.findings.list(product="vault", limit=100)}
    assert findings["private-key"].severity.value == "CRITICAL"
    assert findings["aws-access-key-id"].severity.value == "HIGH"
    assert findings["github-token"].severity.value == "HIGH"
    assert findings["password-assignment"].severity.value == "MEDIUM"
    gh = findings["github-token"]
    assert gh.recommendation and gh.explanation and gh.explanation[0]["sign"] == "+"
    assert {e.kind for e in gh.evidence} == {"object"} and gh.metadata["lines"] == [1]
    assert sum(f["points"] * (1 if f["sign"] == "+" else -1) for f in gh.explanation) == round(gh.confidence * 100)
    assert ctx.store.provenance.for_subject(secret_id)[0].parser == "vault/1.0"
    # tests/ paths get an explained confidence penalty
    maps = next(r for r in data["results"] if r["path"] == "tests/fixtures/maps.txt")
    other = next(r for r in data["results"] if r["path"] == "src/app.py" and r["rule"] == "google-api-key")
    assert maps["confidence"] < other["confidence"]
    assert any(f["sign"] == "-" for f in maps["explanation"])
    assert data["distinct_secrets"] == len(EXPECTED)
    key_file = ctx.workspace.secrets_dir / KEY_FILE
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600


def test_rescan_is_idempotent_and_resolves_fixed_secrets(cli: Any, ctx: RafContext, repo: Path) -> None:
    cli("vault", "scan", str(repo))
    objects_before = ctx.store.objects.count(types=["secret"])
    findings_before = ctx.store.findings.count(product="vault")
    again = cli("vault", "scan", str(repo), "--json").json()
    assert again["findings"]["created"] == 0 and again["findings"]["resolved"] == 0
    assert ctx.store.objects.count(types=["secret"]) == objects_before
    assert ctx.store.findings.count(product="vault") == findings_before
    app = repo / "src" / "app.py"
    app.write_text("\n".join(app.read_text().splitlines()[1:]) + "\n", encoding="utf-8")  # remove the GitHub token
    fixed = cli("vault", "scan", str(repo), "--json").json()
    assert fixed["findings"]["resolved"] >= 1
    statuses = {f.rule_id: f.status for f in ctx.store.findings.list(product="vault", limit=100) if "app.py" in f.title}
    assert statuses["github-token"] == FindingStatus.RESOLVED
    assert statuses["stripe-key"] == FindingStatus.OPEN  # moved from line 2 to 1: same finding, still open
    gh_secret = object_id("secret", f"local|{app.resolve()}|1|github-token")
    assert ctx.store.objects.require(gh_secret).valid_to is not None
    rel = ctx.store.relationships.list(types=["CONTAINS_SECRET"], target=gh_secret)[0]
    assert rel.valid_to is not None
    # scanning another directory never resolves this target's findings
    other = repo.parent / "other"
    other.mkdir()
    (other / "readme.txt").write_text("nothing here\n", encoding="utf-8")
    cli("vault", "scan", str(other))
    assert ctx.store.findings.count(product="vault", statuses=["OPEN"]) == len(EXPECTED) - 1


def test_allowlists(cli: Any, ctx: RafContext, repo: Path, tmp_path: Path) -> None:
    first = cli("vault", "scan", str(repo), "--json").json()
    target = next(r for r in first["results"] if r["path"] == "tests/fixtures/maps.txt")
    added = cli("vault", "allowlist", "add", target["fingerprint"][:16], "--reason", "public demo key", "--json")
    assert added.exit_code == 0 and added.json()["entry"]["fingerprint"] == target["fingerprint"][:16]
    entries = load_allowlist(ctx.workspace.path / "vault-allowlist.yaml")
    assert entries[0].reason == "public demo key"
    second = cli("vault", "scan", str(repo), "--json", "--show-suppressed").json()
    assert ("tests/fixtures/maps.txt", 1, "google-api-key") not in _locations(second["results"])
    suppressed = {(r["path"], r["suppressed_by"].split(":")[0]) for r in second["suppressed"]}
    assert ("tests/fixtures/maps.txt", "allowlist") in suppressed
    assert second["findings"]["suppressed"] == 1
    assert ctx.store.findings.require(target["finding_id"]).status == FindingStatus.SUPPRESSED
    # --allowlist FILE with rule + path glob (JSON)
    extra = tmp_path / "allow.json"
    extra.write_text(json.dumps({"allow": [{"rule": "slack-token", "path": "config.*", "reason": "bot"}]}))
    third = cli("vault", "scan", str(repo), "--json", "--allowlist", str(extra)).json()
    assert ("config.yaml", 5, "slack-token") not in _locations(third["results"])
    assert third["suppressed_count"] == 3
    # removing the workspace entry reopens the finding that Vault suppressed
    (ctx.workspace.path / "vault-allowlist.yaml").unlink()
    fourth = cli("vault", "scan", str(repo), "--json").json()
    assert fourth["findings"]["reopened"] == 2  # the fingerprint entry and the --allowlist slack entry
    assert ctx.store.findings.require(target["finding_id"]).status == FindingStatus.OPEN
    bad = cli("vault", "allowlist", "add", "not-hex", "--reason", "x")
    assert bad.exit_code == 4
    assert cli("vault", "allowlist", "add", target["fingerprint"]).exit_code == 2  # --reason is required


def test_no_store_and_limits(cli: Any, ctx: RafContext, repo: Path, tmp_path: Path) -> None:
    data = cli("vault", "scan", str(repo), "--no-store", "--json").json()
    assert data["stored"] is False and len(data["results"]) == len(EXPECTED)
    assert ctx.store.findings.count(product="vault") == 0
    assert ctx.store.objects.count(types=["secret"]) == 0
    assert cli("config", "set", "vault.max_file_kb", "1").exit_code == 0
    big = tmp_path / "big"
    big.mkdir()
    (big / "huge.env").write_text("X=1\n" * 600, encoding="utf-8")
    report = cli("vault", "scan", str(big), "--json").json()
    assert report["skipped"][0]["reason"].startswith("larger than vault.max_file_kb")
    assert cli("vault", "scan", str(repo / "linked-dir")).exit_code == 4  # symlinked root refused
    assert cli("vault", "scan", str(tmp_path / "missing")).exit_code == 3
    single = cli("vault", "scan", str(repo / ".env"), "--json").json()
    assert {r["path"] for r in single["results"]} == {".env"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs not supported")
def test_fifo_is_skipped_without_blocking(cli: Any, tmp_path: Path) -> None:
    target = tmp_path / "fifo-repo"
    target.mkdir()
    os.mkfifo(target / "pipe")
    data = cli("vault", "scan", str(target), "--json").json()
    assert data["skipped"] == [{"path": "pipe", "reason": "not a regular file"}]


def test_host_option_links_files_to_host(cli: Any, ctx: RafContext, repo: Path) -> None:
    cli("vault", "scan", str(repo / ".env"), "--host", "DEV-01")
    file_id = object_id("file", f"dev-01|{(repo / '.env').resolve()}")
    rels = ctx.store.relationships.list(types=["CONTAINS"], target=file_id)
    assert [r.source_object for r in rels] == ["host:dev-01"]
    assert cli("vault", "scan", str(repo), "--host", "bad|host").exit_code == 4


def test_rules_findings_and_secrets_commands(cli: Any, repo: Path) -> None:
    rules = cli("vault", "rules", "--json").json()
    ids = {r["id"] for r in rules["items"]}
    assert {"aws-access-key-id", "private-key", "password-assignment", "high-entropy", "url-credentials"} <= ids
    cli("vault", "scan", str(repo))
    findings = cli("vault", "findings", "--json", "--severity", "high").json()
    assert findings["schema"] == "raf.vault.findings/v1" and findings["total"] >= 10
    assert all(f["severity"] in ("HIGH", "CRITICAL") for f in findings["items"])
    secrets_list = cli("vault", "secrets", "--json").json()
    assert secrets_list["total"] == len(EXPECTED)
    assert cli("vault", "findings", "--status", "bogus").exit_code == 4
    assert "SECRETS" in cli("vault", "secrets").stdout


# --------------------------------------------------------------------------- detector units


def _detect(text: str, path: str = "settings.env") -> list[tuple[int, str]]:
    return [(d.candidate.line, d.candidate.rule) for d in scan_text(text, path, 4.2)]


def test_placeholders_are_ignored() -> None:
    lines = [
        "PASSWORD=changeme",
        "DB_PASSWORD=${DB_PASSWORD}",
        'password: "<password>"',
        "API_KEY=xxxxxxxxxxxx",
        "token: {{ vault_token }}",
        "secret = %(secret)s",
        "password: !vault |",
        "PASSWORD=",
        "pwd = ****",
        "aws_secret_access_key=" + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
        "DATABASE_URL=postgres://user:${DB_PASS}@db/app",
    ]
    assert _detect("\n".join(lines)) == []
    assert is_placeholder("your_api_key_here") and is_placeholder("$HOME") and not is_placeholder("Zq81kLm2Px")


def test_secret_keys_and_code_mode() -> None:
    assert all(is_secret_key(k) for k in ("DB_PASSWORD", "apiKey", "client_secret", "SECRET_KEY", "auth-token"))
    assert not any(is_secret_key(k) for k in ("token_type", "password_hint", "tokenizer", "secret_name", "cwd"))
    value = "Kp" + _rand(14, 40)
    code = f'password = "{value}"\nconn(password=get_password())\nSECRET_KEY: str = "{value}"\n'
    assert _detect(code, "src/settings.py") == [(1, "password-assignment"), (3, "password-assignment")]
    assert _detect(f"password = {value}\n", "src/settings.py") == []  # expressions in code are not literals
    assert _detect(f"password = {value}\n", "app.ini") == [(1, "password-assignment")]
    assert _detect(f"<password>{value}</password>\n", "web.xml") == [(1, "password-assignment")]


def test_specific_rules_win_overlaps_and_entropy_needs_keyword() -> None:
    token = "ghp_" + _rand(36, 41)
    assert _detect(f"GITHUB_TOKEN={token}\n") == [(1, "github-token")]
    blob = _rand(40, 42)
    assert _detect(f"signing_secret = {blob}\n", "notes.txt") == [(1, "high-entropy")]
    assert _detect(f"checksum {blob}\n", "notes.txt") == []
    hexed = _rand(40, 43, "0123456789abcdef")
    assert _detect(f"auth_token {hexed}\n", "notes.txt") == [(1, "high-entropy")]
    view = LineView([f"api_token: {blob}"], 0, FileKind(config=True, test_like=False), 99.0)
    assert [c.rule for c in detect_line(view)] == ["password-assignment"]


def test_jwt_private_key_and_url_rules() -> None:
    fake_jwt = "eyJ" + _rand(20, 50) + ".eyJ" + _rand(20, 51) + "." + _rand(30, 52)
    assert _detect(f"t = {fake_jwt}\n", "a.txt") == []  # header does not decode to a JWT header
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    assert _detect(f"if line.startswith('{begin}'):\n", "a.py") == []  # marker without key material
    one_line = f'{{"private_key": "{begin}\\n{_rand(64, 53)}\\n{_rand(40, 54)}\\n-----END PRIVATE KEY-----\\n"}}'
    assert _detect(one_line, "sa.json") == [(1, "private-key")]
    local = [d.candidate for d in scan_text("postgres://app:" + _rand(12, 55) + "@localhost/db\n", "a.cfg", 4.2)]
    assert local[0].rule == "url-credentials" and local[0].factors[0].points < 0


def test_hostile_inputs_are_handled(cli: Any, tmp_path: Path) -> None:
    bomb = tmp_path / "allow.yaml"
    bomb.write_text("a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n", encoding="utf-8")
    target = tmp_path / "t"
    target.mkdir()
    huge_header = "eyJ" + "W1" * 5000 + ".eyJ" + _rand(20, 70) + "." + _rand(30, 71)
    (target / "a.txt").write_text(f"auth {huge_header}\n", encoding="utf-8")
    refused = cli("vault", "scan", str(target), "--allowlist", str(bomb))
    assert refused.exit_code == 4 and "aliases" in refused.stderr
    assert cli("vault", "scan", str(target), "--json").exit_code == 0


def test_classify_paths() -> None:
    assert classify(".env.production").config and classify("deploy/values.yaml").config
    assert not classify("src/app.py").config
    assert classify("tests/fixtures/a.txt").test_like and classify("docs/setup.md").test_like
    assert not classify("src/app.py").test_like


# --------------------------------------------------------------------------- service and API


def test_service_queries(ctx: RafContext, repo: Path) -> None:
    service = VaultService(ctx)
    result = service.scan(repo)
    assert result.job_id and ctx.jobs.require(result.job_id).status.value == "COMPLETED"
    items, total = service.findings(status="all")
    assert total == len(EXPECTED) and items
    secrets_view, count = service.secrets()
    assert count == len(EXPECTED) and all("*" in str(s["redacted"]) for s in secrets_view)
    assert ctx.audit.list(operation="vault.scan")[0].details["secrets"] == len(EXPECTED)


def test_same_value_has_same_fingerprint(ctx: RafContext, tmp_path: Path) -> None:
    value = "Qz" + _rand(18, 60)
    (tmp_path / "a.env").write_text(f"DB_PASSWORD={value}\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text(f"password: {value}\nother_password: {value}x\n", encoding="utf-8")
    result = VaultService(ctx).scan(tmp_path, store=False)
    prints = [(r.path, r.fingerprint) for r in sorted(result.results, key=lambda r: (r.path, r.line))]
    assert prints[0][1] == prints[1][1] != prints[2][1]
    assert result.distinct_secrets == 2


@pytest.fixture
def api(raf_home: Path) -> Iterator[Any]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient
    from raf.apps.api.app import create_app

    with TestClient(create_app(env={"RAF_HOME": str(raf_home)})) as client:
        yield client


def test_api_is_read_only_and_redacted(cli: Any, api: Any, repo: Path, secrets: dict[str, str]) -> None:
    cli("vault", "scan", str(repo))
    findings = api.get("/api/v1/vault/findings", params={"status": "all"})
    assert findings.status_code == 200 and findings.json()["total"] == len(EXPECTED)
    secrets_page = api.get("/api/v1/vault/secrets")
    assert secrets_page.status_code == 200 and secrets_page.json()["total"] == len(EXPECTED)
    assert api.get("/api/v1/vault/rules").json()["items"]
    _assert_no_leak([findings.text, secrets_page.text], secrets)
    assert api.post("/api/v1/vault/scan", json={"path": str(repo)}).status_code in (404, 405)
    assert api.get("/api/v1/vault/findings", params={"status": "nope"}).status_code == 422
