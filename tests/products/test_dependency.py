"""R$F Dependency: parsers, versions, ranges, OSV matching, persistence, SBOM, CLI and API."""

from __future__ import annotations

import json
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from raf.core.objects.types import FindingStatus
from raf.products.dependency.model import build_model
from raf.products.dependency.names import ecosystem_from_osv, normalize_name, parse_purl, purl
from raf.products.dependency.osv import (
    AffectedEntry,
    constraint_affected,
    cvss3_base_score,
    parse_osv,
    version_affected,
)
from raf.products.dependency.parsers import detect_kind
from raf.products.dependency.parsers.javascript import parse_package_json, parse_package_lock, parse_yarn_lock
from raf.products.dependency.parsers.other import (
    parse_cargo_lock,
    parse_cargo_toml,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_go_mod,
)
from raf.products.dependency.parsers.python import (
    RequirementsParser,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject,
)
from raf.products.dependency.ranges import constraint_intervals, in_any, osv_intervals
from raf.products.dependency.samples import write_sample_project
from raf.products.dependency.service import DependencyService
from raf.products.dependency.versions import InvalidVersion, compare_versions, sort_versions

REPO = Path(__file__).resolve().parents[2]
ADVISORIES = REPO / "fixtures" / "advisories" / "raven-osv.json"


# --------------------------------------------------------------------------- names and purls


def test_name_normalization_and_purls() -> None:
    assert normalize_name("pypi", "Raven_Auth.Core") == "raven-auth-core"
    assert normalize_name("pypi", "raven--auth__x") == "raven-auth-x"
    assert normalize_name("npm", "@Raven/UI") == "@raven/ui"
    assert purl("npm", "@raven/ui", "2.0.0") == "pkg:npm/%40raven/ui@2.0.0"
    assert purl("go", "github.com/raven/mux", "v1.2.0") == "pkg:golang/github.com/raven/mux@v1.2.0"
    assert purl("pypi", "raven-auth", "1.0+local") == "pkg:pypi/raven-auth@1.0%2Blocal"
    assert parse_purl("pkg:npm/%40raven/ui@2.0.0") == ("npm", "@raven/ui", "2.0.0")
    assert parse_purl("pkg:npm/@raven/ui@2.0.0?arch=x#sub") == ("npm", "@raven/ui", "2.0.0")
    assert parse_purl("pkg:pypi/Raven_Auth@1.0") == ("pypi", "raven-auth", "1.0")
    assert parse_purl("pkg:gem/rails") == ("rubygems", "rails", None)
    assert parse_purl("pkg:composer/raven/sdk@1.0") == ("packagist", "raven/sdk", "1.0")
    assert parse_purl("not-a-purl") is None and parse_purl("pkg:npm") is None
    assert ecosystem_from_osv("crates.io") == "cargo" and ecosystem_from_osv("PyPI") == "pypi"
    assert ecosystem_from_osv("Debian:12") == "debian"


# --------------------------------------------------------------------------- versions


def test_pep440_ordering() -> None:
    ordered = ["0.9", "1.0.dev1", "1.0a1", "1.0a2.dev3", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1.dev1"]
    ordered += ["1.0.post1", "1.0.1", "1.1", "1!0.1"]
    assert sort_versions("pypi", list(reversed(ordered))) == ordered
    assert compare_versions("pypi", "1.0", "1.0.0") == 0
    assert compare_versions("pypi", "1.0+local.7", "1.0") == 0  # local versions ignored
    assert compare_versions("pypi", "1.0-1", "1.0.post1") == 0
    assert compare_versions("pypi", "1.0alpha1", "1.0a1") == 0
    assert compare_versions("pypi", "1.0c1", "1.0rc1") == 0
    assert compare_versions("pypi", "v2.0", "2.0") == 0
    assert compare_versions("pypi", "1.10", "1.9") == 1
    assert compare_versions("pypi", "1.0.0-custom", "1.0.0") == -1  # not PEP 440: generic fallback (letters = pre)


def test_semver_ordering() -> None:
    ordered = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.10.0",
    ]
    assert sort_versions("npm", list(reversed(ordered))) == ordered
    assert compare_versions("npm", "v1.2.3", "=1.2.3") == 0
    assert compare_versions("npm", "1.2.3+build.5", "1.2.3") == 0
    assert compare_versions("cargo", "0.10.0", "0.9.9") == 1
    assert compare_versions("go", "v1.2.4-0.20210101000000-abcdef123456", "v1.2.4") == -1
    assert compare_versions("go", "v0.0.0-20220101000000-aaaa", "v0.0.0-20210101000000-bbbb") == 1
    assert compare_versions("go", "v2.0.0+incompatible", "v2.0.0") == 0


def test_generic_ordering_and_invalid_versions() -> None:
    assert sort_versions("rubygems", ["1.0.0", "1.0.0.rc1", "1.0.0.pre1", "1.0.0.beta2", "0.9"]) == [
        "0.9",
        "1.0.0.beta2",
        "1.0.0.pre1",
        "1.0.0.rc1",
        "1.0.0",
    ]
    assert sort_versions("packagist", ["1.2.4", "1.2.3-p1", "v1.2.3", "1.2.3-RC2", "1.2.3-beta1"]) == [
        "1.2.3-beta1",
        "1.2.3-RC2",
        "v1.2.3",
        "1.2.3-p1",
        "1.2.4",
    ]
    assert compare_versions("rubygems", "1.0", "1.0.0") == 0
    assert compare_versions("maven", "1.0-SNAPSHOT", "1.0") == -1
    with pytest.raises(InvalidVersion):
        compare_versions("packagist", "dev-main", "1.0")


# --------------------------------------------------------------------------- ranges


def _describe(ecosystem: str, constraint: str) -> list[str] | None:
    intervals = constraint_intervals(ecosystem, constraint)
    return None if intervals is None else [i.describe() for i in intervals]


@pytest.mark.parametrize(
    ("ecosystem", "constraint", "expected"),
    [
        ("npm", "^1.2.3", [">=1.2.3, <2.0.0"]),
        ("npm", "^0.2.3", [">=0.2.3, <0.3.0"]),
        ("npm", "^0.0.3", [">=0.0.3, <0.0.4"]),
        ("npm", "~1.2", [">=1.2.0, <1.3.0"]),
        ("npm", "1.x || >=3.0.0", [">=1.0.0, <2.0.0", ">=3.0.0"]),
        ("npm", ">= 1.2 < 2", [">=1.2.0, <2.0.0"]),
        ("npm", "1.2.3 - 2.3", [">=1.2.3, <2.4.0"]),
        ("npm", ">1.2", [">=1.3.0"]),
        ("npm", "<=1.2", ["<1.3.0"]),
        ("npm", "1.2.3", [">=1.2.3, <=1.2.3"]),
        ("npm", "*", ["*"]),
        ("pypi", ">=1.0,<2", [">=1.0, <2"]),
        ("pypi", "~=1.4.2", [">=1.4.2, <1.5.0"]),
        ("pypi", "~=1.4", [">=1.4.0, <2.0.0"]),
        ("pypi", "==1.2.*", [">=1.2.0, <1.3.0"]),
        ("pypi", "!=1.5,>=1.0", [">=1.0"]),
        ("pypi", "^0.2.3", [">=0.2.3, <0.3.0"]),
        ("pypi", "1.2.3", [">=1.2.3, <=1.2.3"]),
        ("pypi", ">1.2", [">1.2"]),
        ("cargo", "1.2", [">=1.2.0, <2.0.0"]),
        ("cargo", "=1.2.3", [">=1.2.3, <=1.2.3"]),
        ("cargo", ">=1.0, <1.5", [">=1.0.0, <1.5.0"]),
        ("rubygems", "~> 2.2", [">=2.2.0, <3.0.0"]),
        ("rubygems", "~> 2.2.0", [">=2.2.0, <2.3.0"]),
        ("rubygems", ">= 1.0, < 2", [">=1.0, <2"]),
        ("packagist", "^1.2 || ~2.1", [">=1.2.0, <2.0.0", ">=2.1.0, <3.0.0"]),
        ("packagist", "~1.2.3", [">=1.2.3, <1.3.0"]),
        ("packagist", "1.0 - 2.0", [">=1.0.0, <2.1.0"]),
        ("packagist", "v1.2.3", [">=1.2.3, <=1.2.3"]),
        ("go", "v1.2.3", [">=v1.2.3, <=v1.2.3"]),
        ("npm", "latest", None),
        ("npm", "git+https://git.raven.example/ui.git", None),
        ("npm", "file:../ui", None),
        ("packagist", "dev-main", None),
        ("pypi", "@ https://x", None),
    ],
)
def test_constraint_intervals(ecosystem: str, constraint: str, expected: list[str] | None) -> None:
    assert _describe(ecosystem, constraint) == expected


def test_osv_events_semantics() -> None:
    fixed = osv_intervals("pypi", [{"fixed": "1.4.2"}, {"introduced": "0"}])  # unsorted on purpose
    assert [in_any("pypi", fixed, v) for v in ("0.1", "1.4.1", "1.4.2", "2.0")] == [True, True, False, False]
    last = osv_intervals("npm", [{"introduced": "1.0.0"}, {"last_affected": "1.9.4"}])
    assert [in_any("npm", last, v) for v in ("0.9.9", "1.0.0", "1.9.4", "1.9.5")] == [False, True, True, False]
    multi = osv_intervals("npm", [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}])
    assert [in_any("npm", multi, v) for v in ("1.1.0", "1.5.0", "2.0.0", "9.0.0")] == [True, False, True, True]
    limit = osv_intervals("npm", [{"introduced": "0"}, {"limit": "3.0.0"}])
    assert in_any("npm", limit, "2.9.9") and not in_any("npm", limit, "3.0.0")
    twice = osv_intervals("pypi", [{"introduced": "1.0"}, {"introduced": "1.5"}, {"fixed": "2.0"}])
    assert in_any("pypi", twice, "1.2") and not in_any("pypi", twice, "2.0")


def test_osv_affected_entries() -> None:
    entry = AffectedEntry(
        "go",
        "github.com/raven/mux",
        ranges=[
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.8.1"}]},
            {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abcdef1"}]},
        ],
    )
    assert version_affected(entry, "v1.8.0") and not version_affected(entry, "v1.8.1")
    listed = AffectedEntry("pypi", "raven-telemetry", versions=["0.9.0", "0.9.1"])
    assert version_affected(listed, "0.9.1") and version_affected(listed, "0.9.1.0")
    assert not version_affected(listed, "0.9.2")
    assert constraint_affected(listed, ">=0.9") and constraint_affected(listed, "")
    assert constraint_affected(listed, ">=0.9.2") is None and constraint_affected(listed, "==0.8.0") is None
    ranged = AffectedEntry("npm", "raven-ui-kit", ranges=[{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}])
    assert constraint_affected(ranged, "^1.5.0") is None and constraint_affected(ranged, "^2.1.0")
    assert constraint_affected(ranged, "git+https://x/y.git") is None  # cannot be interpreted


def test_cvss_and_osv_parsing() -> None:
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N") == 5.3
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert cvss3_base_score("CVSS:3.1/AV:X") is None
    docs = json.loads(ADVISORIES.read_text())
    parsed = {d["id"]: parse_osv(d) for d in docs}
    assert parsed["RAFSIM-2026-0101"].severity.value == "CRITICAL" and parsed["RAFSIM-2026-0101"].cvss == 9.8
    assert parsed["RAFSIM-2026-0102"].severity.value == "HIGH"
    assert parsed["RAFSIM-2026-0102"].severity_source == "database_specific"
    assert parsed["RAFSIM-2026-0103"].affected[0].name == "raven-telemetry"  # PEP 503 normalized
    assert parsed["RAFSIM-2026-0104"].affected[0].fixed_versions() == ["3.0.0"]
    assert parse_osv({"id": "X-1", "affected": []}).severity.value == "MEDIUM"  # no severity: documented default
    with pytest.raises(Exception, match="advisory id"):
        parse_osv({"id": "../../etc"})
    assert all(d["summary"].startswith("(synthetic)") for d in docs)


# --------------------------------------------------------------------------- parsers


def _req_parser(root: Path) -> RequirementsParser:
    return RequirementsParser(root.resolve(), lambda p: p.read_text(encoding="utf-8"))


def test_requirements_parser(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    (root / "reqs").mkdir(parents=True)
    (tmp_path / "outside.txt").write_text("evil-package==6.6.6\n")
    (root / "linked.txt").symlink_to(tmp_path / "outside.txt")
    (root / "reqs" / "base.txt").write_text("Raven_Common[yaml]>=3.0 ; python_version >= '3.10'\n")
    (root / "requirements.txt").write_text(
        "# comment\n"
        "raven-auth==1.2.0  # pinned\n"
        "raven-telemetry >= 0.9, < 1.0 \\\n"
        "    --hash=sha256:00\n"
        "--index-url https://pypi.raven.example/simple\n"
        "-r reqs/base.txt\n"
        "-r ../outside.txt\n"
        "-r linked.txt\n"
        "-e git+https://git.raven.example/tool.git#egg=tool\n"
        "raven-direct @ https://files.raven.example/raven_direct-1.0-py3-none-any.whl\n"
        "-c constraints.txt\n"
        "raven-old (>=1.0)\n"
    )
    results = _req_parser(root).parse((root / "requirements.txt").resolve())
    declared = {d.name: d for r in results for d in r.declared}
    assert set(declared) == {"raven-auth", "raven-telemetry", "raven-common", "raven-direct", "raven-old"}
    assert declared["raven-auth"].exact == "1.2.0" and declared["raven-auth"].line == 2
    assert declared["raven-telemetry"].constraint == ">=0.9,<1.0" and declared["raven-telemetry"].exact is None
    assert declared["raven-telemetry"].line == 3
    assert declared["raven-common"].manifest == "reqs/base.txt" and declared["raven-common"].constraint == ">=3.0"
    assert declared["raven-old"].constraint == ">=1.0" and declared["raven-direct"].constraint == ""
    warnings_text = " ".join(w for r in results for w in r.warnings)
    assert "outside the scan root" in warnings_text and "editable" in warnings_text
    assert "evil-package" not in declared
    dev = _req_parser(root)
    (root / "requirements-dev.txt").write_text("raven-lint==0.4\n")
    assert dev.parse((root / "requirements-dev.txt").resolve())[0].declared[0].scope == "dev"


def test_pyproject_and_python_lockfiles() -> None:
    pyproject = """
[project]
name = "shop"
dependencies = ["raven-auth>=1.0", "Raven_Common~=3.1"]
[project.optional-dependencies]
metrics = ["raven-telemetry>=0.9"]
[dependency-groups]
test = ["raven-testkit==2.0", {include-group = "lint"}]
[tool.poetry.dependencies]
python = "^3.12"
raven-orm = "1.4.0"
raven-cache = {version = "^2.1", optional = true}
raven-local = {path = "../local"}
[tool.poetry.group.docs.dependencies]
raven-docs = "~0.3"
"""
    result = parse_pyproject("pyproject.toml", pyproject)
    by_name = {d.name: d for d in result.declared}
    assert by_name["raven-common"].constraint == "~=3.1" and by_name["raven-common"].scope == "runtime"
    assert by_name["raven-telemetry"].scope == "optional" and by_name["raven-telemetry"].group == "metrics"
    assert by_name["raven-testkit"].scope == "dev" and by_name["raven-testkit"].exact == "2.0"
    assert by_name["raven-orm"].exact == "1.4.0"  # bare Poetry version = exact
    assert by_name["raven-cache"].scope == "optional" and by_name["raven-docs"].scope == "dev"
    assert "python" not in by_name and by_name["raven-auth"].line == 4
    assert any("raven-local" in w for w in result.warnings)
    lock = """
[[package]]
name = "raven-auth"
version = "1.2.0"
groups = ["main"]
[package.dependencies]
Raven_Crypto = ">=2"
[[package]]
name = "raven-crypto"
version = "2.5.1"
category = "main"
[[package]]
name = "raven-testkit"
version = "2.0"
category = "dev"
"""
    poetry = parse_poetry_lock("poetry.lock", lock)
    assert {(p.name, p.version, p.scope) for p in poetry.locked} == {
        ("raven-auth", "1.2.0", "runtime"),
        ("raven-crypto", "2.5.1", "runtime"),
        ("raven-testkit", "2.0", "dev"),
    }
    assert poetry.edges == [(("pypi", "raven-auth", "1.2.0"), ("pypi", "raven-crypto", "2.5.1"))]
    pipfile = json.dumps(
        {
            "_meta": {},
            "default": {"raven-auth": {"version": "==1.2.0"}, "raven-git": {"git": "https://x"}},
            "develop": {"raven-lint": {"version": "==0.4.0"}},
        },
        indent=4,
    )
    pip = parse_pipfile_lock("Pipfile.lock", pipfile)
    assert {(p.name, p.version, p.scope) for p in pip.locked} == {
        ("raven-auth", "1.2.0", "runtime"),
        ("raven-lint", "0.4.0", "dev"),
    }
    assert pip.locked[0].line is not None and pip.warnings


def test_npm_manifests() -> None:
    package_json = json.dumps(
        {
            "dependencies": {"raven-ui-kit": "^2.1.0", "ui-alias": "npm:@raven/ui@^3.0.0", "local": "file:../x"},
            "devDependencies": {"raven-logger": "3.1.0"},
            "optionalDependencies": {"raven-fsevents": "~1.2"},
        },
        indent=2,
    )
    declared = {d.name: d for d in parse_package_json("package.json", package_json).declared}
    assert declared["@raven/ui"].constraint == "^3.0.0" and declared["@raven/ui"].raw_name == "ui-alias"
    assert declared["raven-logger"].exact == "3.1.0" and declared["raven-logger"].scope == "dev"
    assert declared["raven-fsevents"].scope == "optional" and declared["raven-ui-kit"].line == 3
    v3 = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0", "c": "^1.0.0"}},
            "node_modules/a/node_modules/b": {"version": "2.1.0", "dependencies": {"c": "^1.0.0"}},
            "node_modules/b": {"version": "1.0.0"},
            "node_modules/c": {"version": "1.5.0"},
            "node_modules/d": {"version": "1.0.0", "dev": True},
            "node_modules/@s/e": {"version": "0.1.0", "optional": True},
            "node_modules/ws": {"resolved": "packages/ws", "link": True},
            "packages/ws": {"name": "ws", "version": "0.0.1"},
        },
    }
    lock = parse_package_lock("package-lock.json", json.dumps(v3, indent=2))
    refs = {(p.name, p.version): p for p in lock.locked}
    assert set(refs) == {
        ("a", "1.0.0"),
        ("b", "2.1.0"),
        ("b", "1.0.0"),
        ("c", "1.5.0"),
        ("d", "1.0.0"),
        ("@s/e", "0.1.0"),
    }
    assert refs[("a", "1.0.0")].direct and not refs[("b", "2.1.0")].direct and refs[("d", "1.0.0")].scope == "dev"
    assert refs[("@s/e", "0.1.0")].scope == "optional" and refs[("a", "1.0.0")].line is not None
    edges = {(p[1], p[2], c[1], c[2]) for p, c in lock.edges}
    assert ("a", "1.0.0", "b", "2.1.0") in edges  # nested node_modules wins
    assert ("b", "2.1.0", "c", "1.5.0") in edges  # resolved by walking up to the root
    v1 = {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0", "requires": {"b": "^2.0.0"}, "dependencies": {"b": {"version": "2.0.1"}}},
            "b": {"version": "1.0.0", "dev": True},
            "g": {"version": "github:raven/g#abc"},
        },
    }
    old = parse_package_lock("package-lock.json", json.dumps(v1))
    assert {(p.name, p.version) for p in old.locked} == {("a", "1.0.0"), ("b", "2.0.1"), ("b", "1.0.0")}
    assert [(p[1], c[2]) for p, c in old.edges] == [("a", "2.0.1")] and old.warnings


def test_yarn_lockfiles() -> None:
    v1 = (
        "# yarn lockfile v1\n\n\n"
        '"@raven/ui@^2.0.0", "@raven/ui@^2.1.0":\n'
        '  version "2.2.0"\n'
        "  dependencies:\n"
        '    lodash "^4.17.0"\n\n'
        "lodash@^3.0.0:\n"
        '  version "3.10.1"\n\n'
        'lodash@^4.17.0, "lodash@^4.17.20":\n'
        '  version "4.17.21"\n'
    )
    result = parse_yarn_lock("yarn.lock", v1)
    assert {(p.name, p.version) for p in result.locked} == {
        ("@raven/ui", "2.2.0"),
        ("lodash", "3.10.1"),
        ("lodash", "4.17.21"),
    }
    assert [(p[1], c[2]) for p, c in result.edges] == [("@raven/ui", "4.17.21")]
    berry = (
        "__metadata:\n  version: 6\n\n"
        '"lodash@npm:^4.17.0":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n\n'
        '"app@workspace:.":\n  version: 0.0.0-use.local\n  dependencies:\n    lodash: "npm:^4.17.0"\n'
    )
    assert {(p.name, p.version) for p in parse_yarn_lock("yarn.lock", berry).locked} == {("lodash", "4.17.21")}
    package_json = parse_package_json("package.json", json.dumps({"dependencies": {"lodash": "^4.17.20"}}))
    model = build_model("k", "app", None, [package_json, result])
    assert model.dependencies[("npm", "lodash")].resolved == {("npm", "lodash", "4.17.21")}  # constraint-aware
    assert model.packages[("npm", "lodash", "3.10.1")].direct is False


def test_go_cargo_ruby_php_manifests() -> None:
    go = parse_go_mod(
        "go.mod",
        "module example.com/shop\n\ngo 1.22\n\nrequire github.com/raven/single v1.0.0\n\n"
        "require (\n\tgithub.com/Raven/Mux v1.8.0\n\tgolang.org/x/text v0.14.0 // indirect\n)\n\n"
        "replace github.com/raven/single => ../single\n",
    )
    assert {(d.name, d.exact) for d in go.declared} == {
        ("github.com/raven/single", "v1.0.0"),
        ("github.com/raven/mux", "v1.8.0"),
    }
    assert {p.name: p.direct for p in go.locked}["golang.org/x/text"] is False and go.warnings
    cargo = parse_cargo_toml(
        "Cargo.toml",
        '[dependencies]\nserde = "1.0"\nfast = { package = "raven-fast", version = "=0.3.1", optional = true }\n'
        'local = { path = "../local" }\n[dev-dependencies]\ntokio-test = "0.4"\n'
        "[target.'cfg(unix)'.dependencies]\nnix = \"0.27\"\n",
    )
    by_name = {d.name: d for d in cargo.declared}
    assert by_name["raven-fast"].exact == "0.3.1" and by_name["raven-fast"].scope == "optional"
    assert by_name["serde"].exact is None and by_name["tokio-test"].scope == "dev" and "nix" in by_name
    lock = parse_cargo_lock(
        "Cargo.lock",
        '[[package]]\nname = "shop"\nversion = "0.1.0"\ndependencies = ["serde", "syn 2.0.1"]\n\n'
        '[[package]]\nname = "serde"\nversion = "1.0.190"\nsource = "registry+https://x"\n'
        'dependencies = ["syn 1.0.109"]\n\n'
        '[[package]]\nname = "syn"\nversion = "1.0.109"\nsource = "registry+https://x"\n\n'
        '[[package]]\nname = "syn"\nversion = "2.0.1"\nsource = "registry+https://x"\n',
    )
    assert {(p.name, p.version, p.direct) for p in lock.locked} == {
        ("serde", "1.0.190", True),
        ("syn", "1.0.109", False),
        ("syn", "2.0.1", True),
    }
    assert [(p[2], c[2]) for p, c in lock.edges] == [("1.0.190", "1.0.109")]
    gems = parse_gemfile_lock(
        "Gemfile.lock",
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.15.4-x86_64-linux)\n      racc (~> 1.4)\n"
        "    racc (1.7.1)\n    rails (7.1.0)\n\nPLATFORMS\n  x86_64-linux\n\n"
        "DEPENDENCIES\n  nokogiri\n  rails (~> 7.1)\n"
        "\nBUNDLED WITH\n   2.4.10\n",
    )
    assert {(p.name, p.version, p.direct) for p in gems.locked} == {
        ("nokogiri", "1.15.4", True),
        ("racc", "1.7.1", False),
        ("rails", "7.1.0", True),
    }
    assert [(p[1], c[1]) for p, c in gems.edges] == [("nokogiri", "racc")]
    assert {d.name: d.constraint for d in gems.declared} == {"nokogiri": "", "rails": "~> 7.1"}
    composer = parse_composer_lock(
        "composer.lock",
        json.dumps(
            {
                "packages": [
                    {"name": "Raven/SDK", "version": "v2.1.0", "require": {"php": ">=8.1", "raven/http": "^1.0"}},
                    {"name": "raven/http", "version": "1.4.2"},
                ],
                "packages-dev": [{"name": "raven/phpunit-ext", "version": "dev-main"}],
            },
            indent=4,
        ),
    )
    assert {(p.name, p.version, p.scope) for p in composer.locked} == {
        ("raven/sdk", "2.1.0", "runtime"),
        ("raven/http", "1.4.2", "runtime"),
        ("raven/phpunit-ext", "dev-main", "dev"),
    }
    assert [(p[1], c[1]) for p, c in composer.edges] == [("raven/sdk", "raven/http")]


def test_detect_kind() -> None:
    assert detect_kind("requirements.txt") == "requirements" and detect_kind("dev-requirements.txt") == "requirements"
    assert detect_kind("requirements/base.txt") == "requirements" and detect_kind("notes.txt") is None
    assert detect_kind("web/package-lock.json") == "package-lock.json" and detect_kind("npm-shrinkwrap.json")
    assert detect_kind("Cargo.lock") == "Cargo.lock" and detect_kind("go.sum") is None


# --------------------------------------------------------------------------- service: scan, check, re-scan


def _sample(tmp_path: Path, *, upgraded: bool = False) -> Path:
    target = tmp_path / "raven-shop"
    write_sample_project(target, upgraded=upgraded)
    return target


def test_scan_builds_the_dependency_graph(ctx: RafContext, tmp_path: Path) -> None:
    root = _sample(tmp_path)
    service = DependencyService(ctx)
    result = service.scan(root, name="raven-shop")
    project_id = f"project:{root.resolve()}"
    assert result.project["id"] == project_id and result.check is None  # no advisories yet
    assert result.counts == {
        "manifests": 5,
        "declared": 7,
        "packages": 8,
        "direct": 6,
        "transitive": 2,
        "edges": 2,
        "unresolved": 1,
    }
    project = ctx.store.objects.require(project_id)
    assert project.name == "raven-shop" and project.metadata["ecosystems"] == ["npm", "pypi"]
    dep_id = f"dependency:{root.resolve()}|pypi/raven-auth".lower()
    dependency = ctx.store.objects.require(dep_id)
    assert dependency.metadata["constraint"] == "==1.2.0" and len(dependency.metadata["declarations"]) == 2
    package = ctx.store.objects.require("package:pypi/raven-auth@1.2.0")
    assert package.metadata == {
        "ecosystem": "pypi",
        "name": "raven-auth",
        "version": "1.2.0",
        "purl": "pkg:pypi/raven-auth@1.2.0",
    }
    assert ctx.store.relationships.list(types=["DECLARES"], source=project_id, target=dep_id)
    assert ctx.store.relationships.list(types=["RESOLVES_TO"], source=dep_id, target=package.id)
    uses = {r.target_object: r.metadata for r in ctx.store.relationships.list(types=["DEPENDS_ON"], source=project_id)}
    assert uses["package:npm/raven-ui-kit@2.2.0"]["direct"] is True
    assert uses["package:npm/raven-core-js@1.1.3"]["direct"] is False
    assert uses["package:npm/raven-logger@3.1.0"]["scope"] == "dev"
    inner = ctx.store.relationships.list(types=["DEPENDS_ON"], source="package:npm/raven-ui-kit@2.2.0")
    assert {r.target_object for r in inner} == {"package:npm/raven-core-js@1.1.3", "package:npm/raven-icons@1.1.0"}
    assert project_id in inner[0].metadata["sources"]
    assert ctx.store.provenance.for_subject(package.id)[0].parser == "dependency/lockfile"
    names = {node["name"]: node for node in result.tree}
    assert [c["name"] for c in names["raven-ui-kit"]["resolved"][0]["children"]] == ["raven-core-js", "raven-icons"]
    assert names["raven-telemetry"]["resolved"] == []


def test_check_rescan_upgrade_and_idempotency(ctx: RafContext, tmp_path: Path) -> None:
    root = _sample(tmp_path)
    service = DependencyService(ctx)
    service.scan(root, name="raven-shop")
    imported = service.import_advisories(ADVISORIES)
    assert imported.imported == 4 and imported.created == 4 and not imported.rejected
    check = service.check("raven-shop")
    found = {(i.advisory, i.basis): i for i in check.items}
    assert set(found) == {
        ("RAFSIM-2026-0101", "exact"),
        ("RAFSIM-2026-0102", "exact"),
        ("RAFSIM-2026-0103", "constraint"),
    }  # raven-logger 3.1.0 is already fixed (RAFSIM-2026-0104 < 3.0.0)
    auth = found[("RAFSIM-2026-0101", "exact")]
    assert auth.severity.value == "CRITICAL" and auth.confidence == 0.9 and auth.fixed == ["1.4.2"]
    telemetry = found[("RAFSIM-2026-0103", "constraint")]
    assert telemetry.severity.value == "MEDIUM" and telemetry.confidence == 0.55 and telemetry.version is None
    assert found[("RAFSIM-2026-0102", "exact")].severity.value == "HIGH"
    affects = ctx.store.relationships.list(types=["AFFECTS"], target="package:pypi/raven-auth@1.2.0")
    assert [r.source_object for r in affects] == ["vulnerability:RAFSIM-2026-0101"]
    finding = ctx.store.findings.require(auth.finding_id)
    assert finding.product == "dependency" and finding.rule_id == "vulnerable-package"
    assert finding.recommendation.startswith("Upgrade raven-auth from 1.2.0 to 1.4.2")
    assert sum(f["points"] for f in finding.explanation) == 90
    assert {e.id for e in finding.evidence} >= {"vulnerability:RAFSIM-2026-0101", "package:pypi/raven-auth@1.2.0"}
    assert ctx.resolve("RAVEN-SEC-0101").id == "vulnerability:RAFSIM-2026-0101"  # aliases are indexed
    # re-scan of the same tree: no duplicates, nothing ended, checks re-run automatically
    counts = (ctx.store.objects.count(), ctx.store.relationships.count(), ctx.store.findings.count())
    again = service.scan(root, name="raven-shop")
    assert (ctx.store.objects.count(), ctx.store.relationships.count(), ctx.store.findings.count()) == counts
    assert again.stored["objects_created"] == 0 and again.stored["relationships_ended"] == 0
    assert again.check is not None and again.check.findings["created"] == 0
    assert service.check().findings == {"created": 0, "updated": 3, "resolved": 0, "affects_ended": 0}
    # upgrade to fixed versions: findings resolve, stale edges end, history is kept
    write_sample_project(root, upgraded=True)
    upgraded = service.scan(root, name="raven-shop")
    assert upgraded.check is not None and upgraded.check.items == []
    assert upgraded.check.findings["resolved"] == 3
    statuses = {f.metadata["advisory"]: f.status for f in ctx.store.findings.list(product="dependency", limit=50)}
    assert set(statuses.values()) == {FindingStatus.RESOLVED}
    old_edge = ctx.store.relationships.list(types=["DEPENDS_ON"], target="package:pypi/raven-auth@1.2.0")[0]
    assert old_edge.valid_to is not None
    assert ctx.store.objects.get("package:pypi/raven-auth@1.4.2") is not None
    assert service.vulnerable() == [] and len(service.vulnerable(include_unused=True)) == 2
    # a corrupted lockfile makes the scan incomplete: previous packages are kept, nothing resolves by accident
    write_sample_project(root)
    service.scan(root, name="raven-shop")
    (root / "package-lock.json").write_text("{corrupted")
    partial = service.scan(root, name="raven-shop")
    assert partial.stored["relationships_ended"] == 0 and partial.warnings[0].startswith("incomplete scan")
    assert (
        ctx.store.relationships.list(types=["DEPENDS_ON"], target="package:npm/raven-ui-kit@2.2.0")[0].valid_to is None
    )


def test_advisory_import_sources(ctx: RafContext, tmp_path: Path) -> None:
    folder = tmp_path / "osv"
    folder.mkdir()
    docs = json.loads(ADVISORIES.read_text())
    (folder / "one.json").write_text(json.dumps(docs[0]))
    (folder / "api.json").write_text(json.dumps({"vulns": docs[1:3]}))
    (folder / "broken.json").write_text("{not json")
    (folder / "bad-id.json").write_text(json.dumps({"id": "../x", "affected": []}))
    withdrawn = dict(docs[3], id="RAFSIM-2026-0199", withdrawn="2026-10-01T00:00:00Z")
    (folder / "withdrawn.json").write_text(json.dumps(withdrawn))
    (folder / "notes.txt").write_text("ignored")
    result = DependencyService(ctx).import_advisories(folder)
    assert result.imported == 4 and {r["source"] for r in result.rejected} == {"broken.json", "bad-id.json"}
    listed = {a["id"]: a for a in DependencyService(ctx).advisories()}
    assert listed["RAFSIM-2026-0199"]["withdrawn"] and "RAFSIM-2026-0102" in listed
    root = tmp_path / "web"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"dependencies": {"raven-logger": "2.0.0"}}))
    scan = DependencyService(ctx).scan(root)
    assert scan.check is not None and scan.check.items == []  # the only matching advisory is withdrawn
    with pytest.raises(Exception, match="not a readable JSON document"):
        DependencyService(ctx).import_advisories(folder / "broken.json")


def test_sbom_export_import_round_trip(ctx: RafContext, tmp_path: Path) -> None:
    service = DependencyService(ctx)
    root = _sample(tmp_path)
    service.scan(root, name="raven-shop")
    output = tmp_path / "out" / "shop.cdx.json"
    info = service.export_sbom("raven-shop", output)
    assert info["components"] == 8
    document = json.loads(output.read_text())
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.5"
    purls = {c["purl"] for c in document["components"]}
    assert "pkg:npm/raven-ui-kit@2.2.0" in purls and "pkg:pypi/raven-auth@1.2.0" in purls
    root_entry = next(d for d in document["dependencies"] if d["ref"] == f"project:{root.resolve()}")
    assert len(root_entry["dependsOn"]) == 6
    logger = next(c for c in document["components"] if c["name"] == "raven-logger")
    assert logger["scope"] == "excluded"  # dev dependency
    imported = service.import_sbom(output, name="raven-shop-sbom")
    assert imported.project["id"] == "project:raven-shop-sbom"
    original = service.project_graph("raven-shop")
    copy = service.project_graph("raven-shop-sbom")
    assert [(p["id"], p["direct"], p["scope"]) for p in copy["packages"]] == [
        (p["id"], p["direct"], p["scope"]) for p in original["packages"]
    ]
    inner = sorted((e["source"], e["target"]) for e in original["edges"] if e["source"].startswith("package:"))
    assert sorted((e["source"], e["target"]) for e in copy["edges"] if e["source"].startswith("package:")) == inner


def test_spdx_import(ctx: RafContext, tmp_path: Path) -> None:
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "raven-api-sbom",
        "documentDescribes": ["SPDXRef-root"],
        "packages": [
            {"SPDXID": "SPDXRef-root", "name": "raven-api", "versionInfo": "1.0.0"},
            {
                "SPDXID": "SPDXRef-auth",
                "name": "raven-auth",
                "versionInfo": "1.2.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/raven-auth@1.2.0",
                    }
                ],
            },
            {"SPDXID": "SPDXRef-crypto", "name": "raven-crypto", "versionInfo": "2.5.1"},
            {"SPDXID": "SPDXRef-lint", "name": "raven-lint", "versionInfo": "0.4.0"},
            {"SPDXID": "SPDXRef-nover", "name": "mystery"},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-auth"},
            {
                "spdxElementId": "SPDXRef-crypto",
                "relationshipType": "DEPENDENCY_OF",
                "relatedSpdxElement": "SPDXRef-auth",
            },
            {
                "spdxElementId": "SPDXRef-lint",
                "relationshipType": "DEV_DEPENDENCY_OF",
                "relatedSpdxElement": "SPDXRef-root",
            },
        ],
    }
    path = tmp_path / "api.spdx.json"
    path.write_text(json.dumps(spdx))
    result = DependencyService(ctx).import_sbom(path)
    assert result.project["name"] == "raven-api" and result.counts["packages"] == 3
    graph = {p["name"]: p for p in DependencyService(ctx).project_graph("raven-api")["packages"]}
    assert graph["raven-auth"]["direct"] and graph["raven-lint"]["direct"] and not graph["raven-crypto"]["direct"]
    assert graph["raven-lint"]["scope"] == "dev" and graph["raven-crypto"]["ecosystem"] == "generic"
    assert any("mystery" in w for w in result.warnings)
    (tmp_path / "x.json").write_text(json.dumps({"hello": "world"}))
    with pytest.raises(Exception, match="Not a CycloneDX or SPDX"):
        DependencyService(ctx).import_sbom(tmp_path / "x.json")


def test_scan_never_follows_symlinks(ctx: RafContext, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package.json").write_text(json.dumps({"dependencies": {"evil": "1.0.0"}}))
    root = tmp_path / "repo"
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "node_modules" / "x" / "package.json").write_text(json.dumps({"dependencies": {"nested": "1.0.0"}}))
    (root / "package.json").write_text(json.dumps({"dependencies": {"ok": "1.0.0"}}))
    (root / "linked").symlink_to(outside, target_is_directory=True)
    (root / "sub").mkdir()
    (root / "sub" / "package.json").symlink_to(outside / "package.json")
    result = DependencyService(ctx).scan(root)
    assert {n["name"] for n in result.tree} == {"ok"}
    assert {"path": "sub/package.json", "reason": "symlink (not followed)"} in result.skipped


def test_hostile_manifests_are_skipped_not_fatal(ctx: RafContext, tmp_path: Path) -> None:
    root = tmp_path / "hostile"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir()
    (root / "c").mkdir()
    (root / "package.json").write_text(json.dumps({"dependencies": {"ok": "1.0.0"}}))
    (root / "a" / "package-lock.json").write_text("[" * 200_000 + "]" * 200_000)
    (root / "b" / "yarn.lock").write_text("__metadata:\n  version: 6\na: &a [x, x]\nb: [*a, *a]\n")
    (root / "c" / "pyproject.toml").write_text("[project]\ndependencies = 5\n")
    (root / "c" / "package.json").write_text(json.dumps({"dependencies": ["not", "a", "map"]}))
    result = DependencyService(ctx).scan(root)
    reasons = {s["path"]: s["reason"] for s in result.skipped}
    assert "a/package-lock.json" in reasons and "aliases" in reasons["b/yarn.lock"]
    assert {n["name"] for n in result.tree} == {"ok"}
    assert result.warnings[0].startswith("incomplete scan")
    odd = {"id": "ODD-1", "references": {"url": "x"}, "aliases": "nope", "affected": {"x": 1}, "severity": "HIGH"}
    advisory = parse_osv(odd)
    assert advisory.references == [] and advisory.aliases == [] and advisory.affected == []


# --------------------------------------------------------------------------- CLI and API


def test_cli_json_outputs(cli: Any, tmp_path: Path) -> None:
    sample = cli("dependency", "sample", str(tmp_path / "shop"), "--json").json()
    assert sample["schema"] == "raf.dependency.sample/v1" and len(sample["files"]) == 5
    scan = cli("dependency", "scan", str(tmp_path / "shop"), "--name", "raven-shop", "--json")
    assert scan.exit_code == 0, scan.stderr
    data = scan.json()
    assert data["schema"] == "raf.dependency.scan/v1" and data["counts"]["packages"] == 8 and data["check"] is None
    human = cli("dependency", "scan", str(tmp_path / "shop"))
    assert "raven-ui-kit" in human.stdout and "(unresolved)" in human.stdout
    advisories = cli("dependency", "advisories", "import", str(ADVISORIES), "--json").json()
    assert advisories["schema"] == "raf.dependency.advisories.import/v1" and advisories["imported"] == 4
    check = cli("dependency", "check", "raven-shop", "--json").json()
    assert check["schema"] == "raf.dependency.check/v1" and len(check["items"]) == 3
    assert check["by_severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1}
    assert "RAFSIM-2026-0101" in cli("dependency", "check").stdout
    projects = cli("dependency", "projects", "--json").json()
    assert projects["total"] == 1 and projects["items"][0]["open_findings"] == 3
    vulnerable = cli("dependency", "vulnerable", "--json").json()
    assert {v["package"]["name"] for v in vulnerable["items"]} == {"raven-auth", "raven-ui-kit"}
    out = tmp_path / "sbom.json"
    export = cli("dependency", "sbom", "export", "raven-shop", "--output", str(out), "--json").json()
    assert export["schema"] == "raf.dependency.sbom.export/v1" and out.exists()
    sbom = cli("dependency", "sbom", "import", str(out), "--name", "copy", "--json").json()
    assert sbom["schema"] == "raf.dependency.sbom.import/v1" and sbom["counts"]["packages"] == 8
    listing = cli("dependency", "advisories", "list", "--json").json()
    assert listing["total"] == 4
    assert cli("dependency", "scan", str(tmp_path / "missing")).exit_code == 3
    (tmp_path / "notes.txt").write_text("x")
    assert cli("dependency", "scan", str(tmp_path / "notes.txt")).exit_code == 4
    assert cli("dependency", "check", "no-such-project").exit_code == 3
    assert cli("dependency", "sbom", "export", "raven-shop").exit_code == 2  # --output is required


@pytest.fixture
def api(raf_home: Path) -> Iterator[Any]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient
    from raf.apps.api.app import create_app

    with TestClient(create_app(env={"RAF_HOME": str(raf_home)})) as client:
        yield client


def test_api_routes(cli: Any, api: Any, tmp_path: Path) -> None:
    write_sample_project(tmp_path / "shop")
    cli("dependency", "advisories", "import", str(ADVISORIES))
    cli("dependency", "scan", str(tmp_path / "shop"), "--name", "raven-shop")
    projects = api.get("/api/v1/dependency/projects").json()
    assert projects["total"] == 1
    project_id = projects["items"][0]["id"]
    graph = api.get(f"/api/v1/dependency/projects/{project_id}/graph")
    assert graph.status_code == 200 and len(graph.json()["packages"]) == 8
    by_name = api.get("/api/v1/dependency/projects/raven-shop/graph").json()
    assert by_name["project"]["id"] == project_id
    vulnerable = api.get("/api/v1/dependency/vulnerable").json()
    assert vulnerable["total"] == 2 and vulnerable["items"][0]["projects"] == [project_id]
    assert api.get("/api/v1/dependency/projects/nope/graph").status_code == 404
    assert api.post("/api/v1/dependency/scan", json={"path": "/etc"}).status_code in (404, 405)
    assert api.get("/api/v1/dependency/advisories").json()["total"] == 4
