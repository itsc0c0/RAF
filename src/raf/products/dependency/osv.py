"""OSV advisories: offline loading, normalization, CVSS v3 scoring and matching.

Advisories are read from local files only (a single OSV object, a list, an OSV
API ``{"vulns": [...]}`` response, or a directory of ``*.json`` files). Nothing
is fetched from the network.

Severity: the highest CVSS v3.x base score computed from ``severity[].score``
vectors (or a numeric score), else ``database_specific.severity`` (GHSA style:
LOW/MODERATE/HIGH/CRITICAL), else MEDIUM (recorded as an assumption).
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raf.core.errors import InvalidInputError, NotFoundError, RafError
from raf.core.objects.types import Severity
from raf.products.dependency.names import ecosystem_from_osv, normalize_name, parse_purl
from raf.products.dependency.parsers.base import read_text
from raf.products.dependency.ranges import (
    constraint_intervals,
    contains,
    in_any,
    intersect,
    is_empty,
    osv_intervals,
)
from raf.products.dependency.versions import InvalidVersion, compare_versions, sort_versions

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
_EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")
MAX_VERSIONS = 20_000
MAX_FILES = 100_000

# --------------------------------------------------------------------------- CVSS v3.x

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest number with one decimal >= value (float-safe)."""
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000.0
    return (math.floor(integer / 10_000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Base score of a ``CVSS:3.0/...`` or ``CVSS:3.1/...`` vector; None for other versions or bad vectors."""
    if not vector.startswith("CVSS:3."):
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope = metrics["S"]
        cia = [1 - _CVSS3["CIA"][metrics[key]] for key in ("C", "I", "A")]
        iss = 1 - cia[0] * cia[1] * cia[2]
        exploitability = (
            8.22 * _CVSS3["AV"][metrics["AV"]] * _CVSS3["AC"][metrics["AC"]] * _CVSS3_PR[scope][metrics["PR"]]
        ) * _CVSS3["UI"][metrics["UI"]]
    except KeyError:
        return None
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    total = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(total, 10.0))


# --------------------------------------------------------------------------- model


@dataclass(slots=True)
class AffectedEntry:
    ecosystem: str
    name: str  # normalized
    ranges: list[dict[str, Any]] = field(default_factory=list)  # [{"type", "events": [{kind: version}]}]
    versions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"ecosystem": self.ecosystem, "name": self.name, "ranges": self.ranges, "versions": self.versions}

    @classmethod
    def from_dict(cls, data: Any) -> AffectedEntry | None:
        if not isinstance(data, dict) or not data.get("ecosystem") or not data.get("name"):
            return None
        ranges = [r for r in data.get("ranges") or [] if isinstance(r, dict)]
        versions = [str(v) for v in data.get("versions") or []]
        return cls(str(data["ecosystem"]), str(data["name"]), ranges, versions)

    def fixed_versions(self) -> list[str]:
        fixed = {
            str(e["fixed"])
            for r in self.ranges
            if r.get("type") != "GIT"  # commit hashes are not versions
            for e in r.get("events", [])
            if "fixed" in e
        }
        try:
            return sort_versions(self.ecosystem, fixed)
        except InvalidVersion:
            return sorted(fixed)

    def describe(self) -> str:
        parts: list[str] = []
        for rng in self.ranges:
            if rng.get("type") == "GIT":
                continue
            try:
                intervals = osv_intervals(_scheme(self, rng), rng.get("events", []))
            except InvalidVersion:
                continue
            parts.extend(interval.describe() for interval in intervals)
        if self.versions:
            listed = ", ".join(self.versions[:5]) + (" ..." if len(self.versions) > 5 else "")
            parts.append(f"versions {listed}")
        return "; ".join(parts) or "no affected versions listed"


@dataclass(slots=True)
class Advisory:
    id: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    severity_source: str = "default"
    cvss: float | None = None
    cvss_vector: str | None = None
    references: list[dict[str, str]] = field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    withdrawn: str | None = None
    affected: list[AffectedEntry] = field(default_factory=list)

    def metadata(self, source: str) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "details": self.details,
            "aliases": self.aliases,
            "severity": self.severity.value,
            "severity_source": self.severity_source,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "references": self.references,
            "published": self.published,
            "modified": self.modified,
            "withdrawn": self.withdrawn,
            "affected": [entry.to_dict() for entry in self.affected],
            "source": source,
            "format": "osv",
        }

    @classmethod
    def from_metadata(cls, advisory_id: str, meta: dict[str, Any]) -> Advisory:
        affected = [e for e in (AffectedEntry.from_dict(raw) for raw in meta.get("affected") or []) if e]
        return cls(
            id=advisory_id,
            summary=str(meta.get("summary") or ""),
            details=str(meta.get("details") or ""),
            aliases=[str(a) for a in meta.get("aliases") or []],
            severity=Severity.parse(meta.get("severity") or "MEDIUM"),
            severity_source=str(meta.get("severity_source") or "default"),
            cvss=meta.get("cvss") if isinstance(meta.get("cvss"), int | float) else None,
            cvss_vector=meta.get("cvss_vector"),
            references=[r for r in meta.get("references") or [] if isinstance(r, dict)],
            published=meta.get("published"),
            modified=meta.get("modified"),
            withdrawn=meta.get("withdrawn"),
            affected=affected,
        )


# --------------------------------------------------------------------------- parsing


def _as_list(value: Any) -> list[Any]:
    """Untrusted documents may put an object or a string where a list is expected."""
    return value if isinstance(value, list) else []


def _scheme(entry: AffectedEntry, rng: dict[str, Any]) -> str:
    return "semver" if str(rng.get("type", "")).upper() == "SEMVER" else entry.ecosystem


def _affected(raw: Any) -> AffectedEntry | None:
    if not isinstance(raw, dict):
        return None
    package = raw.get("package") if isinstance(raw.get("package"), dict) else {}
    assert isinstance(package, dict)
    ecosystem_raw, name = package.get("ecosystem"), package.get("name")
    if (not ecosystem_raw or not name) and isinstance(package.get("purl"), str):
        parsed = parse_purl(package["purl"])
        if parsed is not None:
            ecosystem, normalized, _ = parsed
            return AffectedEntry(ecosystem, normalized, *_ranges_and_versions(raw))
    if not isinstance(ecosystem_raw, str) or not isinstance(name, str) or not name.strip():
        return None
    ecosystem = ecosystem_from_osv(ecosystem_raw)
    return AffectedEntry(ecosystem, normalize_name(ecosystem, name), *_ranges_and_versions(raw))


def _ranges_and_versions(raw: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    ranges: list[dict[str, Any]] = []
    for rng in _as_list(raw.get("ranges")):
        if not isinstance(rng, dict):
            continue
        events = [
            {kind: str(value)}
            for event in _as_list(rng.get("events"))
            if isinstance(event, dict)
            for kind, value in event.items()
            if kind in _EVENT_KINDS and isinstance(value, str | int | float)
        ]
        ranges.append({"type": str(rng.get("type", "")).upper()[:16], "events": events[:1000]})
    versions = [str(v) for v in _as_list(raw.get("versions")) if isinstance(v, str | int | float)][:MAX_VERSIONS]
    return ranges, versions


def _severity_scores(doc: dict[str, Any]) -> list[tuple[float, str]]:
    entries = list(_as_list(doc.get("severity")))
    for affected in _as_list(doc.get("affected")):
        if isinstance(affected, dict):
            entries.extend(_as_list(affected.get("severity")))
    scores: list[tuple[float, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("score") is None:
            continue
        text = str(entry["score"]).strip()
        try:
            value: float | None = float(text)
        except ValueError:
            value = cvss3_base_score(text)
        if value is not None and 0.0 <= value <= 10.0:
            scores.append((value, text))
    return scores


def _database_severity(doc: dict[str, Any]) -> str | None:
    candidates = [doc.get("database_specific")]
    for affected in _as_list(doc.get("affected")):
        if isinstance(affected, dict):
            candidates.extend([affected.get("database_specific"), affected.get("ecosystem_specific")])
    for candidate in candidates:
        if isinstance(candidate, dict) and isinstance(candidate.get("severity"), str):
            return str(candidate["severity"])
    return None


def _apply_severity(advisory: Advisory, doc: dict[str, Any]) -> None:
    scores = _severity_scores(doc)
    if scores:
        best, text = max(scores)
        advisory.cvss = best
        advisory.cvss_vector = text if text.startswith("CVSS:") else None
        advisory.severity = Severity.parse(best)
        advisory.severity_source = "cvss"
        return
    label = _database_severity(doc)
    if label:
        try:
            advisory.severity = Severity.parse(label)
            advisory.severity_source = "database_specific"
        except InvalidInputError:
            pass


def parse_osv(doc: Any) -> Advisory:
    """Validate and normalize one OSV document (untrusted input; fields are bounded)."""
    if not isinstance(doc, dict):
        raise InvalidInputError("An OSV advisory must be a JSON object.")
    advisory_id = str(doc.get("id") or "").strip()
    if not _ID_RE.match(advisory_id):
        raise InvalidInputError(f"Invalid or missing advisory id {advisory_id[:60]!r}.")
    affected = [entry for entry in (_affected(raw) for raw in _as_list(doc.get("affected"))) if entry is not None]
    references = [
        {"type": str(r.get("type", ""))[:32], "url": str(r.get("url", ""))[:500]}
        for r in _as_list(doc.get("references"))[:20]
        if isinstance(r, dict) and r.get("url")
    ]
    advisory = Advisory(
        id=advisory_id,
        summary=str(doc.get("summary") or "")[:500],
        details=str(doc.get("details") or "")[:4000],
        aliases=[str(a)[:128] for a in _as_list(doc.get("aliases")) if isinstance(a, str)][:50],
        references=references,
        published=str(doc["published"])[:40] if doc.get("published") else None,
        modified=str(doc["modified"])[:40] if doc.get("modified") else None,
        withdrawn=str(doc["withdrawn"])[:40] if doc.get("withdrawn") else None,
        affected=affected,
    )
    _apply_severity(advisory, doc)
    return advisory


def _documents(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("vulns"), list):
        return list(data["vulns"])
    return [data]


def load_osv_documents(path: Path, max_bytes: int) -> tuple[list[tuple[str, Any]], list[dict[str, str]]]:
    """``([(source, document)], [rejected files])``. Directories: ``*.json`` directly inside, no symlinks."""
    target = path.expanduser()
    if target.is_symlink():
        raise InvalidInputError(f"{path} is a symbolic link; pass the real path.")
    if target.is_dir():
        files = sorted(p for p in target.iterdir() if p.suffix.lower() == ".json" and not p.is_symlink())[:MAX_FILES]
    elif target.is_file():
        files = [target]
    else:
        raise NotFoundError(f"{path} does not exist.")
    documents: list[tuple[str, Any]] = []
    rejected: list[dict[str, str]] = []
    for file in files:
        try:
            data = json.loads(read_text(file, max_bytes))
        except (RafError, ValueError, RecursionError) as exc:
            if not target.is_dir():
                raise InvalidInputError(f"{file.name} is not a readable JSON document.") from exc
            rejected.append({"source": file.name, "reason": getattr(exc, "message", "invalid JSON")[:200]})
            continue
        items = _documents(data)
        for index, item in enumerate(items):
            documents.append((f"{file.name}#{index}" if len(items) > 1 else file.name, item))
    return documents, rejected


# --------------------------------------------------------------------------- matching


def version_affected(entry: AffectedEntry, version: str) -> str | None:
    """Why ``version`` is affected by this entry (OSV evaluation), or None."""
    for listed in entry.versions:
        try:
            if listed == version or compare_versions(entry.ecosystem, listed, version) == 0:
                return f"{version} is listed as affected"
        except InvalidVersion:
            continue
    for rng in entry.ranges:
        if rng.get("type") == "GIT":
            continue
        scheme = _scheme(entry, rng)
        try:
            for interval in osv_intervals(scheme, rng.get("events", [])):
                if contains(scheme, interval, version):
                    return f"{version} is in the affected range {interval.describe()}"
        except InvalidVersion:
            continue
    return None


def constraint_affected(entry: AffectedEntry, constraint: str) -> str | None:
    """Why a declared constraint permits an affected version, or None (also when it cannot be interpreted)."""
    allowed = constraint_intervals(entry.ecosystem, constraint)
    if allowed is None:
        return None
    shown = constraint or "*"
    for listed in entry.versions:
        try:
            if in_any(entry.ecosystem, allowed, listed):
                return f"'{shown}' permits affected version {listed}"
        except InvalidVersion:
            continue
    for rng in entry.ranges:
        if rng.get("type") == "GIT":
            continue
        scheme = _scheme(entry, rng)
        try:
            for affected in osv_intervals(scheme, rng.get("events", [])):
                if any(not is_empty(scheme, intersect(scheme, a, affected)) for a in allowed):
                    return f"'{shown}' overlaps the affected range {affected.describe()}"
        except InvalidVersion:
            continue
    return None
