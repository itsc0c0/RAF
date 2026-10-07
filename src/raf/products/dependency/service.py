"""R$F Dependency: dependency inventory, SBOM import/export and offline advisory matching.

``scan`` parses the manifests and lockfiles of a directory (see
:mod:`raf.products.dependency.parsers`), stores the project's dependency model
(:mod:`raf.products.dependency.persist`) and, when advisories have been
imported, checks the project right away. ``check`` matches packages and
constraints against advisories (:mod:`raf.products.dependency.check`).

Everything is offline: advisories come from local OSV files only. Scanning reads
local paths and is therefore CLI-only; the API exposes the stored results.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError, RafError
from raf.core.jobs.manager import JobContext, JobStatus
from raf.core.objects.models import Finding, ObjectDraft, ProvenanceDraft, RafModel, Relationship, SecurityObject
from raf.core.objects.types import FindingStatus, ObjectType
from raf.core.timeutil import format_ts, utcnow
from raf.products.dependency import check as matcher
from raf.products.dependency.check import CheckResult
from raf.products.dependency.model import PackageInfo, ProjectModel, build_model
from raf.products.dependency.osv import Advisory, load_osv_documents, parse_osv
from raf.products.dependency.parsers import PARSERS, REQUIREMENTS, detect_kind
from raf.products.dependency.parsers.base import ManifestResult, PkgRef, read_text
from raf.products.dependency.parsers.python import RequirementsParser
from raf.products.dependency.persist import SOURCE, dependency_id, package_id, plan_model, plan_stale, write_plan
from raf.products.dependency.sbom import detect_format, from_cyclonedx, from_spdx, to_cyclonedx

log = logging.getLogger("raf.products.dependency")

SKIP_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", ".venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "vendor"}
)
MAX_MANIFESTS = 5000
MAX_WALKED_FILES = 200_000
_TREE_NODES = 300


class ScanResult(RafModel):
    project: dict[str, Any]
    root: str
    job_id: str | None = None
    manifests: list[dict[str, Any]] = Field(default_factory=list)
    skipped: list[dict[str, str]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    by_ecosystem: dict[str, dict[str, int]] = Field(default_factory=dict)
    tree: list[dict[str, Any]] = Field(default_factory=list)
    stored: dict[str, Any] = Field(default_factory=dict)
    check: CheckResult | None = None


class AdvisoryImportResult(RafModel):
    job_id: str | None = None
    source: str
    documents: int = 0
    imported: int = 0
    created: int = 0
    updated: int = 0
    rejected: list[dict[str, str]] = Field(default_factory=list)
    advisories: list[dict[str, Any]] = Field(default_factory=list)


class DependencyService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.store = ctx.store

    @property
    def max_bytes(self) -> int:
        return int(self.ctx.settings.get("ingest.max_json_document_mb")) * 1024 * 1024

    # ------------------------------------------------------------------ jobs
    def _run_job(self, kind: str, title: str, params: dict[str, Any], fn: Callable[[JobContext], RafModel]) -> Any:
        box: dict[str, Any] = {}

        def work(job: JobContext) -> dict[str, Any]:
            try:
                box["result"] = fn(job)
            except Exception as exc:
                box["error"] = exc
                raise
            return _job_summary(box["result"].to_json_dict())

        job = self.ctx.jobs.run_inline(kind, title, params, work)
        if "error" in box:
            raise box["error"]
        if job.status != JobStatus.COMPLETED or "result" not in box:
            raise RafError(f"{title} did not complete ({job.id}: {job.status.value.lower()}).")
        result = box["result"]
        result.job_id = job.id
        return result

    # ------------------------------------------------------------------ scanning
    def scan(self, path: Path, *, name: str | None = None, check: bool = True) -> ScanResult:
        root = self._validate_path(path)
        project_name = (name or (root.name if root.is_dir() else root.parent.name) or str(root)).strip()
        if not project_name or len(project_name) > 200:
            raise InvalidInputError("Project names must be 1-200 characters.")

        def work(job: JobContext) -> ScanResult:
            return self._scan(root, project_name, check, job)

        result: ScanResult = self._run_job(
            "dependency.scan", f"Dependency scan {root.name}", {"path": str(root), "name": project_name}, work
        )
        self.ctx.audit.record(
            "dependency.scan",
            affected=[str(result.project["id"])],
            details={"job": result.job_id, "path": str(root), **result.counts},
        )
        return result

    def _validate_path(self, path: Path) -> Path:
        candidate = path.expanduser()
        if candidate.is_symlink():
            raise InvalidInputError(f"{path} is a symbolic link; pass the real path.")
        if not candidate.exists():
            raise NotFoundError(f"{path} does not exist.")
        resolved = candidate.resolve()
        if resolved.is_file() and detect_kind(resolved.name) is None:
            raise InvalidInputError(
                f"{path.name} is not a supported manifest.",
                hint="Pass a directory, or one of: requirements*.txt, " + ", ".join(PARSERS),
            )
        return resolved

    def _scan(self, root: Path, name: str, check: bool, job: JobContext) -> ScanResult:
        skipped: list[dict[str, str]] = []
        files = self._discover(root, skipped)
        base = root if root.is_dir() else root.parent
        before = len(skipped)
        results = self._parse_all(base, files, skipped, job)
        model = build_model(str(root), name, str(root), results)
        complete = len(skipped) == before and not any(s["path"] == "." for s in skipped)
        if not complete:
            model.warnings.insert(0, "incomplete scan: relationships from the previous scan were kept, not ended")
        project_id, stored = self._store_model(model, job.job_id, end_stale=complete)
        result = ScanResult(
            project={"id": project_id, "name": name, "key": str(root), "path": str(root)},
            root=str(root),
            manifests=model.manifests,
            skipped=skipped[:200],
            warnings=model.warnings[:100],
            counts=_counts(model),
            by_ecosystem=_by_ecosystem(model),
            stored=stored,
        )
        if check and self._has_advisories():
            result.check = self._check([self.store.objects.require(project_id)], job.job_id)
        result.tree = _tree(model, result.check)
        return result

    def _discover(self, root: Path, skipped: list[dict[str, str]]) -> list[tuple[Path, str]]:
        if root.is_file():
            kind = detect_kind(root.name)
            return [(root, kind)] if kind else []
        found: list[tuple[Path, str]] = []
        walked = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(dirpath)
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if d not in SKIP_DIRS and not (base / d).is_symlink() and not (base / d / "pyvenv.cfg").is_file()
            ]
            for filename in sorted(filenames):
                walked += 1
                full = base / filename
                kind = detect_kind(full.relative_to(root).as_posix())
                if kind is None:
                    continue
                if full.is_symlink():
                    skipped.append({"path": full.relative_to(root).as_posix(), "reason": "symlink (not followed)"})
                    continue
                found.append((full, kind))
            if len(found) >= MAX_MANIFESTS or walked >= MAX_WALKED_FILES:
                skipped.append({"path": ".", "reason": "manifest/file limit reached; scan a narrower directory"})
                break
        return found

    def _parse_all(
        self, base: Path, files: list[tuple[Path, str]], skipped: list[dict[str, str]], job: JobContext
    ) -> list[ManifestResult]:
        max_bytes = self.max_bytes

        def reader(path: Path) -> str:
            return read_text(path, max_bytes)

        requirements = RequirementsParser(base, reader)
        results: list[ManifestResult] = []
        for index, (path, kind) in enumerate(files):
            job.check_cancelled()
            job.progress(index / max(1, len(files)), path.name)
            rel = path.relative_to(base).as_posix()
            try:
                if kind == REQUIREMENTS:
                    if path not in requirements.seen:
                        results.extend(requirements.parse(path))
                else:
                    results.append(PARSERS[kind](rel, reader(path)))
            except RafError as exc:
                skipped.append({"path": rel, "reason": exc.message})
            except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError) as exc:
                skipped.append({"path": rel, "reason": f"malformed {kind} ({type(exc).__name__})"})
        return results

    def _store_model(
        self, model: ProjectModel, job_id: str | None, *, end_stale: bool = True
    ) -> tuple[str, dict[str, Any]]:
        now = utcnow()
        project_id, plan = plan_model(model, now)
        if end_stale:  # an incomplete scan must not turn unread manifests into "removed" dependencies
            plan_stale(self.store, project_id, plan, now)
        stored = write_plan(self.store, plan, now, job_id)
        self.ctx.refs.remember("object", project_id)
        return project_id, stored

    # ------------------------------------------------------------------ advisories
    def import_advisories(self, path: Path) -> AdvisoryImportResult:
        def work(job: JobContext) -> AdvisoryImportResult:
            return self._import_advisories(path, job)

        result: AdvisoryImportResult = self._run_job(
            "dependency.advisories", f"Import advisories {path.name}", {"path": str(path)}, work
        )
        self.ctx.audit.record(
            "dependency.advisories.import",
            affected=[str(path)],
            details={"job": result.job_id, "imported": result.imported, "rejected": len(result.rejected)},
        )
        return result

    def _import_advisories(self, path: Path, job: JobContext) -> AdvisoryImportResult:
        documents, rejected = load_osv_documents(path, self.max_bytes)
        parsed: dict[str, tuple[str, Advisory]] = {}
        for source, document in documents:
            job.check_cancelled()
            try:
                advisory = parse_osv(document)
            except InvalidInputError as exc:
                rejected.append({"source": source, "reason": exc.message[:200]})
                continue
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
                rejected.append({"source": source, "reason": f"malformed OSV document ({type(exc).__name__})"})
                continue
            parsed[advisory.id] = (source, advisory)
        now = utcnow()
        drafts, provenance = [], []
        for source, advisory in parsed.values():
            tags = {"advisory", "osv"} | ({"withdrawn"} if advisory.withdrawn else set())
            draft = ObjectDraft.make(
                "vulnerability",
                advisory.id,
                metadata=advisory.metadata(source),
                tags=tags,
                source=f"osv:{source}"[:512],
                confidence=0.95,
            )
            draft.observe(now)
            drafts.append(draft)
            provenance.append(
                ProvenanceDraft(
                    subject_id=draft.id,
                    subject_kind="object",
                    source=f"osv:{path.name}"[:512],
                    parser="dependency/osv",
                    record=source[:128],
                    observed_at=now,
                )
            )
        with self.store.transaction() as conn:
            stats = self.store.objects.upsert_drafts(drafts, conn=conn, now=now)
            self.store.provenance.add_many(provenance, job_id=job.job_id, conn=conn)
        return AdvisoryImportResult(
            source=str(path),
            documents=len(documents),
            imported=len(parsed),
            created=stats.created,
            updated=stats.updated,
            rejected=rejected[:200],
            advisories=[_advisory_view(a) for _, a in sorted(parsed.values(), key=lambda x: x[1].id)][:500],
        )

    def _advisory_objects(self) -> list[SecurityObject]:
        return [o for o in self.store.objects.iter_all(types=[ObjectType.VULNERABILITY]) if "advisory" in o.tags]

    def _has_advisories(self) -> bool:
        return any(True for _ in self._advisory_objects())

    def advisories(self) -> list[dict[str, Any]]:
        return [
            _advisory_view(Advisory.from_metadata(obj.name, obj.metadata)) | {"id_object": obj.id}
            for obj in sorted(self._advisory_objects(), key=lambda o: o.name)
        ]

    # ------------------------------------------------------------------ checking
    def check(self, project_ref: str | None = None) -> CheckResult:
        projects = [self.project(project_ref)] if project_ref else self.project_objects()

        def work(job: JobContext) -> CheckResult:
            return self._check(projects, job.job_id)

        result: CheckResult = self._run_job(
            "dependency.check", "Dependency advisory check", {"project": project_ref or "all"}, work
        )
        self.ctx.audit.record(
            "dependency.check",
            affected=[p.id for p in projects][:100],
            details={"job": result.job_id, "vulnerable": len(result.items), **result.findings},
        )
        return result

    def _check(self, projects: list[SecurityObject], job_id: str | None) -> CheckResult:
        advisories = [Advisory.from_metadata(o.name, o.metadata) for o in self._advisory_objects()]
        result = CheckResult(advisories=len(advisories))
        if not advisories:
            result.notes.append("No advisories imported yet: raf dependency advisories import <osv.json | dir>")
        index = matcher.index_advisories(advisories)
        hits: list[matcher.Hit] = []
        targets: set[str] = set()
        for project in projects:
            found, checked, packages, dependencies = matcher.project_hits(self.store, project, index)
            hits.extend(found)
            targets |= checked
            result.packages_checked += packages
            result.dependencies_checked += dependencies
            result.projects.append({"id": project.id, "name": project.name, "vulnerable": len(found)})
        result.findings = self._write_check(projects, hits, targets, job_id)
        result.items = sorted(
            (matcher.item(h) for h in hits), key=lambda i: (-i.severity.rank, i.project, i.package, i.advisory)
        )
        result.by_severity = dict(Counter(i.severity.value for i in result.items))
        return result

    def _write_check(
        self, projects: list[SecurityObject], hits: list[matcher.Hit], targets: set[str], job_id: str | None
    ) -> dict[str, int]:
        now = utcnow()
        rels = [matcher.affects_draft(h, now) for h in hits]
        findings = {f.id: f for f in (matcher.build_finding(h, now) for h in hits)}
        provenance = [matcher.provenance(h, r.id, "relationship", now) for h, r in zip(hits, rels, strict=True)]
        provenance += [matcher.provenance(h, h.finding_id, "finding", now) for h in hits]
        new_rels = {r.id for r in rels}
        current = self.store.relationships.edges(sorted(targets), direction="in", types=["AFFECTS"]) if targets else []
        stale = [r.id for r in current if r.source == SOURCE and r.id not in new_rels]
        checked = {p.id for p in projects}
        others = {f.id for f in self._open_findings() if f.metadata.get("project") not in checked}
        with self.store.transaction() as conn:
            self.store.relationships.upsert_drafts(rels, conn=conn, now=now)
            ended = self.store.relationships.end(stale, now, conn=conn)
            stats = self.store.findings.upsert(findings.values(), conn=conn)
            resolved = self.store.findings.resolve_absent(
                matcher.PRODUCT, matcher.RULES, set(findings) | others, conn=conn
            )
            self.store.provenance.add_many(provenance, job_id=job_id, conn=conn)
        return {"created": stats.created, "updated": stats.updated, "resolved": resolved, "affects_ended": ended}

    def _open_findings(self) -> list[Finding]:
        items: list[Finding] = []
        offset = 0
        while True:
            page = self.store.findings.list(
                product=matcher.PRODUCT, statuses=[FindingStatus.OPEN.value], limit=500, offset=offset
            )
            items.extend(page)
            if len(page) < 500:
                return items
            offset += 500

    # ------------------------------------------------------------------ SBOM
    def import_sbom(self, path: Path, *, name: str | None = None, check: bool = True) -> ScanResult:
        target = path.expanduser()
        if target.is_symlink():
            raise InvalidInputError(f"{path} is a symbolic link; pass the real path.")
        if not target.exists():
            raise NotFoundError(f"{path} does not exist.")
        try:
            document = json.loads(read_text(target, self.max_bytes))
        except (ValueError, RecursionError) as exc:
            raise InvalidInputError(f"{path.name} is not valid JSON.") from exc
        fmt = detect_format(document)

        def work(job: JobContext) -> ScanResult:
            build = from_cyclonedx if fmt == "cyclonedx" else from_spdx
            try:
                model = build(document, "", name)
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
                raise InvalidInputError(f"{target.name} is not a well-formed {fmt} document.") from exc
            model.key = model.name
            model.path = None
            model.manifests = [{"path": target.name, "kind": fmt, "ecosystem": "mixed", "declared": 0}]
            project_id, stored = self._store_model(model, job.job_id)
            result = ScanResult(
                project={"id": project_id, "name": model.name, "key": model.key, "path": None},
                root=str(target.resolve()),
                manifests=model.manifests,
                warnings=model.warnings[:100],
                counts=_counts(model),
                by_ecosystem=_by_ecosystem(model),
                stored=stored,
            )
            if check and self._has_advisories():
                result.check = self._check([self.store.objects.require(project_id)], job.job_id)
            result.tree = _tree(model, result.check)
            return result

        result: ScanResult = self._run_job("dependency.sbom", f"Import SBOM {target.name}", {"path": str(target)}, work)
        self.ctx.audit.record(
            "dependency.sbom.import",
            affected=[str(result.project["id"])],
            details={"job": result.job_id, "format": fmt, **result.counts},
        )
        return result

    def export_sbom(self, project_ref: str, output: Path) -> dict[str, Any]:
        project = self.project(project_ref)
        packages, edges = self._project_packages(project)
        document = to_cyclonedx(
            {"id": project.id, "name": project.name, "version": project.metadata.get("version")}, packages, edges
        )
        target = output.expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        tmp.replace(target)
        info = {
            "path": str(target),
            "format": "CycloneDX 1.5 JSON",
            "project": project.id,
            "components": len(document["components"]),
            "dependencies": sum(len(d["dependsOn"]) for d in document["dependencies"]),
        }
        self.ctx.audit.record("dependency.sbom.export", affected=[project.id], details=info)
        return info

    # ------------------------------------------------------------------ queries
    def project(self, ref: str) -> SecurityObject:
        resolved = self.ctx.resolve(ref, types=[ObjectType.PROJECT])
        assert resolved.obj is not None
        return resolved.obj

    def project_objects(self) -> list[SecurityObject]:
        return sorted(
            (o for o in self.store.objects.iter_all(types=[ObjectType.PROJECT]) if "dependency" in o.tags),
            key=lambda o: (o.name.lower(), o.id),
        )

    def _project_packages(self, project: SecurityObject) -> tuple[list[PackageInfo], set[tuple[PkgRef, PkgRef]]]:
        uses = self.store.relationships.edges([project.id], direction="out", types=["DEPENDS_ON"])
        meta = {r.target_object: r.metadata for r in uses}
        infos: dict[str, PackageInfo] = {}
        for obj in self.store.objects.get_many(meta).values():
            m = obj.metadata
            ref = (str(m.get("ecosystem")), str(m.get("name")), str(m.get("version")))
            infos[obj.id] = PackageInfo(ref, scope=meta[obj.id].get("scope"), direct=bool(meta[obj.id].get("direct")))
        edges: set[tuple[PkgRef, PkgRef]] = set()
        for rel in self.store.relationships.edges(sorted(infos), direction="out", types=["DEPENDS_ON"]):
            sources = rel.metadata.get("sources") or []
            if rel.target_object in infos and rel.source_object in infos and (not sources or project.id in sources):
                edges.add((infos[rel.source_object].ref, infos[rel.target_object].ref))
        return list(infos.values()), edges

    def projects(self) -> list[dict[str, Any]]:
        items = []
        for project in self.project_objects():
            rels = self.store.relationships.edges([project.id], direction="out", types=["DEPENDS_ON", "DECLARES"])
            uses = [r for r in rels if r.relationship_type == "DEPENDS_ON"]
            items.append(
                {
                    "id": project.id,
                    "name": project.name,
                    "path": project.metadata.get("path"),
                    "source": project.metadata.get("source"),
                    "ecosystems": project.metadata.get("ecosystems", []),
                    "dependencies": sum(1 for r in rels if r.relationship_type == "DECLARES"),
                    "packages": len(uses),
                    "direct": sum(1 for r in uses if r.metadata.get("direct")),
                    "open_findings": self.store.findings.count(
                        product=matcher.PRODUCT, statuses=[FindingStatus.OPEN.value], object_id=project.id
                    ),
                    "last_scan": project.metadata.get("last_scan"),
                }
            )
        return items

    def project_graph(self, ref: str) -> dict[str, Any]:
        project = self.project(ref)
        packages, edges = self._project_packages(project)
        ids = [package_id(p.ref) for p in packages]
        affects: dict[str, list[str]] = defaultdict(list)
        for rel in self.store.relationships.edges(ids, direction="in", types=["AFFECTS"]) if ids else []:
            affects[rel.target_object].append(rel.source_object)
        nodes = [
            {
                "id": package_id(p.ref),
                "ecosystem": p.ecosystem,
                "name": p.name,
                "version": p.version,
                "direct": p.direct,
                "scope": p.scope,
                "vulnerabilities": sorted(affects.get(package_id(p.ref), [])),
            }
            for p in sorted(packages, key=lambda p: p.ref)
        ]
        links = [{"source": project.id, "target": n["id"], "type": "DEPENDS_ON"} for n in nodes if n["direct"]]
        links += [{"source": package_id(a), "target": package_id(b), "type": "DEPENDS_ON"} for a, b in sorted(edges)]
        return {
            "project": {"id": project.id, "name": project.name, "path": project.metadata.get("path")},
            "packages": nodes,
            "edges": links,
        }

    def vulnerable(self, *, include_unused: bool = False) -> list[dict[str, Any]]:
        """Packages with active AFFECTS edges; by default only those a project still depends on."""
        rels = [r for r in self.store.relationships.iter_all(types=["AFFECTS"]) if r.valid_to is None]
        rels = [r for r in rels if r.source == SOURCE and r.target_object.startswith("package:")]
        by_package: dict[str, list[Relationship]] = defaultdict(list)
        for rel in rels:
            by_package[rel.target_object].append(rel)
        objects = self.store.objects.get_many(set(by_package) | {r.source_object for r in rels})
        users: dict[str, set[str]] = defaultdict(set)
        if by_package:
            for rel in self.store.relationships.edges(sorted(by_package), direction="in", types=["DEPENDS_ON"]):
                if rel.source_object.startswith("project:"):
                    users[rel.target_object].add(rel.source_object)
        items: list[dict[str, Any]] = []
        for pkg_id, package_rels in sorted(by_package.items()):
            if not include_unused and not users.get(pkg_id):
                continue
            package = objects.get(pkg_id)
            advisories = [_affects_view(r, objects.get(r.source_object)) for r in package_rels]
            advisories.sort(key=lambda a: (-int(a["severity_rank"]), str(a["id"])))
            details: dict[str, Any] = {"id": pkg_id}
            details.update(package.metadata if package else {})
            items.append({"package": details, "advisories": advisories, "projects": sorted(users.get(pkg_id, set()))})
        return items


# --------------------------------------------------------------------------- helpers

_BULKY = ("tree", "items", "advisories", "manifests", "skipped", "warnings")


def _job_summary(data: dict[str, Any]) -> dict[str, Any]:
    """Counts only for the job record (results can be large)."""
    summary = {k: v for k, v in data.items() if k not in (*_BULKY, "check")}
    check = data.get("check")
    if isinstance(check, dict):
        summary["check"] = {k: v for k, v in check.items() if k not in _BULKY}
    return summary


def _advisory_view(advisory: Advisory) -> dict[str, Any]:
    return {
        "id": advisory.id,
        "summary": advisory.summary,
        "severity": advisory.severity.value,
        "severity_source": advisory.severity_source,
        "cvss": advisory.cvss,
        "aliases": advisory.aliases,
        "withdrawn": advisory.withdrawn,
        "affected": [
            {"ecosystem": e.ecosystem, "name": e.name, "ranges": e.describe(), "fixed": e.fixed_versions()}
            for e in advisory.affected
        ],
    }


def _affects_view(rel: Relationship, vulnerability: SecurityObject | None) -> dict[str, Any]:
    meta = vulnerability.metadata if vulnerability else {}
    severity = str(meta.get("severity") or "MEDIUM")
    return {
        "id": vulnerability.name if vulnerability else rel.source_object,
        "object_id": rel.source_object,
        "summary": meta.get("summary"),
        "severity": severity,
        "severity_rank": {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(severity, 2),
        "cvss": meta.get("cvss"),
        "aliases": meta.get("aliases", []),
        "fixed": rel.metadata.get("fixed", []),
        "reason": rel.metadata.get("reason"),
        "since": format_ts(rel.first_seen),
    }


def _counts(model: ProjectModel) -> dict[str, int]:
    direct = sum(1 for p in model.packages.values() if p.direct)
    return {
        "manifests": len(model.manifests),
        "declared": len(model.dependencies),
        "packages": len(model.packages),
        "direct": direct,
        "transitive": len(model.packages) - direct,
        "edges": len(model.edges),
        "unresolved": sum(1 for d in model.dependencies.values() if not d.resolved),
    }


def _by_ecosystem(model: ProjectModel) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = defaultdict(lambda: {"declared": 0, "packages": 0})
    for dependency in model.dependencies.values():
        out[dependency.ecosystem]["declared"] += 1
    for package in model.packages.values():
        out[package.ecosystem]["packages"] += 1
    return dict(sorted(out.items()))


def _tree(model: ProjectModel, check: CheckResult | None) -> list[dict[str, Any]]:
    """Direct dependencies with their resolved versions and (lockfile) children, depth-limited."""
    vulnerable: dict[str, list[str]] = defaultdict(list)
    for item in check.items if check else []:
        vulnerable[item.target_id].append(item.advisory)
    children: dict[PkgRef, list[PkgRef]] = defaultdict(list)
    for parent, child in sorted(model.edges):
        children[parent].append(child)
    budget = [_TREE_NODES]

    def package_node(ref: PkgRef, depth: int, seen: frozenset[PkgRef]) -> dict[str, Any]:
        budget[0] -= 1
        info = model.packages.get(ref)
        node: dict[str, Any] = {
            "id": package_id(ref),
            "ecosystem": ref[0],
            "name": ref[1],
            "version": ref[2],
            "scope": info.scope if info else None,
            "vulnerabilities": vulnerable.get(package_id(ref), []),
            "children": [],
        }
        if depth < 2:
            for child in children.get(ref, []):
                if budget[0] <= 0 or child in seen:
                    break
                node["children"].append(package_node(child, depth + 1, seen | {child}))
        return node

    roots: list[dict[str, Any]] = []
    covered: set[PkgRef] = set()
    for (ecosystem, name), dependency in sorted(model.dependencies.items()):
        if budget[0] <= 0:
            break
        budget[0] -= 1
        resolved = sorted(dependency.resolved)
        covered.update(resolved)
        roots.append(
            {
                "id": dependency_id(model.key, ecosystem, name),
                "ecosystem": ecosystem,
                "name": name,
                "constraint": dependency.constraint,
                "scope": dependency.scope,
                "vulnerabilities": vulnerable.get(dependency_id(model.key, ecosystem, name), []),
                "resolved": [package_node(ref, 1, frozenset({ref})) for ref in resolved],
            }
        )
    for ref, info in sorted(model.packages.items()):
        if info.direct and ref not in covered and budget[0] > 0:
            roots.append(
                {
                    "id": package_id(ref),
                    "ecosystem": ref[0],
                    "name": ref[1],
                    "constraint": None,
                    "scope": info.scope,
                    "vulnerabilities": [],
                    "resolved": [package_node(ref, 1, frozenset({ref}))],
                }
            )
    return roots
