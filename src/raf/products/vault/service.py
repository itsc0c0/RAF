"""R$F Vault: defensive secret hygiene for files and repositories.

A scan walks a file or directory (see :mod:`raf.products.vault.scanner` for the
safety rules), runs the detectors and, unless ``store`` is off, records:

* File objects (``file:<host>|<path>``) and Secret objects
  (``secret:<host>|<path>|<line>|<rule>``) carrying only the rule, the redacted
  value and the keyed fingerprint - never the value;
* ``FILE CONTAINS_SECRET SECRET`` relationships (and ``HOST CONTAINS FILE`` when
  ``--host`` names a host);
* one Finding per (file, rule, fingerprint), with explanation factors;
* provenance for everything written.

Re-scanning a target resolves findings whose secret disappeared, ends the
CONTAINS_SECRET relationship of removed secrets (``valid_to``) and moves
allowlisted findings to SUPPRESSED. Scanning is CLI-only by design: the API
never reads paths on the server.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError, RafError
from raf.core.ids import finding_id, object_id, relationship_id
from raf.core.jobs.manager import JobContext, JobStatus
from raf.core.objects.models import (
    EvidenceRef,
    Finding,
    ObjectDraft,
    ProvenanceDraft,
    RafModel,
    RelationshipDraft,
    SecurityObject,
)
from raf.core.objects.types import FindingStatus, Severity, confidence_level
from raf.core.security.redaction import redact_secret
from raf.core.timeutil import format_ts, utcnow
from raf.products.vault.allowlist import AllowEntry, append_entry, load_allowlist, normalize_fingerprint
from raf.products.vault.detectors import RULE_IDS, RULE_INDEX, RULES, Candidate, Rule
from raf.products.vault.keys import fingerprint, load_or_create_key
from raf.products.vault.scanner import (
    MAX_FILES,
    WalkReport,
    classify,
    iter_files,
    read_text_file,
    relative,
    scan_text,
)

log = logging.getLogger("raf.products.vault")

PRODUCT = "vault"
PARSER = "vault/1.0"
ALLOWLIST_FILE = "vault-allowlist.yaml"
DEFAULT_HOST = "local"
_TEST_PENALTY = 15
_PAGE = 500


class SecretResult(RafModel):
    rule: str
    title: str
    severity: Severity
    confidence: float
    confidence_level: str
    path: str  # relative to the scan root
    line: int
    column: int
    redacted: str
    fingerprint: str
    label: str | None = None
    explanation: list[dict[str, Any]] = Field(default_factory=list)
    suppressed: bool = False
    suppressed_by: str | None = None
    finding_id: str | None = None
    secret_id: str | None = None
    file_id: str | None = None


class SkippedFile(RafModel):
    path: str
    reason: str


class ScanResult(RafModel):
    root: str
    host: str
    stored: bool
    job_id: str | None = None
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    skipped: list[SkippedFile] = Field(default_factory=list)
    results: list[SecretResult] = Field(default_factory=list)
    suppressed_count: int = 0
    suppressed: list[SecretResult] = Field(default_factory=list)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_rule: dict[str, int] = Field(default_factory=dict)
    files_with_secrets: int = 0
    distinct_secrets: int = 0
    findings: dict[str, int] = Field(default_factory=dict)
    allowlists: list[str] = Field(default_factory=list)
    truncated: bool = False

    def summary(self) -> dict[str, Any]:
        """Counts only: stored with the job record."""
        return {
            "root": self.root,
            "host": self.host,
            "stored": self.stored,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "secrets": len(self.results),
            "suppressed": self.suppressed_count,
            "by_severity": self.by_severity,
            "findings": self.findings,
            "truncated": self.truncated,
        }


@dataclass(slots=True)
class _Hit:
    """A detection with everything needed for output and storage (no secret value)."""

    result: SecretResult
    abs_path: str
    end_line: int


@dataclass(slots=True)
class _Scope:
    root: Path
    host: str
    is_file: bool

    def contains(self, path: object) -> bool:
        if not isinstance(path, str) or not path:
            return False
        return path == str(self.root) if self.is_file else Path(path).is_relative_to(self.root)


@dataclass(slots=True)
class _Plan:
    objects: list[ObjectDraft] = field(default_factory=list)
    relationships: list[RelationshipDraft] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    provenance: list[ProvenanceDraft] = field(default_factory=list)
    stale_objects: list[ObjectDraft] = field(default_factory=list)
    stale_relationships: list[str] = field(default_factory=list)


def normalize_host(value: str) -> str:
    """Host names are case-insensitive; keys use the lowercase form (``file:dev-01|/opt/app/.env``)."""
    host = value.strip().lower()
    if not host or len(host) > 253 or "|" in host or any(ch.isspace() or not ch.isprintable() for ch in host):
        raise InvalidInputError(
            f"Invalid host name {value[:80]!r}.", hint="Use a host name without spaces or '|', e.g. --host DEV-01."
        )
    return host


def parse_status(value: str | None) -> list[str] | None:
    if value is None or value.strip().lower() in ("", "all", "any"):
        return None
    try:
        return [FindingStatus(value.strip().upper()).value]
    except ValueError as exc:
        raise InvalidInputError(
            f"Unknown finding status '{value[:40]}'.",
            hint="Use OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE, SUPPRESSED or all.",
        ) from exc


def _signed(label: str, points: int) -> dict[str, Any]:
    return {"label": label, "sign": "+" if points >= 0 else "-", "points": abs(points)}


def assess(rule: Rule, candidate: Candidate, test_like: bool) -> tuple[float, list[dict[str, Any]]]:
    """Confidence = sum of explained factors (percentage points), clamped to [0.05, 0.99]."""
    base = round(rule.confidence * 100)
    factors = [_signed(f"{rule.precision}-precision pattern: {rule.title}", base)]
    factors.extend(_signed(f.label, f.points) for f in candidate.factors)
    if test_like:
        factors.append(_signed("path looks like tests, fixtures, examples or docs", -_TEST_PENALTY))
    total = sum(f["points"] if f["sign"] == "+" else -f["points"] for f in factors)
    return round(min(0.99, max(0.05, total / 100)), 2), factors


def _finding_subject(host: str, abs_path: str, rule: str, fp: str) -> str:
    return f"{host}|{abs_path}|{rule}|{fp}"


class VaultService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.store = ctx.store

    # ------------------------------------------------------------------ configuration
    def rules(self) -> list[dict[str, object]]:
        return [rule.to_dict() for rule in RULES]

    def allowlist_path(self) -> Path:
        return self.ctx.workspace.path / ALLOWLIST_FILE

    def allowlist_entries(self, extra: Path | None = None) -> list[AllowEntry]:
        entries: list[AllowEntry] = []
        workspace_list = self.allowlist_path()
        if workspace_list.exists():
            entries.extend(load_allowlist(workspace_list))
        if extra is not None:
            entries.extend(load_allowlist(extra.expanduser()))
        return entries

    def allowlist_add(
        self, fingerprint_value: str | None, *, reason: str, rule: str | None = None, path_glob: str | None = None
    ) -> AllowEntry:
        if not reason.strip():
            raise InvalidInputError("A reason is required.", hint='Add --reason "why this value is acceptable".')
        entry = {
            "fingerprint": normalize_fingerprint(fingerprint_value) if fingerprint_value else None,
            "rule": rule,
            "path": path_glob,
            "reason": reason.strip(),
        }
        added = append_entry(self.allowlist_path(), entry, actor=self.ctx.audit.actor)
        self.ctx.audit.record(
            "vault.allowlist.add",
            affected=[str(self.allowlist_path())],
            details={k: v for k, v in entry.items() if v},
        )
        return added

    # ------------------------------------------------------------------ scanning
    def scan(
        self,
        path: Path,
        *,
        allowlist: Path | None = None,
        host: str = DEFAULT_HOST,
        store: bool = True,
        show_suppressed: bool = False,
    ) -> ScanResult:
        root = self._validate_root(path)
        host_name = normalize_host(host)
        entries = self.allowlist_entries(allowlist)
        box: dict[str, Any] = {}

        def work(job: JobContext) -> dict[str, Any]:
            try:
                result = self._scan(root, host_name, entries, store, show_suppressed, job)
            except Exception as exc:
                box["error"] = exc
                raise
            box["result"] = result
            return result.summary()

        params = {"path": str(root), "host": host_name, "store": store, "allowlist": str(allowlist or "")}
        job = self.ctx.jobs.run_inline("vault.scan", f"Vault scan {root.name}", params, work)
        if "error" in box:
            raise box["error"]
        if job.status != JobStatus.COMPLETED or "result" not in box:
            raise RafError(f"Vault scan did not complete ({job.id}: {job.status.value.lower()}).")
        result: ScanResult = box["result"]
        result.job_id = job.id
        result.allowlists = sorted({e.source for e in entries})
        self.ctx.audit.record(
            "vault.scan",
            affected=[str(root)],
            details={"job": job.id, **result.summary()},
        )
        return result

    def _validate_root(self, path: Path) -> Path:
        candidate = path.expanduser()
        if candidate.is_symlink():
            raise InvalidInputError(
                f"{path} is a symbolic link; Vault does not follow symlinks.",
                hint="Pass the real path of the file or directory to scan.",
            )
        if not candidate.exists():
            raise NotFoundError(f"{path} does not exist.")
        if not (candidate.is_dir() or candidate.is_file()):
            raise InvalidInputError(f"{path} is neither a regular file nor a directory.")
        return candidate.resolve()

    def _scan(
        self,
        root: Path,
        host: str,
        entries: list[AllowEntry],
        store: bool,
        show_suppressed: bool,
        job: JobContext,
    ) -> ScanResult:
        key = load_or_create_key(self.ctx.workspace.secrets_dir)
        report = WalkReport()
        hits = list(self._detect(root, host, key, report, job))
        for hit in hits:
            self._apply_allowlist(hit, entries)
        visible = [h for h in hits if not h.result.suppressed]
        suppressed = [h for h in hits if h.result.suppressed]
        result = ScanResult(
            root=str(root),
            host=host,
            stored=store,
            files_scanned=report.files_scanned,
            files_skipped=report.skipped_count,
            bytes_scanned=report.bytes_scanned,
            skipped=[SkippedFile(path=s.path, reason=s.reason) for s in report.skipped],
            results=[h.result for h in visible],
            suppressed_count=len(suppressed),
            suppressed=[h.result for h in suppressed] if show_suppressed else [],
            by_severity=dict(Counter(h.result.severity.value for h in visible)),
            by_rule=dict(Counter(h.result.rule for h in visible)),
            files_with_secrets=len({h.abs_path for h in visible}),
            distinct_secrets=len({h.result.fingerprint for h in visible}),
            truncated=report.truncated,
        )
        if store:
            scope = _Scope(root, host, root.is_file())
            result.findings = self._persist(scope, visible, suppressed, report, job.job_id)
        return result

    def _detect(self, root: Path, host: str, key: bytes, report: WalkReport, job: JobContext) -> Iterator[_Hit]:
        max_bytes = int(self.ctx.settings.get("vault.max_file_kb")) * 1024
        threshold = float(self.ctx.settings.get("vault.entropy_threshold"))
        for path in iter_files(root, report):
            report.files_seen += 1
            if report.files_seen > MAX_FILES:
                report.truncated = True
                break
            if report.files_seen % 200 == 0:
                job.check_cancelled()
                job.progress(0.5, f"{report.files_seen} files")
            text, reason = read_text_file(path, max_bytes)
            if text is None:
                report.skip(root, path, reason or "skipped", keep=reason != "symlink (not followed)")
                continue
            report.files_scanned += 1
            report.bytes_scanned += len(text)
            rel = relative(root, path)
            test_like = classify(rel).test_like
            for detection in scan_text(text, rel, threshold):
                yield self._hit(detection.candidate, detection.inline_suppressed, rel, path, host, key, test_like)

    def _hit(
        self, candidate: Candidate, inline: bool, rel: str, path: Path, host: str, key: bytes, test_like: bool
    ) -> _Hit:
        rule = RULE_INDEX[candidate.rule]
        confidence, explanation = assess(rule, candidate, test_like)
        material = candidate.display if candidate.display is not None else candidate.value
        prefix, suffix = rule.redact_keep
        abs_path = str(path)
        fp = fingerprint(key, candidate.value)
        result = SecretResult(
            rule=rule.id,
            title=rule.title,
            severity=candidate.severity or rule.severity,
            confidence=confidence,
            confidence_level=confidence_level(confidence).value,
            path=rel,
            line=candidate.line,
            column=candidate.start + 1,
            redacted=redact_secret(material, keep_prefix=prefix, keep_suffix=suffix),
            fingerprint=fp,
            label=candidate.label,
            explanation=explanation,
            suppressed=inline,
            suppressed_by="inline marker" if inline else None,
            finding_id=finding_id(PRODUCT, rule.id, _finding_subject(host, abs_path, rule.id, fp)),
            secret_id=object_id("secret", f"{host}|{abs_path}|{candidate.line}|{rule.id}"),
            file_id=object_id("file", f"{host}|{abs_path}"),
        )
        return _Hit(result, abs_path, candidate.end_line)

    @staticmethod
    def _apply_allowlist(hit: _Hit, entries: list[AllowEntry]) -> None:
        if hit.result.suppressed:
            return
        for entry in entries:
            if entry.matches(
                rule=hit.result.rule,
                rel_path=hit.result.path,
                abs_path=hit.abs_path,
                fingerprint=hit.result.fingerprint,
            ):
                hit.result.suppressed = True
                hit.result.suppressed_by = "allowlist: " + entry.describe()
                return

    # ------------------------------------------------------------------ persistence
    def _persist(
        self, scope: _Scope, visible: list[_Hit], suppressed: list[_Hit], report: WalkReport, job_id: str
    ) -> dict[str, int]:
        now = utcnow()
        prior = self._prior_findings(scope)
        plan = self._plan(scope, visible, now)
        if not report.truncated:  # a truncated walk did not see every file: nothing can be called removed
            self._plan_stale(plan, scope, {h.result.secret_id or "" for h in visible + suppressed}, report, now)
        visible_ids = {f.id for f in plan.findings}
        suppressed_ids = {h.result.finding_id or "" for h in suppressed}
        kept = {fid for fid, f in prior.items() if report.truncated or f.metadata.get("path") in report.skipped_files}
        out_of_scope = self._open_out_of_scope(scope)
        with self.store.transaction() as conn:
            created = self.store.objects.upsert_drafts(plan.objects, conn=conn, now=now)
            self.store.relationships.upsert_drafts(plan.relationships, conn=conn, now=now)
            if plan.stale_objects:
                self.store.objects.upsert_drafts(plan.stale_objects, conn=conn, now=now)
            self.store.relationships.end(plan.stale_relationships, now, conn=conn)
            stats = self.store.findings.upsert(plan.findings, conn=conn)
            resolved = self.store.findings.resolve_absent(
                PRODUCT, RULE_IDS, visible_ids | suppressed_ids | kept | out_of_scope, conn=conn
            )
            self.store.provenance.add_many(plan.provenance, job_id=job_id, conn=conn)
        suppressed_now = self._sync_suppression(prior, visible_ids, suppressed)
        log.info(
            "vault scan stored",
            extra={"objects_created": created.created, "findings": len(plan.findings), "resolved": resolved},
        )
        return {
            "created": stats.created,
            "updated": stats.updated,
            "resolved": resolved,
            "suppressed": suppressed_now["suppressed"],
            "reopened": suppressed_now["reopened"],
            "removed_secrets": len(plan.stale_objects),
        }

    def _prior_findings(self, scope: _Scope) -> dict[str, Finding]:
        return {
            f.id: f
            for f in self._iter_findings(None)
            if f.metadata.get("host") == scope.host and scope.contains(f.metadata.get("path"))
        }

    def _open_out_of_scope(self, scope: _Scope) -> set[str]:
        return {
            f.id
            for f in self._iter_findings([FindingStatus.OPEN.value])
            if not (f.metadata.get("host") == scope.host and scope.contains(f.metadata.get("path")))
        }

    def _iter_findings(self, statuses: list[str] | None) -> Iterator[Finding]:
        offset = 0
        while True:
            page = self.store.findings.list(product=PRODUCT, statuses=statuses, limit=_PAGE, offset=offset)
            yield from page
            if len(page) < _PAGE:
                return
            offset += _PAGE

    def _plan(self, scope: _Scope, visible: list[_Hit], now: datetime) -> _Plan:
        plan = _Plan()
        source = f"vault:{scope.host}:{scope.root}"[:512]
        groups: dict[str, list[_Hit]] = {}
        for hit in visible:
            groups.setdefault(hit.result.finding_id or "", []).append(hit)
        files: dict[str, str] = {}
        for hit in visible:
            files.setdefault(hit.abs_path, hit.result.path)
            self._plan_secret(plan, scope, hit, source, now)
        for abs_path, rel in files.items():
            self._plan_file(plan, scope, abs_path, rel, source, now)
        for hits in groups.values():
            finding = self._finding(scope, hits, now)
            plan.findings.append(finding)
            plan.provenance.append(self._prov(finding.id, "finding", source, hits[0], now))
        return plan

    def _prov(self, subject: str, kind: str, source: str, hit: _Hit | None, now: datetime) -> ProvenanceDraft:
        record = f"{hit.result.path}:{hit.result.line}"[:128] if hit else None
        return ProvenanceDraft(
            subject_id=subject,
            subject_kind=kind,
            source=source,
            parser=PARSER,
            record=record,
            observed_at=now,
            note=hit.result.rule if hit else None,
        )

    def _plan_file(self, plan: _Plan, scope: _Scope, abs_path: str, rel: str, source: str, now: datetime) -> None:
        draft = ObjectDraft.make(
            "file",
            Path(abs_path).name or abs_path,
            key=f"{scope.host}|{abs_path}",
            metadata={"path": abs_path, "host": scope.host, "relative_path": rel, "scan_root": str(scope.root)},
            tags={"vault"},
            source=PRODUCT,
            confidence=0.9,
        )
        draft.observe(now)
        plan.objects.append(draft)
        plan.provenance.append(self._prov(draft.id, "object", source, None, now))
        if scope.host != DEFAULT_HOST:
            host = ObjectDraft.make("host", scope.host, source=PRODUCT, confidence=0.5, observations=0)
            plan.objects.append(host)
            rel_draft = RelationshipDraft.make(host.id, "CONTAINS", draft.id, source=PRODUCT, confidence=0.9)
            rel_draft.observe(now)
            plan.relationships.append(rel_draft)

    def _plan_secret(self, plan: _Plan, scope: _Scope, hit: _Hit, source: str, now: datetime) -> None:
        r = hit.result
        assert r.secret_id is not None and r.file_id is not None
        name = f"{r.label or r.rule} in {r.path}:{r.line}"
        secret = ObjectDraft(
            type="secret",
            name=name[:200],
            id=r.secret_id,
            source=PRODUCT,
            confidence=r.confidence,
            tags={"vault", r.rule},
            metadata={
                "rule": r.rule,
                "kind": r.title,
                "redacted": r.redacted,
                "fingerprint": r.fingerprint,
                "path": hit.abs_path,
                "relative_path": r.path,
                "line": r.line,
                "end_line": hit.end_line,
                "host": scope.host,
                "severity": r.severity.value,
                "status": "present",
            },
        )
        secret.observe(now)
        plan.objects.append(secret)
        contains = RelationshipDraft.make(
            r.file_id,
            "CONTAINS_SECRET",
            r.secret_id,
            source=PRODUCT,
            confidence=r.confidence,
            metadata={"line": r.line, "rule": r.rule},
        )
        contains.observe(now)
        plan.relationships.append(contains)
        plan.provenance.append(self._prov(secret.id, "object", source, hit, now))
        plan.provenance.append(self._prov(contains.id, "relationship", source, hit, now))

    def _finding(self, scope: _Scope, hits: list[_Hit], now: datetime) -> Finding:
        first = hits[0].result
        best = max((h.result for h in hits), key=lambda r: r.confidence)
        rule = RULE_INDEX[first.rule]
        lines = sorted({h.result.line for h in hits})
        secret_ids = [h.result.secret_id or "" for h in hits]
        where = f"{first.path}:{','.join(map(str, lines[:10]))}"
        description = (
            f"{rule.title} found at {where} ({hits[0].abs_path} on host {scope.host}). "
            f"Redacted value {first.redacted}, fingerprint {first.fingerprint}. {rule.description}"
        )
        return Finding(
            id=first.finding_id or "",
            title=f"{rule.title} in {first.path}",
            description=description,
            severity=max((h.result.severity for h in hits), key=lambda s: s.rank),
            confidence=best.confidence,
            product=PRODUCT,
            rule_id=rule.id,
            affected_objects=[*secret_ids, first.file_id or ""],
            evidence=[
                EvidenceRef(kind="object", id=h.result.secret_id or "", note=f"line {h.result.line}") for h in hits
            ]
            + [EvidenceRef(kind="object", id=first.file_id or "", note="file containing the secret")],
            recommendation=rule.recommendation,
            explanation=best.explanation,
            created_at=now,
            updated_at=now,
            tags=["vault", rule.id],
            metadata={
                "rule": rule.id,
                "fingerprint": first.fingerprint,
                "redacted": first.redacted,
                "host": scope.host,
                "path": hits[0].abs_path,
                "relative_path": first.path,
                "lines": lines,
                "scan_root": str(scope.root),
                "label": first.label,
            },
        )

    def _plan_stale(self, plan: _Plan, scope: _Scope, present: set[str], report: WalkReport, now: datetime) -> None:
        for obj in self._stored_secrets(scope):
            path = obj.metadata.get("path")
            if obj.id in present or obj.valid_to is not None or path in report.skipped_files:
                continue
            plan.stale_objects.append(
                ObjectDraft(
                    type="secret",
                    name=obj.name,
                    id=obj.id,
                    valid_to=now,
                    source=PRODUCT,
                    confidence=obj.confidence,
                    observations=0,
                    metadata={"status": "removed", "removed_at": format_ts(now)},
                )
            )
            file_id = object_id("file", f"{scope.host}|{path}")
            plan.stale_relationships.append(relationship_id(file_id, "CONTAINS_SECRET", obj.id))

    def _stored_secrets(self, scope: _Scope) -> list[SecurityObject]:
        return [
            obj
            for obj in self.store.objects.iter_all(types=["secret"])
            if "vault" in obj.tags
            and obj.metadata.get("host") == scope.host
            and scope.contains(obj.metadata.get("path"))
        ]

    def _sync_suppression(
        self, prior: dict[str, Finding], visible_ids: set[str], suppressed: list[_Hit]
    ) -> dict[str, int]:
        counts = {"suppressed": 0, "reopened": 0}
        reasons = {h.result.finding_id: h.result.suppressed_by or "suppressed" for h in suppressed}
        for fid, reason in reasons.items():
            existing = prior.get(fid or "")
            if existing is not None and existing.status == FindingStatus.OPEN:
                self.store.findings.set_status(existing.id, FindingStatus.SUPPRESSED, f"vault: {reason}"[:500])
                counts["suppressed"] += 1
        for fid in visible_ids:
            existing = prior.get(fid)
            if existing is not None and existing.status == FindingStatus.SUPPRESSED and _vault_suppressed(existing):
                self.store.findings.set_status(fid, FindingStatus.OPEN, "vault: no longer allowlisted")
                counts["reopened"] += 1
        return counts

    # ------------------------------------------------------------------ queries
    def findings(
        self,
        *,
        status: str | None = FindingStatus.OPEN.value,
        min_severity: Severity | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Finding], int]:
        statuses = parse_status(status)
        items = self.store.findings.list(
            product=PRODUCT, statuses=statuses, min_severity=min_severity, limit=limit, offset=offset
        )
        total = self.store.findings.count(product=PRODUCT, statuses=statuses, min_severity=min_severity)
        return items, total

    def secrets(
        self, *, include_removed: bool = False, limit: int = 100, offset: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        objects = [
            obj
            for obj in self.store.objects.iter_all(types=["secret"])
            if "vault" in obj.tags and (include_removed or obj.valid_to is None)
        ]
        objects.sort(key=lambda o: (str(o.metadata.get("path", "")), int(o.metadata.get("line", 0) or 0), o.id))
        return [secret_view(obj) for obj in objects[offset : offset + limit]], len(objects)


def _vault_suppressed(finding: Finding) -> bool:
    history = finding.metadata.get("status_history") or []
    if not isinstance(history, list) or not history or not isinstance(history[-1], dict):
        return False
    return str(history[-1].get("note") or "").startswith("vault:")


def secret_view(obj: SecurityObject) -> dict[str, Any]:
    """Public view of a stored secret object: redacted value and fingerprint only."""
    meta = obj.metadata
    return {
        "id": obj.id,
        "name": obj.name,
        "rule": meta.get("rule"),
        "kind": meta.get("kind"),
        "severity": meta.get("severity"),
        "redacted": meta.get("redacted"),
        "fingerprint": meta.get("fingerprint"),
        "host": meta.get("host"),
        "path": meta.get("path"),
        "relative_path": meta.get("relative_path"),
        "line": meta.get("line"),
        "confidence": obj.confidence,
        "first_seen": format_ts(obj.first_seen),
        "last_seen": format_ts(obj.last_seen),
        "removed": obj.valid_to is not None,
    }


def finding_location(finding: Finding) -> str:
    meta = finding.metadata
    lines: Iterable[Any] = meta.get("lines") or []
    shown = ",".join(str(n) for n in list(lines)[:5])
    return f"{meta.get('relative_path') or meta.get('path') or '?'}:{shown}" if shown else str(meta.get("path", "?"))
