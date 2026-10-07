"""R$F native record normalizer.

Native records (JSON/JSONL lines, or dicts produced by other parsers) are:

* events: ``{"timestamp", "event_type", "actor", "action", "target", "outcome",
  "host", "severity", "confidence", "message", "attributes", "objects",
  "relationships", "incident", "synthetic", "id"}``
* objects: ``{"kind": "object", "type", "name", "key", "metadata", "tags", ...}``
* relationships: ``{"kind": "relationship", "source", "type", "target", ...}``
* incidents: ``{"kind": "incident", "name", "title", "severity", "status", ...}``
* findings: ``{"kind": "finding", "title", "severity", "confidence", "affected", ...}``

Well-known event attributes become involved objects with roles (``src_ip``,
``dst_ip``, ``domain``, ``answers``, ``url``, ``file``, ``image``, ``parent``,
``role``, ``group``, ``resource``, ``policy``, ``service``).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, ClassVar

from raf.core.errors import InvalidInputError
from raf.core.events.taxonomy import category_of, default_action, spec_for
from raf.core.ids import digest, event_id, finding_id, object_id
from raf.core.ingestion.base import (
    IncidentDraft,
    NormalizedRecord,
    Normalizer,
    ParseContext,
    RawRecord,
    RecordRejected,
)
from raf.core.ingestion.refs import ResolveName, object_record_to_draft, ref_to_draft
from raf.core.objects.models import EventDraft, EvidenceRef, Finding, ObjectDraft, RelationshipDraft
from raf.core.objects.types import (
    FindingStatus,
    ObjectType,
    Severity,
    parse_confidence,
    validate_relationship_type,
)
from raf.core.timeutil import format_ts, parse_timestamp_ex, utcnow

_EVENT_TYPE_RE = re.compile(r"^[a-z0-9_]+(?:\.[a-z0-9_-]+){0,5}$")
_EVENT_ID_RE = re.compile(r"^event:[0-9a-f]{24}$")
_TS_KEYS = ("timestamp", "@timestamp", "time", "ts", "event_time")
_OUTCOMES = {
    "success": "success",
    "succeeded": "success",
    "ok": "success",
    "allowed": "success",
    "allow": "success",
    "true": "success",
    "failure": "failure",
    "failed": "failure",
    "fail": "failure",
    "denied": "failure",
    "deny": "failure",
    "blocked": "failure",
    "false": "failure",
    "error": "failure",
    "unknown": "unknown",
}


def parse_event_time(data: dict[str, Any], ctx: ParseContext) -> datetime:
    for key in _TS_KEYS:
        if data.get(key) not in (None, ""):
            parsed = parse_timestamp_ex(data[key], default_tz=ctx.default_tz, reference=ctx.reference_time)
            for warning in parsed.warnings:
                if warning not in ctx.warnings and len(ctx.warnings) < 50:
                    ctx.warnings.append(warning)
            return parsed.value
    raise RecordRejected("Required timestamp could not be determined.", hint="Provide 'timestamp' (ISO-8601 or epoch).")


def normalize_outcome(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return _OUTCOMES.get(str(value).strip().lower(), str(value).strip().lower()[:32])


class NativeNormalizer(Normalizer):
    name: ClassVar[str] = "raf-native"
    version: ClassVar[str] = "1.0"

    def __init__(self, resolve: ResolveName | None = None) -> None:
        self.resolve = resolve
        self._processes: dict[tuple[str, str], str] = {}

    @classmethod
    def score(cls, record: dict[str, Any]) -> float:
        if record.get("kind") in {"object", "relationship", "event", "incident", "finding"}:
            return 1.0
        if "event_type" in record:
            return 0.95
        return 0.0

    # ------------------------------------------------------------------ dispatch
    def normalize(self, record: RawRecord, ctx: ParseContext) -> NormalizedRecord:
        data = record.data
        if not isinstance(data, dict):
            raise RecordRejected(f"Expected a JSON object, got {type(data).__name__}.")
        kind = str(data.get("kind") or "").lower()
        if not kind:
            if "event_type" in data:
                kind = "event"
            elif "relationship_type" in data or ({"source", "target"} <= data.keys() and "type" in data):
                kind = "relationship"
            elif "type" in data and "name" in data:
                kind = "object"
        try:
            if kind == "event":
                return self._event(record, data, ctx)
            if kind == "object":
                return NormalizedRecord(objects=[object_record_to_draft(data, ctx)])
            if kind == "relationship":
                return self._relationship(data, ctx)
            if kind == "incident":
                return self._incident(data, ctx)
            if kind == "finding":
                return self._finding(data, ctx, record)
        except RecordRejected:
            raise
        except InvalidInputError as exc:
            raise RecordRejected(exc.message, reason=exc.reason, hint=exc.hint) from exc
        raise RecordRejected(
            "Unrecognized record: expected an event (event_type) or kind object/relationship/incident/finding."
        )

    # ------------------------------------------------------------------ events
    def _ref(self, value: Any, default: str | None, ctx: ParseContext, field: str) -> ObjectDraft | None:
        return ref_to_draft(value, default, ctx, resolve=self.resolve, field=field)

    def _event(self, record: RawRecord, data: dict[str, Any], ctx: ParseContext) -> NormalizedRecord:
        ts = parse_event_time(data, ctx)
        event_type = str(data.get("event_type") or "").strip().lower()
        if not _EVENT_TYPE_RE.match(event_type) or len(event_type) > 128:
            raise RecordRejected(
                f"Invalid event_type {event_type[:60]!r}.", hint="Use dot-separated lowercase types such as auth.login."
            )
        spec = spec_for(event_type)
        attributes = data.get("attributes") or {}
        if not isinstance(attributes, dict):
            raise RecordRejected("'attributes' must be a mapping.")
        attributes = dict(attributes)
        out = NormalizedRecord()
        drafts: dict[str, ObjectDraft] = {}

        def add(draft: ObjectDraft | None, role: str, ev: EventDraft) -> ObjectDraft | None:
            if draft is None:
                return None
            draft.observe(ts)
            existing = drafts.get(draft.id)
            if existing is None:
                drafts[draft.id] = draft
            else:
                existing.merge(draft)
                existing.observations -= 1
            ev.involve(draft.id, role)
            return drafts[draft.id]

        severity = Severity.parse(data.get("severity")) if data.get("severity") not in (None, "") else Severity.INFO
        raw_id = data.get("id")
        if raw_id:
            eid = str(raw_id) if _EVENT_ID_RE.match(str(raw_id)) else "event:" + digest("native-id", raw_id)
        else:
            eid = event_id(ctx.source.identity, record.locator)
        ev = EventDraft(
            id=eid,
            timestamp=ts,
            event_type=event_type,
            category=category_of(event_type),
            action=str(data.get("action") or default_action(event_type))[:128],
            source=str(data.get("source") or ctx.source.name)[:512],
            parser="",
            outcome=normalize_outcome(data.get("outcome")),
            record=record.locator[:128],
            raw_reference=self._raw_ref(record, ctx),
            raw=ctx.excerpt(record.raw),
            severity=severity,
            confidence=parse_confidence(data.get("confidence"), 0.8),
            attributes=attributes,
            message=str(data["message"])[:4000] if data.get("message") else None,
            synthetic=bool(data.get("synthetic", ctx.source.synthetic)),
        )
        host = add(self._ref(data.get("host"), ObjectType.HOST, ctx, "host"), "host", ev)
        host_key = host.id.split(":", 1)[1] if host is not None else (ctx.source.default_host or "unknown")

        actor_default = spec.actor if spec else ObjectType.USER
        actor_value = data.get("actor")
        if actor_value is None and event_type.startswith("process.") and attributes.get("user"):
            actor_value = attributes.get("user")
        if (
            actor_default == ObjectType.PROCESS
            and isinstance(actor_value, str)
            and not _is_typed(actor_value)
            and not _looks_like_process(actor_value, attributes)
        ):
            # "file.read actor=alice": a bare account name is the user, not a process called "alice".
            actor_default = ObjectType.USER
        actor = add(self._ref(actor_value, actor_default, ctx, "actor"), "actor", ev)

        target_default = spec.target if spec else ObjectType.HOST
        target_value = data.get("target")
        target: ObjectDraft | None
        if event_type.startswith("process.") and (
            target_value is None or (isinstance(target_value, dict) and target_value.get("type") is None)
        ):
            target = self._process_draft(
                target_value, attributes, host_key, ts, ctx, start=event_type == "process.start"
            )
        elif event_type.startswith("file.") and target_value is not None and not _is_typed(target_value):
            target = self._file_draft(str(target_value), host_key, ctx)
        else:
            if (
                event_type.startswith(("iam.role.", "iam.group.", "iam.permission.", "iam.user."))
                and target_value is not None
                and not _is_typed(target_value)
            ):
                target = self._ref(target_value, ObjectType.USER, ctx, "target")
            else:
                target = self._ref(target_value, target_default, ctx, "target")
        if target is None and spec is not None and spec.target == ObjectType.HOST and host is not None:
            target = host
        add(target, "target", ev)
        if actor is not None:
            ev.actor = actor.id
        if target is not None:
            ev.target = target.id

        self._attribute_objects(attributes, event_type, host_key, ts, ctx, ev, add, out)

        for extra in data.get("objects") or []:
            if not isinstance(extra, dict):
                raise RecordRejected("'objects' entries must be mappings.")
            role = str(extra.get("role") or "related")[:32]
            add(self._ref(extra, None, ctx, "object"), role, ev)

        for rel in data.get("relationships") or []:
            out.relationships.append(self._explicit_relationship(rel, ctx, ts, drafts))

        incidents = data.get("incident") or data.get("incidents") or ctx.source.incident
        if incidents:
            names = incidents if isinstance(incidents, list) else [incidents]
            for name in names:
                incident_id = object_id(ObjectType.INCIDENT, str(name))
                ev.incidents.append(incident_id)
                out.incidents.append(IncidentDraft(name=str(name)))
        if data.get("tags"):
            ev.attributes.setdefault("tags", data["tags"])
        out.objects.extend(drafts.values())
        out.events.append(ev)
        return out

    def _raw_ref(self, record: RawRecord, ctx: ParseContext) -> str:
        base = f"evidence:{ctx.source.evidence_id}" if ctx.source.evidence_id else ctx.source.name
        return f"{base}#{record.locator}"[:512]

    def _process_draft(
        self, value: Any, attributes: dict[str, Any], host_key: str, ts: datetime, ctx: ParseContext, *, start: bool
    ) -> ObjectDraft:
        info: dict[str, Any] = dict(value) if isinstance(value, dict) else {}
        if isinstance(value, str | int) and not isinstance(value, bool):
            info.setdefault("name", str(value))
        pid = str(info.get("pid") or attributes.get("pid") or "").strip()
        image = str(info.get("image") or attributes.get("image") or attributes.get("process") or "").strip()
        name = str(info.get("name") or "").strip()
        basename = re.split(r"[\\/]", image)[-1] if image else ""
        if not name:
            name = f"{basename or 'process'}" + (f" [{pid}]" if pid else "")
        if pid:
            known = self._processes.get((host_key, pid))
            if start or known is None:
                key = f"{host_key}|{pid}|{format_ts(ts)}" if start else f"{host_key}|{pid}|{basename or '?'}"
            else:
                key = known.split(":", 1)[1]
        else:
            key = f"{host_key}|{name}"
        meta = {
            k: v
            for k, v in {
                "pid": pid or None,
                "image": image or None,
                "host": host_key,
                "command_line": attributes.get("command_line"),
            }.items()
            if v
        }
        draft = ObjectDraft.make(
            ObjectType.PROCESS, name, key=key, metadata=meta, source=ctx.source.name, synthetic=ctx.source.synthetic
        )
        if pid and start:
            self._processes[(host_key, pid)] = draft.id
        return draft

    def _parent_draft(self, attributes: dict[str, Any], host_key: str, ctx: ParseContext) -> ObjectDraft | None:
        ppid = str(attributes.get("parent_pid") or "").strip()
        pimage = str(attributes.get("parent_image") or attributes.get("parent") or "").strip()
        if not ppid and not pimage:
            return None
        basename = re.split(r"[\\/]", pimage)[-1] if pimage else "process"
        known = self._processes.get((host_key, ppid)) if ppid else None
        if known:
            key = known.split(":", 1)[1]
        else:
            key = f"{host_key}|{ppid or '?'}|{basename}"
        name = f"{basename}" + (f" [{ppid}]" if ppid else "")
        meta = {k: v for k, v in {"pid": ppid or None, "image": pimage or None, "host": host_key}.items() if v}
        return ObjectDraft.make(
            ObjectType.PROCESS,
            name,
            key=key,
            metadata=meta,
            source=ctx.source.name,
            synthetic=ctx.source.synthetic,
            confidence=0.7,
        )

    def _file_draft(self, path: str, host_key: str, ctx: ParseContext) -> ObjectDraft:
        clean = path.strip()
        if not clean:
            raise RecordRejected("Empty file path.")
        basename = re.split(r"[\\/]", clean.rstrip("\\/"))[-1] or clean
        return ObjectDraft.make(
            ObjectType.FILE,
            basename,
            key=f"{host_key}|{clean}",
            metadata={"path": clean, "host": host_key},
            source=ctx.source.name,
            synthetic=ctx.source.synthetic,
        )

    def _attribute_objects(
        self,
        attributes: dict[str, Any],
        event_type: str,
        host_key: str,
        ts: datetime,
        ctx: ParseContext,
        ev: EventDraft,
        add: Any,
        out: NormalizedRecord,
    ) -> None:
        for key, role in (("src_ip", "src_ip"), ("dst_ip", "dst_ip"), ("ip", "ip")):
            if attributes.get(key):
                add(self._ref(str(attributes[key]), ObjectType.IP, ctx, key), role, ev)
        for key in ("domain", "query", "sni"):
            if attributes.get(key):
                add(self._ref(str(attributes[key]), ObjectType.DOMAIN, ctx, key), "domain", ev)
                break
        answers = attributes.get("answers") or attributes.get("resolved_ips")
        if answers:
            for answer in answers if isinstance(answers, list) else [answers]:
                try:
                    add(self._ref(str(answer), ObjectType.IP, ctx, "answer"), "answer", ev)
                except RecordRejected:
                    continue  # CNAME answers etc. are kept as attributes only
        if attributes.get("url") and not event_type.startswith("http."):
            add(self._ref(str(attributes["url"]), ObjectType.URL, ctx, "url"), "url", ev)
        for key in ("file", "file_path", "path"):
            if attributes.get(key) and not event_type.startswith("file."):
                add(self._file_draft(str(attributes[key]), host_key, ctx), "file", ev)
                break
        if event_type == "process.start":
            if attributes.get("image"):
                add(self._file_draft(str(attributes["image"]), host_key, ctx), "image", ev)
            add(self._parent_draft(attributes, host_key, ctx), "parent", ev)
        if event_type.startswith("file.") and attributes.get("process"):
            add(
                self._process_draft({"name": attributes["process"]}, attributes, host_key, ts, ctx, start=False),
                "process",
                ev,
            )
        if attributes.get("role"):
            add(self._ref(attributes["role"], ObjectType.ROLE, ctx, "role"), "role", ev)
        if attributes.get("group"):
            add(self._ref(attributes["group"], ObjectType.GROUP, ctx, "group"), "group", ev)
        if attributes.get("resource"):
            rtype = str(attributes.get("resource_type") or ObjectType.SERVICE)
            add(self._ref(attributes["resource"], rtype, ctx, "resource"), "resource", ev)
        if attributes.get("policy"):
            add(self._ref(attributes["policy"], ObjectType.POLICY, ctx, "policy"), "policy", ev)
        if attributes.get("service") and not event_type.startswith("service."):
            add(self._ref(attributes["service"], ObjectType.SERVICE, ctx, "service"), "service", ev)

    def _explicit_relationship(
        self, rel: Any, ctx: ParseContext, ts: datetime | None, drafts: dict[str, ObjectDraft] | None = None
    ) -> RelationshipDraft:
        if not isinstance(rel, dict):
            raise RecordRejected("Relationship entries must be mappings.")
        rel_type = rel.get("type") or rel.get("relationship_type")
        if not rel_type:
            raise RecordRejected("Relationship has no 'type'.")
        source = self._ref(rel.get("source") or rel.get("source_object"), rel.get("source_type"), ctx, "source")
        target = self._ref(rel.get("target") or rel.get("target_object"), rel.get("target_type"), ctx, "target")
        if source is None or target is None:
            raise RecordRejected("Relationship needs both 'source' and 'target'.")
        if drafts is not None:
            for draft in (source, target):
                drafts.setdefault(draft.id, draft)
        from raf.core.timeutil import parse_timestamp

        def t(key: str) -> datetime | None:
            return parse_timestamp(rel[key]) if rel.get(key) else None

        rel_draft = RelationshipDraft.make(
            source.id,
            validate_relationship_type(str(rel_type)),
            target.id,
            first_seen=t("first_seen") or ts,
            last_seen=t("last_seen") or ts,
            valid_from=t("valid_from"),
            valid_to=t("valid_to"),
            confidence=parse_confidence(rel.get("confidence"), 0.8),
            source=str(rel.get("data_source") or ctx.source.name),
            metadata=dict(rel.get("metadata") or {}),
            synthetic=bool(rel.get("synthetic", ctx.source.synthetic)),
        )
        return rel_draft

    def _relationship(self, data: dict[str, Any], ctx: ParseContext) -> NormalizedRecord:
        drafts: dict[str, ObjectDraft] = {}
        rel = self._explicit_relationship(data, ctx, None, drafts)
        for draft in drafts.values():
            draft.observations = 0  # referenced, not observed
            draft.confidence = min(draft.confidence, 0.5)
        return NormalizedRecord(objects=list(drafts.values()), relationships=[rel])

    def _incident(self, data: dict[str, Any], ctx: ParseContext) -> NormalizedRecord:
        name = str(data.get("name") or data.get("id") or "").strip()
        if not name:
            raise RecordRejected("Incident record has no 'name'.")
        from raf.core.timeutil import parse_timestamp

        incident = IncidentDraft(
            name=name,
            title=data.get("title"),
            severity=data.get("severity"),
            status=data.get("status"),
            description=data.get("description"),
            start=parse_timestamp(data["start"]) if data.get("start") else None,
            end=parse_timestamp(data["end"]) if data.get("end") else None,
            tags=[str(t) for t in data.get("tags") or []],
            event_ids=[str(e) for e in data.get("events") or []],
        )
        return NormalizedRecord(incidents=[incident])

    def _finding(self, data: dict[str, Any], ctx: ParseContext, record: RawRecord) -> NormalizedRecord:
        title = str(data.get("title") or "").strip()
        if not title:
            raise RecordRejected("Finding record has no 'title'.")
        affected: list[str] = []
        objects: list[ObjectDraft] = []
        for ref in data.get("affected") or data.get("affected_objects") or []:
            draft = self._ref(ref, None, ctx, "affected object")
            if draft is not None:
                objects.append(draft)
                affected.append(draft.id)
        now = utcnow()
        rule = str(data.get("rule_id") or "imported")
        product = str(data.get("product") or "import")
        finding = Finding(
            id=str(data.get("id") or finding_id(product, rule, title + "|" + ",".join(sorted(affected)))),
            title=title[:512],
            description=str(data.get("description") or title),
            product=product,
            rule_id=rule,
            severity=Severity.parse(data.get("severity") or "MEDIUM"),
            confidence=parse_confidence(data.get("confidence"), 0.5),
            status=FindingStatus.OPEN,
            affected_objects=affected,
            recommendation=str(data.get("recommendation") or ""),
            evidence=[EvidenceRef(kind="external", id=f"{ctx.source.name}#{record.locator}", note="imported finding")],
            created_at=now,
            updated_at=now,
            tags=[str(t) for t in data.get("tags") or []],
            metadata={"imported_from": ctx.source.name},
        )
        return NormalizedRecord(objects=objects, findings=[finding])


_PROCESS_SUFFIXES = (".exe", ".com", ".bat", ".cmd", ".ps1", ".sh", ".py", ".bin", ".dll")


def _looks_like_process(value: str, attributes: dict[str, Any]) -> bool:
    """A bare actor that names an executable (path, extension) or comes with process details."""
    text = value.strip().lower()
    return (
        "/" in text
        or "\\" in text
        or text.endswith(_PROCESS_SUFFIXES)
        or attributes.get("pid") is not None
        or bool(attributes.get("image"))
    )


def _is_typed(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("type") or value.get("id"))
    if isinstance(value, str):
        from raf.core.ids import try_split_id
        from raf.core.ingestion.refs import is_ip

        return ":" in value and not is_ip(value) and try_split_id(value) is not None
    return False
