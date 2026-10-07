"""Object references inside records.

A reference can be a typed ID string (``host:ws-01``), a bare name (typed by
context, then entity-resolved against existing objects), or a mapping
(``{"type": "user", "name": "alice", "metadata": {...}}``).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any

from raf.core.errors import InvalidInputError
from raf.core.ids import try_split_id
from raf.core.ingestion.base import ParseContext, RecordRejected
from raf.core.objects.models import ObjectDraft
from raf.core.objects.types import ObjectType, parse_confidence, validate_object_type

#: When a bare name is typed by context, these existing types are also acceptable.
COMPATIBLE: dict[str, tuple[str, ...]] = {
    ObjectType.USER: (ObjectType.USER, ObjectType.IDENTITY),
    ObjectType.IDENTITY: (ObjectType.IDENTITY, ObjectType.USER),
    ObjectType.HOST: (ObjectType.HOST,),
    ObjectType.SERVICE: (ObjectType.SERVICE, ObjectType.CLOUD_RESOURCE, ObjectType.HOST),
    ObjectType.CLOUD_RESOURCE: (ObjectType.CLOUD_RESOURCE, ObjectType.SERVICE),
    ObjectType.GROUP: (ObjectType.GROUP,),
    ObjectType.ROLE: (ObjectType.ROLE,),
    ObjectType.NETWORK: (ObjectType.NETWORK,),
}

ResolveName = Callable[[str, Sequence[str]], str | None]

_MAX_NAME = 1000
_DOMAIN_USER_RE = re.compile(r"^(?P<domain>[^\\/]+)[\\/](?P<user>[^\\/]+)$")


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    return True


def normalize_user_name(name: str, strip_domain: bool) -> tuple[str, dict[str, Any]]:
    meta: dict[str, Any] = {}
    match = _DOMAIN_USER_RE.match(name)
    if match and strip_domain:
        meta["domain"] = match["domain"]
        return match["user"], meta
    if strip_domain and "@" in name and not name.startswith("@"):
        user, _, domain = name.partition("@")
        if user and "." in domain:
            meta["upn"] = name
            return user, meta
    return name, meta


def _parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    from raf.core.timeutil import parse_timestamp

    return parse_timestamp(value)


def ref_to_draft(
    value: Any,
    default_type: str | None,
    ctx: ParseContext,
    *,
    resolve: ResolveName | None = None,
    field: str = "reference",
) -> ObjectDraft | None:
    """Build an object draft from a record reference (or None when absent)."""
    if value is None or value == "" or value == "-":
        return None
    explicit_type: str | None = None
    name: str
    key: str | None = None
    metadata: dict[str, Any] = {}
    tags: set[str] = set()
    confidence = 0.8
    if isinstance(value, dict):
        raw_type = value.get("type")
        explicit_type = validate_object_type(str(raw_type)) if raw_type else None
        raw_id = value.get("id")
        if raw_id and not explicit_type:
            split = try_split_id(str(raw_id))
            if split:
                explicit_type, key = split
        name = str(value.get("name") or value.get("key") or (key or raw_id or "")).strip()
        key = str(value["key"]) if value.get("key") else key
        if isinstance(value.get("metadata"), dict):
            metadata = dict(value["metadata"])
        if isinstance(value.get("tags"), list):
            tags = {str(t) for t in value["tags"]}
        if value.get("confidence") is not None:
            confidence = parse_confidence(value["confidence"])
    elif isinstance(value, str | int | float) and not isinstance(value, bool):
        text = str(value).strip()
        split = try_split_id(text) if ":" in text else None
        if split is not None and not is_ip(text):
            explicit_type, key = split
            name = key
        else:
            name = text
    else:
        raise RecordRejected(f"Unsupported {field} value of type {type(value).__name__}.")
    if not name:
        raise RecordRejected(f"Empty {field}.")
    if len(name) > _MAX_NAME:
        raise RecordRejected(f"{field} is implausibly long ({len(name)} characters).")

    obj_type = explicit_type
    if obj_type is None:
        if default_type is None:
            raise RecordRejected(
                f"Cannot infer the object type of {field} '{name[:80]}'.",
                hint="Use a typed reference such as 'host:ws-01'.",
            )
        if default_type == ObjectType.HOST and is_ip(name):
            obj_type = ObjectType.IP
        elif default_type in (ObjectType.USER, ObjectType.IDENTITY):
            name, user_meta = normalize_user_name(name, ctx.user_strip_domain)
            metadata = {**user_meta, **metadata}
            obj_type = default_type
        else:
            obj_type = default_type
        if resolve is not None and obj_type in COMPATIBLE:
            existing = resolve(name, COMPATIBLE[obj_type])
            if existing is not None:
                split = try_split_id(existing)
                if split:
                    obj_type, key = split
    try:
        draft = ObjectDraft.make(
            obj_type,
            name,
            key=key,
            metadata=metadata,
            tags=tags,
            confidence=confidence,
            source=ctx.source.name,
            synthetic=ctx.source.synthetic,
        )
    except InvalidInputError as exc:
        raise RecordRejected(f"Invalid {field}: {exc.message}") from exc
    return draft


def object_record_to_draft(data: dict[str, Any], ctx: ParseContext) -> ObjectDraft:
    """Native ``{"kind": "object", ...}`` record."""
    raw_type = data.get("type") or data.get("object_type")
    raw_id = data.get("id")
    key = data.get("key")
    if not raw_type and raw_id:
        split = try_split_id(str(raw_id))
        if split:
            raw_type, key = split
    if not raw_type:
        raise RecordRejected("Object record has no 'type'.")
    obj_type = validate_object_type(str(raw_type))
    if raw_id and key is None:
        split = try_split_id(str(raw_id))
        if split:
            key = split[1]
    name = str(data.get("name") or key or "").strip()
    if not name:
        raise RecordRejected("Object record has no 'name'.")
    metadata = dict(data.get("metadata") or {})
    if not isinstance(metadata, dict):
        raise RecordRejected("Object 'metadata' must be a mapping.")
    for convenience in ("criticality", "internet_facing", "privileged", "owner", "environment", "os"):
        if convenience in data and convenience not in metadata:
            metadata[convenience] = data[convenience]
    if data.get("aliases"):
        aliases = data["aliases"]
        metadata["aliases"] = [str(a) for a in (aliases if isinstance(aliases, list) else [aliases])]
    tags = data.get("tags") or []
    if not isinstance(tags, list):
        raise RecordRejected("Object 'tags' must be a list.")
    try:
        draft = ObjectDraft.make(
            obj_type,
            name,
            key=str(key) if key is not None else None,
            metadata=metadata,
            tags={str(t) for t in tags},
            confidence=parse_confidence(data.get("confidence"), 0.9),
            source=str(data.get("source") or ctx.source.name),
            synthetic=bool(data.get("synthetic", ctx.source.synthetic)),
            first_seen=_parse_time(data.get("first_seen")),
            last_seen=_parse_time(data.get("last_seen")),
            valid_from=_parse_time(data.get("valid_from")),
            valid_to=_parse_time(data.get("valid_to")),
        )
    except InvalidInputError as exc:
        raise RecordRejected(exc.message, reason=exc.reason) from exc
    return draft
