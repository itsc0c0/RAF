"""Building native R$F records from decoded log lines.

Decoders describe what a line says with these helpers: typed object references (with the role an
object plays in the event), explicit relationships, and the event itself. The native normalizer
turns the result into objects, events and relationships with provenance, exactly as it does for
R$F JSON Lines.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from raf.core.ingestion.logs.values import fingerprint, is_access_key_id, redact_access_key
from raf.core.netaddr import parse_ip
from raf.core.objects.types import ObjectType

#: Actor names that stand for "nobody signed in".
ANONYMOUS = frozenset({"guest", "anonymous", "anon", "public", "unauthenticated", "nobody", "-"})
#: Actor names that stand for the service itself rather than a person.
SYSTEM_ACTORS = frozenset({"system", "service", "internal", "scheduler", "cron", "daemon", "auto", "worker"})

_OUTCOME = {
    "success": "success",
    "succeeded": "success",
    "successful": "success",
    "ok": "success",
    "allow": "success",
    "allowed": "success",
    "accept": "success",
    "accepted": "success",
    "permit": "success",
    "permitted": "success",
    "pass": "success",
    "passed": "success",
    "granted": "success",
    "served": "success",
    "completed": "success",
    "done": "success",
    "true": "success",
    "failure": "failure",
    "failed": "failure",
    "fail": "failure",
    "error": "failure",
    "deny": "failure",
    "denied": "failure",
    "drop": "failure",
    "dropped": "failure",
    "reject": "failure",
    "rejected": "failure",
    "block": "failure",
    "blocked": "failure",
    "forbidden": "failure",
    "unauthorized": "failure",
    "invalid": "failure",
    "false": "failure",
    "timeout": "failure",
}
_LEVEL_SEVERITY = {
    "fatal": "MEDIUM",
    "critical": "MEDIUM",
    "crit": "MEDIUM",
    "alert": "MEDIUM",
    "emerg": "MEDIUM",
    "emergency": "MEDIUM",
    "error": "LOW",
    "err": "LOW",
    "severe": "LOW",
}
_WINDOW = re.compile(
    r"^\s*(?P<h1>\d{1,2}):(?P<m1>\d{2})(?::\d{2})?\s*(?:-|\u2013|to)\s*(?P<h2>\d{1,2}):(?P<m2>\d{2})(?::\d{2})?\s*"
    r"(?P<tz>Z|UTC)?\s*$",
    re.IGNORECASE,
)


def clean(data: dict[str, Any]) -> dict[str, Any]:
    """Drop empty values (None, "", "-", empty containers)."""
    return {k: v for k, v in data.items() if v not in (None, "", "-", [], {})}


def ref(obj_type: str, name: Any, key: Any = None, **metadata: Any) -> dict[str, Any] | None:
    """A typed object reference, or None when there is no name."""
    if name is None:
        return None
    text = str(name).strip()
    if not text or text == "-":
        return None
    out: dict[str, Any] = {"type": obj_type, "name": text[:1000]}
    if key not in (None, ""):
        out["key"] = str(key)[:1000]
    meta = clean(metadata)
    if meta:
        out["metadata"] = meta
    return out


def role(reference: dict[str, Any] | None, role_name: str) -> dict[str, Any] | None:
    """``reference`` involved in the event with ``role_name`` (an ``objects`` entry)."""
    if reference is None:
        return None
    return {**reference, "role": role_name}


def ip(value: Any) -> str | None:
    """The canonical text of an IP address (port suffixes ``1.2.3.4:443`` are removed), or None."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    address = parse_ip(text)
    if address is None and text.count(":") == 1 and "." in text:
        address = parse_ip(text.split(":", 1)[0])
    if address is None and text.startswith("[") and "]:" in text:
        address = parse_ip(text[1 : text.index("]")])
    return address.compressed if address is not None else None


def ip_ref(value: Any) -> dict[str, Any] | None:
    address = ip(value)
    return {"type": ObjectType.IP.value, "name": address} if address else None


def user_ref(name: Any, **metadata: Any) -> dict[str, Any] | str | None:
    """A person or account: a bare name (typed and entity-resolved by the normalizer), or None for
    empty and system placeholders. Anonymous principals keep their name and are marked."""
    if name is None:
        return None
    text = str(name).strip()
    if not text or text == "-":
        return None
    if text.lower() in ANONYMOUS:
        return ref(ObjectType.USER.value, text.lower(), anonymous=True, **metadata)
    if metadata:
        return ref(ObjectType.USER.value, text, **metadata)
    return text


def is_person(name: Any) -> bool:
    if name is None:
        return False
    text = str(name).strip().lower()
    return bool(text) and text not in ANONYMOUS and text not in SYSTEM_ACTORS


def service_ref(name: Any, **metadata: Any) -> dict[str, Any] | None:
    return ref(ObjectType.SERVICE.value, name, **metadata)


def host_ref(name: Any) -> dict[str, Any] | str | None:
    if name is None:
        return None
    text = str(name).strip()
    if not text or text == "-":
        return None
    return ip_ref(text) or text


def credential_ref(access_key_id: str, *, provider: str = "aws") -> dict[str, Any] | None:
    """A cloud access key as a ``secret`` object: redacted name, fingerprint key - never the value."""
    value = access_key_id.strip()
    if not value:
        return None
    kind = "access-key"
    if is_access_key_id(value):
        kind = "long-term access key" if value.startswith("AKIA") else "temporary access key"
        shown = redact_access_key(value)
    else:
        shown = value[:4] + "****" if len(value) > 8 else "****"
    print_ = fingerprint(value)
    return ref(
        ObjectType.SECRET.value,
        shown,
        key=f"{provider}-access-key|{print_}",
        kind=kind,
        provider=provider,
        redacted=shown,
        fingerprint=print_,
    )


def bucket_ref(bucket: str, *, provider: str = "aws") -> dict[str, Any] | None:
    service = "s3" if provider == "aws" else "storage"
    return ref(
        ObjectType.CLOUD_RESOURCE.value,
        bucket,
        key=f"{provider}/{service}/{bucket}",
        service=service,
        platform=provider,
        kind="bucket",
    )


def object_ref(bucket: str, key: str, *, scheme: str = "s3") -> dict[str, Any] | None:
    path = key.lstrip("/")
    if not path:
        return None
    name = path.rstrip("/").rsplit("/", 1)[-1] or path
    return ref(ObjectType.FILE.value, name, key=f"{scheme}://{bucket}/{path}", path=path, bucket=bucket, storage=scheme)


def url_ref(scheme: str, host: str | None, path: str) -> dict[str, Any] | None:
    """The URL of a request without its query string (one object per resource, not per request)."""
    clean_path = path.split("?", 1)[0].split("#", 1)[0] or "/"
    if clean_path.startswith(("http://", "https://")):
        parts = urlsplit(clean_path)
        return ref(ObjectType.URL.value, f"{parts.scheme}://{parts.netloc}{parts.path or '/'}")
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path
    return ref(ObjectType.URL.value, f"{scheme}://{host or 'web'}{clean_path}")


def rel(rel_type: str, source: Any, target: Any, **metadata: Any) -> dict[str, Any] | None:
    if source is None or target is None:
        return None
    out: dict[str, Any] = {"type": rel_type, "source": source, "target": target}
    meta = clean(metadata)
    if meta:
        out["metadata"] = meta
    return out


def outcome(value: Any) -> str | None:
    """A normalized outcome (success | failure | the original word) from booleans, words and codes."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return "success" if value else "failure"
    text = str(value).strip().lower()
    return _OUTCOME.get(text, text[:32] or None)


def status_outcome(code: Any) -> str | None:
    """HTTP-like status codes: 4xx/5xx are failures."""
    try:
        number = int(str(code).strip())
    except (TypeError, ValueError):
        return None
    return "failure" if number >= 400 else "success"


def level_severity(level: Any) -> str | None:
    """Application log levels as event severity: an error is an operational fact, not a security
    verdict, so levels map low (detections raise severity, not log levels)."""
    if level is None:
        return None
    return _LEVEL_SEVERITY.get(str(level).strip().lower())


def slug(text: str, *, limit: int = 48) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", text.strip().lower()).strip("_")[:limit] or "event"


def change_window(window: Any, reference: datetime | None) -> tuple[datetime, datetime] | None:
    """``19:30-20:00Z`` on the day of ``reference`` (an end before the start crosses midnight)."""
    if not isinstance(window, str) or reference is None:
        return None
    m = _WINDOW.match(window)
    if m is None:
        return None
    day = reference.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    try:
        start = day.replace(hour=int(m["h1"]), minute=int(m["m1"]))
        end = day.replace(hour=int(m["h2"]), minute=int(m["m2"]))
    except ValueError:
        return None
    if end <= start:
        end += timedelta(days=1)
    return start, end


def record(
    event_type: str,
    *,
    timestamp: Any = None,
    actor: Any = None,
    target: Any = None,
    host: Any = None,
    outcome_: str | None = None,
    severity: str | None = None,
    action: str | None = None,
    message: str | None = None,
    attributes: dict[str, Any] | None = None,
    objects: list[dict[str, Any] | None] | None = None,
    relationships: list[dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """A native event record (empty parts left out)."""
    data: dict[str, Any] = {"event_type": event_type}
    for key, value in (
        ("timestamp", timestamp),
        ("actor", actor),
        ("target", target),
        ("host", host),
        ("outcome", outcome_),
        ("severity", severity),
        ("action", action[:128] if action else None),
        ("message", message[:4000] if message else None),
    ):
        if value not in (None, "", "-"):
            data[key] = value
    data["attributes"] = clean(attributes or {})
    extra = [o for o in objects or [] if o is not None]
    if extra:
        data["objects"] = extra
    links = [r for r in relationships or [] if r is not None]
    if links:
        data["relationships"] = links
    return data


__all__ = [
    "ANONYMOUS",
    "SYSTEM_ACTORS",
    "bucket_ref",
    "change_window",
    "clean",
    "credential_ref",
    "host_ref",
    "ip",
    "ip_ref",
    "is_person",
    "level_severity",
    "object_ref",
    "outcome",
    "record",
    "ref",
    "rel",
    "role",
    "service_ref",
    "slug",
    "status_outcome",
    "url_ref",
    "user_ref",
]
