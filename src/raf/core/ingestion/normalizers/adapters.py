"""Adapters that map foreign record shapes to native records.

Each adapter translates its dialect (Elastic Common Schema, AWS CloudTrail,
tabular columns, arbitrary JSON) into a native record and delegates to the
native normalizer, so taxonomy, references and provenance behave identically.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from raf.core.ingestion.base import NormalizedRecord, Normalizer, ParseContext, RawRecord, RecordRejected
from raf.core.ingestion.logs.records import bucket_ref, credential_ref, ip, object_ref
from raf.core.ingestion.normalizers.native import NativeNormalizer
from raf.core.objects.types import ObjectType
from raf.core.security.redaction import redact_text


def _get(data: dict[str, Any], dotted: str) -> Any:
    """Read ``a.b.c`` from nested dicts or flat dotted keys."""
    if dotted in data:
        return data[dotted]
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _first(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = _get(data, key)
        if value not in (None, "", [], {}):
            return value
    return None


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", text.strip().lower()).strip("_")[:60] or "event"


class _Adapter(Normalizer):
    def __init__(self, native: NativeNormalizer) -> None:
        self.native = native

    def adapt(self, data: dict[str, Any], ctx: ParseContext) -> dict[str, Any]:
        raise NotImplementedError

    def normalize(self, record: RawRecord, ctx: ParseContext) -> NormalizedRecord:
        if not isinstance(record.data, dict):
            raise RecordRejected(f"Expected a JSON object, got {type(record.data).__name__}.")
        native = self.adapt(record.data, ctx)
        return self.native.normalize(RawRecord(native, record.locator, record.raw), ctx)


# --------------------------------------------------------------------------- ECS


class EcsNormalizer(_Adapter):
    name: ClassVar[str] = "ecs"

    @classmethod
    def score(cls, record: dict[str, Any]) -> float:
        hits = sum(
            1
            for k in (
                "@timestamp",
                "event.category",
                "event.action",
                "host.name",
                "ecs.version",
                "source.ip",
                "user.name",
            )
            if _get(record, k) is not None
        )
        return min(0.9, 0.2 * hits) if "@timestamp" in record or _get(record, "ecs.version") else 0.1 * hits

    def adapt(self, data: dict[str, Any], ctx: ParseContext) -> dict[str, Any]:
        return ecs_record(data)


def ecs_record(data: dict[str, Any]) -> dict[str, Any]:
    """An Elastic Common Schema document as a native event record."""
    categories = _get(data, "event.category") or []
    categories = categories if isinstance(categories, list) else [categories]
    types = _get(data, "event.type") or []
    types = types if isinstance(types, list) else [types]
    action = str(_first(data, "event.action") or "")
    outcome = _first(data, "event.outcome")
    attrs: dict[str, Any] = {}
    for key, field in (
        ("src_ip", "source.ip"),
        ("dst_ip", "destination.ip"),
        ("dst_port", "destination.port"),
        ("src_port", "source.port"),
        ("protocol", "network.transport"),
        ("bytes_out", "source.bytes"),
        ("bytes_in", "destination.bytes"),
        ("pid", "process.pid"),
        ("image", "process.executable"),
        ("command_line", "process.command_line"),
        ("parent_pid", "process.parent.pid"),
        ("parent_image", "process.parent.executable"),
        ("method", "http.request.method"),
        ("status", "http.response.status_code"),
        ("user_agent", "user_agent.original"),
        ("dataset", "event.dataset"),
        ("rule", "rule.name"),
    ):
        value = _first(data, field)
        if value is not None:
            attrs[key] = value
    actor = _first(data, "user.name", "user.id")
    host = _first(data, "host.name", "host.hostname", "agent.hostname")
    target: Any = host
    cats = {str(c).lower() for c in categories}
    kinds = {str(t).lower() for t in types}
    if "authentication" in cats:
        event_type = (
            "auth.failure" if str(outcome).lower() == "failure" else ("auth.logout" if "end" in kinds else "auth.login")
        )
    elif "process" in cats:
        event_type = "process.end" if "end" in kinds else "process.start"
        target = None
        attrs.setdefault("image", _first(data, "process.name"))
    elif "file" in cats:
        mapping = {
            "creation": "file.create",
            "deletion": "file.delete",
            "change": "file.modify",
            "access": "file.read",
        }
        event_type = next((mapping[k] for k in kinds if k in mapping), "file.modify")
        target = _first(data, "file.path", "file.name")
        if _first(data, "process.name"):
            attrs["process"] = _first(data, "process.name")
    elif _first(data, "dns.question.name"):
        event_type = "dns.query"
        target = _first(data, "dns.question.name")
        answers = _first(data, "dns.resolved_ip")
        if answers:
            attrs["answers"] = answers
    elif "web" in cats or _first(data, "url.full", "url.original"):
        event_type = "http.request"
        target = _first(data, "url.full", "url.original")
        actor = actor or attrs.get("src_ip")
    elif "network" in cats:
        event_type = "network.connection"
        actor = host or attrs.get("src_ip")
        target = attrs.get("dst_ip")
    elif "iam" in cats:
        event_type = (
            "iam.group.add"
            if "group" in action
            else "iam.user.create"
            if "creat" in action
            else ("iam.permission.grant")
        )
        target = _first(data, "user.target.name", "related.user") or actor
        actor = _first(data, "user.changes.name") or actor
        if _first(data, "group.name"):
            attrs["group"] = _first(data, "group.name")
    elif "intrusion_detection" in cats or "malware" in cats or _first(data, "rule.name"):
        event_type = "alert"
    else:
        event_type = f"log.{_slug(action)}" if action else "log.message"
    if isinstance(target, list):
        target = target[0] if target else None
    return {
        "timestamp": _first(data, "@timestamp", "event.created"),
        "event_type": event_type,
        "action": action or None,
        "outcome": outcome,
        "actor": actor,
        "target": target,
        "host": host,
        "message": _first(data, "message"),
        "severity": _first(data, "event.severity", "log.level"),
        "attributes": {k: v for k, v in attrs.items() if v is not None},
    }


# --------------------------------------------------------------------------- CloudTrail

_ASSUMED_ROLE = re.compile(r"^arn:aws[\w-]*:sts::(?P<account>\d{12}):assumed-role/(?P<role>[^/]+)/(?P<session>.+)$")
_FEDERATED = re.compile(r"^arn:aws[\w-]*:sts::(?P<account>\d{12}):federated-user/(?P<user>.+)$")
_IAM_GRANTS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
}
_IAM_REVOKES = {
    "DetachUserPolicy",
    "DetachRolePolicy",
    "DetachGroupPolicy",
    "DeleteUserPolicy",
    "DeleteRolePolicy",
    "DeleteGroupPolicy",
}
_IAM_CREDENTIALS = {"CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "CreateServiceSpecificCredential"}
_OBJECT_APIS = {"GetObject", "PutObject", "DeleteObject", "CopyObject", "HeadObject", "GetObjectAcl", "PutObjectAcl"}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _cloudtrail_actor(identity: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """The principal of a CloudTrail ``userIdentity``: an assumed role is its role (the session name
    is an attribute), an IAM user its user, anything else its ARN or type."""
    arn = str(identity.get("arn") or "")
    account = identity.get("accountId")
    itype = identity.get("type")
    issuer = _get(identity, "sessionContext.sessionIssuer") or {}
    attrs: dict[str, Any] = {"identity_type": itype}
    if (m := _ASSUMED_ROLE.match(arn)) is not None:
        role_arn = str(issuer.get("arn") or f"arn:aws:iam::{m['account']}:role/{m['role']}")
        attrs["role_session"] = m["session"]
        meta = {"arn": role_arn, "account": m["account"], "identity_type": itype, "platform": "aws"}
        return {"type": ObjectType.ROLE, "name": m["role"], "key": role_arn, "metadata": meta}, attrs
    if (m := _FEDERATED.match(arn)) is not None:
        meta = {"arn": arn, "account": m["account"], "identity_type": itype, "platform": "aws"}
        return {"type": ObjectType.IDENTITY, "name": m["user"], "key": arn, "metadata": meta}, attrs
    user = (
        identity.get("userName")
        or issuer.get("userName")
        or identity.get("invokedBy")
        or identity.get("principalId")
        or (arn.rsplit("/", 1)[-1] if "/" in arn else None)
        or itype
    )
    meta = {k: v for k, v in {"arn": arn, "account": account, "identity_type": itype, "platform": "aws"}.items() if v}
    return {
        "type": ObjectType.IDENTITY,
        "name": str(user or arn or "unknown"),
        "key": str(arn or user or "unknown"),
        "metadata": meta,
    }, attrs


def cloudtrail_record(data: dict[str, Any]) -> dict[str, Any]:
    """A CloudTrail record as a native event record (shared by the adapter and the mixed-log parser).

    The access key a call was signed with becomes a ``secret`` object (redacted name, fingerprint
    key) with the role ``credential``; S3 object keys become ``file`` objects (``s3://bucket/key``)."""
    identity = _mapping(data.get("userIdentity"))
    actor, actor_attrs = _cloudtrail_actor(identity)
    user = actor["name"]
    name = str(data.get("eventName"))
    service = str(data.get("eventSource") or "aws").split(".")[0]
    params = _mapping(data.get("requestParameters"))
    extra = _mapping(data.get("additionalEventData"))
    failed = bool(data.get("errorCode"))
    source_address = data.get("sourceIPAddress")
    src_ip = ip(source_address)
    attrs: dict[str, Any] = {
        **actor_attrs,
        "api": name,
        "event_source": data.get("eventSource"),
        "region": data.get("awsRegion"),
        "src_ip": src_ip,
        "source_service": source_address if source_address and not src_ip else None,
        "user_agent": data.get("userAgent"),
        "error_code": data.get("errorCode"),
        "error_message": redact_text(str(data["errorMessage"]))[:500] if data.get("errorMessage") else None,
        "account": data.get("recipientAccountId"),
        "request_id": data.get("requestID"),
        "cloudtrail_event_id": data.get("eventID"),
        "cloudtrail_event_type": data.get("eventType"),
        "read_only": data.get("readOnly"),
        "platform": "aws",
        "bytes_out": extra.get("bytesTransferredOut"),
        "bytes_in": extra.get("bytesTransferredIn"),
    }
    objects: list[dict[str, Any]] = []
    key_id = identity.get("accessKeyId")
    if isinstance(key_id, str) and key_id.strip():
        credential = credential_ref(key_id)
        if credential is not None:
            objects.append({**credential, "role": "credential"})
            attrs["access_key"] = credential["name"]
    bucket = params.get("bucketName")
    object_key = params.get("key")
    if bucket:
        attrs["bucket"] = bucket
    if object_key:
        attrs["object_key"] = object_key
    if params.get("prefix"):
        attrs["prefix"] = params.get("prefix")
    target_name = (
        bucket
        or params.get("roleName")
        or params.get("groupName")
        or params.get("instanceId")
        or params.get("functionName")
        or params.get("userName")
        or params.get("policyArn")
        or service
    )
    target: Any = {
        "type": ObjectType.CLOUD_RESOURCE,
        "name": str(target_name),
        "key": f"aws/{service}/{target_name}",
        "metadata": {"service": service},
    }
    if bucket:
        target = bucket_ref(str(bucket)) or target
        if object_key and name in _OBJECT_APIS:
            obj = object_ref(str(bucket), str(object_key))
            if obj is not None:
                objects.append({**obj, "role": "object"})
    event_type = "cloud.api"
    if name == "ConsoleLogin":
        event_type = (
            "auth.failure" if failed or _get(data, "responseElements.ConsoleLogin") == "Failure" else "auth.login"
        )
        attrs["mfa"] = extra.get("MFAUsed")
        target = {
            "type": ObjectType.CLOUD_RESOURCE,
            "name": f"aws-console/{data.get('recipientAccountId')}",
            "metadata": {"service": "signin"},
        }
    elif name in _IAM_GRANTS or name in _IAM_REVOKES:
        event_type = "iam.permission.grant" if name in _IAM_GRANTS else "iam.permission.revoke"
        principal = params.get("userName") or params.get("roleName") or params.get("groupName")
        target = {"type": ObjectType.IDENTITY, "name": str(principal)} if principal else target
        attrs["resource"] = params.get("policyArn") or params.get("policyName")
        attrs["resource_type"] = ObjectType.POLICY
    elif name in ("AddUserToGroup", "RemoveUserFromGroup"):
        event_type = "iam.group.add" if name == "AddUserToGroup" else "iam.group.remove"
        target = {"type": ObjectType.IDENTITY, "name": str(params.get("userName"))}
        attrs["group"] = params.get("groupName")
    elif name in _IAM_CREDENTIALS:
        event_type = "iam.credential.create"
        target = {"type": ObjectType.IDENTITY, "name": str(params.get("userName") or user)}
    elif name == "CreateUser":
        event_type = "iam.user.create"
        target = {"type": ObjectType.IDENTITY, "name": str(params.get("userName") or "unknown")}
    elif name == "AssumeRole":
        role_arn = params.get("roleArn")
        target = {"type": ObjectType.ROLE, "name": str(role_arn).split("/")[-1], "key": str(role_arn)}
    message = f"{name} via {data.get('eventSource')}" + (f" failed: {data.get('errorCode')}" if failed else "")
    if bucket:
        message += f" on {bucket}" + (f"/{object_key}" if object_key else "")
    return {
        "id": data.get("eventID"),
        "timestamp": data.get("eventTime"),
        "event_type": event_type,
        "action": name,
        "outcome": "failure" if failed else "success",
        "actor": actor,
        "target": target,
        "severity": "low" if failed else "info",
        "message": message,
        "attributes": {k: v for k, v in attrs.items() if v is not None and v != ""},
        "objects": objects,
    }


class CloudTrailNormalizer(_Adapter):
    name: ClassVar[str] = "cloudtrail"

    @classmethod
    def score(cls, record: dict[str, Any]) -> float:
        return 0.95 if {"eventTime", "eventName", "eventSource"} <= record.keys() else 0.0

    def adapt(self, data: dict[str, Any], ctx: ParseContext) -> dict[str, Any]:
        return cloudtrail_record(data)


# --------------------------------------------------------------------------- tabular / generic

_COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": (
        "timestamp",
        "time",
        "datetime",
        "date",
        "@timestamp",
        "event_time",
        "eventtime",
        "ts",
        "created",
        "logtime",
        "date_time",
    ),
    "event_type": ("event_type", "eventtype", "type", "event", "category"),
    "action": ("action", "operation", "activity", "verb"),
    "outcome": ("outcome", "result", "status_text", "disposition"),
    "actor": ("actor", "user", "username", "user_name", "account", "principal", "src_user", "subject", "login"),
    "target": (
        "target",
        "host",
        "hostname",
        "computer",
        "device",
        "dest_host",
        "destination",
        "dst_host",
        "resource",
        "object",
    ),
    "src_ip": ("src_ip", "source_ip", "srcip", "client_ip", "src", "sourceaddress", "client", "c_ip"),
    "dst_ip": ("dst_ip", "dest_ip", "destination_ip", "dstip", "dst", "server_ip", "s_ip"),
    "dst_port": ("dst_port", "dest_port", "dport", "port", "destination_port"),
    "message": ("message", "msg", "description", "details", "summary"),
    "severity": ("severity", "level", "priority"),
    "domain": ("domain", "query", "qname", "fqdn", "hostname_requested"),
    "url": ("url", "uri", "request_url", "cs_uri"),
    "image": ("image", "process", "process_name", "exe", "executable"),
    "command_line": ("command_line", "cmdline", "command", "commandline"),
    "file": ("file", "file_path", "filepath", "filename", "path"),
}


def _canon(header: str) -> str:
    return re.sub(r"[^a-z0-9@]+", "_", header.strip().lower()).strip("_")


def map_columns(row: dict[str, Any]) -> dict[str, Any]:
    canon = {_canon(k): v for k, v in row.items() if k is not None}
    mapped: dict[str, Any] = {}
    used: set[str] = set()
    for field, aliases in _COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in canon and canon[alias] not in (None, "") and alias not in used:
                mapped[field] = canon[alias]
                used.add(alias)
                break
    extras = {k: v for k, v in canon.items() if k not in used and v not in (None, "")}
    return {"mapped": mapped, "extras": extras}


def infer_event_type(mapped: dict[str, Any]) -> str:
    if mapped.get("event_type"):
        text = str(mapped["event_type"]).strip().lower()
        if re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_-]+)+", text):
            return text
        aliases = {
            "login": "auth.login",
            "logon": "auth.login",
            "logoff": "auth.logout",
            "logout": "auth.logout",
            "failed_login": "auth.failure",
            "dns": "dns.query",
            "http": "http.request",
            "web": "http.request",
            "proxy": "http.request",
            "process": "process.start",
            "connection": "network.connection",
            "network": "network.connection",
            "alert": "alert",
        }
        return aliases.get(_slug(text), f"log.{_slug(text)}")
    if mapped.get("domain"):
        return "dns.query"
    if mapped.get("url"):
        return "http.request"
    if mapped.get("image") or mapped.get("command_line"):
        return "process.start"
    if mapped.get("dst_ip"):
        return "network.connection"
    if mapped.get("file"):
        return "file.modify"
    return "log.message"


class TabularNormalizer(_Adapter):
    """CSV rows and other flat key/value records, mapped through column aliases."""

    name: ClassVar[str] = "tabular"

    def adapt(self, data: dict[str, Any], ctx: ParseContext) -> dict[str, Any]:
        columns = map_columns(data)
        mapped, extras = columns["mapped"], columns["extras"]
        if not mapped.get("timestamp"):
            raise RecordRejected(
                "Required timestamp could not be determined.", hint="Add a timestamp/time column (ISO-8601 or epoch)."
            )
        event_type = infer_event_type(mapped)
        attributes: dict[str, Any] = dict(extras)
        for key in ("src_ip", "dst_ip", "dst_port", "domain", "url", "image", "command_line"):
            if mapped.get(key) not in (None, ""):
                attributes[key] = mapped[key]
        target = mapped.get("target")
        actor = mapped.get("actor")
        if event_type == "dns.query":
            target = mapped.get("domain")
            actor = actor if actor else (mapped.get("target") or mapped.get("src_ip"))
            if actor == mapped.get("actor") and mapped.get("target"):
                attributes["user"] = mapped.get("actor")
                actor = mapped.get("target")
        elif event_type == "http.request":
            target = mapped.get("url")
            if mapped.get("target"):
                attributes["client_host"] = mapped["target"]
            actor = mapped.get("target") or mapped.get("src_ip") or actor
            if mapped.get("actor"):
                attributes["user"] = mapped["actor"]
        elif event_type == "network.connection":
            target = mapped.get("dst_ip")
            actor = mapped.get("target") or mapped.get("src_ip")
            if mapped.get("actor"):
                attributes["user"] = mapped["actor"]
        elif event_type.startswith("file.") and mapped.get("file"):
            target = mapped.get("file")
        host = mapped.get("target") if event_type in ("process.start", "file.modify", "file.create") else None
        return {
            "timestamp": mapped["timestamp"],
            "event_type": event_type,
            "action": mapped.get("action"),
            "outcome": mapped.get("outcome"),
            "actor": actor,
            "target": target,
            "host": host,
            "message": mapped.get("message"),
            "severity": mapped.get("severity"),
            "attributes": attributes,
        }


class GenericJsonNormalizer(_Adapter):
    """Heuristic fallback for arbitrary JSON objects (flattened one level)."""

    name: ClassVar[str] = "generic-json"

    @classmethod
    def score(cls, record: dict[str, Any]) -> float:
        return 0.05

    def adapt(self, data: dict[str, Any], ctx: ParseContext) -> dict[str, Any]:
        flat: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, dict):
                for sub, sub_value in value.items():
                    if not isinstance(sub_value, dict | list):
                        flat[f"{key}_{sub}"] = sub_value
            else:
                flat[key] = value
        return TabularNormalizer(self.native).adapt(flat, ctx)
