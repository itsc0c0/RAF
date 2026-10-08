"""Decoders for structured payloads: JSON objects and key=value records.

Each decoder recognizes a family by its fields (CloudTrail, Kubernetes audit, GCP and Azure audit,
Azure AD and Okta sign-ins, Windows and Sysmon events, Suricata EVE, Zeek, ECS, identity
providers, EDR process telemetry, network flows, change records, application events, DNS, HTTP and
database records) and maps it onto a native R$F event. Records nobody recognizes still become
events: :func:`generic_record` reads the usual field names (actor, client IP, host, service,
outcome ...) whatever the naming style, and keeps the remaining fields as attributes.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from raf.core.ingestion.logs.frame import Frame
from raf.core.ingestion.logs.records import (
    change_window,
    host_ref,
    ip,
    ip_ref,
    is_person,
    level_severity,
    object_ref,
    outcome,
    record,
    ref,
    rel,
    role,
    service_ref,
    slug,
    status_outcome,
    url_ref,
    user_ref,
)
from raf.core.ingestion.logs.sql import database_record
from raf.core.ingestion.logs.values import Fields, safe_attributes, safe_value
from raf.core.ingestion.normalizers.adapters import cloudtrail_record, ecs_record
from raf.core.objects.types import ObjectType
from raf.core.security.redaction import redact_text
from raf.core.timeutil import TimestampError, format_ts, parse_timestamp

Decoder = Callable[[dict[str, Any], Fields, Frame], dict[str, Any] | None]

# --------------------------------------------------------------------------- field names

TIME = (
    "timestamp",
    "@timestamp",
    "time",
    "ts",
    "eventTime",
    "event_time",
    "datetime",
    "date",
    "published",
    "createdDateTime",
    "created",
    "eventTimestamp",
    "receiveTime",
    "logtime",
    "TimeCreated.SystemTime",
    "TimeCreated",
    "UtcTime",
    "EventTime",
)
ACTOR = (
    "actor",
    "user",
    "username",
    "user_name",
    "userName",
    "userPrincipalName",
    "upn",
    "principal",
    "principalEmail",
    "subject",
    "login",
    "account",
    "account_name",
    "email",
    "actor.alternateId",
    "user.name",
    "user.username",
    "user.email",
    "suser",
    "src_user",
    "TargetUserName",
    "SubjectUserName",
    "User",
    "UserName",
    "requester",
    "caller",
    "identity",
    "uid",
    "user_id",
    "userId",
)
SRC_IP = (
    "src_ip",
    "srcip",
    "src",
    "source_ip",
    "sourceIPAddress",
    "sourceAddress",
    "src_addr",
    "srcaddr",
    "source.ip",
    "client_ip",
    "clientIp",
    "clientIP",
    "client.ipAddress",
    "ipAddress",
    "ip_address",
    "ip",
    "remote_addr",
    "remote_ip",
    "remoteIp",
    "callerIp",
    "callerIpAddress",
    "c_ip",
    "IpAddress",
    "SourceIp",
    "SourceAddress",
    "id.orig_h",
    "orig_h",
    "client",
    "peer",
    "sourceIPs",
)
DST_IP = (
    "dst_ip",
    "dstip",
    "dst",
    "dest_ip",
    "destination_ip",
    "destinationAddress",
    "dst_addr",
    "dstaddr",
    "destination.ip",
    "dest",
    "server_ip",
    "s_ip",
    "DestinationIp",
    "DestAddress",
    "id.resp_h",
    "resp_h",
    "remote_address",
    "target_ip",
)
SRC_PORT = (
    "src_port",
    "sport",
    "srcport",
    "source_port",
    "source.port",
    "spt",
    "SourcePort",
    "id.orig_p",
    "client_port",
    "IpPort",
)
DST_PORT = (
    "dst_port",
    "dport",
    "dstport",
    "dest_port",
    "destination_port",
    "destination.port",
    "dpt",
    "DestinationPort",
    "id.resp_p",
    "port",
    "server_port",
    "remotePort",
    "remote_port",
)
HOST = (
    "host",
    "hostname",
    "host.name",
    "host.hostname",
    "computer",
    "Computer",
    "ComputerName",
    "computer_name",
    "device",
    "device_name",
    "deviceName",
    "node",
    "nodename",
    "server",
    "agent.hostname",
    "dvchost",
    "dvc",
    "machine",
    "instance",
    "observer.hostname",
)
SERVICE = (
    "service",
    "service.name",
    "app",
    "application",
    "app_name",
    "appName",
    "appDisplayName",
    "component",
    "program",
    "logger",
    "logger_name",
    "source_app",
    "serviceName",
)
EVENT = (
    "event",
    "event_name",
    "eventName",
    "eventType",
    "event_type",
    "event.action",
    "action",
    "activity",
    "operation",
    "operationName",
    "op",
    "verb",
    "type",
    "category",
    "msg",
    "message",
)
OUTCOME = (
    "outcome",
    "outcome.result",
    "result",
    "status",
    "decision",
    "disposition",
    "event.outcome",
    "success",
    "succeeded",
    "res",
    "authResult",
    "auth_result",
)
LEVEL = ("level", "severity", "log.level", "lvl", "loglevel", "log_level", "priority")
MESSAGE = ("message", "msg", "displayMessage", "description", "summary", "text", "log")
SESSION = (
    "sessionId",
    "session_id",
    "sid",
    "session",
    "sessionID",
    "authenticationContext.externalSessionId",
    "externalSessionId",
    "LogonId",
    "TargetLogonId",
    "ses",
    "session.id",
)
REQUEST = (
    "request_id",
    "requestId",
    "requestID",
    "req_id",
    "rid",
    "x_request_id",
    "trace_id",
    "traceId",
    "correlation_id",
    "correlationId",
    "transaction_id",
    "transactionId",
    "auditID",
    "uuid",
)
DEVICE = ("deviceId", "device_id", "device", "client.device", "deviceDetail.deviceId", "device.id")
USER_AGENT = (
    "user_agent",
    "userAgent",
    "http_user_agent",
    "client.userAgent.rawUserAgent",
    "useragent",
    "ua",
    "callerSuppliedUserAgent",
    "user_agent.original",
    "cs(User-Agent)",
)
BYTES_IN = (
    "bytes_in",
    "bytesIn",
    "in_bytes",
    "bytes_received",
    "bytesReceived",
    "rcvdbyte",
    "bytes_toclient",
    "resp_bytes",
    "destination.bytes",
    "rx_bytes",
)
BYTES_OUT = (
    "bytes_out",
    "bytesOut",
    "out_bytes",
    "bytes_sent",
    "bytesSent",
    "sentbyte",
    "bytes_toserver",
    "orig_bytes",
    "source.bytes",
    "tx_bytes",
)
TICKET = (
    "ticket",
    "ticket_id",
    "change",
    "change_id",
    "changeId",
    "change_ticket",
    "cr",
    "request_number",
    "rfc",
    "jira",
    "incident_ticket",
)

_AUTH_WORDS = re.compile(
    r"auth|log[_ .-]?[io]n|logon|sign[_ .-]?in|signin|sso|mfa|2fa|otp|session\.start|password|"
    r"credential|kerberos|ntlm",
    re.IGNORECASE,
)
_LOGOUT_WORDS = re.compile(r"log[_ .-]?out|logoff|sign[_ .-]?out|session\.end|session_end", re.IGNORECASE)
_MFA_WORDS = re.compile(r"mfa|challenge|2fa|otp|push|factor", re.IGNORECASE)
_SECRET_FILE = re.compile(
    r"(?i)(?:^|/)(?:\.?env(?:\.[\w-]+)?|[\w.-]*\.env|credentials?(?:\.\w+)?|\.aws/credentials|id_(?:rsa|dsa|ecdsa|ed25519)|"
    r"[\w.-]+\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk)|\.npmrc|\.pypirc|\.netrc|\.pgpass|kubeconfig|"
    r"secrets?(?:\.[\w-]+)?|vault\.(?:json|ya?ml)|token(?:s)?(?:\.\w+)?|\.git-credentials|htpasswd)$"
)


def secret_bearing(path: str) -> bool:
    """A file name that conventionally holds credentials (``.env``, ``id_rsa``, ``*.pem`` ...)."""
    return bool(_SECRET_FILE.search(path.strip()))


def _time(f: Fields) -> str | None:
    value = f.get(*TIME)
    if value is None or isinstance(value, dict | list):
        return None
    return str(value)


def _extras(f: Fields, *, limit: int = 48) -> dict[str, Any]:
    return safe_attributes(f.unused().items(), limit=limit)


def _first_ip(f: Fields, names: tuple[str, ...]) -> str | None:
    for name in names:
        value = f.get(name)
        if isinstance(value, list):
            for item in value:
                if (address := ip(item)) is not None:
                    return address
            continue
        if (address := ip(value)) is not None:
            return address
    return None


def _session(app: str | None, session_id: str | None) -> dict[str, Any] | None:
    if not session_id:
        return None
    scope = app or "session"
    return role(
        ref(ObjectType.SESSION.value, session_id, key=f"{scope}|{session_id}", issuer=app, session_id=session_id),
        "session",
    )


def _message(f: Fields) -> str | None:
    text = f.text(*MESSAGE)
    return redact_text(text)[:4000] if text else None


# --------------------------------------------------------------------------- cloud audit


def _cloudtrail(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    if not ({"eventName", "eventSource"} <= obj.keys()):
        return None
    data = cloudtrail_record(obj)
    data.pop("id", None)  # mixed logs identify events by line, so a re-import stays idempotent
    return data


def _ecs(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    event = obj.get("event")
    if "@timestamp" not in obj or not (
        "ecs" in obj or (isinstance(event, dict) and ({"category", "action", "kind", "dataset"} & event.keys()))
    ):
        return None
    data = ecs_record(obj)
    data.pop("id", None)
    return data


def _k8s_audit(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    if str(obj.get("kind")) != "Event" or not ("auditID" in obj or ("verb" in obj and "objectRef" in obj)):
        return None
    username = f.text("user.username") or "unknown"
    verb = f.text("verb") or "unknown"
    resource = f.text("objectRef.resource") or (f.text("requestURI") or "api").split("?", 1)[0]
    namespace = f.text("objectRef.namespace")
    name = f.text("objectRef.name")
    code = f.integer("responseStatus.code")
    path = "/".join(p for p in ("k8s", namespace or "cluster", resource, name) if p)
    kind = "service-account" if username.startswith("system:serviceaccount:") else "user"
    actor = ref(ObjectType.IDENTITY.value, username, key=f"k8s|{username}", platform="kubernetes", kind=kind)
    target = ref(
        ObjectType.CLOUD_RESOURCE.value, path, key=path, platform="kubernetes", kind=resource, namespace=namespace
    )
    decision = f.text("annotations.authorization.k8s.io/decision")
    attributes = {
        "platform": "kubernetes",
        "verb": verb,
        "k8s_resource": resource,
        "namespace": namespace,
        "name": name,
        "subresource": f.text("objectRef.subresource"),
        "api_group": f.text("objectRef.apiGroup"),
        "status_code": code,
        "audit_id": f.text("auditID"),
        "src_ip": _first_ip(f, ("sourceIPs",)),
        "user_agent": f.text("userAgent"),
        "stage": f.text("stage"),
        "audit_level": f.text("level"),
        "request_uri": f.text("requestURI"),
        "groups": f.get("user.groups"),
        "impersonated_user": f.text("impersonatedUser.username"),
        "decision": decision,
        **_extras(f, limit=16),
    }
    failed = (code is not None and code >= 400) or decision == "forbid"
    shown = f"{resource}/{name}" if name else resource
    return record(
        "cloud.api",
        timestamp=f.text("requestReceivedTimestamp", "stageTimestamp", "timestamp"),
        actor=actor,
        target=target,
        outcome_="failure" if failed else ("success" if code is not None else None),
        severity="low" if failed else None,
        action=verb,
        message=f"{verb} {shown} in {namespace or 'cluster scope'}" + (f" -> {code}" if code is not None else ""),
        attributes=attributes,
    )


def _gcp_audit(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    payload = obj.get("protoPayload")
    if not isinstance(payload, dict) or "methodName" not in payload:
        return None
    method = f.text("protoPayload.methodName") or "unknown"
    principal = f.text("protoPayload.authenticationInfo.principalEmail") or "unknown"
    resource = f.text("protoPayload.resourceName") or f.text("resource.type") or "gcp"
    service = f.text("protoPayload.serviceName") or "gcp"
    code = f.integer("protoPayload.status.code")
    failed = bool(code)
    return record(
        "cloud.api",
        timestamp=f.text("timestamp", "receiveTimestamp"),
        actor=ref(ObjectType.IDENTITY.value, principal, key=f"gcp|{principal}", platform="gcp"),
        target=ref(ObjectType.CLOUD_RESOURCE.value, resource, key=f"gcp/{resource}", service=service, platform="gcp"),
        outcome_="failure" if failed else "success",
        severity="low" if failed else None,
        action=method,
        message=f"{method} on {resource}" + (f" failed: {f.text('protoPayload.status.message')}" if failed else ""),
        attributes={
            "platform": "gcp",
            "api": method,
            "event_source": service,
            "src_ip": ip(f.text("protoPayload.requestMetadata.callerIp")),
            "user_agent": f.text("protoPayload.requestMetadata.callerSuppliedUserAgent"),
            "status_code": code,
            "project": f.text("resource.labels.project_id"),
            "request_id": f.text("insertId"),
            "log_name": f.text("logName"),
            **_extras(f, limit=12),
        },
    )


def _azure_activity(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    if "operationName" not in obj or not ({"caller", "resourceId", "callerIpAddress"} & obj.keys()):
        return None
    operation = f.text("operationName.value", "operationName.localizedValue", "operationName") or "unknown"
    caller = f.text("caller") or "unknown"
    resource = f.text("resourceId") or "azure"
    status = f.text("status.value", "status", "resultType") or ""
    failed = outcome(status) == "failure"
    return record(
        "cloud.api",
        timestamp=f.text("time", "eventTimestamp"),
        actor=ref(ObjectType.IDENTITY.value, caller, key=f"azure|{caller.lower()}", platform="azure"),
        target=ref(ObjectType.CLOUD_RESOURCE.value, resource.rsplit("/", 1)[-1], key=f"azure{resource.lower()}"),
        outcome_="failure" if failed else outcome(status),
        severity="low" if failed else None,
        action=operation,
        message=f"{operation} on {resource}",
        attributes={
            "platform": "azure",
            "api": operation,
            "src_ip": ip(f.text("callerIpAddress")),
            "category": f.text("category.value", "category"),
            "request_id": f.text("correlationId"),
            "resource_id": resource,
            **_extras(f, limit=12),
        },
    )


# --------------------------------------------------------------------------- identity providers


def _auth_event(kind: str | None, result: str | None) -> tuple[str, str | None]:
    """(event type, outcome) of a sign-in record from its kind and result words."""
    text = (result or "").strip().lower()
    if kind and _LOGOUT_WORDS.search(kind):
        return "auth.logout", "success"
    if text in ("mfa_challenge", "challenge", "mfa_required", "mfa", "pending", "interrupted") or (
        text not in ("success", "failure") and kind and _MFA_WORDS.search(kind) and outcome(text) != "failure"
    ):
        return "auth.mfa", "challenge" if outcome(text) not in ("success", "failure") else outcome(text)
    result_outcome = outcome(text)
    if result_outcome == "failure":
        return "auth.failure", "failure"
    return "auth.login", result_outcome or "success"


def _azure_signin(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    if "userPrincipalName" not in obj or not ({"ipAddress", "appDisplayName", "status"} & obj.keys()):
        return None
    code = f.integer("status.errorCode")
    failed = code not in (None, 0)
    app = f.text("appDisplayName", "resourceDisplayName") or "azure-ad"
    return record(
        "auth.failure" if failed else "auth.login",
        timestamp=f.text("createdDateTime"),
        actor=user_ref(f.text("userPrincipalName")),
        target=service_ref(app, kind="application", platform="azure"),
        outcome_="failure" if failed else "success",
        severity="low" if failed else None,
        action="sign-in",
        message=f"Sign-in to {app}" + (f" failed ({code}: {f.text('status.failureReason')})" if failed else ""),
        attributes={
            "platform": "azure",
            "src_ip": ip(f.text("ipAddress")),
            "error_code": code,
            "reason": f.text("status.failureReason"),
            "request_id": f.text("correlationId", "id"),
            "client_app": f.text("clientAppUsed"),
            "conditional_access": f.text("conditionalAccessStatus"),
            "mfa": f.text("mfaDetail.authMethod"),
            "country": f.text("location.countryOrRegion"),
            "city": f.text("location.city"),
            "device_id": f.text("deviceDetail.deviceId"),
            "risk": f.text("riskLevelDuringSignIn"),
            **_extras(f, limit=12),
        },
        objects=[_session(app, f.text("sessionId", "correlationId"))],
    )


def _okta(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    actor = obj.get("actor")
    if "eventType" not in obj or not isinstance(actor, dict) or not isinstance(obj.get("outcome"), dict):
        return None
    kind = f.text("eventType") or "okta"
    result = f.text("outcome.result")
    login = f.text("actor.alternateId") or f.text("actor.displayName") or "unknown"
    app = f.text("target.0.displayName", "target.0.alternateId") or "okta"
    if _AUTH_WORDS.search(kind) or _LOGOUT_WORDS.search(kind):
        event_type, result_outcome = _auth_event(kind, result)
    else:
        event_type, result_outcome = f"log.{slug(kind)}", outcome(result)
    return record(
        event_type,
        timestamp=f.text("published"),
        actor=user_ref(login),
        target=service_ref(app, kind="application", platform="okta"),
        outcome_=result_outcome,
        severity="low" if result_outcome == "failure" else None,
        action=kind,
        message=f.text("displayMessage") or kind,
        attributes={
            "platform": "okta",
            "src_ip": ip(f.text("client.ipAddress")),
            "user_agent": f.text("client.userAgent.rawUserAgent"),
            "reason": f.text("outcome.reason"),
            "request_id": f.text("uuid", "transaction.id"),
            "country": f.text("client.geographicalContext.country"),
            "city": f.text("client.geographicalContext.city"),
            "okta_severity": f.text("severity"),
            **_extras(f, limit=12),
        },
        objects=[_session(app, f.text("authenticationContext.externalSessionId"))],
    )


def _identity(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    """Generic identity-provider / sign-in records (``eventType: user.authentication``, ``outcome``)."""
    kind = f.text("eventType", "event_type", "event", "type", "action", "activity", "operation", "category")
    tag = (frame.tag or "").lower()
    if not (kind and (_AUTH_WORDS.search(kind) or _LOGOUT_WORDS.search(kind))) and tag not in (
        "idp",
        "sso",
        "auth",
        "okta",
        "keycloak",
        "auth0",
        "adfs",
        "radius",
        "vpn",
    ):
        return None
    login = f.text(*ACTOR)
    if not login:
        return None
    result = f.text(*OUTCOME)
    event_type, result_outcome = _auth_event(kind, result)
    app = f.text("app", "application", "client", "client_id", "clientId", "service", "realm", "resource", "target")
    session_id = f.text(*SESSION)
    src = _first_ip(f, SRC_IP)
    device = f.text(*DEVICE)
    shown = {"auth.login": "Sign-in", "auth.failure": "Failed sign-in", "auth.mfa": "MFA challenge"}.get(
        event_type, "Sign-out"
    )
    return record(
        event_type,
        timestamp=_time(f),
        actor=user_ref(login),
        target=service_ref(app or tag or "identity-provider", kind="application"),
        outcome_=result_outcome,
        severity="low" if result_outcome == "failure" else None,
        action=kind or "authentication",
        message=f"{shown} by {login}" + (f" to {app}" if app else "") + (f" from {src}" if src else ""),
        attributes={
            "src_ip": src,
            "device_id": device,
            "session_id": session_id,
            "user_agent": f.text(*USER_AGENT),
            "reason": f.text("reason", "failure_reason", "failureReason", "error", "outcome.reason"),
            "mfa_method": f.text("factor", "mfa_method", "mfaMethod", "authenticator"),
            "result": result,
            **_extras(f, limit=16),
        },
        objects=[_session(app or tag or "idp", session_id)],
    )


# --------------------------------------------------------------------------- Windows / Sysmon

#: Windows Security / System event IDs: (event type, action).
WINDOWS_EVENTS: dict[int, tuple[str, str]] = {
    4624: ("auth.login", "logon"),
    4625: ("auth.failure", "logon"),
    4634: ("auth.logout", "logoff"),
    4647: ("auth.logout", "logoff"),
    4648: ("auth.login", "explicit-credentials"),
    4672: ("auth.privilege", "special-privileges"),
    4688: ("process.start", "process-created"),
    4689: ("process.end", "process-exited"),
    4697: ("log.service_installed", "service-installed"),
    4698: ("log.scheduled_task_created", "scheduled-task-created"),
    4702: ("log.scheduled_task_updated", "scheduled-task-updated"),
    4719: ("policy.change", "audit-policy-changed"),
    4720: ("iam.user.create", "user-created"),
    4722: ("iam.user.enable", "user-enabled"),
    4723: ("iam.credential.create", "password-change"),
    4724: ("iam.credential.create", "password-reset"),
    4725: ("iam.user.disable", "user-disabled"),
    4726: ("iam.user.delete", "user-deleted"),
    4728: ("iam.group.add", "member-added"),
    4732: ("iam.group.add", "member-added"),
    4756: ("iam.group.add", "member-added"),
    4729: ("iam.group.remove", "member-removed"),
    4733: ("iam.group.remove", "member-removed"),
    4757: ("iam.group.remove", "member-removed"),
    4738: ("iam.user.modify", "user-changed"),
    4740: ("auth.lockout", "account-locked"),
    4767: ("iam.user.enable", "account-unlocked"),
    4768: ("auth.login", "kerberos-tgt"),
    4769: ("auth.login", "kerberos-service-ticket"),
    4771: ("auth.failure", "kerberos-preauth-failed"),
    4776: ("auth.login", "ntlm-validation"),
    4663: ("file.read", "object-access"),
    4660: ("file.delete", "object-deleted"),
    5140: ("file.read", "share-access"),
    5145: ("file.read", "share-object-access"),
    5156: ("network.connection", "connection-allowed"),
    5157: ("network.connection", "connection-blocked"),
    1102: ("log.audit_log_cleared", "security-log-cleared"),
    104: ("log.audit_log_cleared", "log-cleared"),
    7045: ("log.service_installed", "service-installed"),
    4104: ("log.powershell_script", "script-block"),
}
SYSMON_EVENTS: dict[int, tuple[str, str]] = {
    1: ("process.start", "process-create"),
    3: ("network.connection", "network-connect"),
    5: ("process.end", "process-terminated"),
    7: ("log.image_loaded", "image-loaded"),
    8: ("log.remote_thread", "create-remote-thread"),
    10: ("log.process_access", "process-access"),
    11: ("file.create", "file-create"),
    12: ("log.registry_change", "registry-object"),
    13: ("log.registry_change", "registry-value-set"),
    15: ("file.create", "file-stream"),
    22: ("dns.query", "dns-query"),
    23: ("file.delete", "file-delete"),
    26: ("file.delete", "file-delete-logged"),
}
_LOGON_TYPES = {
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "8": "cleartext",
    "9": "new-credentials",
    "10": "remote-interactive",
    "11": "cached",
}


def _windows(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    event_id = f.integer(
        "EventID", "EventId", "event_id", "winlog.event_id", "EventCode", "System.EventID", "Event.System.EventID"
    )
    if event_id is None:
        return None
    provider = (
        f.text(
            "ProviderName",
            "provider_name",
            "winlog.provider_name",
            "Provider.Name",
            "SourceName",
            "Channel",
            "winlog.channel",
            "LogName",
        )
        or ""
    )
    computer = f.text("Computer", "computer_name", "winlog.computer_name", "ComputerName", "Hostname", "host.name")
    if not (computer or provider or "EventData" in obj or "event_data" in obj or "winlog" in obj):
        return None
    sysmon = "sysmon" in provider.lower()
    table = SYSMON_EVENTS if sysmon else WINDOWS_EVENTS
    mapped = table.get(event_id)
    event_type, action = mapped if mapped else ("log.windows_event", f"event-{event_id}")

    def data(*names: str) -> str | None:
        prefixed: list[str] = []
        for name in names:
            prefixed += [name, f"EventData.{name}", f"event_data.{name}", f"winlog.event_data.{name}"]
        return f.text(*prefixed)

    status = (data("Status", "FailureReason", "Result") or "").lower()
    if event_id in (4768, 4769, 4776) and status not in ("", "0x0", "0"):
        event_type = "auth.failure"
    target_user = data("TargetUserName", "MemberName", "TargetSid")
    subject_user = data("SubjectUserName")
    user = data("User", "UserName")
    attrs: dict[str, Any] = {
        "event_code": event_id,
        "provider": provider or None,
        "src_ip": ip(data("IpAddress", "SourceIp", "SourceAddress", "ClientAddress")),
        "dst_ip": ip(data("DestinationIp", "DestAddress")),
        "dst_port": data("DestinationPort", "DestPort"),
        "src_port": data("IpPort", "SourcePort"),
        "logon_type": _LOGON_TYPES.get(data("LogonType") or "", data("LogonType")),
        "status": data("Status"),
        "sub_status": data("SubStatus"),
        "workstation": data("WorkstationName"),
        "logon_id": data("TargetLogonId", "LogonId"),
        "domain": None,
        "image": data("NewProcessName", "Image", "ProcessName", "Application"),
        "command_line": safe_value("command_line", data("CommandLine") or ""),
        "pid": data("NewProcessId", "ProcessId"),
        "parent_pid": data("ProcessId") if event_id == 4688 else data("ParentProcessId"),
        "parent_image": data("ParentProcessName", "ParentImage"),
        "service_name": data("ServiceName"),
        "task_name": data("TaskName"),
        "group": data("TargetUserName") if event_type.startswith("iam.group.") else None,
        "query": data("QueryName") if event_type == "dns.query" else None,
        "file": data("TargetFilename", "ObjectName", "ShareName") if event_type.startswith("file.") else None,
        "hashes": data("Hashes"),
    }
    host = computer or frame.host
    actor: Any = None
    target: Any = None
    if event_type.startswith("auth."):
        actor = user_ref(target_user or user or subject_user)
        target = host
    elif event_type.startswith("process."):
        actor = user_ref(subject_user or user)
    elif event_type.startswith("iam."):
        actor = user_ref(subject_user or user)
        if event_type.startswith("iam.group."):
            target = user_ref(data("MemberName", "MemberSid") or target_user)
        else:
            target = user_ref(target_user)
    elif event_type == "network.connection":
        actor = host
        target = ip_ref(attrs["dst_ip"])
    elif event_type == "dns.query":
        actor = host
        target = ref(ObjectType.DOMAIN.value, attrs["query"]) if attrs["query"] else None
    elif event_type.startswith("file."):
        actor = user_ref(subject_user or user)
        target = attrs.pop("file")
    else:
        actor = user_ref(subject_user or user or target_user)
    if event_type in ("network.connection",) and event_id == 5157:
        attrs["blocked"] = True
    failed = event_type == "auth.failure" or event_id == 5157
    severity = "high" if event_type == "log.audit_log_cleared" else ("low" if failed else None)
    return record(
        event_type,
        timestamp=f.text(
            "TimeCreated.SystemTime",
            "TimeCreated",
            "UtcTime",
            "@timestamp",
            "timestamp",
            "EventTime",
            "TimeGenerated",
            "time",
        ),
        actor=actor,
        target=target,
        host=host,
        outcome_="failure" if failed else ("success" if event_type.startswith(("auth.", "iam.")) else None),
        severity=severity,
        action=action,
        message=_message(f) or f"Windows event {event_id} ({action})",
        attributes={**attrs, **_extras(f, limit=24)},
    )


# --------------------------------------------------------------------------- network sensors


def _suricata(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    kind = obj.get("event_type")
    if kind not in ("alert", "dns", "http", "flow", "tls", "fileinfo", "anomaly", "ssh", "smb", "netflow") or not (
        "src_ip" in obj and ("dest_ip" in obj or "dst_ip" in obj)
    ):
        return None
    src, dst = ip(obj.get("src_ip")), ip(obj.get("dest_ip") or obj.get("dst_ip"))
    base = {
        "src_ip": src,
        "dst_ip": dst,
        "src_port": f.integer("src_port"),
        "dst_port": f.integer("dest_port"),
        "protocol": (f.text("proto") or "").lower() or None,
        "flow_id": f.text("flow_id"),
        "sensor": f.text("host", "sensor_name"),
        "community_id": f.text("community_id"),
    }
    ts = f.text("timestamp")
    if kind == "alert":
        signature = f.text("alert.signature") or "Suricata alert"
        level = f.integer("alert.severity")
        severity = {1: "high", 2: "medium", 3: "low"}.get(level or 3, "low")
        return record(
            "alert",
            timestamp=ts,
            actor=ip_ref(src),
            target=ip_ref(dst),
            severity=severity,
            action=f.text("alert.action") or "alert",
            message=signature,
            attributes={
                **base,
                "signature": signature,
                "signature_id": f.integer("alert.signature_id"),
                "alert_category": f.text("alert.category"),
                "rule_severity": level,
            },
        )
    if kind == "dns":
        query = f.text("dns.rrname", "dns.queries.0.rrname")
        answers = (
            [a for a in (f.get("dns.answers") or []) if isinstance(a, dict)]
            if isinstance(f.get("dns.answers"), list)
            else []
        )
        return record(
            "dns.query",
            timestamp=ts,
            actor=ip_ref(src),
            target=ref(ObjectType.DOMAIN.value, query) if query else None,
            action=f.text("dns.type") or "query",
            attributes={
                **base,
                "query": query,
                "qtype": f.text("dns.rrtype"),
                "rcode": f.text("dns.rcode"),
                "answers": [a.get("rdata") for a in answers if ip(a.get("rdata"))] or None,
            },
        )
    if kind == "http":
        hostname = f.text("http.hostname") or dst or "web"
        path = f.text("http.url") or "/"
        status = f.integer("http.status")
        return record(
            "http.request",
            timestamp=ts,
            actor=ip_ref(src),
            target=url_ref("http", hostname, path),
            outcome_=status_outcome(status),
            action=(f.text("http.http_method") or "get").lower(),
            message=f"{f.text('http.http_method') or 'GET'} {hostname}{path} -> {status or '-'}",
            attributes={
                **base,
                "method": f.text("http.http_method"),
                "path": path.split("?", 1)[0],
                "status": status,
                "user_agent": f.text("http.http_user_agent"),
                "bytes": f.integer("http.length"),
                "vhost": hostname,
            },
        )
    if kind == "tls":
        sni = f.text("tls.sni")
        return record(
            "tls.handshake",
            timestamp=ts,
            actor=ip_ref(src),
            target=ref(ObjectType.DOMAIN.value, sni) if sni else ip_ref(dst),
            attributes={**base, "sni": sni, "tls_version": f.text("tls.version"), "ja3": f.text("tls.ja3.hash")},
        )
    return record(
        "network.flow" if kind in ("flow", "netflow") else f"log.suricata_{slug(str(kind))}",
        timestamp=ts,
        actor=ip_ref(src),
        target=ip_ref(dst),
        attributes={
            **base,
            "bytes_out": f.integer("flow.bytes_toserver", "netflow.bytes"),
            "bytes_in": f.integer("flow.bytes_toclient"),
            "packets": f.integer("flow.pkts_toserver", "netflow.pkts"),
            "flow_state": f.text("flow.state"),
            **_extras(f, limit=12),
        },
    )


def _milliseconds(seconds: float | None) -> float | None:
    return round(seconds * 1000, 3) if seconds is not None else None


def _zeek(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    if "uid" not in obj or not ("id.orig_h" in obj or isinstance(obj.get("id"), dict)):
        return None
    src = ip(f.text("id.orig_h"))
    dst = ip(f.text("id.resp_h"))
    base = {
        "src_ip": src,
        "dst_ip": dst,
        "src_port": f.integer("id.orig_p"),
        "dst_port": f.integer("id.resp_p"),
        "zeek_uid": f.text("uid"),
    }
    ts = f.get("ts")
    if f.get("query") is not None:
        query = f.text("query")
        answers = f.get("answers")
        return record(
            "dns.query",
            timestamp=ts,
            actor=ip_ref(src),
            target=ref(ObjectType.DOMAIN.value, query) if query else None,
            attributes={
                **base,
                "query": query,
                "qtype": f.text("qtype_name"),
                "rcode": f.text("rcode_name"),
                "answers": [a for a in answers if ip(a)] if isinstance(answers, list) else None,
            },
        )
    if f.get("method") is not None and f.get("uri") is not None:
        hostname = f.text("host") or dst or "web"
        status = f.integer("status_code")
        return record(
            "http.request",
            timestamp=ts,
            actor=ip_ref(src),
            target=url_ref("http", hostname, f.text("uri") or "/"),
            outcome_=status_outcome(status),
            action=(f.text("method") or "get").lower(),
            attributes={
                **base,
                "method": f.text("method"),
                "path": (f.text("uri") or "/").split("?", 1)[0],
                "status": status,
                "user_agent": f.text("user_agent"),
                "vhost": hostname,
            },
        )
    if f.get("server_name") is not None:
        sni = f.text("server_name")
        return record(
            "tls.handshake",
            timestamp=ts,
            actor=ip_ref(src),
            target=ref(ObjectType.DOMAIN.value, sni) if sni else ip_ref(dst),
            attributes={**base, "sni": sni, "tls_version": f.text("version")},
        )
    if f.get("note") is not None:
        return record(
            "alert",
            timestamp=ts,
            actor=ip_ref(src),
            target=ip_ref(dst),
            severity="medium",
            message=f.text("msg") or f.text("note"),
            attributes={**base, "note": f.text("note")},
        )
    if f.get("auth_success") is not None:
        ok = f.get("auth_success") in (True, "T", "true")
        return record(
            "auth.login" if ok else "auth.failure",
            timestamp=ts,
            actor=ip_ref(src),
            target=ip_ref(dst),
            outcome_="success" if ok else "failure",
            action="ssh",
            attributes={**base, "protocol": "ssh", "client": f.text("client"), "server": f.text("server")},
        )
    return record(
        "network.flow",
        timestamp=ts,
        actor=ip_ref(src),
        target=ip_ref(dst),
        attributes={
            **base,
            "protocol": f.text("proto"),
            "service": None,
            "app_protocol": f.text("service"),
            "bytes_out": f.integer("orig_bytes"),
            "bytes_in": f.integer("resp_bytes"),
            "duration_ms": _milliseconds(f.number("duration")),
            "conn_state": f.text("conn_state"),
        },
    )


def _sum(*values: int | None) -> int | None:
    present = [v for v in values if v is not None]
    return sum(present) if present else None


def _flow(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    src = _first_ip(f, SRC_IP)
    dst = _first_ip(f, DST_IP)
    if not (src and dst):
        return None
    flowish = f.get(
        *BYTES_IN,
        *BYTES_OUT,
        "bytes",
        "packets",
        "pkts",
        *DST_PORT,
        "protocol",
        "proto",
        "decision",
        "durationMs",
        "duration",
    )
    if flowish is None:
        return None
    decision = f.text("decision", "action", "disposition", "verdict", "result")
    result = outcome(decision)
    blocked = result == "failure"
    protocol = f.text("protocol", "proto", "transport", "network.transport")
    dport = f.integer(*DST_PORT)
    bytes_in = f.integer(*BYTES_IN)
    bytes_out = f.integer(*BYTES_OUT)
    total = f.integer("bytes", "total_bytes")
    return record(
        "network.flow",
        timestamp=_time(f),
        actor=ip_ref(src),
        target=ip_ref(dst),
        outcome_=result,
        severity="low" if blocked else None,
        action=decision.lower() if decision else "flow",
        message=f"{src} -> {dst}"
        + (f":{dport}" if dport is not None else "")
        + (f"/{protocol}" if protocol else "")
        + (f" {decision}" if decision else ""),
        attributes={
            "src_ip": src,
            "dst_ip": dst,
            "src_port": f.integer(*SRC_PORT),
            "dst_port": dport,
            "protocol": protocol.lower() if protocol else None,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "bytes": total if total is not None else _sum(bytes_in, bytes_out),
            "packets": f.integer("packets", "pkts"),
            "duration_ms": f.number("durationMs", "duration_ms", "duration"),
            "decision": decision,
            "blocked": True if blocked else None,
            "sensor": f.text("sensor", "observer", "collector", "exporter"),
            "flow_id": f.text("flowId", "flow_id", "id"),
            "direction": f.text("direction"),
            **_extras(f, limit=12),
        },
    )


# --------------------------------------------------------------------------- endpoint


_NETWORK_KIND = re.compile(r"network|connect|socket", re.IGNORECASE)
_FILE_KIND = re.compile(r"file", re.IGNORECASE)
_DNS_KIND = re.compile(r"dns", re.IGNORECASE)


def _endpoint(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    """EDR / process telemetry: process starts, plus network, file and DNS activity of processes."""
    command = f.text(
        "commandLine",
        "command_line",
        "cmdline",
        "CommandLine",
        "process.command_line",
        "cmd",
        "process.cmdline",
        "ProcessCommandLine",
    )
    image = f.text(
        "image",
        "Image",
        "process_path",
        "processPath",
        "exe",
        "executable",
        "process.executable",
        "ImageFileName",
        "FileName",
        "process_name",
        "processName",
        "ProcessName",
    )
    kind = (
        f.text("event", "eventType", "event_type", "action", "type", "event_simpleName", "EventType", "ActionType")
        or ""
    )
    if not (command or image) or "eventName" in obj:
        return None
    host = f.text(*HOST) or frame.host
    user = f.text("user", "User", "UserName", "username", "user.name", "account", "AccountName", "owner")
    pid = f.text("processId", "ProcessId", "pid", "process_id", "process.pid", "TargetProcessId")
    decision = f.text("action", "decision", "disposition", "verdict")
    result = (
        outcome(decision)
        if decision
        and decision.lower() in ("allow", "allowed", "block", "blocked", "deny", "denied", "prevented", "quarantined")
        else None
    )
    if decision and decision.lower() in ("prevented", "quarantined"):
        result = "failure"
    attrs = {
        "image": image,
        "command_line": safe_value("command_line", command) if command else None,
        "pid": pid,
        "parent_pid": f.text("parentProcessId", "ParentProcessId", "ppid", "parent_pid", "process.parent.pid"),
        "parent_image": f.text(
            "parentImage",
            "ParentImage",
            "parent_process",
            "ParentBaseFileName",
            "process.parent.executable",
            "parentProcessName",
        ),
        "user": user,
        "decision": decision,
        "hash": f.text("sha256", "SHA256HashData", "hash", "hashes", "md5", "process.hash.sha256"),
        "signer": f.text("signer", "Signer", "signature"),
        "integrity": f.text("integrityLevel", "IntegrityLevel"),
        "edr_event": kind or None,
    }
    remote = _first_ip(
        f,
        (
            "remoteIp",
            "remote_ip",
            "RemoteIP",
            "dst_ip",
            "DestinationIp",
            "destination.ip",
            "remote_address",
            "RemoteAddress",
        ),
    )
    if remote and (_NETWORK_KIND.search(kind) or not kind):
        port = f.integer("remotePort", "remote_port", "RemotePort", "DestinationPort", "dst_port")
        return record(
            "network.connection",
            timestamp=_time(f),
            actor=host_ref(host) or ip_ref(f.text("localIp", "local_ip")),
            target=ip_ref(remote),
            host=host,
            outcome_=result,
            action=kind or "connect",
            message=f"{image or 'process'} connected to {remote}" + (f":{port}" if port else ""),
            attributes={
                **attrs,
                "dst_ip": remote,
                "dst_port": port,
                "protocol": f.text("protocol", "Protocol"),
                **_extras(f, limit=12),
            },
        )
    path = f.text(
        "targetFilename", "TargetFilename", "file_path", "filePath", "file.path", "path", "FilePath", "TargetFileName"
    )
    if path and _FILE_KIND.search(kind):
        lowered = kind.lower()
        event_type = (
            "file.delete"
            if "delet" in lowered
            else "file.create"
            if "creat" in lowered or "writ" in lowered
            else ("file.modify" if "modif" in lowered or "renam" in lowered else "file.read")
        )
        return record(
            event_type,
            timestamp=_time(f),
            actor=user_ref(user),
            target=path,
            host=host,
            outcome_=result,
            action=kind,
            attributes={**attrs, "process": image, **_extras(f, limit=12)},
        )
    query = f.text("queryName", "QueryName", "dns.question.name", "query")
    if query and _DNS_KIND.search(kind):
        return record(
            "dns.query",
            timestamp=_time(f),
            actor=host_ref(host),
            target=ref(ObjectType.DOMAIN.value, query),
            host=host,
            action=kind,
            attributes={**attrs, "query": query, **_extras(f, limit=12)},
        )
    shown = (command or image or "process")[:200]
    return record(
        "process.start",
        timestamp=_time(f),
        actor=user_ref(user),
        host=host,
        outcome_=result,
        severity="low" if result == "failure" else None,
        action=kind or "process-start",
        message=redact_text(shown) + (f" by {user}" if user else "") + (f" on {host}" if host else ""),
        attributes={**attrs, **_extras(f, limit=12)},
    )


# --------------------------------------------------------------------------- change records


def _change(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    ticket = f.text(*TICKET)
    if not ticket or f.get("window", "start", "planned_start", "window_start", "status", "approved", "state") is None:
        return None
    if f.get("eventName", "commandLine", "verb", "src", "dst") is not None:
        return None
    tag = (frame.tag or "").lower()
    looks_like_change = (
        tag in ("change", "changes", "itsm", "servicenow", "jira", "cab")
        or f.get("window", "window_start", "planned_start", "approved", "cab") is not None
        or bool(re.match(r"(?i)(chg|cr|rfc|change)[-_]?\d+", ticket))
    )
    if not looks_like_change:
        return None
    timestamp = _time(f) or frame.timestamp
    when: datetime | None = None
    if timestamp:
        try:
            when = parse_timestamp(timestamp)
        except TimestampError:
            when = None
    window = f.get("window")
    start = f.text("window_start", "planned_start", "start", "start_time", "scheduled_start")
    end = f.text("window_end", "planned_end", "end", "end_time", "scheduled_end")
    parsed = change_window(window, when) if isinstance(window, str) else None
    if parsed is not None:
        start, end = format_ts(parsed[0]), format_ts(parsed[1])
    status = f.text("status", "state", "approval")
    service = f.text(*SERVICE, "ci", "system", "target", "asset")
    actor = f.text("actor", "requested_by", "requester", "assignee", "implementer", "owner", "user")
    action = f.text("action", "type", "summary", "title", "description") or "change"
    return record(
        "change.record",
        timestamp=timestamp,
        actor=user_ref(actor),
        target=service_ref(service) if service else None,
        outcome_=(status or "").lower() or None,
        action=action,
        message=f"Change {ticket}: {action}"
        + (f" on {service}" if service else "")
        + (f" ({status})" if status else "")
        + (f", window {window}" if isinstance(window, str) else ""),
        attributes={
            "ticket": ticket,
            "change_status": (status or "").lower() or None,
            "window": window if isinstance(window, str) else None,
            "window_start": start,
            "window_end": end,
            "change_service": service,
            "change_actor": actor,
            **_extras(f, limit=16),
        },
    )


# --------------------------------------------------------------------------- application events

_DOWNLOAD = re.compile(r"download|fetch|read|retriev|get(?:object)?\b|export\.served|serve", re.IGNORECASE)
_WRITE = re.compile(r"upload|export|write|put|creat|save|store|copy", re.IGNORECASE)
_DELETE = re.compile(r"delete|remove|purge|unlink", re.IGNORECASE)


def _file_target(f: Fields, service: str | None) -> tuple[dict[str, Any] | None, str | None]:
    """The file or storage object an application record is about: (reference, path)."""
    location = f.text(
        "object",
        "object_key",
        "objectKey",
        "s3_uri",
        "uri",
        "file",
        "file_path",
        "filePath",
        "path",
        "filename",
        "key",
        "artifact",
    )
    if not location:
        return None, None
    if location.startswith(("s3://", "gs://", "az://", "abfs://")):
        scheme, _, rest = location.partition("://")
        bucket, _, key = rest.partition("/")
        return object_ref(bucket, key, scheme=scheme), location
    if location.startswith(("http://", "https://")) or location.startswith("/api/"):
        return None, location
    name = location.rstrip("/").rsplit("/", 1)[-1] or location
    owner = service or "app"
    return ref(ObjectType.FILE.value, name, key=f"{owner}|{location}", path=location, service=service), location


def _app(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    event_name = f.text("event", "event_name", "eventName", "action", "operation", "activity")
    service = f.text(*SERVICE)
    level = f.text(*LEVEL)
    tag = (frame.tag or "").lower()
    if not (event_name or f.get("msg", "message")) or not (service or level or tag in ("app", "application", "api")):
        return None
    actor_name = f.text("actor", "user", "username", "user_id", "userId", "principal", "account", "email", "uid")
    request_id = f.text(*REQUEST)
    result = f.text("result", "outcome", "status")
    result_outcome = outcome(result) if result else None
    target_ref, location = _file_target(f, service)
    name = event_name or "message"
    objects: list[dict[str, Any] | None] = []
    relationships: list[dict[str, Any] | None] = []
    attrs: dict[str, Any] = {
        "level": level.lower() if level else None,
        "app_event": event_name,
        "service": service,
        "request_id": request_id,
        "result": result,
        "pod": f.text("pod", "pod_name", "kubernetes.pod.name"),
        "path": location,
        "bytes": f.integer("bytes", "size", "length", "content_length"),
        "sha256": f.text("sha256", "hash", "checksum"),
        "ticket": f.text(*TICKET),
        "latency_ms": f.number("latency_ms", "latency", "duration_ms", "elapsed_ms"),
        "src_ip": _first_ip(f, SRC_IP),
        "cache": f.text("cache", "link", "visibility", "access"),
    }
    entries = f.get("entries", "files", "members", "contents", "manifest")
    if target_ref is not None and isinstance(entries, list):
        listed = [str(e) for e in entries if isinstance(e, str | int) and str(e).strip()][:64]
        attrs["entries"] = listed
        attrs["secret_entries"] = [e for e in listed if secret_bearing(e)] or None
        container_key = target_ref.get("key") or target_ref["name"]
        for entry in listed:
            entry_ref = ref(
                ObjectType.FILE.value,
                entry.rstrip("/").rsplit("/", 1)[-1] or entry,
                key=f"{container_key}!/{entry}",
                path=entry,
                container=location,
                secret_bearing=True if secret_bearing(entry) else None,
            )
            objects.append(role(entry_ref, "contains"))
            relationships.append(rel("CONTAINS", target_ref, entry_ref, source_record="manifest"))
    fingerprint_value = f.text(
        "credentialFingerprint", "credential_fingerprint", "key_fingerprint", "token_fingerprint", "secret_fingerprint"
    )
    runner = f.text("runner", "agent", "worker", "executor", "node", "hostname", "host")
    if fingerprint_value:
        secret = ref(
            ObjectType.SECRET.value,
            fingerprint_value,
            key=f"fingerprint|{fingerprint_value}",
            kind="credential",
            fingerprint=fingerprint_value,
        )
        objects.append(role(secret, "credential"))
        attrs["credential_fingerprint"] = fingerprint_value
        if service:
            relationships.append(rel("USES", service_ref(service), secret, job=f.text("job", "job_name")))
    if f.text("job", "job_name", "task"):
        attrs["job"] = f.text("job", "job_name", "task")
    lowered = name.lower()
    actor: Any = user_ref(actor_name) if actor_name and actor_name.lower() not in ("system", "-") else None
    if _AUTH_WORDS.search(lowered) and actor_name and is_person(actor_name):
        event_type, result_outcome = _auth_event(lowered, result)
        target: Any = service_ref(service) if service else None
    elif target_ref is not None and _DELETE.search(lowered):
        event_type, target = "file.delete", target_ref
    elif target_ref is not None and _DOWNLOAD.search(lowered):
        event_type, target = "file.read", target_ref
    elif target_ref is not None and _WRITE.search(lowered):
        event_type, target = "file.create", target_ref
    elif actor_name and is_person(actor_name):
        event_type, target = "service.access", service_ref(service) if service else None
    else:
        event_type, target = f"log.{slug(name)}", target_ref or (service_ref(service) if service else None)
    if event_type.startswith("file.") and actor is None:
        actor = service_ref(service) if service else None
    if event_type.startswith("log.") and target_ref is not None and target is not target_ref:
        objects.append(role(target_ref, "file"))
    message = _message(f)
    shown = message or f"{name}" + (f" by {actor_name}" if actor_name else "") + (f" on {service}" if service else "")
    if location and not message:
        shown += f": {location}"
    return record(
        event_type,
        timestamp=_time(f),
        actor=actor,
        target=target,
        host=host_ref(runner) if runner and not f.text("pod") else None,
        outcome_=result_outcome,
        severity=level_severity(level),
        action=name,
        message=shown,
        attributes={**attrs, **_extras(f, limit=24)},
        objects=objects,
        relationships=relationships,
    )


# --------------------------------------------------------------------------- DNS / HTTP / database records


def _dns_json(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    query = f.text("query", "qname", "question.name", "rrname", "query_name", "queryName", "domain")
    if not query or f.get("answers", "rcode", "qtype", "query_type", "response_code", "answer", "rr_type") is None:
        return None
    client = _first_ip(f, SRC_IP)
    answers = f.get("answers", "answer", "resolved_ips")
    listed = [a for a in (answers if isinstance(answers, list) else [answers]) if ip(a)] if answers else []
    return record(
        "dns.query",
        timestamp=_time(f),
        actor=ip_ref(client) or host_ref(f.text(*HOST)),
        target=ref(ObjectType.DOMAIN.value, query),
        outcome_="failure"
        if (f.text("rcode", "response_code") or "").upper() in ("NXDOMAIN", "SERVFAIL", "REFUSED")
        else None,
        attributes={
            "query": query,
            "qtype": f.text("qtype", "query_type", "rr_type", "type"),
            "rcode": f.text("rcode", "response_code"),
            "answers": listed or None,
            "src_ip": client,
            **_extras(f, limit=12),
        },
    )


def _http_json(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    method = f.text("method", "request_method", "http_method", "http.request.method", "cs_method")
    path = f.text("path", "uri", "url", "request_uri", "requestUri", "url.path", "cs_uri_stem", "request")
    status = f.integer("status", "status_code", "statusCode", "response_code", "http.response.status_code", "sc_status")
    if not (method and path and status is not None):
        return None
    if " " in path and path.split(" ", 1)[0].isupper():  # "GET /x HTTP/1.1"
        path = path.split(" ")[1] if len(path.split(" ")) > 1 else path
    client = _first_ip(f, SRC_IP)
    vhost = f.text("vhost", "server_name", "host_header", "http_host", "hostname", "cs_host") or frame.host
    login = f.text("user", "remote_user", "username", "cs_username")
    return record(
        "http.request",
        timestamp=_time(f),
        actor=ip_ref(client) or host_ref(f.text("client", "remote_host")),
        target=url_ref("http", vhost, path),
        host=frame.host,
        outcome_=status_outcome(status),
        severity="low" if status in (401, 403) else None,
        action=method.lower(),
        message=f"{method} {path.split('?', 1)[0]} -> {status}",
        attributes={
            "src_ip": client,
            "method": method,
            "path": path.split("?", 1)[0],
            "query_string": safe_value("query", path.split("?", 1)[1]) if "?" in path else None,
            "status": status,
            "bytes": f.integer("bytes", "body_bytes_sent", "bytes_sent", "size", "sc_bytes"),
            "user_agent": f.text(*USER_AGENT),
            "user": login,
            "request_id": f.text(*REQUEST),
            "vhost": vhost,
            **_extras(f, limit=16),
        },
        objects=[{"name": login, "role": "user"}] if login and login != "-" else [],
    )


def _db_json(obj: dict[str, Any], f: Fields, frame: Frame) -> dict[str, Any] | None:
    statement = f.text("statement", "sql", "query_text", "sql_text", "db.statement")
    database = f.text("database", "db", "dbname", "db.name", "schema")
    if not (statement and database):
        return None
    return database_record(
        engine=f.text("engine", "db.system") or "database",
        host=f.text(*HOST) or frame.host,
        user=f.text("user", "db_user", "username", "db.user"),
        database=database,
        client=_first_ip(f, SRC_IP),
        application=f.text("application", "app", "application_name"),
        level=f.text(*LEVEL),
        message=statement,
        timestamp=_time(f),
        extra=_extras(f, limit=12),
    )


# --------------------------------------------------------------------------- generic


def generic_record(f: Fields, frame: Frame, *, family: str = "json") -> dict[str, Any]:
    """Any record: the usual fields wherever they are, the rest kept as attributes."""
    event_name = f.text(*EVENT)
    actor_name = f.text(*ACTOR)
    src = _first_ip(f, SRC_IP)
    dst = _first_ip(f, DST_IP)
    host = f.text(*HOST) or frame.host
    service = f.text(*SERVICE)
    result = f.text(*OUTCOME)
    level = f.text(*LEVEL) or frame.level
    lowered = (event_name or "").lower()
    target: Any = None
    actor: Any = user_ref(actor_name) if actor_name and is_person(actor_name) else None
    if lowered and (_AUTH_WORDS.search(lowered) or _LOGOUT_WORDS.search(lowered)) and actor is not None:
        event_type, result_outcome = _auth_event(lowered, result)
        target = service_ref(service) if service else host_ref(host)
    elif src and dst:
        event_type, result_outcome = "network.connection", outcome(result)
        actor, target = ip_ref(src), ip_ref(dst)
    elif event_name:
        event_type, result_outcome = f"log.{slug(event_name)}", outcome(result)
        target = service_ref(service) if service else None
    else:
        event_type, result_outcome = "log.message", outcome(result)
        target = service_ref(service) if service else None
    if actor is None and src:
        actor = ip_ref(src)
    message = _message(f) or (event_name or "")
    attrs: dict[str, Any] = {
        "src_ip": src,
        "dst_ip": dst,
        "src_port": f.integer(*SRC_PORT),
        "dst_port": f.integer(*DST_PORT),
        "level": level.lower() if isinstance(level, str) else level,
        "service": service if target is None or event_type.startswith("network.") else None,
        "request_id": f.text(*REQUEST),
        "session_id": f.text(*SESSION),
        "user": actor_name if actor_name and actor is None else None,
        "user_agent": f.text(*USER_AGENT),
        "result": result,
        "record_family": family,
        **_extras(f, limit=48),
    }
    return record(
        event_type,
        timestamp=_time(f),
        actor=actor,
        target=target,
        host=host_ref(host) if host and not event_type.startswith("network.") else None,
        outcome_=result_outcome,
        severity=level_severity(level),
        action=event_name,
        message=message or None,
        attributes=attrs,
        objects=[_session(service or family, attrs["session_id"])] if attrs["session_id"] else [],
    )


#: Decoders in the order they are tried: the most specific signatures first.
JSON_DECODERS: tuple[tuple[str, Decoder], ...] = (
    ("cloudtrail", _cloudtrail),
    ("k8s-audit", _k8s_audit),
    ("gcp-audit", _gcp_audit),
    ("azure-activity", _azure_activity),
    ("azure-signin", _azure_signin),
    ("okta", _okta),
    ("windows", _windows),
    ("suricata", _suricata),
    ("zeek", _zeek),
    ("ecs", _ecs),
    ("change", _change),
    ("identity", _identity),
    ("edr", _endpoint),
    ("flow", _flow),
    ("dns", _dns_json),
    ("http", _http_json),
    ("database", _db_json),
    ("app", _app),
)


def decode_structured(data: dict[str, Any], frame: Frame, *, kv: bool = False) -> tuple[str, dict[str, Any]]:
    """(family, native record) for a JSON object or a key=value record."""
    fields = Fields(data)
    for family, decoder in JSON_DECODERS:
        fields.used.clear()
        result = decoder(data, fields, frame)
        if result is not None:
            return family, result
    fields.used.clear()
    family = "kv" if kv else "json"
    return family, generic_record(fields, frame, family=family)


__all__ = ["JSON_DECODERS", "WINDOWS_EVENTS", "decode_structured", "generic_record", "secret_bearing"]
