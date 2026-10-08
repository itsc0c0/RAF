"""Canonical event taxonomy.

Event types are dot-separated (``category.action``). For each known type the
taxonomy defines the default object types of ``actor`` and ``target`` (used
when a record gives bare names) and a short description. Unknown event types
are accepted; their category is the first segment.
"""

from __future__ import annotations

from dataclasses import dataclass

from raf.core.objects.types import ObjectType


@dataclass(frozen=True, slots=True)
class EventSpec:
    event_type: str
    actor: str | None
    target: str | None
    description: str


_SPECS: tuple[EventSpec, ...] = (
    EventSpec("auth.login", ObjectType.USER, ObjectType.HOST, "Successful authentication / logon."),
    EventSpec("auth.failure", ObjectType.USER, ObjectType.HOST, "Failed authentication attempt."),
    EventSpec("auth.logout", ObjectType.USER, ObjectType.HOST, "Session end / logoff."),
    EventSpec("auth.mfa", ObjectType.USER, ObjectType.HOST, "Multi-factor challenge."),
    EventSpec("auth.privilege", ObjectType.USER, ObjectType.HOST, "Privilege elevation (sudo, su, runas)."),
    EventSpec("auth.lockout", ObjectType.USER, ObjectType.HOST, "Account locked out after failed attempts."),
    EventSpec("process.start", ObjectType.USER, ObjectType.PROCESS, "Process creation."),
    EventSpec("process.end", ObjectType.USER, ObjectType.PROCESS, "Process termination."),
    EventSpec("file.create", ObjectType.PROCESS, ObjectType.FILE, "File created."),
    EventSpec("file.modify", ObjectType.PROCESS, ObjectType.FILE, "File modified."),
    EventSpec("file.delete", ObjectType.PROCESS, ObjectType.FILE, "File deleted."),
    EventSpec("file.read", ObjectType.PROCESS, ObjectType.FILE, "File read / accessed."),
    EventSpec("network.connection", ObjectType.HOST, ObjectType.IP, "Network connection attempt."),
    EventSpec("network.flow", ObjectType.IP, ObjectType.IP, "Network flow summary."),
    EventSpec("dns.query", ObjectType.HOST, ObjectType.DOMAIN, "DNS resolution."),
    EventSpec("http.request", ObjectType.HOST, ObjectType.URL, "HTTP request."),
    EventSpec("tls.handshake", ObjectType.IP, ObjectType.DOMAIN, "TLS handshake (server name indication)."),
    EventSpec("iam.role.assign", ObjectType.IDENTITY, ObjectType.USER, "Role granted to a principal."),
    EventSpec("iam.role.remove", ObjectType.IDENTITY, ObjectType.USER, "Role removed from a principal."),
    EventSpec("iam.group.add", ObjectType.IDENTITY, ObjectType.USER, "Principal added to a group."),
    EventSpec("iam.group.remove", ObjectType.IDENTITY, ObjectType.USER, "Principal removed from a group."),
    EventSpec("iam.permission.grant", ObjectType.IDENTITY, ObjectType.USER, "Permission granted on a resource."),
    EventSpec("iam.permission.revoke", ObjectType.IDENTITY, ObjectType.USER, "Permission revoked."),
    EventSpec("iam.user.create", ObjectType.IDENTITY, ObjectType.USER, "Account created."),
    EventSpec("iam.user.disable", ObjectType.IDENTITY, ObjectType.USER, "Account disabled."),
    EventSpec("iam.user.enable", ObjectType.IDENTITY, ObjectType.USER, "Account enabled."),
    EventSpec("iam.user.modify", ObjectType.IDENTITY, ObjectType.USER, "Account changed."),
    EventSpec("iam.user.delete", ObjectType.IDENTITY, ObjectType.USER, "Account deleted."),
    EventSpec("iam.credential.create", ObjectType.IDENTITY, ObjectType.IDENTITY, "Credential / key created."),
    EventSpec("service.access", ObjectType.USER, ObjectType.SERVICE, "Access to an application or service."),
    EventSpec("policy.change", ObjectType.IDENTITY, ObjectType.POLICY, "Policy modified."),
    EventSpec("cloud.api", ObjectType.IDENTITY, ObjectType.CLOUD_RESOURCE, "Cloud control-plane API call."),
    EventSpec("db.query", ObjectType.IDENTITY, ObjectType.SERVICE, "Database statement."),
    EventSpec("change.record", ObjectType.USER, ObjectType.SERVICE, "Change record: ticket, window, approval."),
    EventSpec("alert", ObjectType.HOST, ObjectType.HOST, "Detection / alert from a security tool."),
    EventSpec("evidence.collected", ObjectType.USER, ObjectType.EVIDENCE, "Evidence acquisition."),
    EventSpec("log.message", ObjectType.HOST, ObjectType.HOST, "Unstructured log line."),
)

EVENT_SPECS: dict[str, EventSpec] = {s.event_type: s for s in _SPECS}

CATEGORIES = (
    "auth",
    "process",
    "file",
    "network",
    "dns",
    "http",
    "tls",
    "iam",
    "service",
    "policy",
    "cloud",
    "db",
    "change",
    "alert",
    "evidence",
    "log",
)


def category_of(event_type: str) -> str:
    return event_type.split(".", 1)[0] if event_type else "log"


def spec_for(event_type: str) -> EventSpec | None:
    spec = EVENT_SPECS.get(event_type)
    if spec is not None:
        return spec
    if event_type.startswith("alert"):
        return EVENT_SPECS["alert"]
    return None


def default_action(event_type: str) -> str:
    return event_type.rsplit(".", 1)[-1] if "." in event_type else event_type
