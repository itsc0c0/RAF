"""Relationship builder: derives first-class relationships from normalized events.

Every derived relationship records the event that produced it (provenance is
attached by the pipeline). Rules only assert what the event supports:
a failed login creates no LOGGED_INTO edge, a blocked connection no
CONNECTED_TO edge, a failed (e.g. denied) access change neither grants nor
ends access (no HAS_ROLE, MEMBER_OF or CAN_ACCESS change), a process that failed
to start creates no process edges and a failed policy change no MODIFIED edge;
removal events *end* relationships (valid_to) rather than deleting history.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from raf.core.objects.models import EventDraft, ObjectDraft, RelationshipDraft
from raf.core.objects.types import ObjectType, RelationshipType

_PRIVILEGED_ACCOUNTS = {"root", "administrator", "system", "nt authority\\system", "admin"}
_PRINCIPALS = {ObjectType.USER, ObjectType.IDENTITY, ObjectType.GROUP, ObjectType.ROLE}


@dataclass(slots=True)
class BuildOutput:
    relationships: list[RelationshipDraft] = field(default_factory=list)
    object_patches: list[ObjectDraft] = field(default_factory=list)


class _Ctx:
    def __init__(self, ev: EventDraft, types: dict[str, str], out: BuildOutput) -> None:
        self.ev = ev
        self.types = types
        self.out = out
        self.roles: dict[str, list[str]] = {}
        for ref in ev.objects:
            self.roles.setdefault(ref.role, []).append(ref.object_id)

    def first(self, *roles: str) -> str | None:
        for role in roles:
            ids = self.roles.get(role)
            if ids:
                return ids[0]
        return None

    def all(self, role: str) -> list[str]:
        return list(self.roles.get(role, []))

    def type_of(self, object_id: str | None) -> str | None:
        if object_id is None:
            return None
        return self.types.get(object_id) or object_id.split(":", 1)[0]

    @property
    def ok(self) -> bool:
        return self.ev.outcome != "failure"

    def rel(
        self,
        source: str | None,
        rel_type: str,
        target: str | None,
        *,
        confidence: float = 1.0,
        end: bool = False,
        **meta: Any,
    ) -> None:
        if not source or not target or source == target:
            return
        ev = self.ev
        metadata = {k: v for k, v in meta.items() if v is not None}
        metadata.setdefault("via", ev.event_type)
        draft = RelationshipDraft.make(
            source,
            rel_type,
            target,
            source=ev.source,
            confidence=round(min(ev.confidence, confidence), 4),
            metadata=metadata,
            synthetic=ev.synthetic,
        )
        if end:
            draft.last_seen = ev.timestamp
            draft.valid_to = ev.timestamp
        else:
            draft.observe(ev.timestamp)
        self.out.relationships.append(draft)


def _auth_login(c: _Ctx) -> None:
    if not c.ok:
        return
    attrs = c.ev.attributes
    c.rel(
        c.ev.actor,
        RelationshipType.LOGGED_INTO,
        c.ev.target,
        method=attrs.get("method"),
        protocol=attrs.get("protocol"),
        logon_type=attrs.get("logon_type"),
    )
    src = c.first("src_ip")
    if src and c.type_of(c.ev.target) in (ObjectType.HOST, ObjectType.IP):
        c.rel(src, RelationshipType.CONNECTED_TO, c.ev.target, confidence=0.9, dst_port=attrs.get("dst_port"))


def _auth_privilege(c: _Ctx) -> None:
    as_user = str(c.ev.attributes.get("as_user") or "").lower()
    if c.ok and as_user in _PRIVILEGED_ACCOUNTS and c.type_of(c.ev.target) == ObjectType.HOST:
        c.rel(
            c.ev.actor, RelationshipType.ADMIN_OF, c.ev.target, confidence=0.9, as_user=as_user, mechanism=c.ev.action
        )


def _process_start(c: _Ctx) -> None:
    if not c.ok:  # the process did not start (e.g. blocked)
        return
    process = c.ev.target
    c.rel(c.first("parent"), RelationshipType.SPAWNED, process)
    if c.type_of(c.ev.actor) in (ObjectType.USER, ObjectType.IDENTITY):
        c.rel(c.ev.actor, RelationshipType.STARTED, process)
    c.rel(process, RelationshipType.EXECUTED, c.first("image"))
    c.rel(c.first("host"), RelationshipType.RUNS, process)


def _process_end(c: _Ctx) -> None:
    c.rel(c.first("host"), RelationshipType.RUNS, c.ev.target, end=True)


_FILE_RELS = {
    "file.create": RelationshipType.CREATED,
    "file.modify": RelationshipType.MODIFIED,
    "file.delete": RelationshipType.DELETED,
    "file.read": RelationshipType.READ,
}


def _file(c: _Ctx) -> None:
    rel_type = _FILE_RELS.get(c.ev.event_type)
    if rel_type is None or not c.ok:
        return
    actor = c.first("process") or c.ev.actor
    c.rel(actor, rel_type, c.ev.target)
    host = c.first("host")
    c.rel(host, RelationshipType.CONTAINS, c.ev.target, confidence=0.9, end=c.ev.event_type == "file.delete")
    c.rel(c.first("bucket"), RelationshipType.CONTAINS, c.ev.target, confidence=0.95)


def _network(c: _Ctx) -> None:
    attrs = c.ev.attributes
    if c.ok and c.ev.attributes.get("blocked") is not True:
        ports = [attrs["dst_port"]] if attrs.get("dst_port") is not None else None
        c.rel(c.ev.actor, RelationshipType.CONNECTED_TO, c.ev.target, protocol=attrs.get("protocol"), ports=ports)
    host, src = c.first("host"), c.first("src_ip")
    if host and src and c.type_of(host) == ObjectType.HOST:
        c.rel(host, RelationshipType.HAS_ADDRESS, src, confidence=0.8)


def _dns(c: _Ctx) -> None:
    domain = c.ev.target if c.type_of(c.ev.target) == ObjectType.DOMAIN else c.first("domain")
    c.rel(c.ev.actor, RelationshipType.RESOLVED, domain)
    for answer in c.all("answer"):
        c.rel(domain, RelationshipType.RESOLVES_TO, answer, confidence=0.95)


def _http(c: _Ctx) -> None:
    c.rel(c.ev.actor, RelationshipType.REQUESTED, c.ev.target, method=c.ev.attributes.get("method"))
    domain, dst = c.first("domain"), c.first("dst_ip")
    if domain and dst:
        c.rel(domain, RelationshipType.RESOLVES_TO, dst, confidence=0.8)


def _tls(c: _Ctx) -> None:
    if c.ok:
        c.rel(c.ev.actor, RelationshipType.CONNECTED_TO, c.ev.target, protocol="tls")


def _role(c: _Ctx) -> None:
    if not c.ok:  # a failed assignment grants nothing, a failed removal ends nothing
        return
    c.rel(
        c.ev.target,
        RelationshipType.HAS_ROLE,
        c.first("role"),
        granted_by=c.ev.actor,
        end=c.ev.event_type == "iam.role.remove",
    )


def _group(c: _Ctx) -> None:
    if not c.ok:  # a failed addition adds nothing, a failed removal ends nothing
        return
    c.rel(
        c.ev.target,
        RelationshipType.MEMBER_OF,
        c.first("group"),
        changed_by=c.ev.actor,
        end=c.ev.event_type == "iam.group.remove",
    )


def _permission(c: _Ctx) -> None:
    if not c.ok:
        return
    c.rel(
        c.ev.target,
        RelationshipType.CAN_ACCESS,
        c.first("resource"),
        granted_by=c.ev.actor,
        access=c.ev.attributes.get("access"),
        end=c.ev.event_type == "iam.permission.revoke",
    )


def _user_state(c: _Ctx) -> None:
    target = c.ev.target
    if not target or not c.ok:
        return
    disabled = c.ev.event_type == "iam.user.disable"
    otype = c.type_of(target) or ObjectType.USER
    patch = ObjectDraft(
        type=otype,
        name=target.split(":", 1)[-1],
        id=target,
        source=c.ev.source,
        confidence=0.1,
        observations=0,
        metadata={"disabled": disabled, "state_changed_at": c.ev.timestamp.isoformat()},
    )
    c.out.object_patches.append(patch)


def _service_access(c: _Ctx) -> None:
    if c.ok:
        c.rel(c.ev.actor, RelationshipType.CAN_ACCESS, c.ev.target, confidence=0.8, observed=True)


#: Error codes meaning the request's credential did not authenticate (as opposed to "not authorized").
_AUTH_ERRORS = frozenset(
    {
        "invalidclienttokenid",
        "signaturedoesnotmatch",
        "invalidaccesskeyid",
        "unrecognizedclientexception",
        "expiredtoken",
        "expiredtokenexception",
        "authfailure",
        "invalidtoken",
    }
)
_OBJECT_RELS = {
    "getobject": RelationshipType.READ,
    "headobject": RelationshipType.READ,
    "putobject": RelationshipType.CREATED,
    "copyobject": RelationshipType.CREATED,
    "deleteobject": RelationshipType.DELETED,
}


def _credential(c: _Ctx) -> None:
    """A request signed with a credential: the credential authenticates as the actor (unless it did not
    authenticate at all) and the source address used it."""
    credential = c.first("credential")
    if credential is None:
        return
    error = str(c.ev.attributes.get("error_code") or "").lower()
    if error not in _AUTH_ERRORS:
        c.rel(credential, RelationshipType.AUTHENTICATES_AS, c.ev.actor, confidence=0.95)
    c.rel(c.first("src_ip"), RelationshipType.USES, credential, confidence=0.9, api=c.ev.action)


def _cloud_api(c: _Ctx) -> None:
    _credential(c)
    if not c.ok:
        return
    if c.type_of(c.ev.target) == ObjectType.ROLE:
        c.rel(c.ev.actor, RelationshipType.CAN_ASSUME, c.ev.target, observed=True)
    elif c.type_of(c.ev.actor) in _PRINCIPALS:
        c.rel(c.ev.actor, RelationshipType.CAN_ACCESS, c.ev.target, confidence=0.7, observed=True, api=c.ev.action)
    stored = c.first("object")
    if stored is not None:
        c.rel(c.ev.target, RelationshipType.CONTAINS, stored, confidence=0.95)
        rel_type = _OBJECT_RELS.get(str(c.ev.action or "").lower())
        if rel_type is not None:
            c.rel(c.ev.actor, rel_type, stored, api=c.ev.action)


def _db_query(c: _Ctx) -> None:
    if not c.ok:
        return
    c.rel(c.ev.actor, RelationshipType.CAN_ACCESS, c.ev.target, confidence=0.8, observed=True)
    c.rel(c.first("host"), RelationshipType.RUNS, c.ev.target, confidence=0.9)


def _policy_change(c: _Ctx) -> None:
    if c.ok:
        c.rel(c.ev.actor, RelationshipType.MODIFIED, c.ev.target)


RULES: dict[str, Callable[[_Ctx], None]] = {
    "auth.login": _auth_login,
    "auth.privilege": _auth_privilege,
    "process.start": _process_start,
    "process.end": _process_end,
    "file.create": _file,
    "file.modify": _file,
    "file.delete": _file,
    "file.read": _file,
    "network.connection": _network,
    "network.flow": _network,
    "dns.query": _dns,
    "http.request": _http,
    "tls.handshake": _tls,
    "iam.role.assign": _role,
    "iam.role.remove": _role,
    "iam.group.add": _group,
    "iam.group.remove": _group,
    "iam.permission.grant": _permission,
    "iam.permission.revoke": _permission,
    "iam.user.disable": _user_state,
    "iam.user.enable": _user_state,
    "service.access": _service_access,
    "cloud.api": _cloud_api,
    "db.query": _db_query,
    "policy.change": _policy_change,
}


def build(ev: EventDraft, types: dict[str, str]) -> BuildOutput:
    out = BuildOutput()
    ctx = _Ctx(ev, types, out)
    rule = RULES.get(ev.event_type)
    if rule is not None:
        rule(ctx)
    if rule is not _cloud_api and "credential" in ctx.roles:
        _credential(ctx)
    return out
