"""Traversal semantics of relationships for exposure modeling.

For each relationship type (and, where it matters, endpoint types) this module
states whether an attacker who controls one endpoint can reasonably act on the
other, in which direction, in which *mode*, with what confidence factor, and
*why*. Blast, IAM paths, Exposure and Ghost all use these rules, so their
answers are consistent and every hop carries an explanation.

Modes
-----
* ``control`` - acting with the privileges of / owning the next object.
* ``reach``   - network reachability only (packets can arrive); it does not by
  itself grant control. Reach continues only through network structure.
* ``trust``   - a trust relationship lets identities of one realm act in another.

This is a defensive *model* of possible impact, not an exploitation engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from raf.core.objects.types import ObjectType

CONTROL = "control"
REACH = "reach"
TRUST = "trust"

_PRINCIPALS = {ObjectType.USER, ObjectType.IDENTITY, ObjectType.GROUP, ObjectType.ROLE, ObjectType.PERMISSION}
_COMPUTE = {ObjectType.HOST, ObjectType.SERVICE, ObjectType.CONTAINER, ObjectType.CLOUD_RESOURCE}


@dataclass(frozen=True, slots=True)
class Traversal:
    mode: str
    factor: float
    why: str  # template with {frm} and {to}


def _t(source_type: str, target_type: str) -> tuple[str, str]:
    return source_type, target_type


def traversals(rel_type: str, source_type: str, target_type: str) -> tuple[Traversal | None, Traversal | None]:
    """Return (forward, reverse) traversals for a relationship ``source -[rel_type]-> target``.

    Forward means moving from the relationship's source to its target.
    """
    st, tt = source_type, target_type
    if rel_type == "LOGGED_INTO":
        return (
            Traversal(
                CONTROL, 0.8, "{frm} has authenticated to {to}; compromised credentials of {frm} can be used on {to}"
            ),
            Traversal(
                CONTROL,
                0.5,
                "{to} has had a session on {frm}; whoever controls {frm} may capture {to}'s credentials or session",
            ),
        )
    if rel_type == "ADMIN_OF":
        return Traversal(CONTROL, 1.0, "{frm} has administrative rights on {to}"), None
    if rel_type == "MEMBER_OF":
        if st in _PRINCIPALS:
            return Traversal(CONTROL, 1.0, "{frm} is a member of {to} and inherits its access"), None
        if tt == ObjectType.NETWORK:
            return (
                Traversal(REACH, 1.0, "{frm} is located in network {to}"),
                Traversal(REACH, 1.0, "{to} is located in network {frm}"),
            )
        return None, None
    if rel_type == "HAS_ROLE":
        return Traversal(CONTROL, 1.0, "{frm} holds the role {to}"), None
    if rel_type == "HAS_PERMISSION":
        return Traversal(CONTROL, 1.0, "{frm} grants the permission {to}"), None
    if rel_type == "CAN_ACCESS":
        return Traversal(CONTROL, 0.9, "{frm} is permitted to access {to}"), None
    if rel_type == "CAN_ASSUME":
        return Traversal(CONTROL, 1.0, "{frm} can assume {to}"), None
    if rel_type == "HAS_IDENTITY":
        return Traversal(CONTROL, 1.0, "{frm} controls the account {to}"), None
    if rel_type == "USES" and tt in (ObjectType.IDENTITY, ObjectType.USER):
        return Traversal(CONTROL, 0.8, "credentials of {to} are present on {frm}"), None
    if rel_type == "RUNS":
        if tt in (ObjectType.SERVICE, ObjectType.CONTAINER):
            return (
                Traversal(CONTROL, 0.9, "{frm} hosts {to}"),
                Traversal(CONTROL, 0.4, "{frm} runs on {to}; code execution in {frm} can extend to its host"),
            )
        if tt == ObjectType.PROCESS:
            return Traversal(CONTROL, 0.9, "{to} runs on {frm}"), None
        return None, None
    if rel_type == "DEPLOYS_TO":
        return Traversal(CONTROL, 0.9, "{frm} deploys code to {to}"), None
    if rel_type == "CONTAINS":
        if st in (ObjectType.CLOUD_RESOURCE, ObjectType.ORGANIZATION) or tt in _COMPUTE:
            return Traversal(CONTROL, 0.9, "{to} is part of {frm}"), None
        if st in (ObjectType.HOST, ObjectType.DIRECTORY) and tt in (ObjectType.FILE, ObjectType.DIRECTORY):
            return Traversal(CONTROL, 1.0, "{to} is stored on {frm}"), None
        return None, None
    if rel_type == "CONTAINS_SECRET":
        return Traversal(CONTROL, 0.9, "the secret {to} is stored in {frm}"), None
    if rel_type == "AUTHENTICATES_AS":
        return Traversal(CONTROL, 1.0, "{frm} is a credential for {to}"), None
    if rel_type == "TRUSTS":
        return None, Traversal(TRUST, 0.8, "{to} trusts {frm}; identities from {frm} are accepted by {to}")
    if rel_type == "OWNS" and st in _PRINCIPALS:
        return Traversal(CONTROL, 0.6, "{frm} owns {to}; ownership usually implies administrative access"), None
    if rel_type == "CAN_REACH":
        return Traversal(REACH, 0.9, "network policy allows traffic from {frm} to {to}"), None
    if rel_type == "CONNECTED_TO" and st in (ObjectType.HOST, ObjectType.IP) and tt in (ObjectType.HOST, ObjectType.IP):
        return Traversal(REACH, 0.6, "{frm} has been observed connecting to {to}"), None
    if rel_type == "HAS_ADDRESS":
        return (
            Traversal(REACH, 1.0, "{to} is an address of {frm}"),
            Traversal(REACH, 1.0, "{frm} is an address of {to}"),
        )
    return None, None


def explain(template: str, frm: str, to: str, metadata: dict[str, Any] | None = None) -> str:
    text = template.format(frm=frm, to=to)
    meta = metadata or {}
    details = []
    for key in ("access", "credential_location", "credential", "ports", "policy", "via", "mechanism"):
        value = meta.get(key)
        if value and key != "via":
            details.append(
                f"{key.replace('_', ' ')}: {', '.join(map(str, value)) if isinstance(value, list) else value}"
            )
    if details:
        text += " (" + "; ".join(details) + ")"
    return text


def is_privileged(obj_type: str, metadata: dict[str, Any] | None, tags: list[str] | None = None) -> bool:
    meta = metadata or {}
    if meta.get("privileged") is True or meta.get("wildcard") is True:
        return True
    return bool(tags and "privileged" in tags)
