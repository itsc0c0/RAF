"""R$F Diff: what changed between two security states, and why it matters.

Every change is classified into a category and given an importance with a
written reason, following documented rules (docs/products/diff.md):

* HIGH   - privilege granted to/through a privileged role or onto a high/critical
           asset; new internet exposure; new vulnerability with CVSS >= 7 on an
           asset; new network reachability into a high/critical zone; a new
           HIGH/CRITICAL finding, one raised to HIGH/CRITICAL, or one that now
           affects more objects.
* MEDIUM - other privilege grants; new hosts, services or identities; new
           vulnerabilities with CVSS < 7; policy changes; other new findings,
           findings raised in severity or affecting more objects, findings
           whose confidence level rose.
* LOW    - removals (risk reduction), package version changes, other
           relationship, metadata or finding changes.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError
from raf.core.objects.models import RafModel
from raf.core.objects.types import Severity, confidence_level
from raf.core.snapshots.service import StateView, resolve_state
from raf.core.timeutil import utcnow

PRIVILEGE_RELS = {
    "HAS_ROLE",
    "MEMBER_OF",
    "CAN_ACCESS",
    "ADMIN_OF",
    "CAN_ASSUME",
    "HAS_PERMISSION",
    "USES",
    "AUTHENTICATES_AS",
    "TRUSTS",
    "DEPLOYS_TO",
    "HAS_IDENTITY",
    "OWNS",
}
NETWORK_RELS = {"CAN_REACH", "ALLOWS", "DENIES"}
ACTIVITY_RELS = {
    "LOGGED_INTO",
    "SPAWNED",
    "STARTED",
    "EXECUTED",
    "CREATED",
    "MODIFIED",
    "DELETED",
    "READ",
    "CONNECTED_TO",
    "RESOLVED",
    "REQUESTED",
    "RUNS",
}
CATEGORIES = (
    "privileges",
    "exposure",
    "vulnerabilities",
    "network",
    "policies",
    "hosts",
    "services",
    "identities",
    "packages",
    "findings",
    "objects",
    "relationships",
    "activity",
)
_HIGH_CRIT = {"high", "critical"}
_PKG_RE = re.compile(r"^package:(?P<eco>[^/]+)/(?P<name>.+)@(?P<version>[^@]+)$")
_VERSION_PART_RE = re.compile(r"[0-9]+|[^0-9]+")
_IMPORTANCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_SEVERITY_RANK = {sev.value: sev.rank for sev in Severity}
_LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


class Change(RafModel):
    category: str
    change: str  # added | removed | changed
    item_kind: str
    item_id: str
    label: str
    importance: str
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


class DiffResult(RafModel):
    a: str
    b: str
    generated_at: datetime
    summary: dict[str, dict[str, int]]
    importance: dict[str, int]
    totals: dict[str, int]
    changes: list[Change]


def _obj_label(body: dict[str, Any] | None, item_id: str) -> str:
    if body and body.get("name"):
        return f"{body['name']} ({body.get('type')})"
    return item_id


def _newest_first(versions: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """``(version, id)`` pairs, highest version first; versions compare number by number (2.10 > 2.9)."""

    def key(item: tuple[str, str]) -> tuple[tuple[tuple[int, int, str], ...], str]:
        parts = _VERSION_PART_RE.findall(item[0])  # imported text: only ASCII digit runs are numbers
        return tuple((0, int(p), "") if p[0] in "0123456789" else (1, 0, p) for p in parts), item[1]

    return sorted(versions, key=key, reverse=True)


def validate_category(value: str) -> str:
    """A change category (case-insensitive); anything else is an :class:`InvalidInputError` naming the valid ones."""
    category = value.strip().lower()
    if category not in CATEGORIES:
        raise InvalidInputError(
            f"Unknown change category '{value}'.",
            hint="Categories: " + ", ".join(CATEGORIES),
            details={"valid_categories": list(CATEGORIES)},
        )
    return category


class DiffService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx

    def diff(self, a_ref: str, b_ref: str) -> DiffResult:
        a = resolve_state(self.ctx, a_ref)
        b = resolve_state(self.ctx, b_ref)
        return self.compare(a, b)

    def compare(self, a: StateView, b: StateView) -> DiffResult:
        changes: list[Change] = []
        obj_a, obj_b = a.hashes.get("object", {}), b.hashes.get("object", {})
        # Object bodies needed for labels/criticality of both endpoints of relationship changes.
        bodies_a = a.body(obj_a.values())
        bodies_b = b.body(obj_b.values())
        objects_a = {i: bodies_a.get(h) for i, h in obj_a.items()}
        objects_b = {i: bodies_b.get(h) for i, h in obj_b.items()}
        changes += self._objects(objects_a, objects_b, obj_a, obj_b)
        changes += self._relationships(a, b, {**objects_a, **objects_b})
        changes += self._findings(a, b)
        changes.sort(key=lambda c: (_IMPORTANCE_RANK[c.importance], c.category, c.item_id))
        summary: dict[str, dict[str, int]] = {}
        for change in changes:
            bucket = summary.setdefault(change.category, {"added": 0, "removed": 0, "changed": 0})
            bucket[change.change] += 1
        importance = Counter(c.importance for c in changes)
        totals = {
            "objects_a": len(obj_a),
            "objects_b": len(obj_b),
            "relationships_a": len(a.hashes.get("relationship", {})),
            "relationships_b": len(b.hashes.get("relationship", {})),
            "changes": len(changes),
        }
        return DiffResult(
            a=a.label,
            b=b.label,
            generated_at=utcnow(),
            summary=summary,
            importance={k: importance.get(k, 0) for k in ("HIGH", "MEDIUM", "LOW")},
            totals=totals,
            changes=changes,
        )

    # ------------------------------------------------------------------ objects
    def _objects(
        self, objects_a: dict[str, Any], objects_b: dict[str, Any], hashes_a: dict[str, str], hashes_b: dict[str, str]
    ) -> list[Change]:
        added = sorted(set(hashes_b) - set(hashes_a))
        removed = sorted(set(hashes_a) - set(hashes_b))
        changed = sorted(i for i in set(hashes_a) & set(hashes_b) if hashes_a[i] != hashes_b[i])
        # A package whose version changed is reported once, as a version change, not also as added and removed.
        changes, paired = self._package_versions(added, removed)
        for item_id in added:
            if item_id not in paired:
                changes.append(self._object_presence(item_id, objects_b.get(item_id) or {}, "added"))
        for item_id in removed:
            if item_id not in paired:
                changes.append(self._object_presence(item_id, objects_a.get(item_id) or {}, "removed"))
        for item_id in changed:
            before, after = objects_a.get(item_id) or {}, objects_b.get(item_id) or {}
            changes.append(self._object_changed(item_id, before, after))
        return changes

    def _package_versions(self, added: list[str], removed: list[str]) -> tuple[list[Change], set[str]]:
        """Version changes: a removed ``package:<eco>/<name>@<v1>`` paired with an added ``...@<v2>`` of the same
        package. With several versions on a side, the newest removed one pairs with the newest added one, and so
        on (versions compared number by number); unpaired versions stay plain additions or removals.

        Returns the changes and the IDs of the paired packages."""
        versions: dict[tuple[str, str], tuple[list[tuple[str, str]], list[tuple[str, str]]]] = {}
        for side, items in ((0, removed), (1, added)):
            for item in items:
                m = _PKG_RE.match(item)
                if m:
                    versions.setdefault((m["eco"], m["name"]), ([], []))[side].append((m["version"], item))
        changes: list[Change] = []
        paired: set[str] = set()
        for (eco, name), (old, new) in sorted(versions.items()):
            for (old_version, old_id), (new_version, new_id) in zip(
                _newest_first(old), _newest_first(new), strict=False
            ):
                paired.update((old_id, new_id))
                changes.append(
                    Change(
                        category="packages",
                        change="changed",
                        item_kind="object",
                        item_id=new_id,
                        label=f"{name} ({eco})",
                        importance="LOW",
                        reason=f"package version changed {old_version} -> {new_version}",
                        details={"from": old_version, "to": new_version, "previous_id": old_id},
                    )
                )
        return changes, paired

    def _object_presence(self, item_id: str, body: dict[str, Any], change: str) -> Change:
        otype = str(body.get("type") or item_id.split(":", 1)[0])
        meta = body.get("metadata") or {}
        crit = str(meta.get("criticality") or "").lower()
        label = _obj_label(body, item_id)
        category = {
            "host": "hosts",
            "service": "services",
            "user": "identities",
            "identity": "identities",
            "package": "packages",
            "policy": "policies",
            "vulnerability": "vulnerabilities",
        }.get(otype, "objects")
        if change == "removed":
            return Change(
                category=category,
                change=change,
                item_kind="object",
                item_id=item_id,
                label=label,
                importance="LOW",
                reason=f"{otype} no longer present",
            )
        importance, reason = "LOW", f"new {otype}"
        if otype in ("host", "service", "identity", "user", "cloud_resource", "container"):
            importance, reason = "MEDIUM", f"new {otype} in the environment"
            if meta.get("internet_facing"):
                importance, reason = "HIGH", f"new internet-facing {otype}"
            elif crit in _HIGH_CRIT:
                importance, reason = "HIGH", f"new {crit}-criticality {otype}"
        if otype == "identity" and meta.get("privileged"):
            importance, reason = "HIGH", "new privileged identity"
        if otype == "policy":
            importance, reason = "MEDIUM", "policy added"
        return Change(
            category=category,
            change=change,
            item_kind="object",
            item_id=item_id,
            label=label,
            importance=importance,
            reason=reason,
        )

    def _object_changed(self, item_id: str, before: dict[str, Any], after: dict[str, Any]) -> Change:
        fields: dict[str, Any] = {}
        mb, ma = before.get("metadata") or {}, after.get("metadata") or {}
        for key in sorted(set(mb) | set(ma)):
            if mb.get(key) != ma.get(key):
                fields[key] = {"from": mb.get(key), "to": ma.get(key)}
        for key in ("name", "tags", "active", "synthetic"):
            if before.get(key) != after.get(key):
                fields[key] = {"from": before.get(key), "to": after.get(key)}
        otype = str(after.get("type") or before.get("type") or "")
        label = _obj_label(after or before, item_id)
        category, importance, reason = "objects", "LOW", "metadata changed: " + ", ".join(sorted(fields)[:6])
        if "internet_facing" in fields:
            category = "exposure"
            if fields["internet_facing"]["to"]:
                importance, reason = "HIGH", "became internet-facing"
            else:
                importance, reason = "LOW", "no longer internet-facing (exposure reduced)"
        elif "criticality" in fields:
            category, importance, reason = (
                "exposure",
                "MEDIUM",
                (f"criticality {fields['criticality']['from']} -> {fields['criticality']['to']}"),
            )
        elif "privileged" in fields and fields["privileged"]["to"]:
            category, importance, reason = "privileges", "HIGH", f"{otype} became privileged"
        elif "disabled" in fields:
            category = "identities"
            importance, reason = (
                ("LOW", "account disabled") if fields["disabled"]["to"] else ("MEDIUM", "account re-enabled")
            )
        elif otype == "policy":
            category, importance, reason = "policies", "MEDIUM", "policy definition changed"
        elif "cvss" in fields:
            category, importance, reason = "vulnerabilities", "MEDIUM", "vulnerability score changed"
        return Change(
            category=category,
            change="changed",
            item_kind="object",
            item_id=item_id,
            label=label,
            importance=importance,
            reason=reason,
            details={"fields": fields},
        )

    # ------------------------------------------------------------------ relationships
    def _relationships(self, a: StateView, b: StateView, objects: dict[str, Any]) -> list[Change]:
        ra, rb = a.hashes.get("relationship", {}), b.hashes.get("relationship", {})
        added = sorted(set(rb) - set(ra))
        removed = sorted(set(ra) - set(rb))
        changed = sorted(i for i in set(ra) & set(rb) if ra[i] != rb[i])
        bodies = {**a.body([ra[i] for i in removed + changed]), **b.body([rb[i] for i in added + changed])}
        changes: list[Change] = []
        for rid in added:
            changes.append(self._rel_change(rid, bodies[rb[rid]], "added", objects))
        for rid in removed:
            changes.append(self._rel_change(rid, bodies[ra[rid]], "removed", objects))
        for rid in changed:
            before, after = bodies[ra[rid]], bodies[rb[rid]]
            if before.get("active") and not after.get("active"):
                changes.append(self._rel_change(rid, after, "removed", objects, note="relationship ended"))
            elif not before.get("active") and after.get("active"):
                changes.append(self._rel_change(rid, after, "added", objects, note="relationship re-activated"))
            else:
                change = self._rel_change(rid, after, "changed", objects)
                change.importance = "LOW"
                change.reason = "relationship attributes changed"
                change.details["from"] = before.get("metadata")
                change.details["to"] = after.get("metadata")
                changes.append(change)
        return changes

    def _rel_change(
        self, rid: str, body: dict[str, Any], change: str, objects: dict[str, Any], note: str | None = None
    ) -> Change:
        rtype, src, dst = body["type"], body["source"], body["target"]
        src_body, dst_body = objects.get(src) or {}, objects.get(dst) or {}
        label = f"{src_body.get('name', src)} -{rtype}-> {dst_body.get('name', dst)}"
        dst_meta = dst_body.get("metadata") or {}
        dst_crit = str(dst_meta.get("criticality") or "").lower()
        details = {"type": rtype, "source": src, "target": dst}
        if rtype in PRIVILEGE_RELS:
            category = "privileges"
            if change == "removed":
                importance, reason = "LOW", note or f"{rtype} removed (privilege reduced)"
            elif dst_meta.get("privileged") or dst_crit in _HIGH_CRIT or rtype == "ADMIN_OF":
                importance = "HIGH"
                reason = note or (
                    f"{rtype} grants access to a {dst_crit or 'privileged'} target"
                    if rtype != "ADMIN_OF"
                    else "administrative rights granted"
                )
            else:
                importance, reason = "MEDIUM", note or f"new {rtype} privilege"
        elif rtype in NETWORK_RELS:
            category = "exposure" if src.endswith(":internet") else "network"
            if change == "removed":
                importance, reason = "LOW", note or "network reachability removed (segmentation)"
            elif src.endswith(":internet"):
                importance, reason = "HIGH", note or "new reachability from the internet"
            elif dst_crit in _HIGH_CRIT:
                importance, reason = "HIGH", note or f"new network path into {dst_crit}-criticality zone"
            else:
                importance, reason = "MEDIUM", note or "new network reachability"
        elif rtype == "AFFECTS":
            category = "vulnerabilities"
            cvss = float((src_body.get("metadata") or {}).get("cvss") or 0)
            details["cvss"] = cvss
            if change == "removed":
                importance, reason = "LOW", note or "vulnerability resolved / patched"
            elif cvss >= 7:
                importance, reason = "HIGH", note or f"new vulnerability (CVSS {cvss}) on {dst_body.get('name', dst)}"
            else:
                importance, reason = "MEDIUM", note or f"new vulnerability (CVSS {cvss})"
        elif rtype in ACTIVITY_RELS:
            category, importance, reason = "activity", "LOW", note or f"{rtype} {change}"
        else:
            category, importance, reason = "relationships", "LOW", note or f"{rtype} {change}"
        return Change(
            category=category,
            change=change,
            item_kind="relationship",
            item_id=rid,
            label=label,
            importance=importance,
            reason=reason,
            details=details,
        )

    # ------------------------------------------------------------------ findings
    def _findings(self, a: StateView, b: StateView) -> list[Change]:
        fa, fb = a.hashes.get("finding", {}), b.hashes.get("finding", {})
        bodies = {**a.body(fa.values()), **b.body(fb.values())}
        changes: list[Change] = []
        for fid in sorted(set(fb) - set(fa)):
            body = bodies.get(fb[fid]) or {}
            sev = str(body.get("severity", "LOW"))
            changes.append(
                Change(
                    category="findings",
                    change="added",
                    item_kind="finding",
                    item_id=fid,
                    label=str(body.get("title", fid)),
                    importance="HIGH" if sev in ("HIGH", "CRITICAL") else "MEDIUM",
                    reason=f"new {sev} finding",
                )
            )
        for fid in sorted(set(fa) - set(fb)):
            body = bodies.get(fa[fid]) or {}
            changes.append(
                Change(
                    category="findings",
                    change="removed",
                    item_kind="finding",
                    item_id=fid,
                    label=str(body.get("title", fid)),
                    importance="LOW",
                    reason="finding no longer present",
                )
            )
        for fid in sorted(i for i in set(fa) & set(fb) if fa[i] != fb[i]):
            before, after = bodies.get(fa[fid]) or {}, bodies.get(fb[fid]) or {}
            changes.append(self._finding_changed(fid, before, after))
        return changes

    def _finding_changed(self, fid: str, before: dict[str, Any], after: dict[str, Any]) -> Change:
        """One change per finding; its importance is the highest of its field changes, its reason lists them."""
        fields: dict[str, Any] = {}
        parts: list[tuple[str, str]] = []  # (importance, reason)
        severe = str(after.get("severity")) in ("HIGH", "CRITICAL")
        sev_a, sev_b = before.get("severity"), after.get("severity")
        if sev_a != sev_b:
            fields["severity"] = {"from": sev_a, "to": sev_b}
            if _SEVERITY_RANK.get(str(sev_b), -1) > _SEVERITY_RANK.get(str(sev_a), -1):
                parts.append(("HIGH" if severe else "MEDIUM", f"severity {sev_a} -> {sev_b}"))
            else:
                parts.append(("LOW", f"severity {sev_a} -> {sev_b} (risk reduced)"))
        affected_a, affected_b = set(before.get("affected") or []), set(after.get("affected") or [])
        if affected_a != affected_b:
            more, fewer = sorted(affected_b - affected_a), sorted(affected_a - affected_b)
            fields["affected_objects"] = {"added": more, "removed": fewer}
            if more:
                parts.append(("HIGH" if severe else "MEDIUM", f"affects {len(more)} more object(s)"))
            if fewer:
                parts.append(("LOW", f"affects {len(fewer)} fewer object(s)"))
        conf_a, conf_b = before.get("confidence"), after.get("confidence")
        if conf_a != conf_b:
            fields["confidence"] = {"from": conf_a, "to": conf_b}
            level_a, level_b = confidence_level(float(conf_a or 0)), confidence_level(float(conf_b or 0))
            raised = _LEVEL_RANK[level_b] > _LEVEL_RANK[level_a]
            text = f"confidence {float(conf_a or 0):.2f} -> {float(conf_b or 0):.2f}"
            parts.append(("MEDIUM", f"{text} ({level_a} -> {level_b})") if raised else ("LOW", text))
        if before.get("status") != after.get("status"):
            fields["status"] = {"from": before.get("status"), "to": after.get("status")}
            parts.append(("LOW", f"status {before.get('status')} -> {after.get('status')}"))
        for key in ("title", "product", "rule_id"):
            if before.get(key) != after.get(key):
                fields[key] = {"from": before.get(key), "to": after.get(key)}
                parts.append(("LOW", f"{key.replace('_', ' ')} changed"))
        if not parts:
            parts.append(("LOW", "finding changed"))
        return Change(
            category="findings",
            change="changed",
            item_kind="finding",
            item_id=fid,
            label=str(after.get("title") or before.get("title") or fid),
            importance=min((importance for importance, _ in parts), key=_IMPORTANCE_RANK.__getitem__),
            reason="; ".join(reason for _, reason in parts),
            details={"fields": fields},
        )
