"""Canonical content of objects, relationships and findings: what snapshots and diffs compare.

Bookkeeping (``updated_at``, ``last_seen``, observation counts, a few volatile metadata keys) is
left out, so re-observing the same state does not look like change. :func:`content_hash` is the
SHA-256 of the canonical JSON. The store writes it on every object and relationship row together
with the row (``content_hash`` column), so snapshots of large workspaces copy hashes instead of
recomputing them.

Bodies are computed from JSON values: metadata exactly as the store returns it. Metadata built in
memory (drafts) is first normalized like a JSON round trip (:func:`json_value`), so a row hashes
the same before and after it is written.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

#: Metadata keys that record when something was looked at, not what it is.
VOLATILE_META = frozenset({"state_changed_at", "status_history", "last_scan", "scanned_at"})


def canonical(value: Any) -> Any:
    """``value`` with dictionary keys sorted and volatile keys dropped at every level."""
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in sorted(value.items()) if k not in VOLATILE_META}
    if isinstance(value, list | tuple):
        return [canonical(v) for v in value]
    return value


def json_value(value: Any) -> Any:
    """``value`` as the store returns it after writing it as JSON (tuples become lists, keys strings).

    Values that are already plain JSON (string keys, lists) are returned as they are without a copy."""
    if _is_json(value):
        return value
    return json.loads(json.dumps(value))


def _is_json(value: Any) -> bool:
    if isinstance(value, dict):
        return all(isinstance(k, str) and _is_json(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_is_json(v) for v in value)
    return value is None or isinstance(value, str | int | float)  # bool is an int


def object_body(
    type_: str, name: str, tags: Iterable[str], metadata: dict[str, Any], active: bool, synthetic: bool
) -> dict[str, Any]:
    return {
        "type": type_,
        "name": name,
        "tags": sorted(tags),
        "metadata": canonical(metadata),
        "active": active,
        "synthetic": synthetic,
    }


def relationship_body(type_: str, source: str, target: str, metadata: dict[str, Any], active: bool) -> dict[str, Any]:
    return {
        "type": type_,
        "source": source,
        "target": target,
        "metadata": canonical({k: v for k, v in metadata.items() if k != "via"}),
        "active": active,
    }


def finding_body(finding: Any) -> dict[str, Any]:
    return {
        "title": finding.title,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "product": finding.product,
        "rule_id": finding.rule_id,
        "affected": sorted(finding.affected_objects),
        "confidence": round(float(finding.confidence), 2),
    }


def content_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
