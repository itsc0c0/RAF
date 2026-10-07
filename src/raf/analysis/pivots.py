"""Cross-product pivots: every object offers the views that make sense for it.

The same pivot list powers ``raf show`` (terminal) and the web UI pivot menu,
so products feel like views into one security universe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from raf.core.objects.types import ObjectType

_ASSETS = {"host", "service", "cloud_resource", "container", "network", "project"}
_PRINCIPALS = {"user", "identity", "group", "role"}
_ACTIVITY = {
    "host",
    "user",
    "identity",
    "process",
    "file",
    "ip",
    "domain",
    "url",
    "service",
    "session",
    "connection",
    "incident",
}


@dataclass(frozen=True, slots=True)
class Pivot:
    key: str  # one-letter shortcut shown in the terminal
    product: str
    label: str
    command: str
    view: str  # web UI route

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "product": self.product,
            "label": self.label,
            "command": self.command,
            "view": self.view,
        }


def _quote(ref: str) -> str:
    return f'"{ref}"' if any(ch.isspace() for ch in ref) else ref


def pivots_for(object_id: str, object_type: str, available: set[str] | None = None) -> list[Pivot]:
    ref = _quote(object_id)
    pivots: list[Pivot] = [
        Pivot("G", "graph", "Graph", f"raf graph {ref}", f"/graph?focus={object_id}"),
    ]
    if object_type in _ACTIVITY or object_type == ObjectType.INCIDENT:
        pivots.append(Pivot("T", "timeline", "Timeline", f"raf timeline {ref}", f"/timeline?object={object_id}"))
    if object_type == ObjectType.INCIDENT:
        pivots.append(Pivot("R", "replay", "Replay", f"raf replay {ref}", f"/replay?incident={object_id}"))
    if object_type != ObjectType.INCIDENT:
        pivots.append(Pivot("X", "trace", "Trace", f"raf trace {ref}", f"/investigate?trace={object_id}"))
    if object_type in _PRINCIPALS or object_type in _ASSETS:
        pivots.append(Pivot("B", "blast", "Blast", f"raf blast {ref}", f"/exposure?blast={object_id}"))
    if object_type in _ASSETS:
        pivots.append(Pivot("P", "exposure", "Exposure", f"raf exposure show {ref}", f"/exposure?object={object_id}"))
    if object_type in _PRINCIPALS:
        pivots.append(Pivot("I", "iam", "IAM paths", f"raf iam show {ref}", f"/exposure?iam={object_id}"))
    pivots.append(
        Pivot("E", "evidence", "Evidence", f"raf evidence list --object {ref}", f"/evidence?object={object_id}")
    )
    pivots.append(Pivot("L", "lens", "Lens", f"raf lens {ref}", f"/investigate?object={object_id}"))
    if available is not None:
        pivots = [p for p in pivots if p.product in available]
    return pivots
