"""Graph export formats: JSON, Cytoscape JSON, GraphML, DOT, CSV edge list."""

from __future__ import annotations

import csv
import io
import json
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from raf.core.errors import InvalidInputError
from raf.core.graph.algorithms import Subgraph

FORMATS = ("json", "cytoscape", "graphml", "dot", "csv")


def export_subgraph(graph: Subgraph, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps(graph.to_json_dict(), indent=2, ensure_ascii=False)
    if fmt == "cytoscape":
        elements: list[dict[str, Any]] = [
            {"data": {"id": n.id, "label": n.name, "type": n.type, "criticality": n.criticality}} for n in graph.nodes
        ]
        elements += [
            {"data": {"id": e.id, "source": e.source, "target": e.target, "label": e.type, "confidence": e.confidence}}
            for e in graph.edges
        ]
        return json.dumps({"elements": elements}, indent=2, ensure_ascii=False)
    if fmt == "graphml":
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="name" for="node" attr.name="name" attr.type="string"/>',
            '  <key id="type" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="criticality" for="node" attr.name="criticality" attr.type="string"/>',
            '  <key id="rel" for="edge" attr.name="relationship_type" attr.type="string"/>',
            '  <key id="confidence" for="edge" attr.name="confidence" attr.type="double"/>',
            '  <graph id="raf" edgedefault="directed">',
        ]
        for n in graph.nodes:
            lines.append(
                f'    <node id={quoteattr(n.id)}><data key="name">{escape(n.name)}</data>'
                f'<data key="type">{escape(n.type)}</data>'
                f'<data key="criticality">{escape(n.criticality or "")}</data></node>'
            )
        for e in graph.edges:
            lines.append(
                f"    <edge id={quoteattr(e.id)} source={quoteattr(e.source)} target={quoteattr(e.target)}>"
                f'<data key="rel">{escape(e.type)}</data>'
                f'<data key="confidence">{e.confidence}</data></edge>'
            )
        lines += ["  </graph>", "</graphml>"]
        return "\n".join(lines) + "\n"
    if fmt == "dot":

        def q(text: str) -> str:
            return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'

        lines = ["digraph raf {", "  rankdir=LR;", "  node [shape=box, fontname=Helvetica];"]
        for n in graph.nodes:
            lines.append(f"  {q(n.id)} [label={q(f'{n.name} ({n.type})')}];")
        for e in graph.edges:
            lines.append(f"  {q(e.source)} -> {q(e.target)} [label={q(e.type)}];")
        lines.append("}")
        return "\n".join(lines) + "\n"
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "relationship_id",
                "source",
                "relationship_type",
                "target",
                "confidence",
                "first_seen",
                "last_seen",
                "valid_to",
            ]
        )
        for e in graph.edges:
            writer.writerow(
                [
                    e.id,
                    e.source,
                    e.type,
                    e.target,
                    e.confidence,
                    e.first_seen or "",
                    e.last_seen or "",
                    e.valid_to or "",
                ]
            )
        return buffer.getvalue()
    raise InvalidInputError(f"Unknown graph export format '{fmt}'.", hint="Formats: " + ", ".join(FORMATS))
