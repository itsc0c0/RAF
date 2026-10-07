"""``raf graph``: the security relationship graph in the terminal."""

from __future__ import annotations

import shlex
from collections import deque
from pathlib import Path
from typing import cast

import typer
from rich.text import Text
from rich.tree import Tree

from raf.core.errors import InvalidInputError
from raf.core.graph.algorithms import Subgraph
from raf.core.graph.export import FORMATS, export_subgraph
from raf.core.graph.source import Direction
from raf.core.objects.types import validate_object_type, validate_relationship_type
from raf.core.query.scope import resolve_scope
from raf.products.graph.service import GraphService, PathResult
from raf.sdk import cli as rt

app = typer.Typer(add_completion=False)

_SUBCOMMANDS = {"path", "neighbors", "export", "stats"}
_TREE_LIMIT = 80


def _node_label(subgraph: Subgraph, node_id: str) -> Text:
    node = subgraph.node_index().get(node_id)
    if node is None:
        return Text(node_id)
    text = Text(node.name, style="bold")
    text.append(f"  {node.type}", style="dim")
    if node.criticality in ("high", "critical"):
        text.append(f"  [{node.criticality.upper()}]", style="red")
    if node.missing:
        text.append("  (not in store)", style="yellow")
    return text


def _layered_tree(subgraph: Subgraph, roots: list[str]) -> dict[str, tuple[str, str, bool]]:
    """Tree parents of a layered view (neighborhood, incident): a neighbor one level closer to a root."""
    depth = {n.id: n.depth for n in subgraph.nodes}
    parent_edge: dict[str, tuple[str, str, bool]] = {}
    for edge in subgraph.edges:
        for child, parent, forward in ((edge.target, edge.source, True), (edge.source, edge.target, False)):
            if child in parent_edge or child in roots:
                continue
            if depth.get(parent, -1) == depth.get(child, -2) - 1:
                parent_edge[child] = (parent, edge.type, forward)
    return parent_edge


def _spanning_forest(subgraph: Subgraph) -> tuple[list[str], dict[str, tuple[str, str, bool]]]:
    """Roots and tree parents of a view without layers (analysis, job, workspace overview): breadth-first trees
    over the view's relationships, each started from the most connected node not yet in a tree (then by ID), so
    every node appears exactly once, either as a root or under a neighbor."""
    adjacency: dict[str, list[tuple[str, str, bool]]] = {}
    for edge in sorted(subgraph.edges, key=lambda e: (e.type, e.source, e.target, e.id)):
        if edge.source == edge.target:
            continue
        adjacency.setdefault(edge.source, []).append((edge.target, edge.type, True))
        adjacency.setdefault(edge.target, []).append((edge.source, edge.type, False))
    order = sorted((n.id for n in subgraph.nodes), key=lambda i: (-len(adjacency.get(i, ())), i))
    members = set(order)
    roots: list[str] = []
    parent_edge: dict[str, tuple[str, str, bool]] = {}
    placed: set[str] = set()
    for start in order:
        if start in placed:
            continue
        roots.append(start)
        placed.add(start)
        queue = deque([start])
        while queue:
            node = queue.popleft()
            for neighbor, etype, forward in adjacency.get(node, ()):
                if neighbor in placed or neighbor not in members:
                    continue
                placed.add(neighbor)
                parent_edge[neighbor] = (node, etype, forward)
                queue.append(neighbor)
    return roots, parent_edge


def render_subgraph(subgraph: Subgraph, title: str) -> None:
    rt.header(f"R$F GRAPH  {title}")
    rt.kv_block(
        [("Nodes", len(subgraph.nodes)), ("Edges", len(subgraph.edges)), ("Depth", subgraph.depth)]
        + ([("As of", rt.ts_text(subgraph.at))] if subgraph.at else []),
        width=8,
    )
    if subgraph.truncated:
        rt.warn("view truncated at graph.max_nodes; narrow it with --rel / --node-type / --depth")
    c = rt.console()
    if not subgraph.nodes:
        c.print("Nothing to show.")
        return
    node_ids = {n.id for n in subgraph.nodes}
    roots = [r for r in subgraph.roots if r in node_ids]
    if roots:
        parent_edge = _layered_tree(subgraph, roots)
    else:  # the scope itself is not a node (analysis, job) or there is none (workspace): every node is a root
        roots, parent_edge = _spanning_forest(subgraph)
    children: dict[str, list[tuple[str, str, bool]]] = {}
    for child, (parent, etype, forward) in sorted(parent_edge.items(), key=lambda kv: (kv[1][1], kv[0])):
        children.setdefault(parent, []).append((child, etype, forward))
    printed = 0  # lines: roots and branches

    def add(branch: Tree, node_id: str) -> None:
        nonlocal printed
        for child, etype, forward in children.get(node_id, []):
            if printed >= _TREE_LIMIT:
                return
            printed += 1
            arrow = Text(f"{etype} → " if forward else f"← {etype} ", style="cyan")
            sub = branch.add(arrow + _node_label(subgraph, child))
            add(sub, child)

    c.print()
    shown_roots = 0
    for root in roots:
        if printed >= _TREE_LIMIT:
            break
        printed += 1
        shown_roots += 1
        tree = Tree(_node_label(subgraph, root))
        add(tree, root)
        c.print(tree)
    unattached = [n for n in subgraph.nodes if n.id not in parent_edge and n.id not in roots]
    if unattached:
        c.print(
            Text(
                f"{len(unattached)} nodes without a tree parent (use --json or the web UI for the full graph)",
                style="dim",
            )
        )
    if printed >= _TREE_LIMIT:
        hidden = len(roots) - shown_roots
        more = f"; {hidden} more root(s) not shown" if hidden else ""
        c.print(
            Text(
                f"... output limited to {_TREE_LIMIT} lines{more} (raf graph ... --json for everything)",
                style="dim",
            )
        )


def render_path(result: PathResult) -> None:
    rt.header(f"R$F GRAPH PATH  {result.source} → {result.target}")
    if not result.found:
        rt.console().print("No path found" + (" following relationship directions" if result.directed else "") + ".")
        if result.directed:
            rt.next_steps([f"raf graph path {shlex.quote(result.source)} {shlex.quote(result.target)}  (undirected)"])
        return
    steps: list[tuple[str, str, str | None]] = []
    for hop in result.hops:
        edge = hop.relationship.type if hop.forward else f"{hop.relationship.type} (reverse)"
        steps.append((hop.source_name, hop.source, edge))
    last = result.hops[-1]
    steps.append((last.target_name, last.target, None))
    rt.console().print()
    rt.render_chain(steps)
    rt.console().print()
    rt.console().print(Text(f"{result.length} hop(s)", style="dim"))


@app.command(
    "graph",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="""Explore the security graph.

Forms:
  raf graph alice | raf graph user alice | raf graph INC-001 | raf graph analysis-3 | raf graph @last
  raf graph path alice DB-01 [--directed]
  raf graph neighbors WS-04
  raf graph export INC-001 --format graphml --output inc.graphml
  raf graph stats""",
)
def graph_cmd(
    words: list[str] = typer.Argument(None, help="Subject, or a subcommand (path, neighbors, export, stats)."),
    depth: int | None = typer.Option(None, "--depth", "-d", min=1, max=6, help="Neighborhood depth."),
    rel: list[str] = typer.Option(None, "--rel", help="Only these relationship types (repeatable)."),
    node_type: list[str] = typer.Option(None, "--node-type", help="Only these object types (repeatable)."),
    at: str | None = typer.Option(None, "--at", help="Graph as of a time (relationships valid then)."),
    max_nodes: int | None = typer.Option(None, "--max-nodes", min=1),
    directed: bool = typer.Option(False, "--directed", help="Paths must follow relationship direction."),
    direction: str = typer.Option("both", "--direction", help="in, out or both."),
    fmt: str = typer.Option("json", "--format", help="Export format: " + ", ".join(FORMATS)),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write export to a file."),
) -> None:
    ctx = rt.ctx()
    service = GraphService(ctx)
    args = list(words or [])
    rel_types = [validate_relationship_type(r) for r in rel] if rel else None
    node_types = [validate_object_type(t) for t in node_type] if node_type else None
    when = rt.parse_time_option(at)
    if direction not in ("in", "out", "both"):
        raise InvalidInputError("--direction must be in, out or both.")
    sub = args[0] if args and args[0] in _SUBCOMMANDS else None
    if sub == "stats":
        stats = service.stats()

        def render_stats() -> None:
            rt.header("R$F GRAPH STATS")
            rt.kv_block(
                [("Objects", f"{stats['total_objects']:,}"), ("Relationships", f"{stats['total_relationships']:,}")],
                width=16,
            )
            rt.console().print()
            rt.table(["OBJECT TYPE", "COUNT"], sorted(stats["objects"].items(), key=lambda kv: -kv[1]))
            rt.console().print()
            rt.table(["RELATIONSHIP", "COUNT"], sorted(stats["relationships"].items(), key=lambda kv: -kv[1]))
            if stats["most_connected"]:
                rt.console().print()
                rt.table(
                    ["MOST CONNECTED", "ID", "DEGREE"],
                    [(m["name"], m["id"], m["degree"]) for m in stats["most_connected"]],
                )

        rt.output("raf.graph.stats/v1", stats, render_stats)
        return
    if sub == "path":
        if len(args) != 3:
            raise InvalidInputError("Usage: raf graph path <from> <to>")
        a, b = ctx.resolve(args[1]), ctx.resolve(args[2])
        result = service.path(a.id, b.id, directed=directed, rel_types=rel_types, at=when)
        rt.output("raf.graph.path/v1", result.to_json_dict() | {"length": result.length}, lambda: render_path(result))
        return
    if sub == "neighbors":
        if len(args) != 2:
            raise InvalidInputError("Usage: raf graph neighbors <object>")
        target = ctx.resolve(args[1])
        ctx.refs.remember("object", target.id)
        graph = service.neighbors(
            target.id,
            direction=cast(Direction, direction),
            rel_types=rel_types,
            at=when,
            limit=max_nodes,
        )
        rt.output("raf.graph/v1", graph.to_json_dict(), lambda: render_subgraph(graph, f"neighbors of {target.label}"))
        return
    scope_words = args[1:] if sub == "export" else args
    scope = resolve_scope(ctx, scope_words)
    for message in scope.notes:
        rt.note(message)
    graph = service.view(
        scope,
        depth=depth,
        rel_types=rel_types,
        node_types=node_types,
        at=when,
        max_nodes=max_nodes,
        direction=cast(Direction, direction),
    )
    if sub == "export" or output is not None:
        text = export_subgraph(graph, fmt)
        if output is not None:
            output.write_text(text, encoding="utf-8")
            ctx.audit.record("graph.export", affected=[scope.id], details={"format": fmt, "path": str(output)})
            rt.output(
                "raf.graph.export/v1",
                {"path": str(output), "format": fmt, "nodes": len(graph.nodes), "edges": len(graph.edges)},
                lambda: rt.success(f"Exported {len(graph.nodes)} nodes / {len(graph.edges)} edges to {output}"),
            )
        else:
            rt.console().out(text) if not rt.STATE.json else rt.emit_json("raf.graph/v1", graph.to_json_dict())
        return

    def render() -> None:
        render_subgraph(graph, f"{scope.label}  ({scope.id})")
        if scope.kind == "object":
            ref = shlex.quote(scope.id)
            rt.next_steps([f"raf timeline {ref}", f"raf trace {ref}", f"raf blast {ref}"])
        elif scope.kind == "incident":
            ref = shlex.quote(scope.label)
            rt.next_steps([f"raf replay {ref}", f"raf timeline {ref}"])

    rt.output("raf.graph/v1", graph.to_json_dict() | {"scope": scope.to_dict()}, render)
