"""``raf trace``: causal chains around an object, with explicit confidence."""

from __future__ import annotations

import shlex

import typer
from rich.text import Text
from rich.tree import Tree

from raf.core.errors import InvalidInputError
from raf.core.objects.types import ObjectType, confidence_level
from raf.products.trace.service import TraceLink, TraceResult, TraceService
from raf.sdk import cli as rt

app = typer.Typer(add_completion=False)


def _link_text(link: TraceLink, names: dict[str, str], backward: bool) -> Text:
    other = link.cause if backward else link.effect
    level = confidence_level(link.confidence).value
    style = "green" if link.kind == "observed" else "yellow"
    text = Text("← " if backward else "→ ", style="dim")
    text.append(f"{link.relation} ", style="cyan")
    text.append(names.get(other, other), style="bold")
    text.append(f"  {rt.ts_text(link.timestamp).replace('T', ' ').replace('Z', '')}", style="dim")
    text.append(f"  [{link.kind}, {level} {link.confidence:.2f}]", style=style)
    if link.provenance.get("source"):
        text.append(f"  {link.provenance.get('source')} {link.provenance.get('record') or ''}", style="dim")
    if link.corroborated_by:
        text.append(f"  +{len(link.corroborated_by)} corroborating source(s)", style="green")
    return text


def render_trace(result: TraceResult) -> None:
    subject = result.subject
    names = {n.id: n.name for n in result.nodes}
    rt.header(f"R$F TRACE  {subject.name}  ({subject.id})")
    rt.kv_block(
        [
            ("Causes", len(result.backward)),
            ("Effects", len(result.forward)),
            ("Observed", sum(1 for lk in result.backward + result.forward if lk.kind == "observed")),
            ("Correlated", sum(1 for lk in result.backward + result.forward if lk.kind == "correlated")),
        ],
        width=12,
    )
    c = rt.console()
    if result.chain:
        c.print()
        c.print(Text("Most supported causal chain", style="bold"))
        steps: list[tuple[str, str, str | None]] = []
        for link in result.chain:
            when = rt.ts_text(link.timestamp).replace("T", " ").replace("Z", "")
            steps.append(
                (
                    names.get(link.cause, link.cause),
                    "",
                    f"{link.relation}  {when}  ({link.kind}, {link.confidence:.2f})",
                )
            )
        steps.append((subject.name, subject.id, None))
        rt.render_chain(steps)
        for link in result.chain:
            c.print(Text(f"  · {link.explanation}", style="dim"))
    for title, links, backward in (
        ("How it became involved (backward)", result.backward, True),
        ("What it did (forward)", result.forward, False),
    ):
        if not links:
            continue
        c.print()
        c.print(Text(title, style="bold"))
        children: dict[int | None, list[TraceLink]] = {}
        for link in links:
            children.setdefault(link.parent_step, []).append(link)
        tree = Tree(Text(subject.name, style="bold"))
        budget = [70]

        def add(
            branch: Tree,
            parent: int | None,
            backward: bool = backward,
            children: dict[int | None, list[TraceLink]] = children,
            budget: list[int] = budget,
        ) -> None:
            for link in children.get(parent, [])[:10]:
                if budget[0] <= 0:
                    return
                budget[0] -= 1
                add(branch.add(_link_text(link, names, backward)), link.step)

        add(tree, None)
        c.print(tree)
        if budget[0] <= 0:
            c.print(Text("... more links (use --json, --depth or --direction)", style="dim"))
    for note in result.notes:
        c.print(Text(f"Note: {note}", style="yellow"))
    if not result.backward and not result.forward and subject.type not in (ObjectType.INCIDENT, ObjectType.EVENT):
        c.print()
        c.print("No events reference this object yet.")


def next_steps(result: TraceResult) -> list[str]:
    """Pivots that work for the traced subject (IDs are quoted for the shell)."""
    subject = result.subject
    if subject.type == ObjectType.INCIDENT:
        ref = shlex.quote(subject.name)
        steps = [f"raf replay {ref}", f"raf timeline {ref}", f"raf graph {ref}"]
    elif subject.type == ObjectType.EVENT:
        steps = [f"raf show {shlex.quote(subject.id)}"]
    else:
        ref = shlex.quote(subject.id)
        steps = [f"raf timeline {ref}", f"raf graph {ref}", f"raf blast {ref}"]
    if result.anchor is not None:
        steps.append(f"raf trace {shlex.quote(result.anchor.object)}")
    return steps


@app.command(
    "trace",
    help="""Trace how an object became involved (backward) and what it did (forward).

Observed links come from single events; correlated links are labeled and never presented as proven causation.
An incident is traced from its most significant event (highest severity, then latest), an event ID from that event.""",
)
def trace_cmd(
    ref: str = typer.Argument(
        ..., help="Object, incident or event (alice, host:ws-04, 'cat [20903]', INC-001, event:..., @last)."
    ),
    direction: str = typer.Option("both", "--direction", help="back, forward or both."),
    depth: int = typer.Option(3, "--depth", min=1, max=6),
) -> None:
    if direction not in ("both", "back", "backward", "forward", "fwd"):
        raise InvalidInputError("--direction must be back, forward or both.")
    ctx = rt.ctx()
    resolved = ctx.resolve(
        ref, accept=("object", "event", "finding", "snapshot")
    )  # the service explains which kinds it traces
    for message in resolved.notes:
        rt.note(message)
    result = TraceService(ctx).trace(resolved.id, direction=direction, depth=depth)
    if result.subject.type == ObjectType.INCIDENT:
        ctx.refs.remember("incident", resolved.id)
    elif resolved.kind == "object":
        ctx.refs.remember("object", resolved.id)

    def render() -> None:
        render_trace(result)
        rt.next_steps(next_steps(result))

    rt.output("raf.trace/v1", result.to_json_dict(), render)
