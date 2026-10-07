"""``raf ghost``: security digital twins (MODEL -> SIMULATE -> COMPARE)."""

from __future__ import annotations

import typer
from rich.text import Text

from raf.core.errors import InvalidInputError
from raf.products.ghost.ops import OPERATIONS
from raf.products.ghost.service import Comparison, GhostModel, GhostOp, GhostService, StateSummary, operation_help
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    help="""Security digital twins: what-if models that never touch real systems.

  raf ghost create prod-model                 freeze the current state as a model
  raf ghost clone prod-model experiment-01    copy a model (or 'current' / a snapshot)
  raf ghost modify experiment-01 --remove-access alice:production --isolate LAB-01
  raf ghost simulate experiment-01            exposure and attack paths inside the model
  raf ghost compare prod-model experiment-01  BASELINE / EXPERIMENT / CHANGE""",
)

_LEVEL_STYLE = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "bold red", "CRITICAL": "bold white on red"}
_METRICS = (
    ("attack_paths", "Attack paths"),
    ("critical_paths", "Critical paths"),
    ("reachable_assets", "Reachable assets"),
    ("entry_points", "Entry points"),
    ("exposed_critical_assets", "Exposed critical assets"),
)


def render_model(model: GhostModel) -> None:
    rt.header(f"R$F GHOST  {model.name}", model.description or None)
    rt.kv_block(
        [
            ("Base", model.base_label),
            ("Base snapshot", model.base_snapshot),
            ("Parent", model.parent or "-"),
            ("Operations", len(model.ops)),
            ("Created", rt.ts_text(model.created_at)),
            ("Updated", rt.ts_text(model.updated_at)),
        ],
        width=14,
    )
    if model.ops:
        rt.console().print()
        render_ops(model.ops, start=1)


def render_ops(ops: list[GhostOp], start: int = 1) -> None:
    c = rt.console()
    for index, op in enumerate(ops, start):
        c.print(
            Text(f"{index:>2}. ", style="dim")
            + Text(f"{op.op} ", style="bold")
            + Text(op.arg)
            + Text(f"  → {op.summary}", style="dim")
        )
        for line in op.explanation[:12]:
            c.print(Text(f"      {line}", style="dim"))


def render_summary(summary: StateSummary) -> None:
    m = summary.metrics
    rt.kv_block(
        [(label, getattr(m, key)) for key, label in _METRICS]
        + [
            (
                "Exposure levels",
                ", ".join(f"{lv} {summary.levels.get(lv, 0)}" for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
            )
        ],
        width=24,
    )


def render_comparison(cmp: Comparison) -> None:
    rt.header(f"R$F GHOST COMPARE  {cmp.a.label} → {cmp.b.label}")
    c = rt.console()
    for title, summary in (("BASELINE", cmp.a), ("EXPERIMENT", cmp.b)):
        c.print(Text(f"{title}  ", style="bold") + Text(summary.label, style="dim"))
        c.print()
        render_summary(summary)
        c.print()
    c.print(Text("CHANGE", style="bold"))
    c.print()
    for key, label in _METRICS:
        value = cmp.delta[key]
        style = "green" if value < 0 else ("red" if value > 0 else "dim")
        c.print(Text(f"  {value:+d} ".rjust(8), style=style) + Text(label.lower()))
    c.print(Text(f"  relationships: -{cmp.relationships_removed} / +{cmp.relationships_added}", style="dim"))
    if cmp.assets:
        c.print()
        rows = []
        for change in cmp.assets[:15]:
            before = f"{change.before['level']} {change.before['score']}" if change.before else "-"
            after = f"{change.after['level']} {change.after['score']}" if change.after else "-"
            rows.append((change.name, before, after))
        rt.table(["ASSET", "BASELINE EXPOSURE", "EXPERIMENT EXPOSURE"], rows)
    if cmp.users:
        c.print()
        rt.table(
            ["USER", "CONTROLLED HIGH/CRITICAL ASSETS", "LOST", "GAINED"],
            [
                (
                    u["name"],
                    f"{u['before']} → {u['after']}",
                    ", ".join(x.split(":", 1)[-1] for x in u["lost"][:5]),
                    ", ".join(x.split(":", 1)[-1] for x in u["gained"][:5]),
                )
                for u in cmp.users
            ],
        )


@app.command("create", help="Create a model from the current workspace (frozen) or a snapshot.")
def create_cmd(
    name: str = typer.Argument(..., help="Model name (e.g. prod-model)."),
    base: str = typer.Option("current", "--from", help="'current' or a snapshot name."),
    description: str = typer.Option("", "--description", "-d"),
) -> None:
    ctx = rt.ctx()
    model = GhostService(ctx).create(name, base=base, description=description)

    def render() -> None:
        rt.success(f"Ghost model '{model.name}' created from {model.base_label}.")
        rt.next_steps([f"raf ghost clone {model.name} experiment-01", f"raf ghost simulate {model.name}"])

    rt.output("raf.ghost.model/v1", model.to_json_dict(), render)


@app.command("clone", help="Clone a model, 'current' or a snapshot into a new model.")
def clone_cmd(source: str = typer.Argument(...), name: str = typer.Argument(...)) -> None:
    ctx = rt.ctx()
    model = GhostService(ctx).clone(source, name)

    def render() -> None:
        rt.success(f"Ghost model '{model.name}' created from {source} ({len(model.ops)} operation(s) copied).")
        rt.next_steps(
            [
                f"raf ghost modify {model.name} --remove-access <user>:<asset>",
                f"raf ghost compare {source} {model.name}",
            ]
        )

    rt.output("raf.ghost.model/v1", model.to_json_dict(), render)


@app.command("list", help="Ghost models in this workspace.")
def list_cmd() -> None:
    ctx = rt.ctx()
    models = GhostService(ctx).models()

    def render() -> None:
        if not models:
            rt.console().print("No Ghost models.")
            rt.next_steps(["raf ghost create prod-model"])
            return
        rt.table(
            ["MODEL", "BASE", "PARENT", "OPS", "UPDATED"],
            [(m.name, m.base_label, m.parent or "", len(m.ops), rt.ts_text(m.updated_at)) for m in models],
        )

    rt.output("raf.ghost.list/v1", {"items": [m.to_json_dict() for m in models]}, render)


@app.command("show", help="Show a model and its operation log.")
def show_cmd(name: str = typer.Argument(...)) -> None:
    ctx = rt.ctx()
    model = GhostService(ctx).get(name)
    rt.output("raf.ghost.model/v1", model.to_json_dict(), lambda: render_model(model))


@app.command("operations", help="List the what-if operations Ghost supports.")
def operations_cmd() -> None:
    rows = operation_help()

    def render() -> None:
        rt.table(["OPERATION", "ARGUMENT", "EFFECT"], rows)

    rt.output(
        "raf.ghost.operations/v1", {"items": [{"op": r[0], "argument": r[1], "effect": r[2]} for r in rows]}, render
    )


@app.command(
    "modify",
    help="""Apply what-if operations to a model (never to real systems).

Operations are applied in the order listed by 'raf ghost operations'; use --op to give an explicit
order ("remove-access alice:production"). --undo removes the last operation.""",
)
def modify_cmd(
    name: str = typer.Argument(...),
    remove_access: list[str] = typer.Option(None, "--remove-access", help="A:B - cut every control path."),
    remove_relationship: list[str] = typer.Option(None, "--remove-relationship", help="rel:ID or 'SRC TYPE DST'."),
    add_segmentation: list[str] = typer.Option(None, "--add-segmentation", help="SRC_ZONE:DST_ZONE."),
    disable_identity: list[str] = typer.Option(None, "--disable-identity"),
    change_role: list[str] = typer.Option(None, "--change-role", help="PRINCIPAL:OLD:NEW."),
    add_role: list[str] = typer.Option(None, "--add-role", help="PRINCIPAL:ROLE."),
    remove_role: list[str] = typer.Option(None, "--remove-role", help="PRINCIPAL:ROLE."),
    remove_exposure: list[str] = typer.Option(None, "--remove-exposure", help="HOST or SERVICE."),
    patch_vuln: list[str] = typer.Option(None, "--patch-vuln", help="VULN[:ASSET]."),
    isolate: list[str] = typer.Option(None, "--isolate", help="HOST."),
    disable_rule: list[str] = typer.Option(None, "--disable-rule", help="POLICY:RULE."),
    deny_flow: list[str] = typer.Option(None, "--deny-flow", help="SRC:DST[:PORTS]."),
    op: list[str] = typer.Option(None, "--op", help="'OPERATION ARGUMENT' (repeatable, keeps order)."),
    undo: bool = typer.Option(False, "--undo", help="Remove the last operation."),
) -> None:
    ctx = rt.ctx()
    service = GhostService(ctx)
    if undo:
        model, removed = service.undo(name)

        def render_undo() -> None:
            rt.success(f"Removed '{removed.op} {removed.arg}' from {model.name} ({len(model.ops)} left).")

        rt.output("raf.ghost.model/v1", model.to_json_dict(), render_undo)
        return
    given = {
        "remove-access": remove_access,
        "remove-relationship": remove_relationship,
        "add-segmentation": add_segmentation,
        "disable-identity": disable_identity,
        "change-role": change_role,
        "add-role": add_role,
        "remove-role": remove_role,
        "remove-exposure": remove_exposure,
        "patch-vuln": patch_vuln,
        "isolate": isolate,
        "disable-rule": disable_rule,
        "deny-flow": deny_flow,
    }
    operations = [(key, value) for key in OPERATIONS for value in (given.get(key) or [])]
    for item in op or []:
        parts = item.strip().split(None, 1)
        if len(parts) != 2:
            raise InvalidInputError(f"--op expects 'OPERATION ARGUMENT', got '{item}'.")
        operations.append((parts[0].lower(), parts[1]))
    if not operations:
        model = service.get(name)

        def render_help() -> None:
            render_model(model)
            rt.console().print()
            rt.table(["OPERATION", "ARGUMENT", "EFFECT"], operation_help())
            rt.next_steps([f"raf ghost modify {model.name} --remove-access alice:production"])

        rt.output("raf.ghost.model/v1", model.to_json_dict(), render_help)
        return
    model, applied = service.modify(name, operations)

    def render() -> None:
        rt.success(f"Applied {len(applied)} operation(s) to {model.name}.")
        render_ops(applied, start=len(model.ops) - len(applied) + 1)
        rt.next_steps(
            [f"raf ghost compare current {model.name}", f"raf snapshot create after --source ghost:{model.name}"]
        )

    rt.output(
        "raf.ghost.modify/v1", {"model": model.to_json_dict(), "applied": [a.to_json_dict() for a in applied]}, render
    )


@app.command("simulate", help="Exposure, attack paths and top risks inside a model (or 'current').")
def simulate_cmd(name: str = typer.Argument(...), limit: int = typer.Option(10, "--limit", min=1)) -> None:
    ctx = rt.ctx()
    service = GhostService(ctx)
    state = service.state_for(name)
    summary, items, _control = service.summarize(state)

    def render() -> None:
        rt.header(f"R$F GHOST SIMULATE  {summary.label}")
        render_summary(summary)
        rt.console().print()
        rt.table(
            ["ASSET", "TYPE", "EXPOSURE", "TOP FACTOR"],
            [
                (
                    i.object["name"],
                    i.object["type"],
                    Text(f"{i.level} {i.score}", style=_LEVEL_STYLE.get(i.level, "")),
                    next((f.label for f in i.factors if f.sign == "+"), ""),
                )
                for i in items[:limit]
            ],
        )

    rt.output(
        "raf.ghost.simulate/v1",
        {"summary": summary.to_json_dict(), "items": [i.to_json_dict() for i in items[:limit]]},
        render,
    )


@app.command("compare", help="Compare two states: Ghost models, 'current' or snapshots.")
def compare_cmd(a: str = typer.Argument(...), b: str = typer.Argument(...)) -> None:
    ctx = rt.ctx()
    comparison = GhostService(ctx).compare(a, b)
    rt.output("raf.ghost.compare/v1", comparison.to_json_dict(), lambda: render_comparison(comparison))


@app.command("delete", help="Delete a model (and its frozen base snapshot when no other model uses it).")
def delete_cmd(name: str = typer.Argument(...)) -> None:
    ctx = rt.ctx()
    service = GhostService(ctx)
    model = service.get(name)
    rt.confirm(f"Delete Ghost model '{model.name}'?", [f"{len(model.ops)} operation(s) will be lost."])
    result = service.delete(model.name)
    rt.output("raf.ghost.delete/v1", result, lambda: rt.success(f"Deleted Ghost model '{model.name}'."))
