"""R$F Ghost: security digital twins. MODEL -> SIMULATE -> COMPARE.

A model is a frozen base state (a snapshot) plus an ordered log of what-if operations whose
effects are stored explicitly. Models never touch the real environment; they are materialized in
memory on demand. Exposure/attack-path metrics are recomputed for every state compared.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import ConflictError, InvalidInputError, NotFoundError
from raf.core.objects.models import RafModel
from raf.core.risk.exposure import AssetExposure, ExposureMetrics, ExposureModel
from raf.core.snapshots.service import SnapshotService, StateView, resolve_state
from raf.core.timeutil import utcnow
from raf.products.ghost.ops import OPERATIONS, run_operation
from raf.products.ghost.state import ModelState, OpEffects

NAMESPACE = "ghost"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
RESERVED = {"current", "now", "workspace"}


class GhostOp(RafModel):
    op: str
    arg: str
    summary: str
    explanation: list[str] = Field(default_factory=list)
    effects: OpEffects
    applied_at: datetime


class GhostModel(RafModel):
    name: str
    base_snapshot: str
    base_label: str
    parent: str | None = None
    description: str = ""
    created_at: datetime
    updated_at: datetime
    ops: list[GhostOp] = Field(default_factory=list)


class StateSummary(RafModel):
    label: str
    metrics: ExposureMetrics
    levels: dict[str, int]
    user_control: dict[str, int]


class AssetChange(RafModel):
    id: str
    name: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None


class Comparison(RafModel):
    a: StateSummary
    b: StateSummary
    delta: dict[str, int]
    assets: list[AssetChange] = Field(default_factory=list)
    users: list[dict[str, Any]] = Field(default_factory=list)
    relationships_removed: int = 0
    relationships_added: int = 0


def validate_model_name(name: str) -> str:
    text = name.strip().lower()
    if not _NAME_RE.match(text) or text in RESERVED:
        raise InvalidInputError(
            f"Invalid Ghost model name '{name}'.",
            hint="Use lowercase letters, digits, '.', '_' or '-' (not 'current').",
        )
    return text


class GhostService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.kv = ctx.store.kv
        self.snapshots = SnapshotService(ctx.store)

    # ------------------------------------------------------------------ storage
    def models(self) -> list[GhostModel]:
        return sorted((GhostModel.model_validate(v) for v in self.kv.items(NAMESPACE).values()), key=lambda m: m.name)

    def get(self, name: str) -> GhostModel:
        raw = self.kv.get(NAMESPACE, name.strip().lower())
        if raw is None:
            raise NotFoundError(
                f"Ghost model '{name}' does not exist.", suggestions=["raf ghost list", f"raf ghost create {name}"]
            )
        return GhostModel.model_validate(raw)

    def _save(self, model: GhostModel) -> None:
        self.kv.set(NAMESPACE, model.name, model.to_json_dict())

    def _base_snapshot_for_current(self, name: str) -> str:
        base = f"ghost-{name}-base"
        candidate, index = base, 1
        while self.snapshots.get(candidate) is not None:
            index += 1
            candidate = f"{base}-{index}"
        self.snapshots.create(candidate, source="workspace", description=f"Frozen base state of Ghost model {name}")
        return candidate

    def create(self, name: str, *, base: str = "current", description: str = "") -> GhostModel:
        name = validate_model_name(name)
        if self.kv.get(NAMESPACE, name) is not None:
            raise ConflictError(f"Ghost model '{name}' already exists.", suggestions=[f"raf ghost delete {name}"])
        now = utcnow()
        if base.strip().lower() in RESERVED:
            snapshot = self._base_snapshot_for_current(name)
            label = f"current at {now.isoformat(timespec='seconds')}"
        else:
            snapshot = self.snapshots.require(base).name
            label = f"snapshot {snapshot}"
        model = GhostModel(
            name=name, base_snapshot=snapshot, base_label=label, description=description, created_at=now, updated_at=now
        )
        self._save(model)
        self.ctx.audit.record("ghost.create", affected=[f"ghost:{name}"], details={"base": label})
        return model

    def clone(self, source: str, name: str) -> GhostModel:
        if source.strip().lower() in RESERVED or self.kv.get(NAMESPACE, source.strip().lower()) is None:
            if source.strip().lower() not in RESERVED and self.snapshots.get(source) is None:
                raise NotFoundError(
                    f"'{source}' is neither a Ghost model, 'current' nor a snapshot.",
                    suggestions=["raf ghost list", "raf snapshot list"],
                )
            return self.create(name, base=source)
        original = self.get(source)
        name = validate_model_name(name)
        if self.kv.get(NAMESPACE, name) is not None:
            raise ConflictError(f"Ghost model '{name}' already exists.")
        now = utcnow()
        model = original.model_copy(
            update={"name": name, "parent": original.name, "created_at": now, "updated_at": now}
        )
        self._save(model)
        self.ctx.audit.record("ghost.clone", affected=[f"ghost:{name}"], details={"from": original.name})
        return model

    def delete(self, name: str) -> dict[str, Any]:
        model = self.get(name)
        self.kv.delete(NAMESPACE, model.name)
        still_used = any(m.base_snapshot == model.base_snapshot for m in self.models())
        removed_snapshot = None
        if not still_used and model.base_snapshot.startswith(f"ghost-{model.name}-base"):
            self.snapshots.delete(model.base_snapshot)
            removed_snapshot = model.base_snapshot
        self.ctx.audit.record(
            "ghost.delete", affected=[f"ghost:{model.name}"], details={"base_snapshot_removed": removed_snapshot}
        )
        return {"model": model.name, "base_snapshot_removed": removed_snapshot}

    # ------------------------------------------------------------------ materialization
    def materialize(self, model: GhostModel) -> ModelState:
        objects, relationships = self.snapshots.materialize(model.base_snapshot)
        state = ModelState(f"ghost:{model.name}", objects, relationships)
        for op in model.ops:
            state.apply(op.effects, model=model.name, when=op.applied_at)
        return state

    def current_state(self) -> ModelState:
        store = self.ctx.store
        return ModelState("current", store.objects.iter_all(), store.relationships.iter_all())

    def state_for(self, ref: str) -> ModelState:
        text = ref.strip()
        lowered = text.lower()
        if lowered in RESERVED:
            return self.current_state()
        if lowered.startswith("ghost:"):
            lowered = lowered.split(":", 1)[1]
        if self.kv.get(NAMESPACE, lowered) is not None:
            return self.materialize(self.get(lowered))
        snapshot = self.snapshots.get(text)
        if snapshot is not None:
            objects, relationships = self.snapshots.materialize(snapshot.name)
            return ModelState(f"snapshot:{snapshot.name}", objects, relationships)
        raise NotFoundError(
            f"'{ref}' is not a Ghost model, 'current' or a snapshot.",
            suggestions=["raf ghost list", "raf snapshot list"],
        )

    # ------------------------------------------------------------------ operations
    def modify(self, name: str, operations: list[tuple[str, str]]) -> tuple[GhostModel, list[GhostOp]]:
        model = self.get(name)
        if not operations:
            raise InvalidInputError("No operation given.", hint="See: raf ghost modify --help")
        state = self.materialize(model)
        applied: list[GhostOp] = []
        for op, arg in operations:
            result = run_operation(state, op, arg, model.name)
            when = utcnow()
            record = GhostOp(
                op=op,
                arg=arg,
                summary=result.summary,
                explanation=result.explanation,
                effects=result.effects,
                applied_at=when,
            )
            state.apply(result.effects, model=model.name, when=when)
            applied.append(record)
        model.ops.extend(applied)
        model.updated_at = utcnow()
        self._save(model)
        self.ctx.audit.record(
            "ghost.modify", affected=[f"ghost:{model.name}"], details={"ops": [f"{o.op} {o.arg}" for o in applied]}
        )
        return model, applied

    def undo(self, name: str) -> tuple[GhostModel, GhostOp]:
        model = self.get(name)
        if not model.ops:
            raise InvalidInputError(f"Ghost model '{model.name}' has no operations to undo.")
        removed = model.ops.pop()
        model.updated_at = utcnow()
        self._save(model)
        self.ctx.audit.record("ghost.undo", affected=[f"ghost:{model.name}"], details={"op": removed.op})
        return model, removed

    # ------------------------------------------------------------------ simulate and compare
    @staticmethod
    def exposure_model(state: ModelState) -> ExposureModel:
        return ExposureModel(state.graph())

    def summarize(self, state: ModelState) -> tuple[StateSummary, list[AssetExposure], dict[str, list[str]]]:
        model = self.exposure_model(state)
        items = model.assess_all()
        levels: dict[str, int] = {}
        for item in items:
            levels[item.level] = levels.get(item.level, 0) + 1
        control = model.user_control()
        summary = StateSummary(
            label=state.label,
            metrics=model.metrics(items),
            levels=levels,
            user_control={u: len(v) for u, v in control.items()},
        )
        return summary, items, control

    def compare(self, a_ref: str, b_ref: str) -> Comparison:
        state_a, state_b = self.state_for(a_ref), self.state_for(b_ref)
        sa, items_a, control_a = self.summarize(state_a)
        sb, items_b, control_b = self.summarize(state_b)
        ma, mb = sa.metrics.model_dump(), sb.metrics.model_dump()
        delta = {k: int(mb[k]) - int(ma[k]) for k in ma}
        by_a = {i.object["id"]: i for i in items_a}
        by_b = {i.object["id"]: i for i in items_b}
        changes = []
        for oid in sorted(set(by_a) | set(by_b)):
            x, y = by_a.get(oid), by_b.get(oid)
            if x is not None and y is not None and x.score == y.score:
                continue
            name = (y or x).object["name"]  # type: ignore[union-attr]
            changes.append(
                AssetChange(
                    id=oid,
                    name=name,
                    before={"score": x.score, "level": x.level} if x else None,
                    after={"score": y.score, "level": y.level} if y else None,
                )
            )
        changes.sort(key=lambda c: -abs((c.after or {"score": 0})["score"] - (c.before or {"score": 0})["score"]))
        users = []
        for user in sorted(set(control_a) | set(control_b)):
            before, after = set(control_a.get(user, [])), set(control_b.get(user, []))
            if before != after:
                users.append(
                    {
                        "id": user,
                        "name": state_b.name(user) if user in state_b.objects else user,
                        "before": len(before),
                        "after": len(after),
                        "lost": sorted(before - after),
                        "gained": sorted(after - before),
                    }
                )
        rel_a, rel_b = set(state_a.relationships), set(state_b.relationships)
        return Comparison(
            a=sa,
            b=sb,
            delta=delta,
            assets=changes[:50],
            users=users,
            relationships_removed=len(rel_a - rel_b),
            relationships_added=len(rel_b - rel_a),
        )

    def state_view(self, name: str) -> StateView:
        """The model as a comparable state (``raf diff``, ``raf snapshot create --source ghost:X``).

        Findings are carried over from the base snapshot unchanged: analyzers are not re-run inside
        models (use ``raf ghost compare`` for recomputed exposure)."""
        model = self.get(name)
        state = self.materialize(model)
        view = StateView.from_items(f"ghost:{model.name}", state.objects.values(), state.relationships.values())
        base = resolve_state(self.ctx, model.base_snapshot)
        view.hashes["finding"] = dict(base.hashes.get("finding", {}))
        view.loader = base.loader
        return view


def ghost_state_provider(ctx: RafContext, name: str) -> StateView:
    return GhostService(ctx).state_view(name)


def operation_help() -> list[tuple[str, str, str]]:
    return [(name, spec[1], spec[2]) for name, spec in OPERATIONS.items()]
