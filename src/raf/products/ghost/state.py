"""In-memory security state of a Ghost model: base snapshot + deterministic operation effects."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.errors import AmbiguousReferenceError, NotFoundError
from raf.core.graph.source import MemoryGraphSource, propagation_source
from raf.core.ids import object_id, relationship_id, try_split_id
from raf.core.objects.models import RafModel, Relationship, SecurityObject
from raf.core.objects.semantics import NON_PROPAGATING_TYPES


class AddedRelationship(RafModel):
    source: str
    type: str
    target: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def id(self) -> str:
        return relationship_id(self.source, self.type, self.target)


class AddedObject(RafModel):
    id: str
    type: str
    name: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class OpEffects(RafModel):
    """What an operation changed. Stored with the operation so replay is exact and fast."""

    removed_relationships: list[str] = Field(default_factory=list)
    added_relationships: list[AddedRelationship] = Field(default_factory=list)
    added_objects: list[AddedObject] = Field(default_factory=list)
    patched_objects: dict[str, dict[str, Any]] = Field(default_factory=dict)  # top-level metadata replace

    def is_empty(self) -> bool:
        return not (
            self.removed_relationships or self.added_relationships or self.added_objects or self.patched_objects
        )


class ModelState:
    def __init__(
        self,
        label: str,
        objects: Iterable[SecurityObject],
        relationships: Iterable[Relationship],
        *,
        lean: bool = False,
    ) -> None:
        self.label = label
        self.objects: dict[str, SecurityObject] = {o.id: o for o in objects}
        # ended relationships are kept (the state stays faithful to its base) but never traversed
        self.relationships: dict[str, Relationship] = {r.id: r for r in relationships}
        #: propagation-only: references without a type resolve among the objects propagation can enter,
        #: even when a few others are present (the ends of relationships an operation edits)
        self.lean = lean
        self._names: dict[str, list[str]] | None = None

    def copy(self, label: str) -> ModelState:
        """An independent state with the same content (cheap: :meth:`apply` replaces objects and
        relationships instead of mutating them, so they can be shared)."""
        return ModelState(label, self.objects.values(), self.relationships.values(), lean=self.lean)

    # ------------------------------------------------------------------ views
    def graph(self) -> MemoryGraphSource:
        """The state as a propagation graph (activity records that propagation never enters are left out)."""
        return propagation_source(self.objects.values(), self.relationships.values())

    def name(self, oid: str) -> str:
        obj = self.objects.get(oid)
        return obj.name if obj else oid.split(":", 1)[-1]

    def active(self) -> list[Relationship]:
        return [r for r in self.relationships.values() if r.valid_to is None]

    def rels(
        self, *, source: str | None = None, target: str | None = None, types: Sequence[str] | None = None
    ) -> list[Relationship]:
        """Active relationships matching the filters."""
        wanted = set(types) if types else None
        out = [
            r
            for r in self.active()
            if (source is None or r.source_object == source)
            and (target is None or r.target_object == target)
            and (wanted is None or r.relationship_type in wanted)
        ]
        return sorted(out, key=lambda r: r.id)

    def touching(self, oid: str, types: Sequence[str] | None = None) -> list[Relationship]:
        wanted = set(types) if types else None
        return sorted(
            (
                r
                for r in self.active()
                if oid in (r.source_object, r.target_object) and (wanted is None or r.relationship_type in wanted)
            ),
            key=lambda r: r.id,
        )

    # ------------------------------------------------------------------ resolution
    def _name_index(self) -> dict[str, list[str]]:
        if self._names is None:
            index: dict[str, list[str]] = defaultdict(list)
            for obj in self.objects.values():
                keys = {obj.name.lower(), obj.id.split(":", 1)[1].lower()}
                for alias in obj.metadata.get("aliases") or []:
                    if isinstance(alias, str):
                        keys.add(alias.lower())
                for key in keys:
                    index[key].append(obj.id)
            self._names = index
        return self._names

    def resolve(self, ref: str, types: Sequence[str] | None = None) -> str:
        """Resolve a reference against the model (not the live workspace)."""
        text = ref.strip()
        split = try_split_id(text) if ":" in text else None
        if split is not None:
            try:
                candidate = object_id(split[0], split[1])
            except Exception:  # noqa: BLE001 - invalid keys fall through to name search
                candidate = text
            if candidate in self.objects and self._eligible(candidate, types):
                return candidate
        matches = [m for m in sorted(set(self._name_index().get(text.lower(), []))) if self._eligible(m, types)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise AmbiguousReferenceError(text, matches)
        kinds = f" ({', '.join(types)})" if types else ""
        raise NotFoundError(
            f"'{text}'{kinds} is not in model {self.label}.",
            hint="Use a name or ID of an object that exists in the model's base state.",
        )

    def _eligible(self, oid: str, types: Sequence[str] | None) -> bool:
        kind = oid.split(":", 1)[0]
        if types is not None:
            return kind in types
        return not self.lean or kind not in NON_PROPAGATING_TYPES

    def resolve_pair(
        self, text: str, first: Sequence[str] | None = None, second: Sequence[str] | None = None
    ) -> tuple[str, str]:
        """Split ``A:B`` (or ``A->B``) where A and B may themselves be typed IDs containing ':'."""
        if "->" in text:
            left, right = text.split("->", 1)
            return self.resolve(left, first), self.resolve(right, second)
        positions = [i for i, ch in enumerate(text) if ch == ":"]
        found: list[tuple[str, str]] = []
        errors: list[Exception] = []
        for pos in positions:
            try:
                found.append((self.resolve(text[:pos], first), self.resolve(text[pos + 1 :], second)))
            except (NotFoundError, AmbiguousReferenceError) as exc:
                errors.append(exc)
        unique = sorted(set(found))
        if len(unique) == 1:
            return unique[0]
        if len(unique) > 1:
            raise AmbiguousReferenceError(text, [f"{a} -> {b}" for a, b in unique])
        if errors:
            raise errors[-1]
        raise NotFoundError(f"Expected 'A:B' or 'A->B', got '{text}'.")

    # ------------------------------------------------------------------ mutation
    def apply(self, effects: OpEffects, *, model: str, when: datetime) -> None:
        for rid in effects.removed_relationships:
            self.relationships.pop(rid, None)
        for obj in effects.added_objects:
            self.objects[obj.id] = SecurityObject(
                id=obj.id,
                type=obj.type,
                name=obj.name,
                created_at=when,
                updated_at=when,
                source=f"ghost:{model}",
                confidence=1.0,
                metadata={**obj.metadata, "ghost": True},
                tags=sorted({*obj.tags, "ghost"}),
                synthetic=True,
            )
        for added in effects.added_relationships:
            self.relationships[added.id] = Relationship(
                id=added.id,
                relationship_type=added.type,
                source_object=added.source,
                target_object=added.target,
                confidence=1.0,
                source=f"ghost:{model}",
                metadata={**added.metadata, "ghost": True},
                created_at=when,
                updated_at=when,
                synthetic=True,
            )
        for oid, patch in effects.patched_objects.items():
            current = self.objects.get(oid)
            if current is not None:
                self.objects[oid] = current.model_copy(
                    update={"metadata": {**current.metadata, **patch}, "updated_at": when}
                )
        self._names = None
