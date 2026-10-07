"""Entity resolution during ingestion.

Bare names typed only by context (an ``actor`` defaults to *user*) are matched
against objects that already exist - in the workspace or earlier in the same
import - so ``svc-deploy`` maps to ``identity:svc-deploy`` instead of creating a
duplicate ``user:svc-deploy``. Resolution is deterministic: the first type in
the compatible-type list wins, and results are cached per (name, types).
"""

from __future__ import annotations

from collections.abc import Sequence

from raf.core.objects.models import ObjectDraft
from raf.core.storage.store import Store


class EntityResolver:
    def __init__(self, store: Store) -> None:
        self.store = store
        self._pending: dict[str, dict[str, str]] = {}  # name_lc -> {type: id}
        self._cache: dict[tuple[str, tuple[str, ...]], str | None] = {}

    def register(self, draft: ObjectDraft) -> None:
        names = {draft.name.lower()}
        aliases = draft.metadata.get("aliases")
        if isinstance(aliases, list):
            names.update(str(a).lower() for a in aliases)
        for name in names:
            slot = self._pending.setdefault(name, {})
            if draft.type not in slot:
                slot[draft.type] = draft.id
                for key in [k for k in self._cache if k[0] == name]:
                    del self._cache[key]

    def resolve(self, name: str, types: Sequence[str]) -> str | None:
        lowered = name.strip().lower()
        key = (lowered, tuple(types))
        if key in self._cache:
            return self._cache[key]
        found: str | None = None
        pending = self._pending.get(lowered, {})
        stored = {o.type: o.id for o in self.store.objects.find_by_name(lowered, list(types))}
        for otype in types:
            if otype in pending:
                found = pending[otype]
                break
            if otype in stored:
                found = stored[otype]
                break
        if len(self._cache) > 200_000:
            self._cache.clear()
        self._cache[key] = found
        return found
