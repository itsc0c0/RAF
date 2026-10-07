"""CLI context references: ``@last``, ``@incident``, ``@analysis``, ``@workspace`` ...

Semantics (kept deliberately predictable):

* Commands that produce or operate on an entity *remember* it under a kind
  (object, incident, analysis, snapshot, job, case, ghost, range, lab).
* ``@<kind>`` resolves to the most recently remembered entity of that kind,
  when the consuming command accepts that kind (``raf show @lab`` is an error,
  never a lab name looked up as an object).
* ``@last`` resolves to the most recently remembered entity whose kind the
  consuming command accepts (``raf graph @last`` accepts objects, incidents and
  analyses; ``raf diff`` accepts snapshots).
* ``@workspace`` is the current workspace name.

References are stored per workspace, so switching workspaces never leaks them.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.storage.repos.misc import KVRepository
from raf.core.timeutil import format_ts, utcnow

KINDS = ("object", "incident", "analysis", "snapshot", "job", "case", "ghost", "range", "lab")
_LABELS = {"case": "evidence case", "ghost": "Ghost model"}
_NAMESPACE = "cli.context"
_HISTORY_LIMIT = 30


class ContextRefs:
    def __init__(self, kv: KVRepository, workspace: str) -> None:
        self.kv = kv
        self.workspace = workspace

    def remember(self, kind: str, ref: str) -> None:
        if kind not in KINDS:
            raise ValueError(f"unknown context kind {kind}")
        history: list[dict[str, Any]] = list(self.kv.get(_NAMESPACE, "history", []) or [])
        history = [h for h in history if not (h.get("kind") == kind and h.get("ref") == ref)]
        history.insert(0, {"kind": kind, "ref": ref, "at": format_ts(utcnow())})
        self.kv.set(_NAMESPACE, "history", history[:_HISTORY_LIMIT])

    def history(self) -> list[dict[str, Any]]:
        return list(self.kv.get(_NAMESPACE, "history", []) or [])

    @staticmethod
    def is_reference(token: str) -> bool:
        return token.startswith("@") and len(token) > 1

    def resolve(self, token: str, accept: Sequence[str] = KINDS) -> tuple[str, str]:
        """Return ``(kind, ref)`` for a context token."""
        name = token[1:].strip().lower()
        if name == "workspace":
            return "workspace", self.workspace
        if name == "selection":
            raise InvalidInputError(
                "@selection is only available in the web UI.", hint="Use @last or an explicit object ID in the CLI."
            )
        history = self.history()
        if name == "last":
            for entry in history:
                if entry.get("kind") in accept:
                    return str(entry["kind"]), str(entry["ref"])
            raise NotFoundError(
                "@last does not refer to anything yet in this workspace.",
                reason=f"No remembered {', '.join(accept)} reference.",
                hint="Run a command first (for example 'raf analyze <file>' or 'raf graph user alice').",
            )
        if name not in KINDS:
            raise InvalidInputError(
                f"Unknown context reference '{token}'.", hint="Use @last, @workspace or @" + ", @".join(KINDS) + "."
            )
        if name not in accept:
            label = _LABELS.get(name, name)
            article = "an" if label[0] in "aeiou" else "a"
            raise InvalidInputError(
                f"{token} refers to {article} {label}, which this command does not accept.",
                hint="Use @last or @" + ", @".join(k for k in KINDS if k in accept) + ".",
            )
        for entry in history:
            if entry.get("kind") == name:
                return name, str(entry["ref"])
        raise NotFoundError(f"{token} does not refer to anything yet in this workspace.")
