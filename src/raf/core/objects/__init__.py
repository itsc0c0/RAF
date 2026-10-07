"""The R$F Security Object Model.

Models live in :mod:`raf.core.objects.models`, enumerations in :mod:`raf.core.objects.types` and
traversal semantics in :mod:`raf.core.objects.semantics`. Names are re-exported lazily so that
importing a submodule (for example ``raf.core.ids`` -> ``raf.core.objects.types``) never pulls in
the models module and creates an import cycle.
"""

from __future__ import annotations

import importlib
from typing import Any

_MODELS = (
    "Event",
    "EventDraft",
    "EventObject",
    "EventObjectRef",
    "EvidenceRef",
    "Finding",
    "Incident",
    "ObjectDraft",
    "ProvenanceDraft",
    "ProvenanceRecord",
    "RafModel",
    "Relationship",
    "RelationshipDraft",
    "SecurityObject",
    "merge_metadata",
)
_TYPES = (
    "ASSET_TYPES",
    "PRINCIPAL_TYPES",
    "ConfidenceLevel",
    "Criticality",
    "FindingStatus",
    "ObjectType",
    "RelationshipType",
    "Severity",
    "confidence_level",
    "parse_confidence",
    "validate_object_type",
    "validate_relationship_type",
)
_EXPORTS = {**dict.fromkeys(_MODELS, "raf.core.objects.models"), **dict.fromkeys(_TYPES, "raf.core.objects.types")}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module 'raf.core.objects' has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)
