"""Canonical models of the R$F Security Object Model.

* ``*Draft`` dataclasses are mutable builders used by producers (parsers,
  generators, analyzers). Drafts with the same ID merge deterministically.
* Pydantic models (``SecurityObject``, ``Relationship``, ``Event``, ``Finding``)
  are the persisted/public representation used by services, the API and the
  JSON output of the CLI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field

from raf.core.ids import object_id, relationship_id
from raf.core.objects.types import (
    ConfidenceLevel,
    Criticality,
    FindingStatus,
    Severity,
    confidence_level,
    validate_object_type,
    validate_relationship_type,
)


class RafModel(BaseModel):
    """Base model: strict about unknown fields, JSON friendly."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# --------------------------------------------------------------------------- helpers


def _min_dt(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _max_dt(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


_UNION_LIST_KEYS = frozenset({"aliases", "sources", "addresses", "ports", "sans"})


def merge_metadata(base: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    """Recursive metadata merge. Newer scalar values win; nested dicts merge;
    a few well-known list keys (aliases, sources, addresses, ports, sans) union."""
    result = dict(base)
    for key, value in update.items():
        current = result.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            result[key] = merge_metadata(current, value)
        elif key in _UNION_LIST_KEYS and isinstance(current, list) and isinstance(value, list):
            merged = list(current)
            for item in value:
                if item not in merged:
                    merged.append(item)
            result[key] = merged
        else:
            result[key] = value
    return result


# --------------------------------------------------------------------------- drafts


@dataclass(slots=True)
class ObjectDraft:
    type: str
    name: str
    id: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    source: str = "unknown"
    confidence: float = 0.8
    tags: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)
    observations: int = 1
    synthetic: bool = False

    @classmethod
    def make(cls, obj_type: str, name: str, *, key: str | None = None, **kwargs: Any) -> ObjectDraft:
        otype = validate_object_type(obj_type)
        tags = kwargs.pop("tags", None)
        return cls(
            type=otype,
            name=str(name).strip() or str(key),
            id=object_id(otype, key if key is not None else name),
            tags=set(tags or ()),
            **kwargs,
        )

    def observe(self, ts: datetime | None) -> None:
        if ts is not None:
            self.first_seen = _min_dt(self.first_seen, ts)
            self.last_seen = _max_dt(self.last_seen, ts)

    def merge(self, other: ObjectDraft) -> None:
        if other.id != self.id:
            raise ValueError(f"cannot merge {other.id} into {self.id}")
        if other.confidence > self.confidence and other.name:
            self.name = other.name
        self.first_seen = _min_dt(self.first_seen, other.first_seen)
        self.last_seen = _max_dt(self.last_seen, other.last_seen)
        self.valid_from = _min_dt(self.valid_from, other.valid_from)
        if other.valid_to is not None and (self.valid_to is None or other.valid_to > self.valid_to):
            self.valid_to = other.valid_to
        if (
            self.valid_to is not None
            and other.valid_to is None
            and other.last_seen is not None
            and other.last_seen > self.valid_to
        ):
            self.valid_to = None
        if self.source == "unknown":
            self.source = other.source
        self.confidence = max(self.confidence, other.confidence)
        self.tags |= other.tags
        self.metadata = merge_metadata(self.metadata, other.metadata)
        self.observations += other.observations
        if other.observations > 0:  # a mere reference must not change provenance flags
            self.synthetic = self.synthetic and other.synthetic


@dataclass(slots=True)
class RelationshipDraft:
    type: str
    source_id: str
    target_id: str
    id: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    source: str = "unknown"
    confidence: float = 0.8
    metadata: dict[str, Any] = field(default_factory=dict)
    observations: int = 1
    synthetic: bool = False

    @classmethod
    def make(cls, source_id: str, rel_type: str, target_id: str, **kwargs: Any) -> RelationshipDraft:
        rtype = validate_relationship_type(rel_type)
        return cls(
            type=rtype,
            source_id=source_id,
            target_id=target_id,
            id=relationship_id(source_id, rtype, target_id),
            **kwargs,
        )

    def observe(self, ts: datetime | None) -> None:
        if ts is not None:
            self.first_seen = _min_dt(self.first_seen, ts)
            self.last_seen = _max_dt(self.last_seen, ts)

    def merge(self, other: RelationshipDraft) -> None:
        if other.id != self.id:
            raise ValueError(f"cannot merge {other.id} into {self.id}")
        self.first_seen = _min_dt(self.first_seen, other.first_seen)
        self.last_seen = _max_dt(self.last_seen, other.last_seen)
        self.valid_from = _min_dt(self.valid_from, other.valid_from)
        if other.valid_to is not None and (self.valid_to is None or other.valid_to > self.valid_to):
            self.valid_to = other.valid_to
        if (
            self.valid_to is not None
            and other.valid_to is None
            and other.last_seen is not None
            and other.last_seen > self.valid_to
        ):
            self.valid_to = None
        if self.source == "unknown":
            self.source = other.source
        self.confidence = max(self.confidence, other.confidence)
        self.metadata = merge_metadata(self.metadata, other.metadata)
        self.observations += other.observations
        if other.observations > 0:  # a mere reference must not change provenance flags
            self.synthetic = self.synthetic and other.synthetic


@dataclass(slots=True)
class EventObjectRef:
    object_id: str
    role: str


@dataclass(slots=True)
class EventDraft:
    id: str
    timestamp: datetime
    event_type: str
    category: str
    action: str
    source: str
    parser: str
    outcome: str | None = None
    actor: str | None = None
    target: str | None = None
    objects: list[EventObjectRef] = field(default_factory=list)
    record: str | None = None
    raw_reference: str | None = None
    raw: str | None = None
    severity: Severity = Severity.INFO
    confidence: float = 0.8
    attributes: dict[str, Any] = field(default_factory=dict)
    relationships: list[str] = field(default_factory=list)
    message: str | None = None
    synthetic: bool = False
    incidents: list[str] = field(default_factory=list)

    def involve(self, object_id_: str | None, role: str) -> None:
        if not object_id_:
            return
        for ref in self.objects:
            if ref.object_id == object_id_ and ref.role == role:
                return
        self.objects.append(EventObjectRef(object_id_, role))


@dataclass(slots=True)
class ProvenanceDraft:
    subject_id: str
    subject_kind: str  # object | relationship | finding
    source: str
    parser: str | None = None
    record: str | None = None
    event_id: str | None = None
    observed_at: datetime | None = None
    evidence_id: str | None = None
    source_sha256: str | None = None
    note: str | None = None


# --------------------------------------------------------------------------- persisted models


class SecurityObject(RafModel):
    id: str
    type: str
    name: str
    created_at: datetime
    updated_at: datetime
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    source: str = "unknown"
    confidence: float = 0.8
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    observations: int = 1
    synthetic: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confidence_level(self) -> ConfidenceLevel:
        return confidence_level(self.confidence)

    @property
    def criticality(self) -> Criticality | None:
        return Criticality.of(self.metadata, self.tags)

    def label(self) -> str:
        return self.name or self.id


class Relationship(RafModel):
    id: str
    relationship_type: str
    source_object: str
    target_object: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    confidence: float = 0.8
    source: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)
    observations: int = 1
    created_at: datetime
    updated_at: datetime
    synthetic: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def timestamp(self) -> datetime | None:
        """When the relationship was first established (first observation)."""
        return self.first_seen or self.valid_from

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confidence_level(self) -> ConfidenceLevel:
        return confidence_level(self.confidence)

    def active_at(self, at: datetime | None) -> bool:
        if at is None:
            return self.valid_to is None
        start = self.valid_from or self.first_seen
        if start is not None and start > at:
            return False
        return not (self.valid_to is not None and self.valid_to <= at)


class EventObject(RafModel):
    object_id: str
    role: str


class Event(RafModel):
    id: str
    timestamp: datetime
    event_type: str
    category: str
    action: str
    outcome: str | None = None
    actor: str | None = None
    target: str | None = None
    objects: list[EventObject] = Field(default_factory=list)
    source: str
    parser: str
    record: str | None = None
    raw_reference: str | None = None
    raw: str | None = None
    severity: Severity = Severity.INFO
    confidence: float = 0.8
    attributes: dict[str, Any] = Field(default_factory=dict)
    relationships: list[str] = Field(default_factory=list)
    message: str | None = None
    synthetic: bool = False
    job_id: str | None = None
    incidents: list[str] = Field(default_factory=list)
    ingested_at: datetime | None = None

    def involved(self, role: str | None = None) -> list[str]:
        return [ref.object_id for ref in self.objects if role is None or ref.role == role]


class EvidenceRef(RafModel):
    """Pointer from a conclusion to supporting data."""

    kind: str  # object | relationship | event | evidence | finding | policy | rule | external
    id: str
    note: str | None = None


class Finding(RafModel):
    id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    product: str
    rule_id: str
    status: FindingStatus = FindingStatus.OPEN
    affected_objects: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    recommendation: str = ""
    explanation: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confidence_level(self) -> ConfidenceLevel:
        return confidence_level(self.confidence)


class Incident(RafModel):
    id: str
    name: str
    title: str
    status: str = "open"
    severity: Severity = Severity.MEDIUM
    start: datetime | None = None
    end: datetime | None = None
    description: str = ""
    source: str = "unknown"
    event_count: int = 0
    created_at: datetime
    updated_at: datetime
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProvenanceRecord(RafModel):
    subject_id: str
    subject_kind: str
    source: str
    parser: str | None = None
    record: str | None = None
    event_id: str | None = None
    observed_at: datetime | None = None
    evidence_id: str | None = None
    source_sha256: str | None = None
    job_id: str | None = None
    note: str | None = None
    recorded_at: datetime | None = None
