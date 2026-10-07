"""Ingestion contracts: sources, raw records, parsers and normalizers.

RAW SOURCE -> Parser (bytes -> RawRecord) -> Normalizer (RawRecord -> NormalizedRecord)
-> entity resolution -> relationship builder -> store.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from pathlib import Path
from typing import IO, Any, ClassVar

from raf.core.errors import InvalidInputError
from raf.core.objects.models import EventDraft, Finding, ObjectDraft, RelationshipDraft


class RecordRejected(InvalidInputError):
    """A single record could not be normalized. The import continues."""

    code = "raf.record_rejected"


@dataclass(slots=True)
class SourceInfo:
    name: str
    path: Path | None = None
    sha256: str | None = None
    size: int | None = None
    evidence_id: str | None = None
    synthetic: bool = False
    incident: str | None = None
    default_host: str | None = None

    @property
    def identity(self) -> str:
        """Stable identity used to derive event IDs (content hash when known)."""
        return self.sha256 or self.name


@dataclass(slots=True)
class RawRecord:
    data: Any
    locator: str
    raw: str | None = None
    normalizer: str | None = None  # force a normalizer for this record
    parser_label: str | None = None  # e.g. "syslog-sshd/1.0" (defaults to the parser's label)
    error: RecordRejected | None = None  # framing error: the record is rejected, the import continues

    @classmethod
    def rejected(cls, locator: str, message: str, raw: str | None = None) -> RawRecord:
        return cls(None, locator, raw, error=RecordRejected(message))


@dataclass(slots=True)
class IncidentDraft:
    name: str
    title: str | None = None
    severity: str | None = None
    status: str | None = None
    description: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    tags: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class NormalizedRecord:
    objects: list[ObjectDraft] = field(default_factory=list)
    relationships: list[RelationshipDraft] = field(default_factory=list)
    events: list[EventDraft] = field(default_factory=list)
    incidents: list[IncidentDraft] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ParseContext:
    """Per-import settings and helpers available to parsers and normalizers."""

    source: SourceInfo
    default_tz: tzinfo
    reference_time: datetime | None
    max_record_bytes: int
    raw_max_bytes: int
    store_raw: bool
    user_strip_domain: bool = True
    options: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def excerpt(self, raw: str | None) -> str | None:
        if raw is None or not self.store_raw:
            return None
        encoded = raw.encode("utf-8", "replace")
        if len(encoded) <= self.raw_max_bytes:
            return raw
        return encoded[: self.raw_max_bytes].decode("utf-8", "ignore") + "...[truncated]"


class Parser(ABC):
    """Decodes a source into raw records. Implementations must stream (bounded memory)."""

    name: ClassVar[str]
    version: ClassVar[str] = "1.0"
    description: ClassVar[str] = ""
    extensions: ClassVar[tuple[str, ...]] = ()
    #: default normalizer for records this parser yields
    normalizer: ClassVar[str] = "raf-native"

    @classmethod
    @abstractmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        """Confidence (0..1) that this parser handles the file."""

    @abstractmethod
    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        """Yield raw records. Raise RecordRejected only for unrecoverable framing problems."""

    @property
    def label(self) -> str:
        return f"{self.name}/{self.version}"


class Normalizer(ABC):
    """Maps a structured record (dict) to canonical objects/events/relationships."""

    name: ClassVar[str]
    version: ClassVar[str] = "1.0"

    @classmethod
    def score(cls, record: dict[str, Any]) -> float:
        """How well this normalizer fits a sample record (used for auto-selection)."""
        return 0.0

    @abstractmethod
    def normalize(self, record: RawRecord, ctx: ParseContext) -> NormalizedRecord: ...
