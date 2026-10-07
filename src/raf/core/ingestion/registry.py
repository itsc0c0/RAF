"""Parser and normalizer registry with format detection."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from raf.core.errors import InvalidInputError
from raf.core.ingestion.base import Normalizer, Parser
from raf.core.ingestion.normalizers import (
    CloudTrailNormalizer,
    EcsNormalizer,
    GenericJsonNormalizer,
    NativeNormalizer,
    TabularNormalizer,
)
from raf.core.ingestion.parsers.structured import CsvParser, JsonLinesParser, JsonParser
from raf.core.ingestion.parsers.textlogs import AccessLogParser, SyslogParser, TextLogParser
from raf.core.ingestion.refs import ResolveName

NormalizerFactory = Callable[[NativeNormalizer], Normalizer]


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: dict[str, type[Parser]] = {}
        self._normalizers: dict[str, NormalizerFactory] = {}

    @classmethod
    def default(cls) -> ParserRegistry:
        registry = cls()
        for parser in (JsonLinesParser, JsonParser, CsvParser, SyslogParser, AccessLogParser, TextLogParser):
            registry.register_parser(parser)
        registry.register_normalizer("ecs", EcsNormalizer)
        registry.register_normalizer("cloudtrail", CloudTrailNormalizer)
        registry.register_normalizer("tabular", TabularNormalizer)
        registry.register_normalizer("generic-json", GenericJsonNormalizer)
        return registry

    def register_parser(self, parser: type[Parser]) -> None:
        self._parsers[parser.name] = parser

    def register_normalizer(self, name: str, factory: NormalizerFactory) -> None:
        self._normalizers[name] = factory

    def parsers(self) -> list[type[Parser]]:
        return list(self._parsers.values())

    def get(self, name: str) -> type[Parser]:
        try:
            return self._parsers[name]
        except KeyError:
            raise InvalidInputError(
                f"Unknown input format '{name}'.", hint="Formats: " + ", ".join(sorted(self._parsers))
            ) from None

    def detect(self, path: Path, head: bytes) -> tuple[type[Parser], float] | None:
        best: tuple[type[Parser], float] | None = None
        for parser in self._parsers.values():
            try:
                score = parser.sniff(path, head)
            except Exception:  # noqa: BLE001 - a sniffer must never break detection
                score = 0.0
            if best is None or score > best[1]:
                best = (parser, score)
        if best is None or best[1] < 0.2:
            return None
        return best

    def normalizers(self, resolve: ResolveName | None) -> dict[str, Normalizer]:
        native = NativeNormalizer(resolve)
        result: dict[str, Normalizer] = {"raf-native": native}
        for name, factory in self._normalizers.items():
            result[name] = factory(native)
        return result
