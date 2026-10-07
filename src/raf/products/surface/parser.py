"""Ingestion parser so ``raf import`` / ``raf analyze`` recognize surface inventories.

Detection is conservative: a ``raf-surface/1`` format marker in the first 64 KB (JSON, YAML or a
JSON Lines header line), or a CSV header with a ``kind`` column whose first rows hold surface
record kinds. The parser yields the same R$F-native records as ``raf surface import``. It never
changes the authorized scope: a ``scope`` section is reported as a warning (apply it with
``raf surface import FILE --apply-scope`` after reviewing it).
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from pathlib import Path
from typing import IO, ClassVar

from raf.core.errors import InvalidInputError
from raf.core.ingestion.base import ParseContext, Parser, RawRecord
from raf.core.timeutil import utcnow
from raf.products.surface.convert import build
from raf.products.surface.formats import detect_format, parse_document
from raf.products.surface.model import FORMAT, LABEL, MAX_DOCUMENT_BYTES, RECORD_KINDS

_CSV_HINTS = frozenset({"name", "address", "ip", "host", "value", "port", "fingerprint_sha256", "provider", "asset"})


def sniff_surface(head: bytes, suffix: str) -> float:
    text = head[:65536].decode("utf-8", "replace")
    if FORMAT in text.lower():
        return 0.98
    if suffix not in (".csv", ".txt", ""):
        return 0.0
    lines = [line for line in text.splitlines() if line.strip()][:6]
    if len(lines) < 2:
        return 0.0
    try:
        rows = list(csv.reader(io.StringIO("\n".join(lines))))
    except csv.Error:
        return 0.0
    header = ["_".join(cell.strip().lower().split()) for cell in rows[0]]
    if "kind" not in header or not (_CSV_HINTS & set(header)):
        return 0.0
    index = header.index("kind")
    kinds = {row[index].strip().lower() for row in rows[1:] if len(row) > index and row[index].strip()}
    if kinds and kinds <= set(RECORD_KINDS):
        return 0.96
    return 0.0


class SurfaceInventoryParser(Parser):
    name: ClassVar[str] = "raf-surface"
    version: ClassVar[str] = "1.0"
    description: ClassVar[str] = "Surface inventories (raf-surface/1): JSON, JSON Lines, YAML, CSV"
    extensions: ClassVar[tuple[str, ...]] = (".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".csv")
    normalizer: ClassVar[str] = "raf-native"

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        return sniff_surface(head, path.suffix.lower())

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        data = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(data) > MAX_DOCUMENT_BYTES:
            yield RawRecord.rejected(
                "document", f"Surface inventories are limited to {MAX_DOCUMENT_BYTES // (1024 * 1024)} MB."
            )
            return
        path = ctx.source.path
        name = path.name if path else ctx.source.name
        try:
            document = parse_document(data, detect_format(name, data[:65536]))
        except InvalidInputError as exc:
            yield RawRecord.rejected("document", exc.message)
            return
        conversion = build(document, observed=document.as_of or utcnow())
        for warning in conversion.warnings[:20]:
            ctx.warnings.append(f"{name}: {warning}")
        if document.scope:
            ctx.warnings.append(
                f"{name}: {len(document.scope)} scope entries were not applied (raf import never changes the "
                "authorized scope; review them, then run raf surface import FILE --apply-scope)"
            )
        for rejected in conversion.rejected:
            yield RawRecord.rejected(rejected.locator, rejected.reason, rejected.raw)
        for native in conversion.natives:
            yield RawRecord(native.data, native.locator, parser_label=LABEL, normalizer="raf-native")
