"""JSON, JSON Lines and CSV parsers (streaming where the format allows it)."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any, ClassVar

from raf.core.errors import ResourceLimitExceeded
from raf.core.ingestion.base import ParseContext, Parser, RawRecord, RecordRejected
from raf.core.security.files import iter_lines

_NATIVE_SECTIONS = ("objects", "relationships", "incidents", "events", "findings")
_SECTION_KIND = {
    "objects": "object",
    "relationships": "relationship",
    "incidents": "incident",
    "events": "event",
    "findings": "finding",
}
_CONTAINER_KEYS = ("Records", "records", "events", "items", "data", "logs", "results", "entries", "alerts")


def _json_lines(head: bytes, n: int = 5) -> int:
    count = 0
    for line in head.splitlines()[: n + 1]:
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            return 0
        if not isinstance(value, dict):
            return 0
        count += 1
        if count >= n:
            break
    return count


class JsonLinesParser(Parser):
    name: ClassVar[str] = "jsonl"
    description: ClassVar[str] = "JSON Lines / NDJSON (one JSON object per line)"
    extensions: ClassVar[tuple[str, ...]] = (".jsonl", ".ndjson", ".jsonlines")
    normalizer: ClassVar[str] = "auto"

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        lines = _json_lines(head)
        score = 0.0
        if lines >= 2:
            score = 0.9
        elif lines == 1 and len(head.strip().splitlines()) == 1:
            score = 0.4
        if path.suffix.lower() in cls.extensions:
            score = max(score, 0.7) + 0.05
        return min(score, 1.0)

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        for line in iter_lines(stream, ctx.max_record_bytes):
            locator = f"line {line.number}"
            if line.text is None:
                yield RawRecord.rejected(locator, f"Line exceeds {ctx.max_record_bytes} bytes.")
                continue
            if not line.text.strip():
                continue
            try:
                value = json.loads(line.text)
            except json.JSONDecodeError as exc:
                yield RawRecord.rejected(locator, f"Malformed JSON: {exc.msg} (column {exc.colno}).", line.text)
                continue
            except RecursionError:
                yield RawRecord.rejected(locator, "JSON nesting is too deep.", line.text[:4096])
                continue
            yield RawRecord(value, locator, line.text)


def iter_json_array(stream: IO[bytes], max_element: int) -> Iterator[tuple[int, Any, str]]:
    """Stream elements of a top-level JSON array without loading the document."""
    decoder = json.JSONDecoder()
    reader = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
    buffer = ""
    started = False
    index = 0
    eof = False
    while True:
        if not eof and len(buffer) < 65536:
            chunk = reader.read(262144)
            if chunk:
                buffer += chunk
            else:
                eof = True
        stripped = buffer.lstrip()
        if not started:
            if not stripped and eof:
                return
            if not stripped:
                continue
            if stripped[0] != "[":
                raise RecordRejected("Expected a JSON array.")
            buffer = stripped[1:]
            started = True
            continue
        buffer = stripped.lstrip(",").lstrip()
        if buffer.startswith("]"):
            return
        if not buffer:
            if eof:
                raise RecordRejected("Unterminated JSON array.")
            continue
        try:
            value, end = decoder.raw_decode(buffer)
        except RecursionError as exc:
            raise RecordRejected(f"JSON nesting is too deep in array element {index}.") from exc
        except json.JSONDecodeError as exc:
            if eof or len(buffer) > max_element:
                if len(buffer) > max_element:
                    raise ResourceLimitExceeded(f"JSON array element {index} exceeds {max_element} bytes.") from exc
                raise RecordRejected(f"Malformed JSON in array element {index}: {exc.msg}.") from exc
            chunk = reader.read(262144)
            if chunk:
                buffer += chunk
            else:
                eof = True
            continue
        yield index, value, buffer[:end]
        index += 1
        buffer = buffer[end:]


class JsonParser(Parser):
    name: ClassVar[str] = "json"
    description: ClassVar[str] = "JSON documents: arrays, {Records: [...]}, R$F native documents"
    extensions: ClassVar[tuple[str, ...]] = (".json",)
    normalizer: ClassVar[str] = "auto"

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        text = head.lstrip()
        if text[:1] not in (b"[", b"{"):
            return 0.0
        if _json_lines(head) >= 2:
            return 0.3
        score = 0.75
        if path.suffix.lower() == ".json":
            score = 0.85
        return score

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        first = stream.read(1)
        while first and first.isspace():
            first = stream.read(1)
        if not first:
            return
        combined = io.BufferedReader(_Prefixed(first, stream))
        if first == b"[":
            try:
                for index, value, raw in iter_json_array(combined, ctx.max_record_bytes):
                    yield RawRecord(value, f"[{index}]", raw)
            except RecordRejected as exc:
                yield RawRecord(None, "array", error=exc)
            return
        limit = int(ctx.options.get("max_json_document_bytes", 256 * 1024 * 1024))
        data = combined.read(limit + 1)
        if len(data) > limit:
            raise ResourceLimitExceeded(
                "JSON document is too large to load in one piece.",
                hint="Convert it to JSON Lines (one record per line) for streaming import.",
            )
        try:
            document = json.loads(data.decode("utf-8", "replace"))
        except RecursionError:
            yield RawRecord.rejected("document", "JSON nesting is too deep.")
            return
        except json.JSONDecodeError as exc:
            yield RawRecord.rejected("document", f"Malformed JSON document: {exc.msg} (line {exc.lineno}).")
            return
        yield from self._document(document)

    def _document(self, document: Any) -> Iterator[RawRecord]:
        if isinstance(document, list):
            for index, item in enumerate(document):
                yield RawRecord(item, f"[{index}]", _dump(item))
            return
        if not isinstance(document, dict):
            yield RawRecord.rejected("document", "JSON document is neither an object nor an array.")
            return
        if any(isinstance(document.get(s), list) for s in _NATIVE_SECTIONS) and (
            "raf_format" in document or "objects" in document or "relationships" in document
        ):
            for section in _NATIVE_SECTIONS:
                for index, item in enumerate(document.get(section) or []):
                    if isinstance(item, dict):
                        item = {"kind": _SECTION_KIND[section], **item}
                    yield RawRecord(item, f"{section}[{index}]", _dump(item), normalizer="raf-native")
            return
        hits = document.get("hits")
        if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
            for index, hit in enumerate(hits["hits"]):
                source = hit.get("_source", hit) if isinstance(hit, dict) else hit
                yield RawRecord(source, f"hits[{index}]", _dump(source))
            return
        for key in _CONTAINER_KEYS:
            if isinstance(document.get(key), list):
                normalizer = "cloudtrail" if key == "Records" else None
                for index, item in enumerate(document[key]):
                    yield RawRecord(item, f"{key}[{index}]", _dump(item), normalizer=normalizer)
                return
        yield RawRecord(document, "document", _dump(document))


class _Prefixed(io.RawIOBase):
    """A readable stream that replays an already-consumed prefix."""

    def __init__(self, prefix: bytes, stream: IO[bytes]) -> None:
        self.prefix = prefix
        self.stream = stream

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        view = memoryview(buffer)
        if self.prefix:
            n = min(len(view), len(self.prefix))
            view[:n] = self.prefix[:n]
            self.prefix = self.prefix[n:]
            return n
        data = self.stream.read(len(view))
        view[: len(data)] = data
        return len(data)


def _dump(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)[:65536]
    except (TypeError, ValueError):
        return str(value)[:65536]


class CsvParser(Parser):
    name: ClassVar[str] = "csv"
    description: ClassVar[str] = "CSV / TSV with a header row (columns mapped by common aliases)"
    extensions: ClassVar[tuple[str, ...]] = (".csv", ".tsv")
    normalizer: ClassVar[str] = "tabular"

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        text = head.decode("utf-8", "replace")
        lines = [ln for ln in text.splitlines()[:10] if ln.strip()]
        if len(lines) < 2:
            return 0.0
        try:
            dialect = csv.Sniffer().sniff("\n".join(lines[:5]), delimiters=",;\t|")
        except csv.Error:
            return 0.0
        counts = {line.count(dialect.delimiter) for line in lines[:5]}
        if len(counts) != 1 or 0 in counts:
            return 0.1
        score = 0.65
        if path.suffix.lower() in cls.extensions:
            score = 0.9
        if lines[0].lstrip().startswith(("{", "[")):
            score = 0.05
        return score

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        text = io.TextIOWrapper(stream, encoding="utf-8-sig", errors="replace", newline="")
        sample = text.read(65536)
        text.seek(0)
        try:
            dialect: Any = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        csv.field_size_limit(max(ctx.max_record_bytes, 131072))
        reader = csv.DictReader(text, dialect=dialect, restkey="_extra_columns")
        if not reader.fieldnames:
            return
        try:
            for row in reader:
                locator = f"row {reader.line_num}"
                if row.get("_extra_columns"):
                    if len(ctx.warnings) < 50:
                        ctx.warnings.append(f"{locator}: more values than header columns")
                    row.pop("_extra_columns", None)
                raw = dialect.delimiter.join("" if v is None else str(v) for v in row.values())
                yield RawRecord({k: v for k, v in row.items() if k is not None}, locator, raw)
        except csv.Error as exc:
            yield RawRecord.rejected(f"row {reader.line_num}", f"CSV framing error: {exc}")
