"""Surface inventory formats: ``raf-surface/1`` documents (JSON or YAML), JSON Lines and CSV.

Inventory files are untrusted input. They are read with safe parsers only (``json``, a YAML safe
loader that also refuses aliases, ``csv``), limited in size (20 MB), number of records (50,000),
line length and nesting depth. Problems with the document as a whole (not JSON, wrong format
marker, ``records`` not a list) refuse the import; problems with a single record are reported
with the record's locator while the rest of the file is imported.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PurePath
from typing import Any

import yaml

from raf.core.errors import InvalidInputError, ResourceLimitExceeded
from raf.products.surface.model import (
    FORMAT,
    MAX_DOCUMENT_BYTES,
    MAX_LINE_BYTES,
    MAX_RECORDS,
    MAX_SCOPE_ENTRIES,
    clean_text,
    parse_time,
    safe_display,
)

FORMATS = ("json", "jsonl", "yaml", "csv")
SUFFIXES = {
    ".json": "json",
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".csv": "csv",
}
#: Sections of a raf-surface/1 document that hold records of one kind.
SECTIONS = {
    "domains": "domain",
    "dns": "dns",
    "dns_records": "dns",
    "ips": "ip",
    "addresses": "ip",
    "services": "service",
    "certificates": "certificate",
    "cloud_assets": "cloud_asset",
    "owners": "owner",
}
TOP_LEVEL_KEYS = frozenset({"format", "organization", "as_of", "description", "scope", "records", *SECTIONS})
MAX_WARNINGS = 50
MAX_FRAMING_ERRORS = 1000


@dataclass(slots=True)
class RawItem:
    """One record (or scope entry) as found in the document, before validation."""

    locator: str
    data: Any
    kind: str | None = None  # implied by the document section


@dataclass(slots=True)
class SurfaceDocument:
    format: str
    items: list[RawItem] = field(default_factory=list)
    scope: list[RawItem] = field(default_factory=list)
    rejections: list[tuple[str, str]] = field(default_factory=list)  # framing errors: (locator, reason)
    warnings: list[str] = field(default_factory=list)
    organization: str | None = None
    as_of: datetime | None = None
    overflow: int = 0  # records beyond MAX_RECORDS (not imported)

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS and message not in self.warnings:
            self.warnings.append(message)


class _NoAliasLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses anchors' aliases (no alias-expansion resource exhaustion)."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()  # type: ignore[no-untyped-call]
            raise yaml.composer.ComposerError(
                None, None, "YAML aliases are not allowed in surface inventories", event.start_mark
            )
        return super().compose_node(parent, index)


def detect_format(name: str, head: bytes) -> str:
    """Format from the file suffix, else from the content."""
    suffix = PurePath(name).suffix.lower()
    if suffix in SUFFIXES:
        return SUFFIXES[suffix]
    text = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if text[:1] in (b"{", b"["):
        lines = [line.strip() for line in text.split(b"\n") if line.strip()][:3]
        if len(lines) >= 2 and all(line.startswith(b"{") and line.endswith(b"}") for line in lines):
            return "jsonl"
        return "json"
    first = text.split(b"\n", 1)[0].lower()
    if b"kind" in first and b"," in first:
        return "csv"
    return "yaml"


def parse_document(data: bytes, fmt: str) -> SurfaceDocument:
    """Parse an inventory document of the given format (json, jsonl, yaml or csv)."""
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ResourceLimitExceeded(
            f"The inventory is {len(data) / 1e6:.1f} MB; surface inventories are limited to "
            f"{MAX_DOCUMENT_BYTES // (1024 * 1024)} MB.",
            hint="Split the inventory into several files.",
        )
    text = data.decode("utf-8-sig", "replace")
    if fmt == "json":
        document = from_structure(_load_json(text), "json")
    elif fmt == "yaml":
        document = from_structure(_load_yaml(text), "yaml")
    elif fmt == "jsonl":
        document = _jsonl(text)
    elif fmt == "csv":
        document = _csv(text)
    else:
        raise InvalidInputError(f"Unknown inventory format {fmt!r}.", hint="Use json, jsonl, yaml or csv.")
    if document.overflow:
        document.rejections.append(
            ("document", f"{document.overflow:,} records beyond the limit of {MAX_RECORDS:,} were not read.")
        )
    return document


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except RecursionError as exc:
        raise InvalidInputError("The inventory is nested too deeply.") from exc
    except ValueError as exc:  # JSONDecodeError, oversized integers
        detail = (
            f"{exc.msg} (line {exc.lineno}, column {exc.colno})"
            if isinstance(exc, json.JSONDecodeError)
            else str(exc)[:160]
        )
        raise InvalidInputError(f"The inventory is not valid JSON: {detail}.") from exc


def _load_yaml(text: str) -> Any:
    try:
        return yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506 - SafeLoader subclass (no aliases)
    except RecursionError as exc:
        raise InvalidInputError("The inventory is nested too deeply.") from exc
    except (yaml.YAMLError, ValueError) as exc:
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        raise InvalidInputError(f"The inventory is not valid YAML: {safe_display(first, 200)}") from exc


def _extend(document: SurfaceDocument, items: list[Any], section: str, kind: str | None) -> None:
    for index, item in enumerate(items):
        if len(document.items) >= MAX_RECORDS:
            document.overflow += len(items) - index
            return
        locator = f"{section}[{index}]" if section else f"[{index}]"
        document.items.append(RawItem(locator, item, kind))


def _header(document: SurfaceDocument, header: dict[Any, Any]) -> None:
    marker = header.get("format")
    if marker is not None and str(marker).strip() != FORMAT:
        raise InvalidInputError(
            f"Unsupported inventory format {safe_display(marker, 60)!r}.", hint=f"Surface reads {FORMAT} documents."
        )
    try:
        document.organization = clean_text(header.get("organization"), "organization")
    except InvalidInputError as exc:
        document.warn(f"organization ignored: {exc.message}")
    try:
        document.as_of = parse_time(header.get("as_of"), "as_of")
    except InvalidInputError as exc:
        document.warn(f"as_of ignored: {exc.message}")
    scope = header.get("scope")
    if scope is not None:
        if not isinstance(scope, list):
            raise InvalidInputError("'scope' must be a list of entries.")
        if len(scope) > MAX_SCOPE_ENTRIES:
            raise ResourceLimitExceeded(f"'scope' has {len(scope)} entries (limit {MAX_SCOPE_ENTRIES}).")
        document.scope = [RawItem(f"scope[{i}]", item) for i, item in enumerate(scope)]


def from_structure(doc: Any, fmt: str) -> SurfaceDocument:
    """A parsed JSON/YAML value: a raf-surface/1 document or a plain list of records."""
    document = SurfaceDocument(format=fmt)
    if isinstance(doc, list):
        _extend(document, doc, "", None)
        return document
    if not isinstance(doc, dict):
        raise InvalidInputError(
            "A surface inventory must be a raf-surface/1 document (an object) or a list of records."
        )
    _header(document, doc)
    for key in doc:
        if not isinstance(key, str) or key not in TOP_LEVEL_KEYS:
            document.warn(f"unknown top-level key {safe_display(key, 60)!r} ignored")
    records = doc.get("records")
    if records is not None:
        if not isinstance(records, list):
            raise InvalidInputError("'records' must be a list.")
        _extend(document, records, "records", None)
    for section, kind in SECTIONS.items():
        items = doc.get(section)
        if items is None:
            continue
        if not isinstance(items, list):
            raise InvalidInputError(f"'{section}' must be a list.")
        _extend(document, items, section, kind)
    if not document.items and not document.scope:
        document.warn("the document contains no records")
    return document


def _jsonl(text: str) -> SurfaceDocument:
    document = SurfaceDocument(format="jsonl")
    for number, line in enumerate(text.split("\n"), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        locator = f"line {number}"
        if len(stripped) > MAX_LINE_BYTES:
            document.rejections.append((locator, f"Line exceeds {MAX_LINE_BYTES // 1024} KB."))
            continue
        try:
            value = json.loads(stripped)
        except RecursionError:
            document.rejections.append((locator, "JSON nesting is too deep."))
            continue
        except ValueError as exc:
            reason = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)[:120]
            document.rejections.append((locator, f"Malformed JSON: {reason}."))
            continue
        if isinstance(value, dict) and "kind" not in value and "format" in value:
            if document.items:
                document.warn(f"{locator}: a format header after the first record is ignored")
                continue
            _header(document, value)
            continue
        if len(document.items) >= MAX_RECORDS:
            document.overflow += 1
            continue
        document.items.append(RawItem(locator, value))
    return document


def _column(name: str) -> str:
    return "_".join(name.strip().strip('"').lower().replace("-", " ").split())


def _csv(text: str) -> SurfaceDocument:
    document = SurfaceDocument(format="csv")
    reader = csv.reader(io.StringIO(text, newline=""))
    header: list[str] | None = None
    errors = 0
    while True:
        try:
            row = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:
            if header is None:
                raise InvalidInputError(f"Malformed CSV header: {exc}") from exc
            errors += 1
            document.rejections.append((f"line {reader.line_num}", f"CSV framing error: {exc}"))
            if errors >= MAX_FRAMING_ERRORS:
                document.rejections.append(("document", "Too many CSV framing errors; the rest was not read."))
                break
            continue
        if not any(cell.strip() for cell in row):
            continue
        if header is None:
            header = [_column(cell) for cell in row]
            if "kind" not in header:
                raise InvalidInputError(
                    "A CSV surface inventory needs a 'kind' column.",
                    hint="Columns are record fields (kind, name, type, value, address, port ...).",
                )
            if len(set(header)) != len(header):
                document.warn("duplicate CSV columns: the first occurrence of each is used")
            continue
        if len(row) > len(header):
            document.warn(f"line {reader.line_num}: more values than header columns (extra values ignored)")
        record: dict[str, str] = {}
        for column, cell in zip(header, row, strict=False):
            if column and column not in record and cell.strip():
                record[column] = cell
        if len(document.items) >= MAX_RECORDS:
            document.overflow += 1
            continue
        document.items.append(RawItem(f"line {reader.line_num}", record))
    if header is None:
        raise InvalidInputError("The CSV inventory is empty.")
    return document
