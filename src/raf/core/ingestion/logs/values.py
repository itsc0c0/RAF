"""Payload value parsing for mixed logs: JSON objects, key=value pairs (logfmt), CEF and LEEF,
nested field access, and redaction of credential-like values.

Everything here treats its input as untrusted text: sizes are bounded, nothing is evaluated, and
values of credential-like fields never leave in clear text.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from functools import lru_cache
from typing import Any

from raf.core.security.redaction import redact_secret, redact_text

MAX_PAIRS = 256
MAX_JSON_DEPTH = 64

_KV = re.compile(
    r"(?:^|(?<=[\s,;|]))(?P<key>[A-Za-z_@][\w.\-@/\[\]]{0,63})=(?P<value>\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s,;|\"']*)"
)
_CEF = re.compile(r"^(?:.*?\s)?CEF:(?P<version>\d+)\|(?P<rest>.*)$")
_LEEF = re.compile(r"^(?:.*?\s)?LEEF:(?P<version>[12]\.0)\|(?P<rest>.*)$")
_CEF_KEY = re.compile(r"(?:^|\s)(?P<key>[A-Za-z0-9_.\[\]-]{1,64})=")
_SECRET_FIELD = re.compile(
    r"(?i)(?:^|[._-])(?:pass(?:word|wd|phrase)?|pwd|secret|client[_-]?secret|api[_-]?key|apikey|token|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|auth[_-]?(?:header|token)|cookie|"
    r"set[_-]?cookie|private[_-]?key|secret[_-]?access[_-]?key|session[_-]?token|x[_-]?api[_-]?key|credentials?)$"
)
_PATH_LIKE = re.compile(r"^(?:/|~|[A-Za-z]:\\)")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACCESS_KEY_ID = re.compile(r"^(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|AIPA)[A-Z0-9]{12,}$")


# --------------------------------------------------------------------------- JSON


def _depth_ok(value: Any, depth: int = 0) -> bool:
    if depth > MAX_JSON_DEPTH:
        return False
    if isinstance(value, dict):
        return all(_depth_ok(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return all(_depth_ok(v, depth + 1) for v in value)
    return True


def json_object(text: str) -> dict[str, Any] | None:
    """The JSON object ``text`` holds (surrounding blanks allowed), or None."""
    stripped = text.strip()
    if len(stripped) < 2 or stripped[0] != "{" or stripped[-1] != "}":
        return None
    try:
        value = json.loads(stripped)
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, dict) or not _depth_ok(value):
        return None
    return value


def embedded_json(text: str) -> tuple[str, dict[str, Any]] | None:
    """A JSON object that ends the payload after some text (``event: {...}``): (prefix, object)."""
    start = text.find("{")
    if start <= 0 or not text.rstrip().endswith("}"):
        return None
    value = json_object(text[start:])
    return (text[:start].strip(), value) if value is not None else None


# --------------------------------------------------------------------------- key=value


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1]
    return value


def kv_pairs(text: str) -> dict[str, str]:
    """``key=value`` pairs (quoted values allowed), first occurrence of a key wins."""
    pairs: dict[str, str] = {}
    for match in _KV.finditer(text):
        key = match["key"]
        if key not in pairs:
            pairs[key] = _unquote(match["value"])
            if len(pairs) >= MAX_PAIRS:
                break
    return pairs


def kv_coverage(text: str) -> tuple[int, float]:
    """(pairs, share of the text's characters covered by pairs): how much a line is key=value."""
    covered = 0
    count = 0
    for match in _KV.finditer(text):
        count += 1
        covered += match.end() - match.start()
        if count >= MAX_PAIRS:
            break
    stripped = len(text.strip()) or 1
    return count, covered / stripped


# --------------------------------------------------------------------------- CEF / LEEF


def _split_unescaped(text: str, sep: str, limit: int) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == sep and len(parts) < limit:
            parts.append("".join(current))
            current = []
            if len(parts) == limit:
                parts.append(text[index + 1 :])
                return parts
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _cef_extension(text: str) -> dict[str, str]:
    keys = list(_CEF_KEY.finditer(text))
    result: dict[str, str] = {}
    for index, match in enumerate(keys[:MAX_PAIRS]):
        end = keys[index + 1].start() if index + 1 < len(keys) else len(text)
        value = text[match.end() : end].strip()
        result.setdefault(match["key"], value.replace("\\=", "=").replace("\\n", "\n").replace("\\\\", "\\"))
    return result


def parse_cef(text: str) -> dict[str, Any] | None:
    """``CEF:0|vendor|product|version|signature|name|severity|extension`` (a syslog prefix is allowed)."""
    m = _CEF.match(text)
    if m is None:
        return None
    parts = _split_unescaped(m["rest"], "|", 6)
    if len(parts) < 7:
        return None
    vendor, product, version, signature, name, severity, extension = parts[:7]
    return {
        "cef_version": m["version"],
        "vendor": vendor,
        "product": product,
        "product_version": version,
        "signature": signature,
        "name": name,
        "severity": severity,
        "extension": _cef_extension(extension),
    }


def parse_leef(text: str) -> dict[str, Any] | None:
    """``LEEF:1.0|vendor|product|version|eventid|attributes`` (tab separated; LEEF 2.0 names its delimiter)."""
    m = _LEEF.match(text)
    if m is None:
        return None
    parts = _split_unescaped(m["rest"], "|", 5 if m["version"] == "2.0" else 4)
    if len(parts) < 5:
        return None
    vendor, product, version, event_id = parts[:4]
    delimiter = "\t"
    attributes = parts[4]
    if m["version"] == "2.0" and len(parts) >= 6:
        spec, attributes = parts[4], parts[5]
        if spec.lower().startswith("x") and len(spec) > 1:
            try:
                delimiter = chr(int(spec[1:], 16))
            except ValueError:
                delimiter = "\t"
        elif spec:
            delimiter = spec[0]
    fields: dict[str, str] = {}
    for item in attributes.split(delimiter)[:MAX_PAIRS]:
        key, sep, value = item.partition("=")
        if sep and key.strip():
            fields.setdefault(key.strip(), value.strip())
    return {"vendor": vendor, "product": product, "product_version": version, "event_id": event_id, "fields": fields}


# --------------------------------------------------------------------------- field access


@lru_cache(maxsize=65536)
def snake(key: str) -> str:
    """``sourceIPAddress`` / ``Source-IP`` / ``source.ip`` -> ``source_ip_address`` / ``source_ip`` ..."""
    text = _CAMEL.sub("_", key.replace("IPAddress", "IpAddress").replace("IP", "Ip").replace("ID", "Id"))
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def flatten(data: dict[str, Any], *, prefix: str = "", depth: int = 0, limit: int = 512) -> dict[str, Any]:
    """Nested dicts to ``a.b.c`` keys (lists of scalars are kept; lists of dicts index their items)."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if len(out) >= limit:
            break
        name = f"{prefix}{key}"
        if isinstance(value, dict) and depth < 6:
            out.update(flatten(value, prefix=name + ".", depth=depth + 1, limit=limit - len(out)))
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value) and depth < 6:
            for index, item in enumerate(value[:8]):
                out.update(flatten(item, prefix=f"{name}.{index}.", depth=depth + 1, limit=limit - len(out)))
        else:
            out[name] = value
    return out


class Fields:
    """Case- and style-insensitive access to a record's (flattened) fields."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.flat = flatten(data)
        self._index: dict[str, str] = {}
        for key in self.flat:
            self._index.setdefault(key, key)
            self._index.setdefault(key.lower(), key)
            self._index.setdefault(snake(key), key)
        self.used: set[str] = set()

    def raw_key(self, name: str) -> str | None:
        key = self._index.get(name) or self._index.get(name.lower())
        return key if key is not None else self._index.get(snake(name))

    def get(self, *names: str) -> Any:
        """The first non-empty value among ``names`` (``a.b`` paths, any naming style)."""
        for name in names:
            key = self.raw_key(name)
            if key is None:
                continue
            value = self.flat[key]
            if value in (None, "", [], {}, "-"):
                continue
            self.used.add(key)
            return value
        return None

    def text(self, *names: str) -> str | None:
        value = self.get(*names)
        if value is None or isinstance(value, dict):
            return None
        if isinstance(value, list):
            value = next((v for v in value if isinstance(v, str | int | float) and v != ""), None)
            if value is None:
                return None
        return str(value).strip() or None

    def number(self, *names: str) -> float | None:
        value = self.get(*names)
        if isinstance(value, bool):
            return None
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                return None
        return None

    def integer(self, *names: str) -> int | None:
        number = self.number(*names)
        return int(number) if number is not None and abs(number) < 2**62 else None

    def items(self) -> Iterator[tuple[str, Any]]:
        yield from self.flat.items()

    def unused(self) -> dict[str, Any]:
        return {k: v for k, v in self.flat.items() if k not in self.used}


# --------------------------------------------------------------------------- redaction


def is_secret_field(name: str) -> bool:
    """A field whose value is a credential (``password``, ``apiKey``, ``Authorization`` ...)."""
    return bool(_SECRET_FIELD.search(snake(name).replace("_", "-"))) or bool(_SECRET_FIELD.search(name))


def fingerprint(value: str) -> str:
    """A short, unkeyed SHA-256 fingerprint for correlating an identifier without printing it."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def is_access_key_id(value: str) -> bool:
    return bool(_ACCESS_KEY_ID.match(value.strip()))


def redact_access_key(value: str) -> str:
    return redact_secret(value, keep_prefix=4, keep_suffix=4)


def safe_value(name: str, value: Any) -> Any:
    """``value`` as it may be stored: credential-like fields are redacted, long text is bounded and
    secret-looking substrings in text are masked."""
    if isinstance(value, str):
        if is_secret_field(name) and value and value != "-" and not _PATH_LIKE.match(value):
            return redact_secret(value)
        text = value if len(value) <= 2048 else value[:2048] + "...[truncated]"
        return redact_text(text)
    if isinstance(value, list):
        return [safe_value(name, v) for v in value[:64]]
    if isinstance(value, dict):
        return {str(k)[:64]: safe_value(str(k), v) for k, v in list(value.items())[:64]}
    return value


def safe_attributes(pairs: Iterable[tuple[str, Any]], *, limit: int = 64) -> dict[str, Any]:
    """Extra source fields kept as event attributes (bounded, redacted, scalar keys)."""
    out: dict[str, Any] = {}
    for key, value in pairs:
        if len(out) >= limit:
            break
        if value in (None, "", [], {}):
            continue
        name = snake(str(key))[:64] or "field"
        if name in out:
            continue
        out[name] = safe_value(str(key), value)
    return out


__all__ = [
    "Fields",
    "embedded_json",
    "fingerprint",
    "flatten",
    "is_access_key_id",
    "is_secret_field",
    "json_object",
    "kv_coverage",
    "kv_pairs",
    "parse_cef",
    "parse_leef",
    "redact_access_key",
    "safe_attributes",
    "safe_value",
    "snake",
]
