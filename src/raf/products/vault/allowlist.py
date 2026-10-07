"""Vault allowlists: accepted findings by fingerprint, rule and/or path glob.

File format (YAML via ``yaml.safe_load``, or JSON)::

    allow:
      - fingerprint: 3f9a0c...        # 12-64 hex characters (prefix match)
        reason: revoked test key
      - rule: high-entropy
        path: "tests/fixtures/*"      # fnmatch glob on the path relative to the scan root
        reason: generated fixtures

Every condition present in an entry must match. A top-level list of entries is
also accepted. Allowlists are never read from the scanned tree itself: scanned
content is untrusted and must not be able to hide its own secrets.
"""

from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.timeutil import format_ts, utcnow
from raf.products.vault.detectors import RULE_INDEX

MAX_ALLOWLIST_BYTES = 1024 * 1024
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{12,64}$")


@dataclass(frozen=True, slots=True)
class AllowEntry:
    reason: str
    source: str
    fingerprint: str | None = None
    rule: str | None = None
    path: str | None = None

    def matches(self, *, rule: str, rel_path: str, abs_path: str, fingerprint: str) -> bool:
        if self.fingerprint is not None and not fingerprint.startswith(self.fingerprint):
            return False
        if self.rule is not None and self.rule != rule:
            return False
        return self.path is None or fnmatchcase(rel_path, self.path) or fnmatchcase(abs_path, self.path)

    def describe(self) -> str:
        parts = [f"{name}={value}" for name, value in (("rule", self.rule), ("path", self.path)) if value]
        if self.fingerprint:
            parts.insert(0, f"fingerprint={self.fingerprint[:16]}")
        return ", ".join(parts) + (f" ({self.reason})" if self.reason else "")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"reason": self.reason, "source": self.source}
        for name in ("fingerprint", "rule", "path"):
            if getattr(self, name) is not None:
                data[name] = getattr(self, name)
        return data


def normalize_fingerprint(value: str) -> str:
    text = value.strip().lower()
    if not FINGERPRINT_RE.match(text):
        raise InvalidInputError(
            f"'{value[:80]}' is not a Vault fingerprint.",
            hint="Use the fingerprint shown by 'raf vault scan' (12 to 64 hexadecimal characters).",
        )
    return text


def _entry(raw: Any, index: int, source: str) -> AllowEntry:
    if not isinstance(raw, dict):
        raise InvalidInputError(f"Allowlist entry {index} in {source} must be a mapping.")
    unknown = sorted(set(map(str, raw)) - {"fingerprint", "rule", "path", "reason", "added_at", "added_by"})
    if unknown:
        raise InvalidInputError(f"Allowlist entry {index} in {source} has unknown keys: {', '.join(unknown)}.")
    fingerprint = normalize_fingerprint(str(raw["fingerprint"])) if raw.get("fingerprint") else None
    rule = str(raw["rule"]).strip() if raw.get("rule") else None
    if rule is not None and rule not in RULE_INDEX:
        raise InvalidInputError(
            f"Allowlist entry {index} in {source} names an unknown rule '{rule[:60]}'.",
            hint="Rules: " + ", ".join(RULE_INDEX),
        )
    path = str(raw["path"]).strip() if raw.get("path") else None
    if path is not None and len(path) > 1024:
        raise InvalidInputError(f"Allowlist entry {index} in {source} has a path glob longer than 1024 characters.")
    if fingerprint is None and rule is None and path is None:
        raise InvalidInputError(f"Allowlist entry {index} in {source} needs a fingerprint, rule or path.")
    return AllowEntry(
        reason=str(raw.get("reason") or "")[:500], source=source, fingerprint=fingerprint, rule=rule, path=path
    )


def _read_document(path: Path) -> Any:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise NotFoundError(f"Allowlist {path} does not exist.") from exc
    if not stat.S_ISREG(info.st_mode):
        raise InvalidInputError(f"Allowlist {path} must be a regular file (symlinks are not followed).")
    if info.st_size > MAX_ALLOWLIST_BYTES:
        raise InvalidInputError(f"Allowlist {path} is larger than {MAX_ALLOWLIST_BYTES // 1024} KiB.")
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        if path.suffix.lower() == ".json":
            return json.loads(text)
        if any(isinstance(event, yaml.AliasEvent) for event in yaml.parse(text, Loader=yaml.SafeLoader)):
            raise InvalidInputError(f"Allowlist {path} uses YAML aliases, which are not allowed.")
        return yaml.safe_load(text)
    except (ValueError, yaml.YAMLError, RecursionError) as exc:
        raise InvalidInputError(f"Allowlist {path} is not valid {path.suffix.lstrip('.') or 'YAML'}.") from exc


def _entries_of(document: Any) -> list[Any]:
    if document is None:
        return []
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("allow", "allowlist", "entries"):
            if key in document:
                value = document[key]
                return value if isinstance(value, list) else []
        return []
    raise InvalidInputError("An allowlist must be a list of entries or a mapping with an 'allow' list.")


def load_allowlist(path: Path) -> list[AllowEntry]:
    document = _read_document(path)
    return [_entry(raw, index, str(path)) for index, raw in enumerate(_entries_of(document))]


def append_entry(path: Path, entry: dict[str, Any], actor: str) -> AllowEntry:
    """Append an entry to a YAML allowlist (created when missing), validating it first."""
    record = {k: v for k, v in entry.items() if v not in (None, "")}
    record["added_at"] = format_ts(utcnow())
    record["added_by"] = actor
    allow = _entry(record, 0, str(path))
    existing: list[Any] = _entries_of(_read_document(path)) if path.exists() else []
    existing.append(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    header = "# R$F Vault allowlist (raf vault allowlist add). Entries match by fingerprint, rule and/or path.\n"
    tmp.write_text(header + yaml.safe_dump({"allow": existing}, sort_keys=False, allow_unicode=True), "utf-8")
    tmp.replace(path)
    return allow
