"""Evidence storage: content-addressed, read-only copies and hash-chained chain of custody.

Originals are never modified or moved: an imported artifact is *copied* into
``<workspace>/evidence/<sha256[:2]>/<sha256><.ext>`` while its SHA-256 is computed, the copy is
made read-only, and every action on an item (acquired, stored, parsed, verified, noted, exported,
linked) is appended to a custody chain in which each entry commits to the previous one.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from raf.core.errors import IntegrityError, InvalidInputError
from raf.core.objects.models import RafModel
from raf.core.timeutil import utcnow

GENESIS = "0" * 64
_EXT_RE = re.compile(r"^\.[a-z0-9]{1,10}$")
CHUNK = 1024 * 1024


class CustodyEntry(RafModel):
    seq: int
    at: datetime
    action: str  # acquired | stored | parsed | verified | note | exported | linked | derived
    actor: str
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str


def actor_name(interface: str) -> str:
    try:
        user = getpass.getuser()
    except (KeyError, OSError):  # no passwd entry in some containers
        user = "unknown"
    return f"{interface}:{user}"


def _entry_hash(prev_hash: str, seq: int, at: datetime, action: str, actor: str, details: dict[str, Any]) -> str:
    body = json.dumps(
        {"seq": seq, "at": at.isoformat(), "action": action, "actor": actor, "details": details},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def append_custody(
    chain: list[CustodyEntry],
    action: str,
    actor: str,
    details: dict[str, Any] | None = None,
    at: datetime | None = None,
) -> CustodyEntry:
    when = at or utcnow()
    prev = chain[-1].hash if chain else GENESIS
    seq = len(chain) + 1
    data = dict(details or {})
    entry = CustodyEntry(
        seq=seq,
        at=when,
        action=action,
        actor=actor,
        details=data,
        prev_hash=prev,
        hash=_entry_hash(prev, seq, when, action, actor, data),
    )
    chain.append(entry)
    return entry


def verify_custody(chain: list[CustodyEntry]) -> tuple[bool, str | None]:
    prev = GENESIS
    for index, entry in enumerate(chain, 1):
        if entry.seq != index or entry.prev_hash != prev:
            return False, f"custody entry {index} is out of order or does not follow entry {index - 1}"
        expected = _entry_hash(entry.prev_hash, entry.seq, entry.at, entry.action, entry.actor, entry.details)
        if expected != entry.hash:
            return False, f"custody entry {index} ({entry.action}) was altered"
        prev = entry.hash
    return True, None


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


class StoredFile(RafModel):
    sha256: str
    size: int
    relative: str  # path inside the evidence store
    deduplicated: bool


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def path_for(self, relative: str) -> Path:
        candidate = (self.root / relative).resolve()
        if not candidate.is_relative_to(self.root.resolve()):
            raise IntegrityError("Evidence path escapes the evidence store.")
        return candidate

    def put(self, source: Path, *, max_bytes: int) -> StoredFile:
        """Copy ``source`` into the store (hashing while copying); the original is only read."""
        info = source.stat()
        if not stat.S_ISREG(info.st_mode):
            raise InvalidInputError(f"{source} is not a regular file.")
        if info.st_size > max_bytes:
            raise InvalidInputError(
                f"{source.name} is {info.st_size:,} bytes; the limit is {max_bytes:,} (ingest.max_file_mb)."
            )
        self.root.mkdir(parents=True, exist_ok=True)
        suffix = source.suffix.lower() if _EXT_RE.match(source.suffix.lower()) else ""
        digest = hashlib.sha256()
        size = 0
        fd, tmp_name = tempfile.mkstemp(prefix=".incoming-", dir=self.root)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as out, source.open("rb") as src:
                for block in iter(lambda: src.read(CHUNK), b""):
                    size += len(block)
                    if size > max_bytes:
                        raise InvalidInputError(f"{source.name} grew beyond the size limit while being copied.")
                    digest.update(block)
                    out.write(block)
            sha = digest.hexdigest()
            relative = f"{sha[:2]}/{sha}{suffix}"
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if sha256_of(target) != sha:
                    raise IntegrityError(f"Stored evidence {relative} does not match its name; refusing to reuse it.")
                tmp.unlink()
                return StoredFile(sha256=sha, size=size, relative=relative, deduplicated=True)
            tmp.replace(target)
            os.utime(target, (info.st_atime, info.st_mtime))
            target.chmod(stat.S_IRUSR | stat.S_IRGRP)
            return StoredFile(sha256=sha, size=size, relative=relative, deduplicated=False)
        finally:
            if tmp.exists():
                tmp.unlink()

    def check(self, relative: str, expected_sha256: str) -> dict[str, Any]:
        path = self.path_for(relative)
        if not path.exists():
            return {"ok": False, "reason": "stored copy is missing", "actual": None}
        actual = sha256_of(path)
        writable = bool(path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        if actual != expected_sha256:
            return {"ok": False, "reason": "SHA-256 mismatch: the stored copy changed", "actual": actual}
        if writable:
            return {
                "ok": True,
                "reason": "hash matches, but the stored copy is writable (expected read-only)",
                "actual": actual,
            }
        return {"ok": True, "reason": None, "actual": actual}

    def export(self, relative: str, destination: Path) -> Path:
        source = self.path_for(relative)
        target = destination.expanduser()
        if target.is_dir():
            target = target / source.name
        if target.exists():
            raise InvalidInputError(f"{target} already exists; R$F does not overwrite files on export.")
        shutil.copy2(source, target)
        target.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        return target
