"""Directory / file metadata ingestion (DFIR-style MAC timeline of modification times).

Symlinks are recorded but never followed. File contents are hashed (bounded
size) but never interpreted. Modification times become ``file.modify`` events
with reduced confidence, because timestamps on disk can be altered.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raf.core.errors import ResourceLimitExceeded

if TYPE_CHECKING:
    from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions, IngestReport

MAX_HASH_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 200_000


def _sha256(path: Path, size: int) -> str | None:
    if size > MAX_HASH_BYTES:
        return None
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError:
        return None
    return hasher.hexdigest()


def filesystem_records(root: Path, host: str) -> Iterator[dict[str, Any]]:
    base = root.resolve()
    yield {
        "kind": "object",
        "type": "directory",
        "name": base.name or str(base),
        "key": f"{host}|{base}",
        "metadata": {"path": str(base), "host": host},
    }
    count = 0
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        parent_key = f"{host}|{dirpath}"
        for name in dirnames + sorted(filenames):
            count += 1
            if count > MAX_ENTRIES:
                raise ResourceLimitExceeded(f"{root} has more than {MAX_ENTRIES} entries.")
            path = Path(dirpath) / name
            try:
                info = path.lstat()
            except OSError:
                continue
            is_dir = stat.S_ISDIR(info.st_mode)
            is_link = stat.S_ISLNK(info.st_mode)
            otype = "directory" if is_dir else "file"
            key = f"{host}|{path}"
            meta: dict[str, Any] = {
                "path": str(path),
                "host": host,
                "size": info.st_size,
                "mode": stat.filemode(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
            }
            if is_link:
                meta["symlink_target"] = str(path.readlink())
                meta["symlink"] = True
            elif not is_dir and stat.S_ISREG(info.st_mode):
                digest = _sha256(path, info.st_size)
                if digest:
                    meta["sha256"] = digest
            mtime = datetime.fromtimestamp(info.st_mtime, UTC)
            yield {
                "kind": "object",
                "type": otype,
                "name": name,
                "key": key,
                "metadata": meta,
                "last_seen": mtime.isoformat(),
            }
            yield {
                "kind": "relationship",
                "source": f"directory:{parent_key}",
                "type": "CONTAINS",
                "target": f"{otype}:{key}",
                "confidence": 1.0,
            }
            if not is_dir:
                yield {
                    "event_type": "file.modify",
                    "timestamp": mtime.isoformat(),
                    "host": host,
                    "target": {"type": "file", "name": name, "key": key},
                    "confidence": 0.6,
                    "message": f"mtime of {path}",
                    "id": f"fs:{key}:{info.st_mtime_ns}",
                    "attributes": {"observed_from": "filesystem metadata", "size": info.st_size, "path": str(path)},
                }


def ingest_filesystem(pipeline: IngestionPipeline, root: Path, options: IngestOptions) -> IngestReport:
    host = options.default_host or "local"
    report = pipeline.ingest_records(
        filesystem_records(root, host),
        source_name=f"filesystem:{root.resolve()}",
        options=options,
        label="filesystem/1.0",
    )
    report.format = "filesystem"
    report.path = str(root.resolve())
    return report
