"""Captures uploaded through the API: stored in the workspace under a generated name, addressed by ID only.

An upload is streamed to a temporary file in ``<workspace>/uploads/protocol/`` while
its size is counted against ``api.max_upload_mb`` and its SHA-256 computed; only a
pcap/pcapng file is kept, renamed to ``<id>.cap`` where the ID is the first 32 hex
characters of the hash. A small JSON record keeps the sanitized original file name
and the upload time; uploads are listed from these records.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import re
import tempfile
from contextlib import suppress
from pathlib import Path, PurePath
from typing import IO, BinaryIO

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError, ResourceLimitExceeded
from raf.core.timeutil import ensure_utc, format_ts, utcnow
from raf.products.protocol.decoders.base import printable_text
from raf.products.protocol.reader import CHUNK, sniff_capture
from raf.products.protocol.summary import StoredUpload, UploadInfo

UPLOAD_ID = re.compile(r"[0-9a-f]{32}")
UPLOAD_SUBDIR = "protocol"
_MULTIPART_SLACK = 64 * 1024  # form boundaries and part headers around the uploaded file
_RECORD_MAX_BYTES = 64 * 1024  # a record is a few hundred bytes; anything larger was not written by save()
_SHA256 = re.compile(r"[0-9a-f]{64}")


class UploadStore:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx

    @property
    def directory(self) -> Path:
        directory = self.ctx.workspace.uploads_dir / UPLOAD_SUBDIR
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def save(self, source: BinaryIO, filename: str | None, *, declared_size: int | None = None) -> UploadInfo:
        """Store an uploaded capture under a generated name, within ``api.max_upload_mb``."""
        limit = int(self.ctx.settings.get("api.max_upload_mb")) * 1024 * 1024
        if declared_size is not None and declared_size > limit + _MULTIPART_SLACK:
            raise _too_large(f"the request announces {declared_size:,} bytes", limit)
        directory = self.directory
        fd, temp_name = tempfile.mkstemp(dir=directory, prefix=".upload-", suffix=".part")
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                size, digest, head = _copy_limited(source, out, limit)
            if sniff_capture(head) is None:
                raise InvalidInputError(
                    "The upload is not a pcap or pcapng capture.",
                    hint="Upload a libpcap (.pcap, .cap) or pcapng (.pcapng) file.",
                )
            upload_id = digest[:32]
            temp.replace(directory / f"{upload_id}.cap")
        except BaseException:
            with suppress(OSError):
                temp.unlink(missing_ok=True)
            raise
        info = UploadInfo(id=upload_id, name=_display_name(filename), size=size, sha256=digest)
        record = info.to_json_dict() | {"uploaded_at": format_ts(utcnow())}
        (directory / f"{upload_id}.json").write_text(json.dumps(record), encoding="utf-8")
        self.ctx.audit.record("protocol.upload", affected=[upload_id], details={"size": size, "sha256": digest})
        return info

    def get(self, upload_id: str) -> tuple[Path, UploadInfo]:
        """Path and metadata of a capture uploaded earlier to this workspace."""
        if not UPLOAD_ID.fullmatch(upload_id):
            raise InvalidInputError(
                "Invalid upload ID.",
                hint="Use the 32 hexadecimal characters returned by POST /api/v1/protocol/inspect.",
            )
        path = self.directory / f"{upload_id}.cap"
        if not path.is_file():
            raise NotFoundError(
                f"No uploaded capture {upload_id} in workspace '{self.ctx.workspace.name}'.",
                hint="Upload it with POST /api/v1/protocol/inspect.",
            )
        try:
            record = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
            info = UploadInfo.model_validate({k: record[k] for k in ("id", "name", "size", "sha256")})
        except (OSError, ValueError, KeyError, TypeError):
            info = UploadInfo(id=upload_id, name=f"upload-{upload_id}", size=path.stat().st_size, sha256="")
        return path, info

    def list(self, *, limit: int = 100) -> tuple[builtins.list[StoredUpload], int]:
        """Uploads of this workspace, newest first: at most ``limit`` of them, and how many there are.

        Only complete uploads are listed: a capture together with a record that describes it. Anything
        else in the directory (a ``.part`` file still being written, a capture whose record is missing,
        unreadable or inconsistent, a record without its capture) is skipped, never an error.
        """
        directory = self.ctx.workspace.uploads_dir / UPLOAD_SUBDIR  # not created here: listing writes nothing
        try:
            with os.scandir(directory) as entries:
                names = {entry.name for entry in entries if entry.is_file(follow_symlinks=False)}
        except OSError:  # no upload yet (or the directory cannot be read)
            return [], 0
        uploads = []
        for name in names:
            upload_id, _, suffix = name.partition(".")
            if suffix == "json" and UPLOAD_ID.fullmatch(upload_id) and f"{upload_id}.cap" in names:
                upload = _stored_upload(directory, upload_id)
                if upload is not None:
                    uploads.append(upload)
        uploads.sort(key=lambda u: (u.uploaded_at, u.id), reverse=True)
        return uploads[: max(limit, 0)], len(uploads)


def _stored_upload(directory: Path, upload_id: str) -> StoredUpload | None:
    """The upload ``<id>.json`` describes, or None when the record is incomplete or does not match ``<id>.cap``."""
    record_path = directory / f"{upload_id}.json"
    try:
        capture_size = (directory / f"{upload_id}.cap").stat(follow_symlinks=False).st_size
        if record_path.stat(follow_symlinks=False).st_size > _RECORD_MAX_BYTES:
            return None
        record = json.loads(record_path.read_text(encoding="utf-8"))
        upload = StoredUpload.model_validate({k: record[k] for k in ("id", "name", "size", "sha256", "uploaded_at")})
    except (OSError, ValueError, KeyError, TypeError, RecursionError):  # removed meanwhile, being written, damaged
        return None
    matches = upload.id == upload_id and upload.size == capture_size and upload.sha256.startswith(upload_id)
    if not matches or not _SHA256.fullmatch(upload.sha256):
        return None
    upload.uploaded_at = ensure_utc(upload.uploaded_at)
    return upload


def _copy_limited(source: BinaryIO, out: IO[bytes], limit: int) -> tuple[int, str, bytes]:
    """Copy in chunks, stopping as soon as ``limit`` is exceeded; returns (size, sha256, first bytes)."""
    hasher = hashlib.sha256()
    size, head = 0, b""
    while chunk := source.read(CHUNK):
        size += len(chunk)
        if size > limit:
            raise _too_large(f"more than {limit:,} bytes received", limit)
        if len(head) < 16:
            head += chunk[: 16 - len(head)]
        hasher.update(chunk)
        out.write(chunk)
    return size, hasher.hexdigest(), head


def _too_large(reason: str, limit: int) -> ResourceLimitExceeded:
    return ResourceLimitExceeded(
        f"The upload exceeds the configured limit of {limit // (1024 * 1024)} MB (api.max_upload_mb).",
        reason=reason,
        hint="Raise api.max_upload_mb, or analyze large captures locally with: raf protocol inspect <file>",
    )


def _display_name(filename: str | None) -> str:
    """The client's file name for display only (never used as a path)."""
    base = PurePath((filename or "").replace("\\", "/")).name
    return printable_text(base, 200) or "upload"
