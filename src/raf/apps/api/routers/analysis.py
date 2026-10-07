"""Analysis API routes (``POST /analyze``, ``GET /analyses``), mounted at /api/v1.

Inputs reach the API only as uploads: no route accepts a server path, so an API client can never
make R$F read files of the server. Uploads are size-limited (``api.max_upload_mb``), stored in the
workspace under their SHA-256 and then analyzed exactly like ``raf analyze``.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Any, BinaryIO

from fastapi import APIRouter, File, Form, Query, UploadFile

from raf.analysis.analyze import AnalyzeOptions, analyze_path, get_analysis
from raf.apps.api.deps import Ctx
from raf.core.errors import InvalidInputError, ResourceLimitExceeded

router = APIRouter(tags=["analysis"])

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_SUFFIXES = {".pcap", ".pcapng", ".cap", ".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".log", ".txt", ".raf", ".xml"}
_CHUNK = 1024 * 1024


def safe_upload_name(filename: str | None) -> str:
    base = Path((filename or "").replace("\\", "/")).name
    cleaned = _SAFE_NAME.sub("_", base).strip("._") or "upload"
    return cleaned[:100]


def _store_upload(directory: Path, source: BinaryIO, name: str, limit: int) -> tuple[Path, str]:
    directory.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(dir=directory, prefix=".upload-", suffix=".part")
    temp = Path(temp_name)
    try:
        hasher, size = hashlib.sha256(), 0
        with os.fdopen(fd, "wb") as out:
            while chunk := source.read(_CHUNK):
                size += len(chunk)
                if size > limit:
                    raise ResourceLimitExceeded(
                        f"The upload is larger than the limit of {limit // (1024 * 1024)} MB.",
                        hint="Raise api.max_upload_mb or analyze the file locally with raf analyze.",
                    )
                hasher.update(chunk)
                out.write(chunk)
        if size == 0:
            raise InvalidInputError("The upload is empty.")
        digest = hasher.hexdigest()
        suffix = Path(name).suffix.lower()
        target = directory / f"{digest[:32]}{suffix if suffix in _SUFFIXES else '.bin'}"
        temp.replace(target)
        target.chmod(0o444)
    except BaseException:
        with suppress(OSError):
            temp.unlink(missing_ok=True)
        raise
    return target, digest


@router.post("/analyze")
def analyze_upload(
    ctx: Ctx,
    file: Annotated[UploadFile, File(description="File to analyze (size limited by api.max_upload_mb).")],
    incident: Annotated[str | None, Form(max_length=128)] = None,
    correlate: Annotated[bool, Form()] = True,
) -> dict[str, Any]:
    """Upload a file (pcap, JSON/JSONL/CSV/log, SBOM, R$F bundle, policy document) and analyze it.

    Returns the analysis: ``{id, detected_type, detected_label, status, steps: [{name, product,
    status, detail, duration_ms, stats}], stats, suggestions, job_ids, incidents}``."""
    name = safe_upload_name(file.filename)
    limit = int(ctx.settings.get("api.max_upload_mb")) * 1024 * 1024
    path, digest = _store_upload(ctx.workspace.uploads_dir / "analyze", file.file, name, limit)
    ctx.audit.record("analysis.upload", affected=[digest], details={"name": name, "size": path.stat().st_size})
    options = AnalyzeOptions(incident=incident, source_name=name, correlate=correlate)
    data: dict[str, Any] = analyze_path(ctx, path, options).to_json_dict()
    data["input"] = name  # never reveal server paths
    return data


@router.get("/analyses")
def list_analyses(ctx: Ctx, limit: Annotated[int, Query(ge=1, le=500)] = 50) -> dict[str, Any]:
    records = ctx.store.analyses.list(limit=limit)
    items = []
    for record in records:
        item = record.to_json_dict()
        item["input"] = record.stats.get("input_name") or Path(record.input).name
        items.append(item)
    return {"items": items, "total": ctx.store.analyses.count()}


@router.get("/analyses/{analysis_id}")
def show_analysis(ctx: Ctx, analysis_id: str) -> dict[str, Any]:
    record = get_analysis(ctx, analysis_id)
    data: dict[str, Any] = record.to_json_dict()
    data["input"] = record.stats.get("input_name") or Path(record.input).name
    data["job_ids"] = record.job_ids
    return data
