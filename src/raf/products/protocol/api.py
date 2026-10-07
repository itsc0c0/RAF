"""R$F Protocol API routes (mounted at /api/v1/protocol).

Captures reach the API only as uploads: they are stored in the workspace under a
generated name and referenced by upload ID afterwards. No route accepts a path.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, UploadFile

from raf.core.timeutil import parse_timestamp
from raf.products.protocol.filters import PacketFilter
from raf.products.protocol.service import ProtocolService
from raf.sdk.api import Ctx

router = APIRouter()

UploadId = Annotated[str, Query(min_length=32, max_length=32, pattern="^[0-9a-f]{32}$", description="Upload ID")]
Limit = Annotated[int, Query(ge=1, le=1000)]
Port = Annotated[int | None, Query(ge=0, le=65535)]
FlowId = Annotated[int | None, Query(ge=1)]


def _filter(
    protocol: str | None, host: str | None, port: int | None, flow: int | None, start: str | None, end: str | None
) -> PacketFilter:
    return PacketFilter.build(
        protocol=protocol,
        host=host,
        port=port,
        flow_id=flow,
        start=parse_timestamp(start) if start else None,
        end=parse_timestamp(end) if end else None,
    )


def _declared_length(request: Request) -> int | None:
    value = request.headers.get("content-length", "")
    return int(value) if value.isdigit() else None


@router.post("/inspect")
def inspect_upload(
    ctx: Ctx,
    request: Request,
    file: UploadFile,
    protocol: str | None = None,
    host: str | None = None,
    port: Port = None,
    flow: FlowId = None,
    start: str | None = None,
    end: str | None = None,
    limit: Limit = 50,
) -> dict[str, Any]:
    """Upload a capture (multipart field ``file``, at most ``api.max_upload_mb``) and summarize it."""
    service = ProtocolService(ctx)
    packet_filter = _filter(protocol, host, port, flow, start, end)
    upload = service.uploads.save(file.file, file.filename, declared_size=_declared_length(request))
    path, _info = service.uploads.get(upload.id)
    result = service.inspect(path, packet_filter=packet_filter, limit=limit, name=upload.name, expose_path=False)
    return {"upload": upload.to_json_dict(), **result.to_json_dict()}


@router.get("/inspect")
def inspect_again(
    ctx: Ctx,
    upload: UploadId,
    protocol: str | None = None,
    host: str | None = None,
    port: Port = None,
    flow: FlowId = None,
    start: str | None = None,
    end: str | None = None,
    limit: Limit = 50,
) -> dict[str, Any]:
    """Summarize a previously uploaded capture again (for example with other filters)."""
    service = ProtocolService(ctx)
    path, info = service.uploads.get(upload)
    packet_filter = _filter(protocol, host, port, flow, start, end)
    result = service.inspect(path, packet_filter=packet_filter, limit=limit, name=info.name, expose_path=False)
    return {"upload": info.to_json_dict(), **result.to_json_dict()}


@router.get("/packet")
def packet(
    ctx: Ctx, upload: UploadId, n: Annotated[int, Query(ge=1, description="Packet number (1 = first)")]
) -> dict[str, Any]:
    """All decoded layers and explained fields of packet ``n`` of an uploaded capture."""
    service = ProtocolService(ctx)
    path, info = service.uploads.get(upload)
    detail = service.packet(path, n, name=info.name, expose_path=False, sha256=info.sha256)
    return {"upload": info.to_json_dict(), **detail.to_json_dict()}


@router.get("/flows")
def flows(ctx: Ctx, upload: UploadId, sort: str = "id", limit: Limit = 200) -> dict[str, Any]:
    """Flows of an uploaded capture (sort: id, bytes, packets, duration)."""
    service = ProtocolService(ctx)
    path, info = service.uploads.get(upload)
    result = service.flows(path, limit=limit, sort=sort, name=info.name, expose_path=False)
    return {"upload": info.to_json_dict(), **result.to_json_dict()}
