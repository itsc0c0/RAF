"""R$F Protocol service: inspect captures, explain packets, list flows, generate and receive captures.

The CLI, the API and the ``pcap`` ingestion parser all go through this module:

* :class:`ProtocolService` (workspace-bound): file and upload limits from settings, results for humans/JSON;
* :func:`capture_events` (stream-bound): the analysis and event records the ingestion parser needs;
* :class:`~raf.products.protocol.uploads.UploadStore` (``ProtocolService.uploads``): captures received by the API.

Defensive analysis only: files are read, never executed or replayed; nothing is decrypted.
"""

from __future__ import annotations

import hashlib
import io
import os
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path
from typing import IO, Any

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.security.files import check_input_file
from raf.products.protocol.analysis import CaptureAnalysis, analyze_stream
from raf.products.protocol.decoders.packet import decode_packet
from raf.products.protocol.decoders.tables import LINK_TYPES
from raf.products.protocol.events import NativeRecord, capture_records
from raf.products.protocol.filters import PacketFilter
from raf.products.protocol.flows import Flow, FlowTable
from raf.products.protocol.model import DecodedPacket, ns_to_datetime, tree_lines
from raf.products.protocol.reader import (
    CHUNK,
    DEFAULT_MAX_PACKETS,
    ByteSource,
    CaptureInfo,
    CaptureLimits,
    CaptureReader,
    open_capture,
)
from raf.products.protocol.summary import (
    FLOW_SORTS,
    CaptureFile,
    FlowsResult,
    GenerateResult,
    InspectResult,
    PacketDetail,
    capture_file,
    dns_rows,
    flow_rows,
    http_rows,
    packet_totals,
    protocol_counts,
    tls_rows,
)
from raf.products.protocol.synthetic import SCENARIOS
from raf.products.protocol.uploads import UploadStore

_TIMESTAMP_PROBE = 1000  # packets examined to find the first timestamp


def capture_events(
    stream: ByteSource, limits: CaptureLimits | None = None
) -> tuple[CaptureAnalysis, Iterator[NativeRecord]]:
    """Analysis plus the native event records it yields (flows, DNS queries, HTTP requests, TLS handshakes)."""
    analysis = analyze_stream(stream, limits)
    return analysis, capture_records(analysis)


class _HashingSource:
    """Reads through to a binary file while hashing what passes, so a single read yields the SHA-256."""

    def __init__(self, handle: IO[bytes]) -> None:
        self._handle = handle
        self._hasher = hashlib.sha256()

    def read(self, size: int = -1, /) -> bytes:
        data = self._handle.read(size)
        self._hasher.update(data)
        return data

    def hexdigest(self) -> str:
        """Hash the rest of the file too (when analysis stopped early) and return the digest."""
        for chunk in iter(lambda: self._handle.read(CHUNK), b""):
            self._hasher.update(chunk)
        return self._hasher.hexdigest()


class ProtocolService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.uploads = UploadStore(ctx)

    # ------------------------------------------------------------------ limits and files
    def limits(self, max_packets: int | None = None) -> CaptureLimits:
        if max_packets is not None and max_packets < 1:
            raise InvalidInputError("--max-packets must be at least 1.")
        return CaptureLimits(max_packets=max_packets or DEFAULT_MAX_PACKETS)

    def _check(self, path: Path) -> os.stat_result:
        max_bytes = int(self.ctx.settings.get("ingest.max_file_mb")) * 1024 * 1024
        return check_input_file(path, max_bytes)

    @staticmethod
    def _open(stream: ByteSource, limits: CaptureLimits, name: str) -> CaptureReader:
        try:
            return open_capture(stream, limits)
        except InvalidInputError as exc:
            raise InvalidInputError(f"{name}: {exc.message}", reason=exc.reason, hint=exc.hint) from exc

    def _analyze(
        self, path: Path, name: str, limits: CaptureLimits, packet_filter: PacketFilter | None
    ) -> tuple[CaptureAnalysis, str]:
        with _reading(path) as handle:
            source = _HashingSource(handle)
            try:
                analysis = analyze_stream(source, limits, packet_filter)
            except InvalidInputError as exc:
                raise InvalidInputError(f"{name}: {exc.message}", reason=exc.reason, hint=exc.hint) from exc
            return analysis, source.hexdigest()

    def _file(self, info: CaptureInfo, path: Path, name: str | None, expose_path: bool, **extra: Any) -> CaptureFile:
        return capture_file(info, name=name or path.name, path=str(path) if expose_path else None, **extra)

    # ------------------------------------------------------------------ inspect / flows / packet
    def inspect(
        self,
        path: Path,
        *,
        packet_filter: PacketFilter | None = None,
        limit: int = 50,
        max_packets: int | None = None,
        name: str | None = None,
        expose_path: bool = True,
    ) -> InspectResult:
        stat = self._check(path)
        analysis, digest = self._analyze(path, name or path.name, self.limits(max_packets), packet_filter)
        flows = [f for f in analysis.flows if not analysis.filter.active or f.id in analysis.matched_flow_ids]
        dns, tls, http = dns_rows(analysis.dns), tls_rows(analysis.tls), http_rows(analysis.http)
        return InspectResult(
            file=self._file(analysis.info, path, name, expose_path, size=stat.st_size, sha256=digest),
            filters=analysis.filter.to_dict(),
            packets=packet_totals(analysis),
            protocols=protocol_counts(analysis),
            flows=flow_rows(flows, limit),
            flows_total=len(flows),
            dns=dns[:limit],
            dns_total=len(dns),
            tls=tls[:limit],
            tls_total=len(tls),
            http=http[:limit],
            http_total=len(http),
            warnings=analysis.warnings,
            truncated=analysis.truncated,
            limit_reached=analysis.limit_reached,
        )

    def flows(
        self,
        path: Path,
        *,
        limit: int = 100,
        sort: str = "id",
        max_packets: int | None = None,
        name: str | None = None,
        expose_path: bool = True,
    ) -> FlowsResult:
        if sort not in FLOW_SORTS:
            raise InvalidInputError(f"Cannot sort flows by '{sort}'.", hint="Use one of: " + ", ".join(FLOW_SORTS))
        stat = self._check(path)
        analysis, digest = self._analyze(path, name or path.name, self.limits(max_packets), None)
        return FlowsResult(
            file=self._file(analysis.info, path, name, expose_path, size=stat.st_size, sha256=digest),
            packets=packet_totals(analysis),
            flows=flow_rows(analysis.flows, limit, sort),
            flows_total=len(analysis.flows),
            sort=sort,
            warnings=analysis.warnings,
            truncated=analysis.truncated,
            limit_reached=analysis.limit_reached,
        )

    def packet(
        self,
        path: Path,
        number: int,
        *,
        max_packets: int | None = None,
        name: str | None = None,
        expose_path: bool = True,
    ) -> PacketDetail:
        if number < 1:
            raise InvalidInputError("Packet numbers start at 1.")
        stat = self._check(path)
        label = name or path.name
        limits = self.limits(max_packets)
        with _reading(path) as handle:
            reader = self._open(handle, limits, label)
            table = FlowTable(limits.max_flows)
            seen = 0
            for raw in reader.packets():
                seen = raw.number
                pkt = decode_packet(raw)
                flow = table.add(pkt)
                if raw.number == number:
                    capture = self._file(reader.info, path, name, expose_path, size=stat.st_size, sha256=None)
                    return packet_detail(pkt, flow, capture)
        raise NotFoundError(
            f"{label} has {seen:,} readable packets; there is no packet {number}.",
            reason=reader.warnings[0] if reader.warnings else None,
            hint="Raise --max-packets to read further." if reader.limit_reached else None,
            suggestions=[f"raf protocol inspect {label}"],
        )

    def first_timestamp(self, path: Path) -> datetime | None:
        """Time of the first timestamped packet (anchor for --from/--to like 23:14 or +30s)."""
        self._check(path)
        with _reading(path) as handle:
            reader = self._open(handle, CaptureLimits(max_packets=_TIMESTAMP_PROBE), path.name)
            for raw in reader.packets():
                if raw.timestamp_ns is not None:
                    return ns_to_datetime(raw.timestamp_ns)
        return None

    # ------------------------------------------------------------------ synthetic captures
    def generate(self, output: Path, scenario: str, seed: int) -> GenerateResult:
        builder = SCENARIOS.get(scenario)
        if builder is None:
            raise InvalidInputError(f"Unknown scenario '{scenario}'.", hint="Scenarios: " + ", ".join(SCENARIOS))
        if output.is_dir():
            raise InvalidInputError(f"{output} is a directory.", hint="Give a file name such as capture.pcap.")
        data = builder(seed)
        partial = output.with_name(output.name + ".partial")
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            partial.write_bytes(data)
            partial.replace(output)
        except OSError as exc:
            with suppress(OSError):
                partial.unlink(missing_ok=True)
            raise InvalidInputError(f"Cannot write {output}.", reason=exc.strerror or str(exc)) from exc
        packets = sum(1 for _ in open_capture(io.BytesIO(data)).packets())
        digest = hashlib.sha256(data).hexdigest()
        result = GenerateResult(
            path=str(output), scenario=scenario, seed=seed, packets=packets, bytes=len(data), sha256=digest
        )
        self.ctx.audit.record("protocol.generate", affected=[str(output)], details=result.to_json_dict())
        return result


# --------------------------------------------------------------------------- helpers


@contextmanager
def _reading(path: Path) -> Iterator[IO[bytes]]:
    """Open a capture for reading; OS errors become readable R$F errors."""
    try:
        handle = path.open("rb")
    except OSError as exc:
        raise InvalidInputError(f"Cannot read {path}.", reason=exc.strerror or str(exc)) from exc
    with handle:
        yield handle


def packet_detail(pkt: DecodedPacket, flow: Flow | None, capture: CaptureFile) -> PacketDetail:
    flow_text = None
    if flow is not None:
        flow_text = f"{flow.protocol} {flow.a.endpoint} ↔ {flow.b.endpoint}"
    return PacketDetail(
        file=capture,
        number=pkt.number,
        timestamp=pkt.timestamp,
        captured_length=pkt.captured_length,
        original_length=pkt.original_length,
        interface=pkt.interface,
        link_type=LINK_TYPES.get(pkt.link_type, f"link type {pkt.link_type}"),
        flow_id=flow.id if flow else None,
        flow=flow_text,
        protocols=list(dict.fromkeys(pkt.protocols)),
        info=pkt.info,
        tree=tree_lines(pkt.root) if pkt.root else [],
        layers=pkt.root.to_dict() if pkt.root else {},
        malformed=list(pkt.malformed),
    )
