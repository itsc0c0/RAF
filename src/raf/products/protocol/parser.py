"""``pcap`` ingestion parser: ``raf import capture.pcap`` turns a capture into flows, DNS, HTTP and TLS events."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import IO, ClassVar

from raf.core.ingestion.base import ParseContext, Parser, RawRecord
from raf.products.protocol.reader import DEFAULT_MAX_PACKETS, CaptureLimits, sniff_capture
from raf.products.protocol.service import capture_events

MAX_WARNINGS = 50


class PcapParser(Parser):
    name: ClassVar[str] = "pcap"
    version: ClassVar[str] = "1.0"
    description: ClassVar[str] = "Packet captures (libpcap/pcapng): flows, DNS queries, HTTP requests, TLS handshakes"
    extensions: ClassVar[tuple[str, ...]] = (".pcap", ".pcapng", ".cap")
    normalizer: ClassVar[str] = "raf-native"

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        return 1.0 if sniff_capture(head) is not None else 0.0

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        max_packets = int(ctx.options.get("pcap_max_packets") or DEFAULT_MAX_PACKETS)
        analysis, records = capture_events(stream, CaptureLimits(max_packets=max_packets))
        warnings = list(analysis.warnings)
        if analysis.malformed_packets:
            warnings.insert(0, f"{analysis.malformed_packets} malformed packets (raf protocol inspect shows why)")
        for warning in warnings[:MAX_WARNINGS]:
            ctx.warnings.append(f"pcap: {warning}")
        for record in records:
            if record.data is None:
                yield RawRecord.rejected(record.locator, record.problem or "no event could be built")
            else:
                yield RawRecord(record.data, record.locator, None, parser_label=self.label)
