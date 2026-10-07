"""Entry point of the dissector: raw captured bytes -> :class:`DecodedPacket`."""

from __future__ import annotations

import logging

from raf.products.protocol.decoders.link import decode_link
from raf.products.protocol.model import DecodedPacket, Layer, RawPacket

log = logging.getLogger("raf.protocol")


def decode_packet(raw: RawPacket) -> DecodedPacket:
    """Decode every layer R$F understands. Never raises.

    Truncated or inconsistent headers mark the affected layer ``malformed``. As a last
    line of defense, an unexpected decoder bug is logged and recorded in
    ``internal_error`` instead of aborting the analysis of the remaining packets.
    """
    pkt = DecodedPacket(
        number=raw.number,
        timestamp_ns=raw.timestamp_ns,
        captured_length=raw.captured_length,
        original_length=raw.original_length,
        interface=raw.interface,
        link_type=raw.link_type,
    )
    try:
        pkt.root = decode_link(raw.link_type, raw.data, pkt)
    except Exception as exc:
        log.error("decoder failure on packet %s", raw.number, exc_info=True, extra={"file_only": True})
        pkt.internal_error = f"{type(exc).__name__}: {str(exc)[:200]}"
        pkt.root = Layer("Frame", malformed="internal decoder error (logged); the packet was skipped")
        pkt.note_malformed("Frame", "internal decoder error")
    if raw.captured_length < raw.original_length and pkt.root is not None:
        pkt.root.add(
            "captured_length",
            f"{raw.captured_length} of {raw.original_length} bytes",
            "Only part of the packet was saved (capture snap length); later layers may be cut short",
        )
    return pkt
