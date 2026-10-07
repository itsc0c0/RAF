"""``raf protocol``: packet captures explained (inspect, packet, flows, generate)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import typer
from rich.text import Text

from raf.core.timeutil import format_ts
from raf.products.protocol.filters import PROTOCOLS, PacketFilter
from raf.products.protocol.model import endpoint_text
from raf.products.protocol.reader import DEFAULT_MAX_PACKETS
from raf.products.protocol.service import ProtocolService
from raf.products.protocol.summary import FLOW_SORTS, FlowSummary, InspectResult, PacketDetail, PacketTotals
from raf.products.protocol.synthetic import SCENARIOS
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="""Packet captures (pcap / pcapng) explained: layers, fields, flows, DNS, HTTP and TLS metadata.

Examples:
  raf protocol inspect capture.pcap [--protocol dns] [--host 10.30.0.5] [--port 443] [--flow 2] [--from 23:14]
  raf protocol packet capture.pcap 7
  raf protocol flows capture.pcap --sort bytes
  raf protocol generate demo.pcap --scenario raven-inc001 --seed 1

Defensive analysis of saved files only: no live capture, no TCP reassembly, no decryption.""",
)

_MAX_PACKETS_HELP = "Stop reading after this many packets."


def _short(value: datetime | None) -> str:
    return (format_ts(value) or "-").replace("T", " ").replace("Z", "")


def _size(value: int) -> str:
    for unit, scale in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if value >= scale:
            return f"{value / scale:.1f} {unit}"
    return f"{value} B"


def _packets_line(packets: PacketTotals) -> str:
    matched = f" ({packets.matched:,} matched)" if packets.matched != packets.total else ""
    malformed = f", {packets.malformed:,} malformed" if packets.malformed else ""
    return f"{packets.total:,}{matched}{malformed} · {_size(packets.bytes)}"


def _window(packets: PacketTotals) -> str:
    if packets.first is None:
        return "-"
    span = f" ({packets.duration_s:.3f} s)" if packets.duration_s is not None else ""
    return f"{_short(packets.first)} → {_short(packets.last)}{span}"


def render_flows(flows: list[FlowSummary]) -> None:
    rt.table(
        ["FLOW", "PROTO", "CLIENT", "SERVER", "APP", "PKTS OUT/IN", "BYTES OUT/IN", "DURATION", "TCP FLAGS"],
        [
            (
                f.id,
                f.protocol,
                endpoint_text(f.client, f.client_port),
                endpoint_text(f.server, f.server_port),
                f.app if f.app_evidence != "port" else f"{f.app}?",
                f"{f.packets_out}/{f.packets_in}",
                f"{_size(f.bytes_out)} / {_size(f.bytes_in)}",
                f"{f.duration_s:.3f}s" if f.duration_s is not None else "-",
                " ".join(f.tcp_flags),
            )
            for f in flows
        ],
    )


def _more(shown: int, total: int, what: str) -> None:
    if total > shown:
        rt.console().print(Text(f"... {total - shown:,} more {what} (use --limit or --json)", style="dim"))


def render_inspect(result: InspectResult) -> None:
    _render_overview(result)
    c = rt.console()
    if result.protocols:
        c.print()
        rows = [(p.protocol, f"{p.packets:,}", _size(p.bytes)) for p in result.protocols]
        rt.table(["PROTOCOL", "PACKETS", "BYTES"], rows)
    if result.flows:
        c.print()
        render_flows(result.flows)
        _more(len(result.flows), result.flows_total, "flows")
    _render_dns(result)
    _render_tls(result)
    _render_http(result)
    _render_warnings(result.warnings)


def _render_overview(result: InspectResult) -> None:
    file = result.file
    rt.header(f"R$F PROTOCOL  {file.name}")
    rows: list[tuple[str, object]] = [
        ("Format", f"{file.format} {file.version} ({file.byte_order}), {', '.join(file.link_types) or '-'}"),
        ("Packets", _packets_line(result.packets)),
        ("Window", _window(result.packets)),
        ("Flows", f"{result.flows_total:,}"),
    ]
    if file.sha256:
        rows.append(("SHA-256", file.sha256))
    terms = [f"{k} {v}" for k, v in result.filters.items() if v is not None]
    if terms:
        rows.append(("Filters", ", ".join(terms)))
    rt.kv_block(rows, width=10)


def _render_dns(result: InspectResult) -> None:
    if not result.dns:
        return
    rt.console().print()
    rt.table(
        ["DNS NAME", "TYPE", "ANSWERS", "RCODE", "QUERIES", "CLIENTS"],
        [
            (d.name, d.type, ", ".join(d.answers) or "-", ",".join(d.rcodes) or "-", d.queries, ", ".join(d.clients))
            for d in result.dns
        ],
    )
    _more(len(result.dns), result.dns_total, "DNS names")


def _render_tls(result: InspectResult) -> None:
    if not result.tls:
        return
    c = rt.console()
    c.print()
    rt.table(
        ["TLS SERVER NAME (SNI)", "SERVER", "ALPN", "VERSION", "HELLOS", "CLIENTS"],
        [
            (
                t.sni or "(none)",
                ", ".join(t.servers),
                ",".join(t.alpn) or "-",
                ", ".join(t.versions),
                t.handshakes,
                ", ".join(t.clients),
            )
            for t in result.tls
        ],
    )
    c.print(Text("Server names are sent in clear text; encrypted payloads are never decrypted.", style="dim"))
    _more(len(result.tls), result.tls_total, "server names")


def _render_http(result: InspectResult) -> None:
    if not result.http:
        return
    rt.console().print()
    rt.table(
        ["HTTP HOST", "SERVER", "REQUESTS", "METHODS", "PATHS", "STATUS", "USER-AGENT"],
        [
            (
                h.host,
                ", ".join(h.servers),
                h.requests,
                ",".join(h.methods),
                ", ".join(h.paths[:3]),
                ",".join(map(str, h.statuses)) or "-",
                (h.user_agents[0] if h.user_agents else "-")[:60],
            )
            for h in result.http
        ],
    )
    _more(len(result.http), result.http_total, "HTTP hosts")


def _render_warnings(warnings: list[str]) -> None:
    if not warnings:
        return
    c = rt.console()
    c.print()
    c.print(Text(f"Warnings ({len(warnings)})", style="bold yellow"))
    for warning in warnings[:12]:
        c.print(Text(f"  {warning}", style="yellow"))
    if len(warnings) > 12:
        c.print(Text(f"  ... {len(warnings) - 12} more (--json shows all)", style="dim"))


def render_packet(detail: PacketDetail) -> None:
    rt.header(f"R$F PROTOCOL  packet {detail.number} of {detail.file.name}")
    length = f"{detail.captured_length:,} bytes captured ({detail.original_length:,} on the wire)"
    rows: list[tuple[str, object]] = [
        ("Time", format_ts(detail.timestamp) or "-"),
        ("Length", length),
        ("Interface", f"{detail.interface} ({detail.link_type})"),
        ("Flow", f"{detail.flow_id}  {detail.flow}" if detail.flow_id else "-"),
    ]
    if detail.malformed:
        rows.append(("Malformed", Text("; ".join(detail.malformed), style="yellow")))
    rt.kv_block(rows, width=11)
    c = rt.console()
    c.print()
    for line in detail.tree:
        c.print(Text(line))
    _render_layer(detail.layers)


def _render_layer(layer: dict[str, object]) -> None:
    fields = layer.get("fields")
    if isinstance(fields, list) and fields:
        c = rt.console()
        c.print()
        title = Text(str(layer.get("name")), style="bold")
        if layer.get("malformed"):
            title.append(f"  malformed: {layer.get('malformed')}", style="yellow")
        c.print(title)
        rt.table(["FIELD", "VALUE", "MEANING"], [(f["name"], _value(f["value"]), f["explanation"]) for f in fields])
    children = layer.get("children")
    for child in children if isinstance(children, list) else []:
        _render_layer(child)


def _value(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(map(str, value)) or "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return "-" if value is None else str(value)


@app.command("inspect")
def inspect_cmd(
    path: Path = typer.Argument(..., help="Capture file (.pcap, .pcapng, .cap)."),
    protocol: str | None = typer.Option(None, "--protocol", "-p", help="Only packets of: " + ", ".join(PROTOCOLS)),
    host: str | None = typer.Option(None, "--host", help="Only packets to or from this IP address."),
    port: int | None = typer.Option(None, "--port", min=0, max=65535, help="Only packets with this TCP/UDP port."),
    flow: int | None = typer.Option(None, "--flow", min=1, help="Only packets of this flow (raf protocol flows)."),
    start: str | None = typer.Option(None, "--from", help="Window start: ISO time, epoch, HH:MM[:SS] or +30s."),
    end: str | None = typer.Option(None, "--to", help="Window end (same forms as --from)."),
    limit: int = typer.Option(25, "--limit", min=1, max=10000, help="Rows shown per table."),
    max_packets: int = typer.Option(DEFAULT_MAX_PACKETS, "--max-packets", min=1, help=_MAX_PACKETS_HELP),
) -> None:
    """Summarize a capture: protocols, flows, DNS names, TLS server names, HTTP hosts and warnings."""
    service = ProtocolService(rt.ctx())
    anchor = service.first_timestamp(path) if start or end else None
    packet_filter = PacketFilter.build(
        protocol=protocol,
        host=host,
        port=port,
        flow_id=flow,
        start=rt.parse_time_option(start, anchor=anchor),
        end=rt.parse_time_option(end, anchor=anchor),
    )
    result = service.inspect(path, packet_filter=packet_filter, limit=limit, max_packets=max_packets)

    def render() -> None:
        render_inspect(result)
        first = result.flows[0].id if result.flows else 1
        rt.next_steps(
            [
                f"raf protocol packet {path} 1",
                f"raf protocol inspect {path} --flow {first}",
                f"raf protocol flows {path} --sort bytes",
                f"raf import {path}",
            ]
        )

    rt.output("raf.protocol.inspect/v1", result.to_json_dict(), render)


@app.command("packet")
def packet_cmd(
    path: Path = typer.Argument(..., help="Capture file."),
    number: int = typer.Argument(..., min=1, help="Packet number (1 = first packet)."),
    max_packets: int = typer.Option(DEFAULT_MAX_PACKETS, "--max-packets", min=1, help=_MAX_PACKETS_HELP),
) -> None:
    """Every decoded layer and field of one packet, each with a short explanation."""
    detail = ProtocolService(rt.ctx()).packet(path, number, max_packets=max_packets)

    def render() -> None:
        render_packet(detail)
        steps = [f"raf protocol packet {path} {number + 1}"]
        if detail.flow_id:
            steps.append(f"raf protocol inspect {path} --flow {detail.flow_id}")
        rt.next_steps(steps)

    rt.output("raf.protocol.packet/v1", detail.to_json_dict(), render)


@app.command("flows")
def flows_cmd(
    path: Path = typer.Argument(..., help="Capture file."),
    sort: str = typer.Option("id", "--sort", help="Order: " + ", ".join(FLOW_SORTS) + " (largest first)."),
    limit: int = typer.Option(100, "--limit", min=1, max=100000, help="Flows shown."),
    max_packets: int = typer.Option(DEFAULT_MAX_PACKETS, "--max-packets", min=1, help=_MAX_PACKETS_HELP),
) -> None:
    """Bidirectional flows with client/server inference, bytes per direction and TCP flags."""
    result = ProtocolService(rt.ctx()).flows(path, limit=limit, sort=sort, max_packets=max_packets)

    def render() -> None:
        rt.header(f"R$F PROTOCOL FLOWS  {result.file.name}")
        rt.kv_block([("Packets", _packets_line(result.packets)), ("Flows", f"{result.flows_total:,}")], width=10)
        rt.console().print()
        if not result.flows:
            rt.console().print("No IP flows in this capture.")
        else:
            render_flows(result.flows)
            rt.console().print(Text("app? = guessed from the server port (no payload decoded)", style="dim"))
            _more(len(result.flows), result.flows_total, "flows")
        _render_warnings(result.warnings)
        if result.flows:
            rt.next_steps([f"raf protocol inspect {path} --flow {result.flows[0].id}"])

    rt.output("raf.protocol.flows/v1", result.to_json_dict(), render)


@app.command("generate")
def generate_cmd(
    output: Path = typer.Argument(..., help="Capture file to write (classic pcap)."),
    scenario: str = typer.Option("raven-inc001", "--scenario", help="Scenario: " + ", ".join(SCENARIOS)),
    seed: int = typer.Option(1, "--seed", help="Seed: the same seed always produces the same bytes."),
) -> None:
    """Write a deterministic synthetic capture (Raven INC-001 excerpt, benign traffic, or malformed packets)."""
    if output.exists():
        rt.confirm(f"{output} already exists. Overwrite it?")
    result = ProtocolService(rt.ctx()).generate(output, scenario, seed)

    def render() -> None:
        rt.success(f"Wrote {result.packets:,} packets ({_size(result.bytes)}) to {result.path}")
        rt.kv_block([("Scenario", f"{result.scenario} (seed {result.seed})"), ("SHA-256", result.sha256)], width=10)
        rt.next_steps([f"raf protocol inspect {output}", f"raf import {output}"])

    rt.output("raf.protocol.generate/v1", result.to_json_dict(), render)
