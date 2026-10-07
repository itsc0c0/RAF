# R$F Protocol

R$F Protocol reads saved packet captures (libpcap `.pcap` / `.cap` and `.pcapng`) and explains
them: every decoded header field comes with a one-line explanation of what it means, packets
are grouped into bidirectional flows with an explained client/server inference, and DNS, HTTP and
TLS metadata are summarized. Captures can also be imported into the workspace, where flows, DNS
queries, HTTP requests and TLS handshakes become events and relationships in the security graph.

Status: **BETA** · category: specialized analysis · command: `raf protocol` · API: `/api/v1/protocol`

R$F Protocol is a defensive analysis tool. It never captures live traffic, never sends packets and
never decrypts anything: encrypted TLS records are labeled and counted, not opened.

## Commands

```text
raf protocol inspect FILE [--protocol P] [--host IP] [--port N] [--flow ID] [--from T] [--to T] [--limit N] [--max-packets N]
raf protocol packet FILE N [--max-packets N]
raf protocol flows FILE [--sort id|bytes|packets|duration] [--limit N] [--max-packets N]
raf protocol generate OUTPUT --scenario raven-inc001|benign|malformed --seed N
```

All commands accept the global flags (`--json`, `--quiet`, `--workspace` ...). JSON documents carry a
schema id: `raf.protocol.inspect/v1`, `raf.protocol.packet/v1`, `raf.protocol.flows/v1`,
`raf.protocol.generate/v1`.

### inspect

A one-pass summary of a capture: file format and SHA-256, packets and bytes per protocol
(`eth`, `vlan`, `sll`, `ip`, `ipv6`, `tcp`, `udp`, `icmp`, `icmpv6`, `dns`, `http`, `tls`), the flow
table, DNS names with their answers and response codes, TLS server names (SNI) with ALPN and the
negotiated version, HTTP hosts with methods, paths, status codes and user agents, and warnings
(truncated file, malformed packets, limits reached).

Filters restrict which packets are counted and which flows, names and hosts are listed:

| Option | Meaning |
|---|---|
| `--protocol P` | packets carrying protocol P (`ip` = IPv4; `icmp` matches ICMP and ICMPv6) |
| `--host IP` | packets from or to this address (IPv4 or IPv6) |
| `--port N` | packets with TCP/UDP source or destination port N |
| `--flow ID` | packets of one flow (IDs from `raf protocol flows`) |
| `--from T`, `--to T` | time window: ISO-8601, epoch, `HH:MM[:SS]` on the capture's first day, or `+30s` / `+5m` from the first packet |
| `--limit N` | rows per table (default 25) |

Flow statistics always describe the whole flow, even when only some of its packets match a filter.
Flow IDs are assigned in order of first appearance and do not change with filters.

```text
$ raf protocol inspect fixtures/pcap/raven-inc001.pcap --host 10.30.0.5
$ raf protocol inspect capture.pcapng --protocol dns --limit 100
$ raf protocol inspect capture.pcap --from 23:14 --to +2m --json
```

### packet

Every decoded layer of one packet as a tree, then each layer's fields with their explanations:

```text
Ethernet  02:00:0a:1e:00:05 → 02:00:00:00:00:01
└── IPv4  10.30.0.5 → 198.51.100.23 ttl=64 TCP
    └── TCP  56516 → 443 [PSH, ACK] seq=2028277858
        └── TLS  Handshake: ClientHello (SNI files.exfil-test.example)

IPv4
FIELD   VALUE  MEANING
ttl     64     TTL: hop limit, decremented by each router; the packet is dropped at 0
...
```

Malformed layers are marked (`[malformed: header length 12 bytes is below the 20-byte minimum]`);
everything decoded before the problem is still shown.

### flows

Bidirectional 5-tuple flows (protocol, both addresses, both ports): packets and bytes per direction
(IP-level bytes and application payload bytes), first/last packet, duration, TCP flags seen, the
inferred client and server and why, an application hint (`dns`, `http`, `tls`, `other`; a `?` marks a
guess from the server port when no payload was decoded) and the
[Community ID](https://github.com/corelight/community-id-spec) of TCP/UDP flows, the same flow hash
Zeek, Suricata and Arkime compute, for pivoting across tools.

The server side is inferred from the strongest available evidence: who sent the TCP SYN, who
answered with SYN-ACK, who sent the application requests (DNS query, HTTP request, TLS
ClientHello, ICMP echo request), which port is a well-known service port, and finally who sent the
first packet. The reason is part of every flow (`server_reason`).

### generate

Deterministic synthetic captures (classic pcap, Ethernet, valid IPv4/TCP/UDP checksums); the same
seed always produces the same bytes.

| Scenario | Content |
|---|---|
| `raven-inc001` | INC-001 excerpt around 2026-10-06 23:14 UTC: APP-01 (10.30.0.5) resolves `files.exfil-test.example` via DC-01 (10.10.0.5), gets 198.51.100.23, opens TCP/443, sends a TLS ClientHello with that SNI and several large encrypted-looking segments; meanwhile WS-01 (10.10.1.21) resolves `intranet.raven.example` and fetches two pages over HTTP from 10.40.0.5:80 |
| `benign` | office traffic: DNS, HTTPS with SNI, intranet HTTP, ICMP echo on VLAN 10, IPv6 DNS (AAAA) and ICMPv6 |
| `malformed` | deliberately broken packets for parser-robustness experiments (for example in R$F Lab): truncated headers, impossible lengths, DNS compression loops, oversized TLS records, control characters in names, random mutations, and a final record cut short |

"Encrypted" TLS payloads in synthetic captures are seeded random filler: there is no key and nothing
to decrypt. `fixtures/pcap/raven-inc001.pcap` is `raf protocol generate ... --scenario raven-inc001 --seed 1`
(a test keeps the file and the generator in sync). An existing output file is only overwritten with
confirmation (`--yes` in scripts).

## Importing captures

`raf import capture.pcap` (or `.pcapng`) is detected by its magic bytes (parser `pcap/1.0`, native
records) and produces:

| Event | Actor → target | Attributes |
|---|---|---|
| `network.flow` (one per flow, at its first packet) | client IP → server IP | `flow_id`, `community_id`, `protocol`, `app`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `packets`, `packets_out/in`, `bytes_out/in`, `payload_bytes_out/in`, `duration_s`, `tcp_flags`, `server_inference` |
| `dns.query` (query matched with its response) | client IP → domain | `query_type`, `answers`, `rcode`, `src_ip`, `dst_ip` (resolver), `transport`, `transaction_id` |
| `http.request` | client IP → URL (Host header + path) | `method`, `path`, `host`, `domain`, `user_agent`, `status`, `src_ip`, `dst_ip`, `dst_port` |
| `tls.handshake` (one per ClientHello) | client IP → SNI domain (server IP without SNI) | `sni`, `alpn`, `tls_version`, `cipher_suite`, `src_ip`, `dst_ip`, `dst_port` |

The relationship builder then records `CONNECTED_TO` (flows, TLS), `RESOLVED` and `RESOLVES_TO`
(DNS), `REQUESTED` (HTTP). Imported into the Raven demo workspace, the INC-001 capture links
APP-01's address `ip:10.30.0.5` to `domain:files.exfil-test.example` and `ip:198.51.100.23`. Record
locators are `flow N` and `packet N`, so every event points back to the packet that produced it.
Re-importing the same file creates no duplicates.

## API

| Method | Path | Description |
|---|---|---|
| POST | `/protocol/inspect` (multipart field `file`; query: `protocol`, `host`, `port`, `flow`, `start`, `end`, `limit`) | store the upload and return `{upload: {id, name, size, sha256}, ...inspect summary}` |
| GET | `/protocol/uploads?limit=` | earlier uploads, newest first: `{items: [{id, name, size, sha256, uploaded_at}], total}` (`limit` 1–1000, default 100) |
| GET | `/protocol/inspect?upload=&...` | summarize an earlier upload again (other filters) |
| GET | `/protocol/packet?upload=&n=` | layers and explained fields of packet `n` |
| GET | `/protocol/flows?upload=&sort=&limit=` | flow table |

Uploads are limited by `api.max_upload_mb`, checked to be pcap/pcapng, and stored in the workspace's
`uploads/protocol/` directory under a generated name (the first 32 hex characters of their SHA-256,
which is also the upload ID) next to a small JSON record (sanitized original name, size, hash, time).
`GET /protocol/uploads` lists uploads from these records, newest first; an entry is listed only when its
capture and a record that matches it (same ID, size and hash) are both complete, so an upload still being
written or a damaged record is skipped instead of failing the listing (a capture whose record is damaged
can still be opened by its ID). Routes only accept upload IDs, never paths, and responses never reveal
server paths. Uploads are kept until the workspace is deleted.

## How fields are explained

Each decoder adds fields as `(name, value, explanation)`. Explanations are short and practical: what
the field is, what normal values look like and, where it matters, what is suspicious (`TTL: hop
limit, decremented by each router; the packet is dropped at 0`, `SNI: hostname the client asks
for; sent in clear text before encryption starts`, `SYN and FIN both set: never sent by a normal
TCP stack`). Values are shown as captured: checksums are displayed but not validated, the raw TCP
sequence numbers are not made relative.

## Supported protocols

* **Capture formats**: classic libpcap in both byte orders with microsecond or nanosecond
  timestamps; pcapng sections in either byte order, interface description blocks (link type,
  snap length, `if_tsresol`, `if_tsoffset`, `if_name`), enhanced, simple and obsolete packet
  blocks, multiple interfaces and sections; all other block types are skipped.
* **Link layer**: Ethernet II (802.3/LLC frames are identified, not decoded), 802.1Q / 802.1ad VLAN
  tags (up to 4 stacked), Linux cooked capture v1 and v2, raw IP (link types 101, 228, 229, 12, 14),
  BSD/OpenBSD loopback.
* **Network**: IPv4 (all header fields, DF/MF flags, fragment offset, options), IPv6 (hop-by-hop,
  routing, fragment, destination options and AH extension headers are skipped safely).
* **Transport**: TCP (ports, sequence/acknowledgment numbers, flags, window, options), UDP, ICMP and
  ICMPv6 with names for common types and codes (echo, unreachable, time exceeded, neighbor discovery).
* **Application**: DNS over UDP/TCP 53 (and mDNS/LLMNR) with name compression; A, AAAA, CNAME, NS,
  MX, TXT, PTR, SOA, SRV and EDNS0 OPT records. HTTP/1.x request and status lines with Host,
  User-Agent and Content-Length. TLS record layer, ClientHello (version, SNI, ALPN, cipher suites,
  supported versions and groups, ECH presence) and ServerHello (negotiated version and cipher suite,
  HelloRetryRequest), alerts, heartbeat length checks.

## Limits

* **No TCP reassembly and no IP reassembly.** HTTP, DNS-over-TCP and TLS are decoded from the start
  of individual segments. A ClientHello split over two segments shows the part in the first one;
  continuation segments are reported as "not recognized". Non-first IP fragments are attributed to
  their flow when the first fragment was seen, but not decoded.
* **No decryption.** TLS application data, encrypted handshake messages and encrypted alerts are only
  labeled and counted. QUIC and other UDP protocols are not decoded.
* **Resource limits.** Files above `ingest.max_file_mb` are refused before reading; uploads above
  `api.max_upload_mb` are refused while streaming. At most 1,000,000 packets are read by default
  (`--max-packets` on the `raf protocol` commands; `raf import` always uses the default). Packets
  above 262,144 captured bytes stop the read of a classic pcap (they mean the file is corrupt) and are
  skipped in pcapng. At most 100,000 flows and 100,000 DNS, HTTP and TLS records each are kept; DNS
  names are limited to 255 octets and 32 compression pointers; at most 64 DNS records, 16 TLS records
  per segment and 8 KB of HTTP headers are decoded. Hitting a limit produces a warning, never a crash.
* **Throughput.** Pure Python, one CPU core: about 15,000 packets per second were measured during
  development, so a million-packet capture takes roughly a minute. Every field is decoded with its
  explanation, even for summaries.
* **Truncated files** are read up to the last complete packet and reported in the warnings.
* Timestamps of pcapng simple packet blocks are unknown (the format does not store them); such
  packets are listed but carry no time.

## Safety notes

* Every length read from a file or packet is checked before use; reads go through a bounds-checked
  cursor and stream from disk, so memory stays bounded by the largest accepted packet, whatever the
  file size. Malformed input marks the affected layer `malformed` with a reason; it does not abort the
  analysis. A fuzz test feeds random bytes to the file reader and the packet decoder.
* Text from packets (DNS names, SNI, HTTP request targets and headers, interface names) is
  sanitized before display: control characters and terminal escape sequences are rendered as
  `\xNN` (or `\DDD` in DNS presentation format), so a hostile capture cannot rewrite your terminal.
* Uploaded files are never executed and never served back; they are addressed only by their
  generated ID within the workspace.
