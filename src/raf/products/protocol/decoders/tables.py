"""Name tables for protocol numbers (only the values security engineers meet in practice)."""

from __future__ import annotations

LINK_TYPES: dict[int, str] = {
    0: "BSD loopback",
    1: "Ethernet",
    12: "Raw IP",
    14: "Raw IP",
    101: "Raw IP",
    105: "IEEE 802.11",
    108: "OpenBSD loopback",
    113: "Linux cooked capture (SLL)",
    127: "IEEE 802.11 radiotap",
    228: "Raw IPv4",
    229: "Raw IPv6",
    276: "Linux cooked capture v2 (SLL2)",
}

ETHERTYPES: dict[int, str] = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8035: "RARP",
    0x8100: "802.1Q VLAN",
    0x86DD: "IPv6",
    0x8847: "MPLS",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE discovery",
    0x8864: "PPPoE session",
    0x888E: "EAPOL (802.1X)",
    0x88A8: "802.1ad QinQ",
    0x88CC: "LLDP",
    0x88E5: "MACsec",
    0x88F7: "PTP",
    0x9100: "802.1Q QinQ (legacy)",
}

VLAN_ETHERTYPES = frozenset({0x8100, 0x88A8, 0x9100})

IP_PROTOCOLS: dict[int, str] = {
    0: "IPv6 Hop-by-Hop Options",
    1: "ICMP",
    2: "IGMP",
    4: "IPv4-in-IP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-in-IP",
    43: "IPv6 Routing",
    44: "IPv6 Fragment",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    59: "No Next Header",
    60: "IPv6 Destination Options",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    115: "L2TP",
    132: "SCTP",
    135: "Mobility",
    136: "UDP-Lite",
}

#: short lowercase names used for flows and filters
IP_PROTOCOL_KEYS: dict[int, str] = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 47: "gre", 50: "esp", 132: "sctp"}

IPV4_OPTIONS: dict[int, str] = {
    0: "End of options",
    1: "NOP",
    7: "Record Route",
    68: "Timestamp",
    130: "Security",
    131: "Loose Source Route",
    136: "Stream ID",
    137: "Strict Source Route",
    148: "Router Alert",
}

TCP_FLAG_BITS: tuple[tuple[int, str], ...] = (  # low bit first, as packet tools display them: [SYN, ACK]
    (0x001, "FIN"),
    (0x002, "SYN"),
    (0x004, "RST"),
    (0x008, "PSH"),
    (0x010, "ACK"),
    (0x020, "URG"),
    (0x040, "ECE"),
    (0x080, "CWR"),
    (0x100, "AE"),
)

TCP_OPTIONS: dict[int, str] = {
    0: "End of options",
    1: "NOP",
    2: "MSS",
    3: "Window scale",
    4: "SACK permitted",
    5: "SACK",
    8: "Timestamps",
    19: "MD5 signature",
    28: "User timeout",
    29: "TCP-AO",
    30: "Multipath TCP",
    34: "TCP Fast Open",
}

ICMP_TYPES: dict[int, str] = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

ICMP_CODES: dict[int, dict[int, str]] = {
    3: {
        0: "network unreachable",
        1: "host unreachable",
        2: "protocol unreachable",
        3: "port unreachable",
        4: "fragmentation needed and DF set",
        5: "source route failed",
        6: "destination network unknown",
        7: "destination host unknown",
        9: "network administratively prohibited",
        10: "host administratively prohibited",
        13: "communication administratively prohibited",
    },
    5: {
        0: "redirect for network",
        1: "redirect for host",
        2: "redirect for TOS and network",
        3: "redirect for TOS and host",
    },
    11: {0: "TTL exceeded in transit", 1: "fragment reassembly time exceeded"},
    12: {0: "pointer indicates the error", 1: "missing a required option", 2: "bad length"},
}

ICMPV6_TYPES: dict[int, str] = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    130: "Multicast Listener Query",
    131: "Multicast Listener Report",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect",
    143: "Multicast Listener Report v2",
}

ICMPV6_CODES: dict[int, dict[int, str]] = {
    1: {
        0: "no route to destination",
        1: "communication administratively prohibited",
        2: "beyond scope of source address",
        3: "address unreachable",
        4: "port unreachable",
        5: "source address failed policy",
        6: "reject route to destination",
    },
    3: {0: "hop limit exceeded in transit", 1: "fragment reassembly time exceeded"},
    4: {0: "erroneous header field", 1: "unrecognized next header", 2: "unrecognized IPv6 option"},
}

DNS_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    251: "IXFR",
    252: "AXFR",
    255: "ANY",
    257: "CAA",
}

DNS_CLASSES: dict[int, str] = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}

DNS_OPCODES: dict[int, str] = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE", 6: "DSO"}

DNS_RCODES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

TLS_CONTENT_TYPES: dict[int, str] = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
    24: "Heartbeat",
}

TLS_VERSIONS: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

TLS_HANDSHAKE_TYPES: dict[int, str] = {
    0: "HelloRequest",
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    5: "EndOfEarlyData",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
    22: "CertificateStatus",
    24: "KeyUpdate",
}

TLS_EXTENSIONS: dict[int, str] = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_master_secret",
    27: "compress_certificate",
    28: "record_size_limit",
    35: "session_ticket",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    49: "post_handshake_auth",
    50: "signature_algorithms_cert",
    51: "key_share",
    57: "quic_transport_parameters",
    17513: "application_settings",
    65037: "encrypted_client_hello",
    65281: "renegotiation_info",
}

TLS_GROUPS: dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x11EC: "X25519MLKEM768",
    0x6399: "X25519Kyber768Draft00",
}

TLS_CIPHER_SUITES: dict[int, str] = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x5600: "TLS_FALLBACK_SCSV",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

TLS_ALERT_LEVELS: dict[int, str] = {1: "warning", 2: "fatal"}

TLS_ALERTS: dict[int, str] = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    22: "record_overflow",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    116: "certificate_required",
    120: "no_application_protocol",
}

#: TCP/UDP ports of common services (used to infer the server side of a flow)
SERVICE_PORTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    853: "dns-over-tls",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1883: "mqtt",
    2049: "nfs",
    3128: "http-proxy",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5353: "mdns",
    5355: "llmnr",
    5432: "postgres",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-https",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


def is_grease(value: int) -> bool:
    """GREASE values (RFC 8701) are random-looking placeholders clients send to keep servers tolerant."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def tls_version_name(value: int) -> str:
    if is_grease(value):
        return f"GREASE (0x{value:04x})"
    name = TLS_VERSIONS.get(value)
    if name:
        return name
    if value >> 8 == 0x7F:
        return f"TLS 1.3 draft {value & 0xFF}"
    return f"unknown (0x{value:04x})"


def tls_cipher_name(value: int) -> str:
    if is_grease(value):
        return f"GREASE (0x{value:04x})"
    return TLS_CIPHER_SUITES.get(value, f"0x{value:04x}")


def tls_extension_name(value: int) -> str:
    if is_grease(value):
        return "GREASE"
    return TLS_EXTENSIONS.get(value, f"unknown ({value})")


def tls_group_name(value: int) -> str:
    if is_grease(value):
        return "GREASE"
    return TLS_GROUPS.get(value, f"0x{value:04x}")
