"""Per-line format detection for mixed logs.

Every line is framed (:mod:`raf.core.ingestion.logs.frame`) and its payload decoded by the first
decoder that recognizes it, in this order:

1. a JSON object (CloudTrail, Kubernetes audit, sign-ins, Windows, EDR, flows, application events
   ... see :mod:`raf.core.ingestion.logs.structured`), also inside container log wrappers
   (Docker ``{"log": ...}``, CRI ``stdout F ...``) or after a short prefix;
2. CEF and LEEF;
3. Windows events as single-line XML;
4. text formats, the ones the line's source tag hints at first (web access/error logs, DNS servers,
   PostgreSQL, auditd, Cisco ASA, Squid, VPC flow logs, S3 access logs, syslog daemons);
5. key=value records (decoded like JSON objects);
6. free text, with its addresses, accounts and URLs extracted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from raf.core.ingestion.logs.frame import Frame, frame_line
from raf.core.ingestion.logs.records import host_ref, ip, ip_ref, outcome, record, url_ref, user_ref
from raf.core.ingestion.logs.structured import decode_structured
from raf.core.ingestion.logs.text import TEXT_DECODERS, free_text
from raf.core.ingestion.logs.values import (
    embedded_json,
    json_object,
    kv_coverage,
    kv_pairs,
    parse_cef,
    parse_leef,
    safe_attributes,
)

_XML_EVENT = re.compile(r"^\s*<Event[\s>]")
_XML_FIELD = re.compile(
    r"<(?P<tag>EventID|Computer|Channel|Level|Keywords|Task|EventRecordID)(?:\s[^>]*)?>(?P<value>[^<]*)</(?P=tag)>"
)
_XML_PROVIDER = re.compile(r"<Provider\s[^>]*Name=['\"](?P<name>[^'\"]+)['\"]")
_XML_TIME = re.compile(r"<TimeCreated\s[^>]*SystemTime=['\"](?P<value>[^'\"]+)['\"]")
_XML_DATA = re.compile(r"<Data\s+Name=['\"](?P<name>[^'\"]+)['\"]\s*>(?P<value>[^<]*)</Data>")
_CRI_PREFIX = re.compile(r"^(?:F|P) ")
_HINTS: dict[str, list[int]] = {}
for _index, (_name, _hints, _decoder) in enumerate(TEXT_DECODERS):
    for _hint in _hints:
        _HINTS.setdefault(_hint, []).append(_index)


@dataclass(slots=True)
class Decoded:
    family: str  # the decoder that recognized the line (web-access, cloudtrail, k8s-audit, text ...)
    record: dict[str, Any]  # native R$F record; "timestamp" may still be missing (the frame's is used)


def _xml_unescape(text: str) -> str:
    return (
        text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&apos;", "'")
        .replace("&amp;", "&")
    )


def _windows_xml(payload: str) -> dict[str, Any] | None:
    """A Windows event rendered as XML on one line (wevtutil / EVTX exports). Fields are read with
    bounded patterns; no XML parser runs on untrusted input."""
    if not _XML_EVENT.match(payload) or len(payload) > 262144:
        return None
    data: dict[str, Any] = {}
    for match in _XML_FIELD.finditer(payload):
        data.setdefault(match["tag"], _xml_unescape(match["value"].strip()))
    if "EventID" not in data:
        return None
    if provider := _XML_PROVIDER.search(payload):
        data["ProviderName"] = provider["name"]
    if created := _XML_TIME.search(payload):
        data["TimeCreated"] = created["value"]
    event_data = {m["name"]: _xml_unescape(m["value"]) for m in _XML_DATA.finditer(payload)}
    if event_data:
        data["EventData"] = event_data
    return data


_ALERT_WORDS = ("alert", "attack", "intrusion", "malware", "exploit", "scan", "trojan", "virus", "injection",
                "xss", "brute", "c2", "command and control", "ransom")  # fmt: skip
_CEF_SEVERITY = {"low": "low", "medium": "medium", "high": "high", "very-high": "critical", "very high": "critical"}


def _cef_severity(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in _CEF_SEVERITY:
        return _CEF_SEVERITY[text]
    try:
        number = float(text)
    except ValueError:
        return None
    return "critical" if number >= 9 else "high" if number >= 7 else "medium" if number >= 4 else "low"


def _security_record(fields: dict[str, Any], header: dict[str, Any], frame: Frame, family: str) -> dict[str, Any]:
    """CEF / LEEF events: authentication, web, firewall or alert events from their usual keys."""

    def get(*names: str) -> Any:
        for name in names:
            value = fields.get(name)
            if value not in (None, "", "-"):
                return value
        return None

    name = str(header.get("name") or header.get("event_id") or "event")
    category = str(get("cat", "category") or "")
    action = str(get("act", "action", "outcome") or "")
    src, dst = ip(get("src", "sourceAddress", "srcip")), ip(get("dst", "destinationAddress", "dstip"))
    login = get("suser", "usrName", "sourceUserName", "duser", "destinationUserName")
    request = get("request", "url")
    severity = _cef_severity(header.get("severity") or get("sev", "severity"))
    result = outcome(action) if action else outcome(get("outcome"))
    words = f"{name} {category}".lower()
    attrs = {
        "vendor": header.get("vendor"),
        "product": header.get("product"),
        "signature_id": header.get("signature") or header.get("event_id"),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": get("spt", "srcPort", "sourcePort"),
        "dst_port": get("dpt", "dstPort", "destinationPort"),
        "protocol": (str(get("proto", "app")) or "").lower() or None,
        "category": category or None,
        "device_action": action or None,
        "user": login,
        **safe_attributes(fields.items(), limit=32),
    }
    host = get("dvchost", "deviceHostName", "dhost", "shost") or frame.host
    timestamp = get("rt", "end", "start", "devTime", "deviceReceiptTime")
    alerting = any(w in words for w in _ALERT_WORDS) or severity in ("high", "critical")
    if any(w in words for w in ("login", "logon", "auth", "sign-in", "signin")) and login and not alerting:
        event_type = "auth.failure" if result == "failure" or "fail" in words else "auth.login"
        return record(
            event_type,
            timestamp=timestamp,
            actor=user_ref(login),
            target=host_ref(host),
            host=host,
            outcome_="failure" if event_type == "auth.failure" else "success",
            severity=severity,
            action=name,
            message=name,
            attributes=attrs,
        )
    if alerting:
        return record(
            "alert",
            timestamp=timestamp,
            actor=ip_ref(src) or user_ref(login),
            target=ip_ref(dst) or host_ref(host),
            host=host,
            outcome_=result,
            severity=severity or "medium",
            action=name,
            message=name,
            attributes={**attrs, "request": request, "detector": f"{header.get('vendor')} {header.get('product')}"},
        )
    if request:
        target = url_ref("http", None, str(request)) if "://" in str(request) else url_ref("http", host, str(request))
        return record(
            "http.request",
            timestamp=timestamp,
            actor=ip_ref(src),
            target=target,
            outcome_=result,
            severity=severity,
            action=str(get("requestMethod") or "request").lower(),
            message=name,
            attributes={**attrs, "method": get("requestMethod")},
        )
    if src and dst and result == "failure":
        return record(
            "network.connection",
            timestamp=timestamp,
            actor=ip_ref(src),
            target=ip_ref(dst),
            outcome_="failure",
            severity=severity or "low",
            action=action or "deny",
            message=name,
            attributes={**attrs, "blocked": True},
        )
    if severity == "medium":
        return record(
            "alert",
            timestamp=timestamp,
            actor=ip_ref(src) or user_ref(login),
            target=ip_ref(dst) or host_ref(host),
            host=host,
            outcome_=result,
            severity=severity,
            action=name,
            message=name,
            attributes={**attrs, "detector": f"{header.get('vendor')} {header.get('product')}"},
        )
    if src and dst:
        return record(
            "network.connection",
            timestamp=timestamp,
            actor=ip_ref(src),
            target=ip_ref(dst),
            outcome_=result,
            severity=severity,
            action=action or name,
            message=name,
            attributes=attrs,
        )
    return record(
        f"log.{family}",
        timestamp=timestamp,
        actor=user_ref(login) if login else ip_ref(src),
        host=host,
        outcome_=result,
        severity=severity,
        action=name,
        message=name,
        attributes=attrs,
    )


def _container(obj: dict[str, Any], frame: Frame) -> Decoded | None:
    """Docker json-file lines: the logged line is decoded like any other, with the wrapper's time."""
    inner = obj.get("log")
    if not isinstance(inner, str) or not ({"time", "stream"} & obj.keys()) or len(obj) > 6:
        return None
    nested = frame_line(inner.rstrip("\r\n"))
    if nested.timestamp is None and isinstance(obj.get("time"), str):
        nested.timestamp = obj["time"]
    decoded = decode_line(nested)
    decoded.record.setdefault("timestamp", obj.get("time"))
    decoded.record.setdefault("attributes", {})["stream"] = obj.get("stream")
    return decoded


def decode_line(frame: Frame) -> Decoded:
    """The native record of one framed line (never fails: free text is the last resort)."""
    payload = frame.payload.strip()
    if frame.tag in ("stdout", "stderr") and _CRI_PREFIX.match(payload):  # CRI container log line
        inner = frame_line(payload[2:])
        if inner.timestamp is None:
            inner.timestamp = frame.timestamp
        decoded = decode_line(inner)
        decoded.record.setdefault("attributes", {})["stream"] = frame.tag
        return decoded
    obj = json_object(payload)
    if obj is not None:
        wrapped = _container(obj, frame)
        if wrapped is not None:
            return wrapped
        family, data = decode_structured(obj, frame)
        return Decoded(family, data)
    embedded = embedded_json(payload)
    if embedded is not None and len(embedded[0]) <= 120:
        prefix, obj = embedded
        family, data = decode_structured(obj, frame)
        if prefix:
            data.setdefault("attributes", {})["prefix"] = prefix[:120]
        return Decoded(family, data)
    # CEF/LEEF headers look like a syslog program name ("CEF:0|..."): read them from the whole line
    if "CEF:" in frame.text and (cef := parse_cef(frame.text)) is not None:
        return Decoded("cef", _security_record(cef["extension"], cef, frame, "cef"))
    if "LEEF:" in frame.text and (leef := parse_leef(frame.text)) is not None:
        return Decoded("leef", _security_record(leef["fields"], leef, frame, "leef"))
    if payload.startswith("<Event") and (xml := _windows_xml(payload)) is not None:
        family, data = decode_structured(xml, frame)
        return Decoded(f"{family}-xml" if family == "windows" else family, data)
    tag = (frame.tag or "").lower()
    order = [*_HINTS.get(tag, ()), *(i for i in range(len(TEXT_DECODERS)) if i not in _HINTS.get(tag, ()))]
    for index in order:
        name, _hints, decoder = TEXT_DECODERS[index]
        found = decoder(frame)
        if found is not None:
            return Decoded(name, found)
    pairs, coverage = kv_coverage(payload)
    if pairs >= 2 and coverage >= 0.5:
        family, data = decode_structured(kv_pairs(payload), frame, kv=True)
        return Decoded(family, data)
    return Decoded("text", free_text(frame))


def finish(decoded: Decoded, frame: Frame) -> dict[str, Any]:
    """The decoded record completed with what only the frame knows (time, reporting host, source tag, level)."""
    data = decoded.record
    if data.get("timestamp") in (None, ""):
        data["timestamp"] = frame.timestamp
    attributes = data.setdefault("attributes", {})
    event_type = str(data.get("event_type") or "")
    if frame.host and "host" not in data and not event_type.startswith(("network.", "dns.", "http.", "cloud.")):
        data["host"] = host_ref(frame.host)
    elif frame.host and data.get("host") != frame.host:
        attributes.setdefault("reporter", frame.host)
    if frame.tag:
        attributes.setdefault("log_source", frame.tag)
    if frame.level:
        attributes.setdefault("level", frame.level)
    if frame.structured:
        attributes.setdefault("structured_data", safe_attributes(frame.structured.items(), limit=16))
    attributes.setdefault("log_format", decoded.family)
    return data


def source_label(decoded: Decoded, frame: Frame) -> str:
    """How a line's source is counted in import summaries: its tag, else the decoder."""
    if frame.tag and frame.framing in ("tagged", "iso-syslog", "rfc3164", "rfc5424"):
        return frame.tag.lower()[:48]
    return decoded.family


__all__ = ["Decoded", "decode_line", "finish", "source_label"]
