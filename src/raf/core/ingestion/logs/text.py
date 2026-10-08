"""Decoders for text payloads: web access and error logs, DNS servers, databases, Linux audit,
firewalls and proxies, cloud flow and storage access logs, syslog daemons - and, for anything
else, free text with its addresses, accounts and URLs extracted.

Each decoder returns a native event record, or None when the payload is not its format; the
dispatcher tries them in order (the ones the line's source tag hints at first).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from raf.core.ingestion.logs.frame import Frame
from raf.core.ingestion.logs.records import (
    bucket_ref,
    host_ref,
    ip,
    ip_ref,
    level_severity,
    object_ref,
    outcome,
    record,
    ref,
    rel,
    url_ref,
    user_ref,
)
from raf.core.ingestion.logs.sql import database_record
from raf.core.ingestion.logs.values import kv_pairs, safe_attributes, safe_value
from raf.core.ingestion.parsers.textlogs import extract_program
from raf.core.objects.types import ObjectType
from raf.core.security.redaction import redact_text

TextDecoder = Callable[[Frame], dict[str, Any] | None]

# --------------------------------------------------------------------------- web access / error logs

_ACCESS = re.compile(
    r'^(?:(?P<vhost>[\w.-]+(?::\d+)?) (?=\S+ \S+ \S+ (?:\[|")))?(?P<client>\S+) (?P<ident>\S+) (?P<user>"[^"]*"|\S+) '
    r'(?:\[(?P<ts>[^\]]+)\] )?"(?P<method>[A-Z]{3,10}) (?P<path>\S+)(?: (?P<proto>HTTP/[\d.]+))?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?(?P<tail>.*)$'
)
_ACCESS_ALIASES = {
    "rt": "response_time",
    "request_time": "response_time",
    "rid": "request_id",
    "req_id": "request_id",
    "requestid": "request_id",
    "x_request_id": "request_id",
    "upstream": "upstream",
    "upstream_addr": "upstream",
    "ups": "upstream",
    "xff": "x_forwarded_for",
    "x_forwarded_for": "x_forwarded_for",
}
_NGINX_ERROR = re.compile(
    r"^(?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<msg>.*?)"
    r'(?:, client: (?P<client>[^,]+))?(?:, server: (?P<server>[^,]*))?(?:, request: "(?P<request>[^"]*)")?'
    r'(?:, upstream: "(?P<upstream>[^"]*)")?(?:, host: "(?P<host>[^"]*)")?(?:, referrer: "(?P<ref>[^"]*)")?$'
)


def _access(frame: Frame) -> dict[str, Any] | None:
    m = _ACCESS.match(frame.payload)
    if m is None:
        return None
    client = m["client"]
    if not ip(client) and m["vhost"] is None and ip(m["ident"]):  # "vhost client - user ..." without a port
        return None
    status = int(m["status"])
    user = m["user"].strip('"')
    path = m["path"]
    tail = kv_pairs(m["tail"]) if m["tail"].strip() else {}
    extras: dict[str, Any] = {}
    for key, value in tail.items():
        extras[_ACCESS_ALIASES.get(key.lower(), key)] = value
    upstream = extras.pop("upstream", None)
    vhost = m["vhost"].rsplit(":", 1)[0] if m["vhost"] else None
    server = frame.host
    clean_path = path.split("?", 1)[0]
    attributes = {
        "src_ip": ip(client),
        "client": client if not ip(client) else None,
        "method": m["method"],
        "path": clean_path,
        "query_string": safe_value("query", path.split("?", 1)[1]) if "?" in path else None,
        "status": status,
        "bytes": int(m["size"]) if m["size"] != "-" else None,
        "protocol": m["proto"],
        "referrer": m["ref"] if m["ref"] not in (None, "-") else None,
        "user_agent": m["ua"],
        "user": user if user != "-" else None,
        "vhost": vhost,
        "service": upstream if upstream and not ip(upstream.split(":")[0]) else None,
        "upstream": upstream,
        **safe_attributes(extras.items(), limit=24),
    }
    return record(
        "http.request",
        timestamp=m["ts"],
        actor=ip_ref(client) or host_ref(client),
        target=url_ref("http", vhost or server, path),
        host=server,
        outcome_="failure" if status >= 400 else "success",
        severity="low" if status in (401, 403) else None,
        action=m["method"].lower(),
        message=f"{m['method']} {clean_path} -> {status}" + (f" ({upstream})" if upstream else ""),
        attributes=attributes,
        objects=[{"name": user, "role": "user"}] if user and user != "-" else [],
    )


def _nginx_error(frame: Frame) -> dict[str, Any] | None:
    if frame.level is None:
        return None
    m = _NGINX_ERROR.match(frame.payload)
    if m is None:
        return None
    client = m["client"]
    request = m["request"] or ""
    parts = request.split(" ")
    attrs = {
        "src_ip": ip(client),
        "level": frame.level,
        "server_name": m["server"],
        "upstream": m["upstream"],
        "vhost": m["host"],
        "nginx_pid": m["pid"],
        "connection": m["cid"],
    }
    message = redact_text(m["msg"])
    if len(parts) >= 2:
        return record(
            "http.request",
            actor=ip_ref(client) or host_ref(client),
            target=url_ref("http", m["host"] or m["server"] or frame.host, parts[1]),
            host=frame.host,
            outcome_="failure",
            severity=level_severity(frame.level),
            action=parts[0].lower(),
            message=message,
            attributes={**attrs, "method": parts[0], "path": parts[1].split("?", 1)[0]},
        )
    return record(
        "log.web_error",
        actor=ip_ref(client),
        host=frame.host,
        severity=level_severity(frame.level),
        message=message,
        attributes=attrs,
    )


# --------------------------------------------------------------------------- DNS servers

_BIND_QUERY = re.compile(
    r"^(?:queries: )?(?:info: )?client (?:@0x[0-9a-fA-F]+ )?(?P<client>[0-9a-fA-F.:]+)#\s?(?P<port>\d+)"
    r"(?: \((?P<qname>[^)]*)\))?: (?:view (?P<view>[^:]+): )?query: (?P<q>\S+) (?P<cls>\S+) (?P<type>\S+) "
    r"(?P<flags>\S*)(?: \((?P<server>[^)]+)\))?(?P<tail>.*)$"
)
_DNSMASQ = re.compile(
    r"^(?P<op>query|reply|cached|forwarded|config)(?:\[(?P<type>\w+)\])? (?P<q>\S+) (?P<rel>from|is|to) (?P<value>\S+)$"
)


def _bind(frame: Frame) -> dict[str, Any] | None:
    m = _BIND_QUERY.match(frame.payload)
    if m is None:
        return None
    tail = m["tail"] or ""
    rcode = re.search(r"response:\s*(\w+)", tail)
    ttl = re.search(r"ttl=(\d+)", tail)
    answers = [a for a in re.findall(r"answer[s]?[:=]\s*([\w.:]+)", tail) if ip(a)]
    failed = rcode is not None and rcode.group(1).upper() in ("NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR")
    # "(10.0.0.53)": the address the logging server received the query on - one of its own
    server = ip(m["server"]) if m["server"] else None
    owner = ref(ObjectType.HOST.value, frame.host) if frame.host and not ip(frame.host) else None
    return record(
        "dns.query",
        actor=ip_ref(m["client"]),
        target=ref(ObjectType.DOMAIN.value, m["q"]),
        host=frame.host,
        outcome_="failure" if failed else None,
        action="query",
        message=f"{m['client']} query {m['q']} {m['type']}" + (f" -> {rcode.group(1)}" if rcode else ""),
        attributes={
            "src_ip": ip(m["client"]),
            "src_port": int(m["port"]),
            "dst_ip": server,
            "query": m["q"],
            "qclass": m["cls"],
            "qtype": m["type"],
            "flags": m["flags"] or None,
            "recursion_desired": "+" in (m["flags"] or ""),
            "view": m["view"],
            "rcode": rcode.group(1) if rcode else None,
            "ttl": int(ttl.group(1)) if ttl else None,
            "answers": answers or None,
        },
        relationships=[rel("HAS_ADDRESS", owner, ip_ref(server), observed_as="dns server address")],
    )


def _dnsmasq(frame: Frame) -> dict[str, Any] | None:
    if (frame.tag or "").lower() not in ("dnsmasq", "pihole", "pihole-ftl"):
        return None
    m = _DNSMASQ.match(frame.payload)
    if m is None:
        return None
    if m["op"] == "query":
        return record(
            "dns.query",
            actor=ip_ref(m["value"]) or host_ref(m["value"]),
            target=ref(ObjectType.DOMAIN.value, m["q"]),
            host=frame.host,
            action="query",
            attributes={"query": m["q"], "qtype": m["type"], "src_ip": ip(m["value"])},
        )
    answer = ip(m["value"])
    return record(
        "dns.query" if m["op"] in ("reply", "cached") else "log.dns_forward",
        target=ref(ObjectType.DOMAIN.value, m["q"]),
        host=frame.host,
        action=m["op"],
        attributes={"query": m["q"], "answers": [answer] if answer else None, "answer": m["value"]},
    )


# --------------------------------------------------------------------------- databases

_PG_KV = re.compile(r"^(?P<kv>(?:[a-z_]+=\S*\s+)+)(?P<level>[A-Z]+\d?):\s+(?P<msg>.*)$")
_PG_STD = re.compile(
    r"^(?:\[(?P<pid>\d+)\]\s+)?(?:(?P<user>[^@\s\[]+)@(?P<db>[^\s\[]+)\s+)?"
    r"(?P<level>LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG\d?|DETAIL|HINT|STATEMENT|CONTEXT):\s+(?P<msg>.*)$"
)
_PG_DURATION = re.compile(
    r"^duration: (?P<ms>[\d.]+) ms(?:\s+(?:statement|execute [^:]*|parse [^:]*|bind [^:]*): (?P<sql>.*))?$"
)
_PG_STATEMENT = re.compile(r"^statement: (?P<sql>.*)$")
_PG_AUTHORIZED = re.compile(r"^connection authorized: user=(?P<user>\S+)(?: database=(?P<db>\S+))?")
_PG_FAILED = re.compile(r'^password authentication failed for user "(?P<user>[^"]+)"')
_PG_NO_ROLE = re.compile(r'^role "(?P<user>[^"]+)" does not exist')
_PG_HBA = re.compile(
    r'^no pg_hba\.conf entry for host "(?P<host>[^"]+)", user "(?P<user>[^"]+)", database "(?P<db>[^"]+)"'
)
_PG_DISCONNECT = re.compile(
    r"^disconnection: session time: (?P<t>\S+) user=(?P<user>\S+) database=(?P<db>\S+) host=(?P<host>\S+)"
)
_PG_HINTS = ("postgres", "postgresql", "pgsql", "postmaster", "pgbouncer", "rds-postgres")


def _postgres(frame: Frame) -> dict[str, Any] | None:
    tag = (frame.tag or "").lower()
    payload = frame.payload
    kv: dict[str, str] = {}
    m = _PG_KV.match(payload)
    if m is not None:
        kv = kv_pairs(m["kv"])
        level, message, pg_user, pg_db = m["level"], m["msg"], kv.get("user"), kv.get("db") or kv.get("database")
    else:
        std = _PG_STD.match(payload)
        if std is None or not (tag in _PG_HINTS or std["user"] or (frame.timestamp and "UTC" in frame.timestamp)):
            return None
        level, message, pg_user, pg_db = std["level"], std["msg"], std["user"], std["db"]
    if tag not in _PG_HINTS and not (kv and ({"user", "db", "database"} & kv.keys())) and not pg_user:
        return None
    client = kv.get("client") or kv.get("host") or kv.get("remote")
    application = kv.get("app") or kv.get("application_name")
    common: dict[str, Any] = {
        "engine": "postgres",
        "host": frame.host,
        "database": pg_db,
        "application": application,
        "level": level,
        "extra": safe_attributes(
            ((k, v) for k, v in kv.items() if k not in ("user", "db", "database", "client", "app")), limit=8
        ),
    }
    if d := _PG_DURATION.match(message):
        sql = d["sql"]
        if sql:
            return database_record(user=pg_user, client=client, message=sql, duration_ms=float(d["ms"]), **common)
        return database_record(
            user=pg_user,
            client=client,
            message=message,
            duration_ms=float(d["ms"]),
            event_type="log.db_duration",
            **common,
        )
    if s := _PG_STATEMENT.match(message):
        return database_record(user=pg_user, client=client, message=s["sql"], **common)
    if a := _PG_AUTHORIZED.match(message):
        common["database"] = a["db"] or pg_db
        return database_record(
            user=a["user"], client=client, message=message, event_type="auth.login", outcome="success", **common
        )
    for pattern in (_PG_FAILED, _PG_NO_ROLE):
        if fail := pattern.match(message):
            return database_record(
                user=fail["user"],
                client=client,
                message=message,
                event_type="auth.failure",
                outcome="failure",
                **common,
            )
    if h := _PG_HBA.match(message):
        common["database"] = h["db"]
        return database_record(
            user=h["user"], client=h["host"], message=message, event_type="auth.failure", outcome="failure", **common
        )
    if x := _PG_DISCONNECT.match(message):
        common["database"] = x["db"]
        return database_record(
            user=x["user"], client=x["host"], message=message, event_type="auth.logout", outcome="success", **common
        )
    return database_record(user=pg_user, client=client, message=message, event_type="log.db_message", **common)


# --------------------------------------------------------------------------- Linux audit

_AUDIT = re.compile(
    r"^(?:node=(?P<node>\S+) )?type=(?P<type>[A-Z_]+) "
    r"msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s?(?P<rest>.*)$"
)
_HEX = re.compile(r"^[0-9A-Fa-f]+$")


def _audit_value(value: str) -> str:
    """auditd hex-encodes values with spaces or special characters."""
    if len(value) >= 2 and len(value) % 2 == 0 and _HEX.match(value):
        try:
            decoded = bytes.fromhex(value).decode("utf-8", "replace")
        except ValueError:
            return value
        if decoded.isprintable() or "\x00" in decoded:
            return decoded.replace("\x00", " ").strip()
    return value


def _auditd(frame: Frame) -> dict[str, Any] | None:
    m = _AUDIT.match(frame.payload) or _AUDIT.match(frame.text)
    if m is None:
        return None
    kind = m["type"]
    rest = m["rest"]
    inner = re.search(r"msg='(?P<inner>[^']*)'", rest)
    pairs = kv_pairs(rest)
    if inner:
        pairs.update(kv_pairs(inner["inner"]))
    host = m["node"] or frame.host
    res = pairs.get("res") or pairs.get("success")
    result = outcome({"yes": "success", "no": "failure"}.get(str(res).lower(), res)) if res else None
    account = pairs.get("acct") or pairs.get("id")
    exe = pairs.get("exe")
    base_attrs = {
        "audit_type": kind,
        "audit_serial": m["serial"],
        "uid": pairs.get("uid"),
        "auid": pairs.get("auid"),
        "exe": exe,
        "audit_key": pairs.get("key") if pairs.get("key") not in (None, "(null)") else None,
        "terminal": pairs.get("terminal"),
        "src_ip": ip(pairs.get("addr")),
    }
    timestamp = m["epoch"]
    if kind in ("USER_AUTH", "USER_LOGIN", "USER_ERR"):
        event_type = "auth.failure" if result == "failure" or kind == "USER_ERR" else "auth.login"
        return record(
            event_type,
            timestamp=timestamp,
            actor=user_ref(_audit_value(account)) if account else None,
            target=host,
            host=host,
            outcome_="failure" if event_type == "auth.failure" else "success",
            severity="low" if event_type == "auth.failure" else None,
            action=(pairs.get("op") or kind).lower(),
            message=f"{kind} {pairs.get('op') or ''} acct={account} res={res}",
            attributes=base_attrs,
        )
    if kind == "EXECVE":
        args = [_audit_value(pairs[f"a{i}"]) for i in range(64) if f"a{i}" in pairs]
        command = " ".join(args)
        return record(
            "process.start",
            timestamp=timestamp,
            host=host,
            action="execve",
            message=redact_text(command)[:300],
            attributes={
                **base_attrs,
                "command_line": safe_value("command_line", command),
                "image": args[0] if args else None,
            },
        )
    if kind == "SYSCALL" and exe:
        return record(
            "process.start" if pairs.get("syscall") in ("59", "322", "execve", "execveat") else "log.audit_syscall",
            timestamp=timestamp,
            actor=user_ref(pairs.get("AUID") or pairs.get("UID")),
            host=host,
            outcome_=result,
            action=f"syscall-{pairs.get('syscall')}",
            message=f"{_audit_value(exe)} ({pairs.get('comm')}) syscall {pairs.get('syscall')} "
            f"success={pairs.get('success')}",
            attributes={
                **base_attrs,
                "image": _audit_value(exe),
                "pid": pairs.get("pid"),
                "parent_pid": pairs.get("ppid"),
                "comm": pairs.get("comm"),
                "syscall": pairs.get("syscall"),
            },
        )
    if kind == "USER_CMD":
        command = _audit_value(pairs.get("cmd", ""))
        return record(
            "auth.privilege",
            timestamp=timestamp,
            actor=user_ref(pairs.get("AUID") or pairs.get("auid")),
            target=host,
            host=host,
            outcome_=result,
            action="sudo",
            message=redact_text(command)[:300],
            attributes={
                **base_attrs,
                "command": safe_value("command", command),
                "cwd": _audit_value(pairs.get("cwd", "")),
            },
        )
    if kind in ("ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "USER_MGMT", "GRP_MGMT"):
        mapping = {
            "ADD_USER": "iam.user.create",
            "DEL_USER": "iam.user.delete",
            "ADD_GROUP": "iam.group.create",
            "DEL_GROUP": "iam.group.delete",
        }
        return record(
            mapping.get(kind, "iam.user.modify"),
            timestamp=timestamp,
            actor=user_ref(pairs.get("AUID") or pairs.get("auid")),
            target=user_ref(_audit_value(account)) if account else None,
            host=host,
            outcome_=result,
            action=(pairs.get("op") or kind).lower(),
            attributes=base_attrs,
        )
    return record(
        f"log.audit_{kind.lower()}",
        timestamp=timestamp,
        host=host,
        outcome_=result,
        severity="medium" if kind in ("CONFIG_CHANGE", "DAEMON_END", "DAEMON_ABORT") else None,
        action=kind.lower(),
        message=redact_text(rest)[:500],
        attributes={**base_attrs, **safe_attributes(pairs.items(), limit=24)},
    )


# --------------------------------------------------------------------------- firewalls and proxies

_ASA = re.compile(r"^%(?P<vendor>ASA|FTD|FWSM|PIX)-(?P<sev>\d)-(?P<id>\d{6}): (?P<msg>.*)$")
_ASA_ENDPOINT = r"(?P<{0}if>[\w-]+):(?P<{0}>[\d.a-fA-F:]+?)/(?P<{0}port>\d+)"
_ASA_DENY = re.compile(
    r"Deny (?P<proto>\w+) src " + _ASA_ENDPOINT.format("src") + r" dst " + _ASA_ENDPOINT.format("dst")
)
_ASA_BUILT = re.compile(
    r"Built (?P<dir>inbound|outbound) (?P<proto>\w+) connection \d+ for "
    + _ASA_ENDPOINT.format("src")
    + r"(?: \([^)]*\))? to "
    + _ASA_ENDPOINT.format("dst")
)
_ASA_TEARDOWN = re.compile(
    r"Teardown (?P<proto>\w+) connection \d+ for "
    + _ASA_ENDPOINT.format("src")
    + r" to "
    + _ASA_ENDPOINT.format("dst")
    + r".*?bytes (?P<bytes>\d+)"
)
_ASA_USER = re.compile(r'user = "?(?P<user>[^":]+?)"?(?: :|$)|for user "(?P<user2>[^"]+)"|User <(?P<user3>[^>]+)>')
_ASA_AUTH = {
    113004: "auth.login",
    113005: "auth.failure",
    605004: "auth.failure",
    605005: "auth.login",
    611101: "auth.login",
    611102: "auth.failure",
    716001: "auth.login",
    716002: "auth.logout",
    113019: "auth.logout",
    722022: "auth.login",
    722023: "auth.logout",
}


def _cisco_asa(frame: Frame) -> dict[str, Any] | None:
    m = _ASA.search(frame.payload)
    if m is None:
        return None
    msg_id = int(m["id"])
    message = m["msg"]
    sev = int(m["sev"])
    attrs: dict[str, Any] = {"asa_id": msg_id, "asa_severity": sev, "vendor": m["vendor"]}
    if d := _ASA_DENY.search(message):
        return record(
            "network.connection",
            actor=ip_ref(d["src"]),
            target=ip_ref(d["dst"]),
            host=frame.host,
            outcome_="failure",
            severity="low",
            action="deny",
            message=message,
            attributes={
                **attrs,
                "src_ip": ip(d["src"]),
                "dst_ip": ip(d["dst"]),
                "src_port": int(d["srcport"]),
                "dst_port": int(d["dstport"]),
                "protocol": d["proto"].lower(),
                "blocked": True,
                "interface_in": d["srcif"],
                "interface_out": d["dstif"],
            },
        )
    for pattern, event_type in ((_ASA_BUILT, "network.connection"), (_ASA_TEARDOWN, "network.flow")):
        if c := pattern.search(message):
            groups = c.groupdict()
            return record(
                event_type,
                actor=ip_ref(c["src"]),
                target=ip_ref(c["dst"]),
                host=frame.host,
                outcome_="success",
                action="built" if event_type == "network.connection" else "teardown",
                message=message,
                attributes={
                    **attrs,
                    "src_ip": ip(c["src"]),
                    "dst_ip": ip(c["dst"]),
                    "src_port": int(c["srcport"]),
                    "dst_port": int(c["dstport"]),
                    "protocol": c["proto"].lower(),
                    "bytes": int(groups["bytes"]) if groups.get("bytes") else None,
                    "direction": groups.get("dir"),
                },
            )
    if msg_id in _ASA_AUTH:
        u = _ASA_USER.search(message)
        login = (u["user"] or u["user2"] or u["user3"]) if u else None
        addresses = [a for a in re.findall(r"[\d]{1,3}(?:\.\d{1,3}){3}", message) if ip(a)]
        event_type = _ASA_AUTH[msg_id]
        return record(
            event_type,
            actor=user_ref(login) if login else ip_ref(addresses[0] if addresses else None),
            target=frame.host,
            host=frame.host,
            outcome_="failure" if event_type == "auth.failure" else "success",
            severity="low" if event_type == "auth.failure" else None,
            action=f"asa-{msg_id}",
            message=message,
            attributes={**attrs, "src_ip": addresses[0] if addresses else None},
        )
    return _free_text(frame, message=message, extra={**attrs, "level": str(sev)})


_SQUID = re.compile(
    r"^\s*(?P<elapsed>\d+) (?P<client>\S+) (?P<code>[A-Z_]+)/(?P<status>\d{3}) (?P<bytes>\d+) (?P<method>[A-Z]+) "
    r"(?P<url>\S+) (?P<user>\S+) (?P<hier>[A-Z_]+)/(?P<peer>\S+)(?: (?P<type>\S+))?"
)


def _squid(frame: Frame) -> dict[str, Any] | None:
    if frame.framing != "epoch":
        return None
    m = _SQUID.match(frame.payload)
    if m is None:
        return None
    url = m["url"]
    if m["method"] == "CONNECT" and "://" not in url:
        url = f"https://{url}/"
    status = int(m["status"])
    user = m["user"] if m["user"] != "-" else None
    return record(
        "http.request",
        actor=ip_ref(m["client"]) or host_ref(m["client"]),
        target=url_ref("http", None, url) if "://" in url else url_ref("http", m["peer"], url),
        host=frame.host,
        outcome_="failure" if status >= 400 or "DENIED" in m["code"] else "success",
        severity="low" if "DENIED" in m["code"] else None,
        action=m["method"].lower(),
        message=f"{m['method']} {url.split('?', 1)[0]} -> {m['code']}/{status}",
        attributes={
            "src_ip": ip(m["client"]),
            "method": m["method"],
            "status": status,
            "bytes": int(m["bytes"]),
            "cache_result": m["code"],
            "user": user,
            "dst_ip": ip(m["peer"]),
            "content_type": m["type"] if m["type"] != "-" else None,
            "elapsed_ms": int(m["elapsed"]),
            "proxy": "squid",
        },
        objects=[{"name": user, "role": "user"}] if user else [],
    )


# --------------------------------------------------------------------------- cloud flow and storage logs

_VPC_FLOW = re.compile(
    r"^(?P<version>[2-9]) (?P<account>\d{12}|unknown|-) (?P<eni>eni-[0-9a-f]+|-) (?P<src>\S+) (?P<dst>\S+) "
    r"(?P<sport>\d+|-) (?P<dport>\d+|-) (?P<proto>\d+|-) (?P<packets>\d+|-) (?P<bytes>\d+|-) (?P<start>\d{10}) "
    r"(?P<end>\d{10}) (?P<action>ACCEPT|REJECT|-) (?P<status>OK|NODATA|SKIPDATA)$"
)
_PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "58": "icmpv6", "132": "sctp"}


def _vpc_flow(frame: Frame) -> dict[str, Any] | None:
    m = _VPC_FLOW.match(frame.payload)
    if m is None:
        return None
    if m["status"] != "OK":
        return record(
            "log.flow_nodata", timestamp=m["start"], attributes={"interface": m["eni"], "status": m["status"]}
        )
    rejected = m["action"] == "REJECT"

    def number(value: str | None) -> int | None:
        return int(value) if value not in (None, "-") else None

    return record(
        "network.flow",
        timestamp=m["start"],
        actor=ip_ref(m["src"]),
        target=ip_ref(m["dst"]),
        outcome_="failure" if rejected else "success",
        severity="low" if rejected else None,
        action=m["action"].lower(),
        message=f"{m['src']}:{m['sport']} -> {m['dst']}:{m['dport']} "
        f"{_PROTOCOLS.get(m['proto'], m['proto'])} {m['action']}",
        attributes={
            "src_ip": ip(m["src"]),
            "dst_ip": ip(m["dst"]),
            "src_port": number(m["sport"]),
            "dst_port": number(m["dport"]),
            "protocol": _PROTOCOLS.get(m["proto"], m["proto"]),
            "packets": number(m["packets"]),
            "bytes": number(m["bytes"]),
            "account": m["account"],
            "interface": m["eni"],
            "blocked": True if rejected else None,
            "flow_end": m["end"],
            "platform": "aws",
        },
    )


_S3_ACCESS = re.compile(
    r"^(?P<owner>\S+) (?P<bucket>\S+) \[(?P<ts>[^\]]+)\] (?P<ip>\S+) (?P<requester>\S+) (?P<reqid>\S+) "
    r'(?P<op>\S+) (?P<key>\S+) "(?P<request>[^"]*)" (?P<status>\S+) (?P<error>\S+) (?P<bytes>\S+) (?P<size>\S+) '
    r'(?P<total>\S+) (?P<turnaround>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"(?P<tail>.*)$'
)


def storage_access_record(
    *,
    bucket: str,
    key: str | None,
    operation: str,
    requester: str | None,
    remote: str | None,
    status: Any,
    request_id: str | None,
    bytes_sent: Any,
    timestamp: Any = None,
    error: str | None = None,
    user_agent: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """An object-storage access record (S3 server access log and similar)."""
    op = operation.upper()
    if ".GET.OBJECT" in op or op.endswith("GET_OBJECT"):
        event_type = "file.read"
    elif ".PUT.OBJECT" in op or ".POST.OBJECT" in op or ".COPY.OBJECT" in op:
        event_type = "file.create"
    elif ".DELETE.OBJECT" in op:
        event_type = "file.delete"
    else:
        event_type = "cloud.api"
    target_object = object_ref(bucket, key) if key and key != "-" and event_type.startswith("file.") else None
    principal: Any = None
    if requester and requester != "-":
        name = requester.rsplit("/", 1)[-1] if requester.startswith("arn:") else requester
        principal = ref(ObjectType.IDENTITY.value, name, key=requester if requester.startswith("arn:") else name)
    else:
        principal = user_ref("anonymous")
    status_number = int(status) if str(status).isdigit() else None
    sent = int(bytes_sent) if str(bytes_sent).isdigit() else None
    failed = status_number is not None and status_number >= 400
    return record(
        event_type,
        timestamp=timestamp,
        actor=principal,
        target=target_object or bucket_ref(bucket),
        outcome_="failure" if failed else "success",
        severity="low" if failed else None,
        action=op,
        message=f"{op} {bucket}/{key or ''} -> {status}" + (f" ({sent} bytes)" if sent is not None else ""),
        attributes={
            "platform": "aws",
            "bucket": bucket,
            "object_key": key if key != "-" else None,
            "operation": op,
            "src_ip": ip(remote),
            "status": status_number,
            "error_code": error if error and error != "-" else None,
            "bytes_sent": sent,
            "request_id": request_id,
            "user_agent": user_agent,
            **(extra or {}),
        },
        objects=[_bucket_role(bucket)] if target_object is not None else [],
    )


def _bucket_role(bucket: str) -> dict[str, Any] | None:
    reference = bucket_ref(bucket)
    return {**reference, "role": "bucket"} if reference is not None else None


def _s3_access(frame: Frame) -> dict[str, Any] | None:
    m = _S3_ACCESS.match(frame.payload)
    if m is not None and (m["op"].startswith(("REST.", "WEBSITE.", "BATCH.")) or m["op"] == "-"):
        return storage_access_record(
            bucket=m["bucket"],
            key=m["key"],
            operation=m["op"],
            requester=m["requester"],
            remote=m["ip"],
            status=m["status"],
            request_id=m["reqid"],
            bytes_sent=m["bytes"],
            timestamp=m["ts"],
            error=m["error"],
            user_agent=m["ua"] if m["ua"] != "-" else None,
            extra={"object_size": m["size"] if m["size"] != "-" else None, "total_time_ms": m["total"]},
        )
    pairs = kv_pairs(frame.payload)
    if "bucket" in pairs and ("op" in pairs or "operation" in pairs):
        known = {
            "bucket",
            "key",
            "op",
            "operation",
            "requester",
            "remote_ip",
            "status",
            "request_id",
            "bytes_sent",
            "error",
            "user_agent",
        }
        return storage_access_record(
            bucket=pairs["bucket"],
            key=pairs.get("key"),
            operation=pairs.get("op") or pairs.get("operation") or "-",
            requester=pairs.get("requester"),
            remote=pairs.get("remote_ip") or pairs.get("ip"),
            status=pairs.get("status"),
            request_id=pairs.get("request_id"),
            bytes_sent=pairs.get("bytes_sent") or pairs.get("bytes"),
            error=pairs.get("error"),
            user_agent=pairs.get("user_agent"),
            extra=safe_attributes(((k, v) for k, v in pairs.items() if k not in known), limit=12),
        )
    return None


# --------------------------------------------------------------------------- syslog daemons

_SYSLOG_PROGRAMS = ("sshd", "sudo", "su", "systemd-logind", "cron", "crond", "kernel")
_SSH_MESSAGE = re.compile(r"^(?:Accepted|Failed|Invalid user|Disconnected from|Connection closed by)\b")


def _syslog_program(frame: Frame) -> dict[str, Any] | None:
    program = (frame.tag or "").lower()
    message = frame.payload
    if not program.startswith(_SYSLOG_PROGRAMS):
        if _SSH_MESSAGE.match(frame.message):
            program, message = "sshd", frame.message
        elif "SRC=" in message and "DST=" in message and "PROTO=" in message:
            program = "kernel"
        else:
            return None
    base: dict[str, Any] = {
        "timestamp": frame.timestamp,
        "host": frame.host,
        "message": message,
        "attributes": {"program": frame.tag or program, "program_pid": frame.pid},
    }
    data, label = extract_program(program, message, base)
    if label == "syslog":  # a message of a known daemon that the extractors do not cover
        return None
    data["attributes"] = {k: v for k, v in data["attributes"].items() if v is not None}
    if data.get("host") is None:
        data.pop("host", None)
    return data


# --------------------------------------------------------------------------- free text

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?![\w.])")
_IPV6 = re.compile(
    r"(?<![\w:])((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{0,4})(?![\w:])"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{1,2048}")
_USER_PATTERNS = (
    re.compile(r"(?i)\b(?:user(?:name)?|account|login|uid|acct)[=:]\s*\"?(?P<name>[\w.@\\-]{1,128})\"?"),
    re.compile(r"(?i)\bfor (?:invalid )?user (?P<name>[\w.@\\-]{1,128})"),
    re.compile(r"(?i)\buser (?P<name>[\w.@\\-]{1,128}) (?:logged|authenticated|failed|signed)"),
    re.compile(r"(?i)\b(?:by|as) user (?P<name>[\w.@\\-]{1,128})"),
)
_FROM = re.compile(r"(?i)\b(?:from|src|source|client)[=: ]+\[?(?P<ip>[0-9a-fA-F.:]{3,45})\]?")
_TO = re.compile(r"(?i)\b(?:to|dst|dest|destination)[=: ]+\[?(?P<ip>[0-9a-fA-F.:]{3,45})\]?")
_AUTH_FAIL = re.compile(
    r"(?i)\b(?:failed password|authentication failure|auth(?:entication)? failed|login failed|failed login|"
    r"invalid (?:user|password|credentials)|incorrect password|access denied for user|bad password|logon failure)\b"
)
_AUTH_OK = re.compile(
    r"(?i)\b(?:accepted (?:password|publickey|keyboard)|logged in|login successful|successful login|"
    r"authentication succeeded|session opened for user|signed in)\b"
)
_DENY = re.compile(r"(?i)\b(?:denied|blocked|dropped|rejected|refused)\b")
_LEVEL_WORD = re.compile(r"(?i)\b(?P<level>fatal|critical|error|warn(?:ing)?)\b")


def _free_text(frame: Frame, *, message: str | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Any line: addresses, e-mail accounts, URLs and user names are extracted; authentication
    successes and failures and denied connections are recognized from their usual wording."""
    text = message if message is not None else (frame.message if frame.framing == "tagged" else frame.payload)
    addresses: list[str] = []
    for match in _IPV4.finditer(text):
        if (address := ip(match.group(1))) and address not in addresses:
            addresses.append(address)
    for match in _IPV6.finditer(text):
        if (address := ip(match.group(1))) and address not in addresses and ":" in address:
            addresses.append(address)
    user: str | None = None
    for pattern in _USER_PATTERNS:
        if u := pattern.search(text):
            user = u["name"]
            break
    emails = list(dict.fromkeys(_EMAIL.findall(text)))[:8]
    if user is None and emails:
        user = emails[0]
    urls = list(dict.fromkeys(u.rstrip(".,;)") for u in _URL.findall(text)))[:8]
    src = next((ip(m["ip"]) for m in _FROM.finditer(text) if ip(m["ip"])), None)
    dst = next((ip(m["ip"]) for m in _TO.finditer(text) if ip(m["ip"])), None)
    if src is None and len(addresses) == 1:
        src = addresses[0]
    level = frame.level
    if level is None and (lw := _LEVEL_WORD.search(text[:80])):
        level = lw["level"].lower()
    host = frame.host
    objects: list[dict[str, Any] | None] = []
    for address in addresses:
        if address not in (src, dst):
            objects.append({"type": ObjectType.IP.value, "name": address, "role": "related"})
    for url in urls[:4]:
        objects.append({"type": ObjectType.URL.value, "name": url.split("?", 1)[0], "role": "url"})
    attrs: dict[str, Any] = {
        "src_ip": src,
        "dst_ip": dst,
        "program": frame.tag,
        "program_pid": frame.pid,
        "level": level,
        "emails": emails or None,
        "urls": [safe_value("url", u) for u in urls] or None,
        "addresses": addresses[:16] or None,
        **(extra or {}),
    }
    shown = redact_text(text)
    if _AUTH_FAIL.search(text):
        return record(
            "auth.failure",
            actor=user_ref(user) if user else ip_ref(src),
            target=host_ref(host) or (ip_ref(dst) if dst else None),
            host=host,
            outcome_="failure",
            severity="low",
            action="authentication",
            message=shown,
            attributes=attrs,
            objects=objects,
        )
    if _AUTH_OK.search(text) and user:
        return record(
            "auth.login",
            actor=user_ref(user),
            target=host_ref(host),
            host=host,
            outcome_="success",
            action="authentication",
            message=shown,
            attributes=attrs,
            objects=objects,
        )
    if _DENY.search(text) and src and dst:
        return record(
            "network.connection",
            actor=ip_ref(src),
            target=ip_ref(dst),
            host=host,
            outcome_="failure",
            severity="low",
            action="deny",
            message=shown,
            attributes={**attrs, "blocked": True},
            objects=objects,
        )
    if user:
        objects.append({"name": user, "role": "user"})
    return record(
        "log.message",
        host=host,
        severity=level_severity(level),
        message=shown,
        attributes=attrs,
        objects=objects,
    )


free_text = _free_text

#: Text decoders with the source tags that hint at them (tried first for those tags).
TEXT_DECODERS: tuple[tuple[str, tuple[str, ...], TextDecoder], ...] = (
    (
        "web-access",
        ("nginx", "apache", "httpd", "access", "web", "caddy", "haproxy", "traefik", "envoy", "lb", "alb"),
        _access,
    ),
    ("s3-access", ("s3", "s3-access", "s3access", "storage", "gcs", "blob"), _s3_access),
    ("vpc-flow", ("vpc", "vpcflow", "vpc-flow", "flowlogs", "flow"), _vpc_flow),
    ("squid", ("squid", "proxy"), _squid),
    ("dns-bind", ("bind", "bind9", "named", "dns"), _bind),
    ("dnsmasq", ("dnsmasq", "pihole", "pihole-ftl"), _dnsmasq),
    ("postgres", _PG_HINTS, _postgres),
    ("web-error", ("nginx", "nginx-error", "error"), _nginx_error),
    ("auditd", ("audit", "auditd", "audispd"), _auditd),
    ("cisco-asa", ("asa", "ftd", "cisco", "firewall"), _cisco_asa),
    ("syslog", _SYSLOG_PROGRAMS, _syslog_program),
)


__all__ = ["TEXT_DECODERS", "free_text", "storage_access_record"]
