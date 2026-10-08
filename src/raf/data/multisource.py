"""A dense multi-source log of Raven Industries (synthetic, deterministic).

One hour of interleaved lines from a dozen sources - nginx, AWS CloudTrail, Kubernetes audit, BIND,
PostgreSQL, the identity provider, application JSON, EDR, flow sensors, S3 server access logs, the
change calendar, sshd, auditd, a WAF (CEF) and Windows (XML) - in which one attack is buried among
routine activity and decoys:

* 21:40 a support bundle is downloaded through a public link by 198.51.100.77; its manifest lists
  ``deploy.env``;
* 21:41 the CI service user's access key is used from that address: discovery, eight reads from
  ``raven-backups`` (about 320 MB), a denied ``AttachUserPolicy``, and the matching egress flow;
* the same key is also used by the CI runner from its usual internal address.

Decoys that must not become findings: an approved change (CHG-1017) deleting old pods inside its
window, an export carrying its ticket (FIN-301), routine sign-in failures spread over internal clients.
Low-severity facts that are worth seeing but are not part of the attack: an Internet scanner probing
for sensitive paths (all refused) and a travelling user signing in with MFA from a public address.

All addresses are private or documentation ranges; the access key is AWS's documentation example.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from typing import Any

START = datetime(2026, 10, 6, 21, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
ATTACKER = "198.51.100.77"
SCANNER = "203.0.113.66"
TRAVEL = "192.0.2.44"
ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
USERS = ("alice", "bob", "carol", "dave", "erin")
CLIENTS = ("10.10.1.21", "10.10.1.22", "10.10.2.31", "10.10.2.32", "10.10.3.40")
SERVICES = ("shop-api", "payments", "reports", "search", "billing")
NODES = tuple(f"10.40.0.{n}" for n in range(10, 22))
DOMAINS = ("api.raven.example", "sso.raven.example", "s3.eu-west-1.amazonaws.com", "metrics.raven.example")
_STATEMENT = "SELECT id, status FROM orders WHERE customer_id = $1 LIMIT 20"  # logged text, never executed
PATHS = ("/api/v1/orders", "/api/v1/me", "/api/v1/search", "/login", "/static/app.js", "/healthz")


def _ts(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}Z"


def _json(data: dict[str, Any]) -> str:
    return json.dumps(data, separators=(",", ":"))


class _Log:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.lines: list[tuple[datetime, int, str]] = []
        self.counter = 0

    def add(self, at: datetime, text: str) -> None:
        self.counter += 1
        self.lines.append((at, self.counter, f"{_ts(at)} {text}"))

    def hex(self, n: int) -> str:
        return "".join(self.rng.choice("0123456789abcdef") for _ in range(n))

    def text(self) -> str:
        return "".join(line + "\n" for _at, _n, line in sorted(self.lines))


def _cloudtrail(
    log: _Log,
    at: datetime,
    source: str,
    name: str,
    *,
    ip: str,
    identity: dict[str, Any],
    params: dict[str, Any] | None = None,
    error: str | None = None,
    request_id: str | None = None,
) -> str:
    record: dict[str, Any] = {
        "eventTime": _ts(at),
        "eventSource": f"{source}.amazonaws.com",
        "eventName": name,
        "awsRegion": "eu-west-1",
        "sourceIPAddress": ip,
        "userAgent": "aws-cli/2.17",
        "userIdentity": identity,
    }
    if params:
        record["requestParameters"] = params
    if error:
        record["errorCode"] = error
    record["requestID"] = request_id or log.hex(16)
    return f"cloudtrail {_json(record)}"


def _routine(log: _Log, minutes: int) -> None:
    rng = log.rng
    end = START + timedelta(minutes=minutes)
    at = START
    while at < end:
        at += timedelta(milliseconds=rng.randint(300, 2600))
        kind = rng.choices(
            ("nginx", "app", "dns", "idp", "k8s", "cloud", "db", "edr", "flow"),
            weights=(26, 20, 12, 10, 9, 8, 6, 4, 5),
        )[0]
        client = rng.choice(CLIENTS)
        user = rng.choice(USERS)
        service = rng.choice(SERVICES)
        if kind == "nginx":
            status = rng.choices((200, 304, 401, 404, 429, 500), weights=(78, 8, 4, 4, 3, 3))[0]
            who = user if rng.random() < 0.4 else "-"
            log.add(
                at,
                f'nginx[web-0{rng.randint(1, 2)}] {client} - {who} "GET {rng.choice(PATHS)} HTTP/1.1" {status} '
                f'{rng.randint(90, 24000)} "-" "Mozilla/5.0" rt={rng.random():.3f} rid=req-{log.hex(10)} '
                f"upstream={service}",
            )
        elif kind == "app":
            actor = user if rng.random() < 0.6 else "system"
            level = rng.choices(("INFO", "WARN", "ERROR"), weights=(90, 8, 2))[0]
            log.add(
                at,
                "app "
                + _json(
                    {
                        "level": level,
                        "service": service,
                        "pod": f"{service}-{log.hex(4)}",
                        "event": rng.choice(("search.query", "cache.hit", "order.list", "report.render")),
                        "request_id": f"req-{log.hex(10)}",
                        "actor": actor,
                        "latency_ms": rng.randint(5, 900),
                        "result": "ok" if level != "ERROR" else "retry",
                    }
                ),
            )
        elif kind == "dns":
            log.add(
                at,
                f"bind9[dns-01] client {client}#{rng.randint(1024, 65000)}: query: {rng.choice(DOMAINS)} IN A +E(0)K "
                f"(10.40.0.53); response: NOERROR ttl={rng.choice((30, 60, 300))}",
            )
        elif kind == "idp":
            outcome = rng.choices(("SUCCESS", "FAILURE", "MFA_CHALLENGE"), weights=(86, 10, 4))[0]
            log.add(
                at,
                "idp "
                + _json(
                    {
                        "eventType": "user.authentication",
                        "actor": f"{user}@raven.example",
                        "outcome": outcome,
                        "clientIp": client,
                        "app": "raven-sso",
                        "deviceId": f"dev-{rng.randint(100, 140)}",
                        "sessionId": f"sid-{log.hex(12)}",
                    }
                ),
            )
        elif kind == "k8s":
            log.add(
                at,
                "k8s-audit "
                + _json(
                    {
                        "kind": "Event",
                        "level": "Metadata",
                        "verb": rng.choice(("get", "list", "watch", "update")),
                        "user": {"username": f"system:serviceaccount:prod:{service}"},
                        "sourceIPs": [rng.choice(NODES)],
                        "objectRef": {"resource": rng.choice(("pods", "leases", "configmaps")), "namespace": "prod"},
                        "responseStatus": {"code": 200},
                        "auditID": log.hex(16),
                    }
                ),
            )
        elif kind == "cloud":
            name, source = rng.choice(
                (("DescribeInstances", "ec2"), ("GetCallerIdentity", "sts"), ("GetParameter", "ssm"))
            )
            identity = {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{service}/job-{rng.randint(1000, 9999)}",
            }
            log.add(at, _cloudtrail(log, at, source, name, ip=rng.choice(NODES), identity=identity))
        elif kind == "db":
            log.add(
                at,
                f"postgres[db-01] user=app_ro db=shop app={service} client={client} LOG: duration: "
                f"{rng.uniform(1, 90):.3f} ms statement: {_STATEMENT}",
            )
        elif kind == "edr":
            log.add(
                at,
                "edr "
                + _json(
                    {
                        "event": "ProcessStart",
                        "hostname": rng.choice(("ci-01", "app-01", "app-02")),
                        "user": rng.choice(("ci", "app", "root")),
                        "image": "/usr/bin/python3",
                        "commandLine": rng.choice(("python3 healthcheck.py", "git fetch --quiet")),
                        "processId": rng.randint(1000, 30000),
                        "parentProcessId": rng.randint(1, 999),
                        "action": "allow",
                    }
                ),
            )
        else:
            log.add(
                at,
                "netflow "
                + _json(
                    {
                        "src": client,
                        "dst": rng.choice(NODES),
                        "dport": rng.choice((443, 5432, 53)),
                        "protocol": "tcp",
                        "bytesOut": rng.randint(400, 60000),
                        "bytesIn": rng.randint(800, 250000),
                        "durationMs": rng.randint(20, 30000),
                        "decision": "allow",
                    }
                ),
            )


def _attack(log: _Log) -> None:
    at = START + timedelta(minutes=40, seconds=5)
    bundle = "build/2026-10-06/support-bundle.zip"
    log.add(
        at,
        f'nginx[web-01] {ATTACKER} - - "GET /exports/{bundle} HTTP/1.1" 200 18110 "-" "python-requests/2.32" '
        "rt=0.040 rid=req-attack0001 upstream=artifact-store",
    )
    log.add(
        at + timedelta(milliseconds=60),
        "app "
        + _json(
            {
                "level": "INFO",
                "service": "artifact-store",
                "event": "artifact.download",
                "actor": "anonymous",
                "path": bundle,
                "bytes": 18110,
                "cache": "public-link",
                "request_id": "req-attack0001",
            }
        ),
    )
    log.add(
        at + timedelta(milliseconds=120),
        "app "
        + _json(
            {
                "level": "WARN",
                "service": "artifact-store",
                "event": "manifest.index",
                "path": bundle,
                "entries": ["build.log", "deploy.env", "heap.json"],
                "request_id": "req-attack0001",
                "result": "served",
            }
        ),
    )
    key = {"type": "IAMUser", "userName": "svc-ci", "accessKeyId": ACCESS_KEY}
    at = START + timedelta(minutes=41, seconds=2)
    log.add(at, _cloudtrail(log, at, "sts", "GetCallerIdentity", ip=ATTACKER, identity=key))
    at += timedelta(seconds=3)
    log.add(at, _cloudtrail(log, at, "s3", "ListBuckets", ip=ATTACKER, identity=key))
    at += timedelta(seconds=9)
    prefix = "db/2026-10-05/"
    log.add(
        at,
        _cloudtrail(
            log,
            at,
            "s3",
            "ListObjectsV2",
            ip=ATTACKER,
            identity=key,
            params={"bucketName": "raven-backups", "prefix": prefix},
            request_id="ct-list-0001",
        ),
    )
    log.add(
        at + timedelta(milliseconds=250),
        f"s3-access bucket=raven-backups requester=svc-ci key={prefix} op=REST.GET.BUCKET status=200 "
        f"remote_ip={ATTACKER} request_id=ct-list-0001 bytes_sent=4210",
    )
    sizes = [40_118_272, 39_874_560, 40_402_944, 40_011_776, 39_960_064, 40_271_872, 40_108_032, 39_985_152]
    for index, size in enumerate(sizes):
        at += timedelta(seconds=8)
        request = f"ct-get-{index:04d}"
        object_key = f"{prefix}part-{index:05d}.gz"
        log.add(
            at,
            _cloudtrail(
                log,
                at,
                "s3",
                "GetObject",
                ip=ATTACKER,
                identity=key,
                params={"bucketName": "raven-backups", "key": object_key},
                request_id=request,
            ),
        )
        log.add(
            at + timedelta(milliseconds=180),
            f"s3-access bucket=raven-backups requester=svc-ci key={object_key} op=REST.GET.OBJECT status=200 "
            f"remote_ip={ATTACKER} request_id={request} bytes_sent={size}",
        )
    at += timedelta(seconds=21)
    log.add(
        at,
        _cloudtrail(
            log,
            at,
            "iam",
            "AttachUserPolicy",
            ip=ATTACKER,
            identity=key,
            params={"userName": "svc-ci", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            error="AccessDenied",
        ),
    )
    at += timedelta(seconds=17)
    log.add(
        at,
        "netflow "
        + _json(
            {
                "src": ATTACKER,
                "dst": "52.95.150.20",
                "dport": 443,
                "protocol": "tcp",
                "bytesOut": 11204,
                "bytesIn": sum(sizes) + 6000,
                "durationMs": 81000,
                "decision": "allow",
                "sensor": "egress-01",
            }
        ),
    )
    at += timedelta(seconds=40)
    log.add(at, _cloudtrail(log, at, "sts", "GetCallerIdentity", ip="10.40.0.30", identity=key))
    log.add(
        at + timedelta(seconds=7),
        "app "
        + _json(
            {
                "level": "INFO",
                "service": "ci",
                "event": "job.completed",
                "job": "nightly-build",
                "runner": "ci-01",
                "credentialFingerprint": "sha256:5f1a0c93be27",
                "request_id": "req-ci-0042",
                "result": "ok",
            }
        ),
    )


def _decoys(log: _Log) -> None:
    at = START + timedelta(minutes=12)
    for index, path in enumerate(("/wp-login.php", "/.env", "/server-status", "/.git/HEAD", "/phpmyadmin", "/.env")):
        log.add(
            at + timedelta(seconds=2 * index),
            f'nginx[web-02] {SCANNER} - - "GET {path} HTTP/1.1" 404 162 "-" "curl/8.6.0" rt=0.002 '
            f"rid=scan-{index:03d} upstream=shop-api",
        )
    at = START + timedelta(minutes=22)
    for offset, outcome in ((0, "MFA_CHALLENGE"), (9, "SUCCESS")):
        log.add(
            at + timedelta(seconds=offset),
            "idp "
            + _json(
                {
                    "eventType": "user.authentication",
                    "actor": "carol@raven.example",
                    "outcome": outcome,
                    "clientIp": TRAVEL,
                    "app": "raven-sso",
                    "deviceId": "dev-131",
                    "sessionId": "sid-travel-2201",
                }
            ),
        )
    at = START + timedelta(minutes=25)
    log.add(
        at,
        "change "
        + _json(
            {
                "ticket": "CHG-1017",
                "service": "payments",
                "actor": "deploy-bot",
                "action": "rolling_restart",
                "status": "approved",
                "window": "21:20-21:50Z",
            }
        ),
    )
    for index in range(3):
        log.add(
            at + timedelta(seconds=15 + 20 * index),
            "k8s-audit "
            + _json(
                {
                    "kind": "Event",
                    "verb": "delete",
                    "user": {"username": "system:serviceaccount:ops:deploy-bot"},
                    "sourceIPs": ["10.40.0.11"],
                    "objectRef": {"resource": "pods", "namespace": "prod", "name": f"payments-old-{index}"},
                    "responseStatus": {"code": 200},
                    "auditID": f"chg-1017-{index}",
                }
            ),
        )
    log.add(
        START + timedelta(minutes=55),
        "app "
        + _json(
            {
                "level": "INFO",
                "service": "reports",
                "event": "export.completed",
                "actor": "finance.batch",
                "object": "s3://raven-reports/approved/q3-summary.csv",
                "bytes": 151_204_118,
                "ticket": "FIN-301",
                "request_id": "req-fin-301",
            }
        ),
    )


def _other_formats(log: _Log) -> None:
    """A few lines in further formats the mixed-log parser recognizes."""
    at = START + timedelta(minutes=5)
    log.add(at, "bastion-01 sshd[2211]: Accepted publickey for ops from 10.10.1.22 port 50022 ssh2")
    login = at + timedelta(minutes=1)
    log.add(
        login,
        f"audit type=USER_LOGIN msg=audit({login.timestamp():.3f}:4101): pid=2213 uid=0 auid=1003 ses=7 "
        'msg=\'op=login acct="ops" exe="/usr/sbin/sshd" hostname=10.10.1.22 addr=10.10.1.22 terminal=ssh '
        "res=success'",
    )
    log.add(
        at + timedelta(minutes=2),
        "waf CEF:0|Raven|EdgeWAF|2.1|942100|SQL injection attempt blocked|5|src=203.0.113.90 dst=10.10.0.10 "
        "spt=51515 dpt=443 request=/search?q=1%27%20OR%201%3D1 act=blocked cat=attack",
    )
    log.add(
        at + timedelta(minutes=3),
        "winlog <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider "
        "Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><TimeCreated "
        "SystemTime='2026-10-06T21:08:00.000Z'/><Computer>ws-07.raven.example</Computer></System><EventData>"
        "<Data Name='TargetUserName'>dave</Data><Data Name='LogonType'>10</Data><Data Name='IpAddress'>10.10.2.32"
        "</Data></EventData></Event>",
    )


def multisource_log(seed: int = 11, minutes: int = 60) -> str:
    """The dense multi-source log (deterministic for a seed)."""
    log = _Log(seed)
    _routine(log, minutes)
    _attack(log)
    _decoys(log)
    _other_formats(log)
    return log.text()


__all__ = ["ACCESS_KEY", "ATTACKER", "SCANNER", "multisource_log"]
