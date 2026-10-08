"""R$F detections: rules over normalized events, whatever source and parser produced them.

Each rule states what it matched (evidence events), what it compared against (the baseline of the
same scope: the share of cloud calls from internal addresses, the size of routine flows, a user's
earlier sign-ins ...) and why the severity is what it is. Rules are deterministic: the same events
give the same findings, with stable IDs, so a re-run updates instead of duplicating, and a finding a
re-run no longer produces is resolved.

Activity that an approved change record covers (a destructive operation inside its window, by its
actor, on its service) or that carries its own ticket (an export with a change number) is reported
as **explained**, not as a finding. Detections that share an entity - an address, an identity, a
credential, a bucket, an artifact - within two hours are correlated into a suspected incident whose
description is the time-ordered narrative of the chain; the incident and the chain finding say
"suspected", and every step cites its events.
"""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.ids import digest, finding_id, object_id
from raf.core.ingestion.logs.structured import secret_bearing
from raf.core.netaddr import ip_scope, parse_networks
from raf.core.objects.models import Event, EvidenceRef, Finding, RafModel
from raf.core.objects.types import FindingStatus, ObjectType, Severity
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import format_ts, utcnow

PRODUCT = "timeline"

_KEY_CAP = 100_000  # distinct keys tracked per collection
_LIST_CAP = 5_000  # items kept per key
_EVIDENCE_CAP = 40  # events cited per finding
_CHAIN_GAP = timedelta(hours=2)
_MB = 1_000_000  # sizes are reported in SI units (logs count bytes)
_CLOUD_PLATFORMS = frozenset({"aws", "gcp", "azure"})
_INTERNAL_SCOPES = frozenset({"internal", "loopback", "link-local"})


# --------------------------------------------------------------------------- rules


@dataclass(frozen=True, slots=True)
class RuleInfo:
    id: str
    title: str
    tactic: str
    techniques: tuple[str, ...]
    description: str
    recommendation: str


_RULE_LIST = (
    RuleInfo(
        "web-recon",
        "Web reconnaissance",
        "Reconnaissance",
        ("T1595.003",),
        "One client requested many well-known sensitive paths (admin consoles, VCS metadata, actuator, "
        "backups) or produced a burst of client errors.",
        "Block or rate-limit the source if it keeps probing; check that none of the probed paths exist.",
    ),
    RuleInfo(
        "exposed-artifact",
        "Sensitive artifact served publicly",
        "Credential Access",
        ("T1552.001", "T1213"),
        "An archive, dump or diagnostics bundle was downloaded without authentication or from a public "
        "address; when its manifest lists credential files they must be treated as disclosed.",
        "Disable the public link, rotate every credential the artifact contained, and review who else downloaded it.",
    ),
    RuleInfo(
        "cloud-credential-public",
        "Cloud identity used from a public address",
        "Initial Access",
        ("T1078.004",),
        "Calls signed by an identity came from a public address while the environment's cloud activity "
        "comes from internal networks, or with a long-term access key, or by a service identity.",
        "Deactivate the access key, review the identity's recent calls, and find where the key was stored.",
    ),
    RuleInfo(
        "bulk-storage-read",
        "Bulk read from cloud storage",
        "Collection",
        ("T1530",),
        "Many objects or a large volume were read from one bucket by one identity and address in a short window.",
        "Determine what the objects contain, notify data owners, and block the reading identity.",
    ),
    RuleInfo(
        "cloud-persistence",
        "Credential or permission change by a suspicious identity",
        "Persistence",
        ("T1098.001", "T1136.003"),
        "An identity created credentials, users or permission grants from a public address, while flagged "
        "for misuse, as a service identity, or was denied doing so.",
        "Remove any credential or grant that was created, and restrict the identity's IAM permissions.",
    ),
    RuleInfo(
        "large-transfer",
        "Unusually large network transfer",
        "Exfiltration",
        ("T1048",),
        "A flow moved far more data than the routine flows of the same scope.",
        "Identify the process or identity behind the flow and what data moved.",
    ),
    RuleInfo(
        "brute-force",
        "Repeated authentication failures",
        "Credential Access",
        ("T1110.001",),
        "An account failed to authenticate many times in a short window, well above its own failure rate.",
        "Check the source, enforce MFA and lockout, and reset the password if a success followed.",
    ),
    RuleInfo(
        "password-spray",
        "Password spraying",
        "Credential Access",
        ("T1110.003",),
        "One address failed to authenticate as several accounts in a short window.",
        "Block the source and check every targeted account for later successful sign-ins.",
    ),
    RuleInfo(
        "mfa-fatigue",
        "Repeated MFA challenges",
        "Credential Access",
        ("T1621",),
        "An account received many MFA challenges in a short window.",
        "Ask the user whether they triggered them; reset the password if not.",
    ),
    RuleInfo(
        "new-external-signin",
        "Sign-in from a new public address",
        "Initial Access",
        ("T1078",),
        "A user signed in from a public address never seen for them, while their other sign-ins come from "
        "internal networks.",
        "Confirm with the user (travel, remote work); revoke the session if unknown.",
    ),
    RuleInfo(
        "destructive-change",
        "Destructive operation outside a change",
        "Impact",
        ("T1489", "T1485"),
        "Workloads, secrets, roles or cloud resources were deleted or terminated, and no approved change "
        "record covers the actor, service and time.",
        "Confirm the operation with its owner and restore what was removed if it was not intended.",
    ),
    RuleInfo(
        "log-tampering",
        "Audit logging disabled or cleared",
        "Defense Evasion",
        ("T1562.008", "T1070.001"),
        "Audit or security logging was stopped, deleted or cleared.",
        "Re-enable logging, preserve what remains, and treat the window as unobserved.",
    ),
    RuleInfo(
        "suspicious-command",
        "Suspicious command line",
        "Execution",
        ("T1059",),
        "A process ran a command line typical of download-and-execute, reverse shells, credential dumping "
        "or defense evasion.",
        "Isolate the host and investigate the process tree and its parent.",
    ),
    RuleInfo(
        "credential-access",
        "Credential file or secret search",
        "Credential Access",
        ("T1552.001",),
        "A file that conventionally holds credentials (.env, private keys, cloud credentials, shadow) was read, "
        "or a command searched for such files.",
        "Rotate the credentials the file holds and find who used them afterwards.",
    ),
    RuleInfo(
        "service-account-new-source",
        "Service account signed in from a new source",
        "Lateral Movement",
        ("T1078", "T1021"),
        "A service account with a stable sign-in source authenticated from an address it never used before.",
        "Confirm the change with the service owner; if unknown, rotate the account's credentials.",
    ),
    RuleInfo(
        "security-alert",
        "Alert reported by a security tool",
        "Detection",
        (),
        "A security tool in the data raised an alert (IDS, EDR, SIEM or cloud detector).",
        "Triage the alert with the tool that raised it; R$F relays it with its evidence.",
    ),
    RuleInfo(
        "risky-sql",
        "Risky database statement",
        "Collection",
        ("T1005", "T1059"),
        "A database statement read or exported files, ran commands, changed privileges or destroyed data.",
        "Confirm the statement with the database owner; restrict the role's privileges.",
    ),
    RuleInfo(
        "dns-tunneling",
        "DNS tunneling pattern",
        "Command and Control",
        ("T1071.004",),
        "One client queried many long, unique names under one domain.",
        "Inspect the client and block the domain at the resolver.",
    ),
    RuleInfo(
        "large-export",
        "Large data export without a ticket",
        "Exfiltration",
        ("T1567",),
        "An application exported or served a large volume of data without a change or request reference.",
        "Confirm the export with the data owner.",
    ),
    RuleInfo(
        "attack-chain",
        "Correlated attack chain",
        "Multiple",
        (),
        "Several detections share entities (addresses, identities, credentials, data) within two hours.",
        "Handle the suspected incident as one case: contain the shared entities first.",
    ),
)
RULES: dict[str, RuleInfo] = {r.id: r for r in _RULE_LIST}

_PROBE_PATH = re.compile(
    r"(?i)(?:^|/)(?:wp-admin|wp-login\.php|xmlrpc\.php|phpmyadmin|pma|adminer(?:\.php)?|\.git(?:/|$)|\.svn|\.hg|"
    r"\.env(?:\.\w+)?$|\.aws|\.ssh|actuator(?:/|$)|server-status|server-info|\.ds_store|config\.php|setup\.php|"
    r"cgi-bin|boaform|hnap1|vendor/phpunit|solr/|jenkins|manager/html|console(?:/|$)|\.well-known/security|"
    r"id_rsa|backup(?:\.\w+)?$|dump\.sql|db\.sql|web\.config|owa/|autodiscover|telescope|_profiler|debug/)"
)
_ARTIFACT_PATH = re.compile(
    r"(?i)(?:\.(?:zip|tar|tgz|tar\.gz|gz|bz2|xz|7z|rar|bak|sql|dump|db|sqlite|env|pem|key|pfx|p12|kdbx|jks|log)$|"
    r"(?:^|/)(?:backups?|dumps?|exports?|diagnostics?|support-bundles?|artifacts?|debug|snapshots?)(?:/|$))"
)
_PUBLIC_LINK = re.compile(r"(?i)public|anonymous|shared[-_ ]?link|presigned|unauthenticated|guest")
_ANONYMOUS = frozenset({"guest", "anonymous", "anon", "public", "unauthenticated", "nobody"})
_SERVICE_IDENTITY = re.compile(
    r"(?i)(?:^|[-_.:/])(?:svc|service|bot|ci|cd|deploy|pipeline|automation|robot|app)(?:$|[-_.:/])"
)
_DISCOVERY_APIS = frozenset(
    {
        "GetCallerIdentity",
        "ListBuckets",
        "ListUsers",
        "ListRoles",
        "ListAccessKeys",
        "GetAccountAuthorizationDetails",
        "ListAttachedUserPolicies",
        "ListUserPolicies",
        "DescribeInstances",
        "ListSecrets",
        "ListFunctions",
        "GetUser",
        "ListGroupsForUser",
    }
)
_READ_APIS = frozenset({"GetObject", "HeadObject", "ListObjects", "ListObjectsV2", "SelectObjectContent"})
_PERSISTENCE_APIS = frozenset(
    {
        "CreateAccessKey",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "CreateUser",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "AddUserToGroup",
        "CreateRole",
        "UpdateAssumeRolePolicy",
        "CreateServiceSpecificCredential",
        "CreateServiceAccountKey",
        "SetIamPolicy",
    }
)
_TAMPER_APIS = frozenset(
    {
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
        "DeleteFlowLogs",
        "DeleteDetector",
        "DisableSecurityHub",
        "DeleteConfigurationRecorder",
        "StopConfigurationRecorder",
        "DisableAlarmActions",
    }
)
_DESTRUCTIVE_APIS = re.compile(r"^(?:Delete|Terminate|Destroy|Purge)(?!Object$|Objects$|MarkerAuto)")
_K8S_DESTRUCTIVE = frozenset({"delete", "deletecollection"})
_K8S_RESOURCES = frozenset(
    {
        "pods",
        "deployments",
        "statefulsets",
        "daemonsets",
        "replicasets",
        "services",
        "secrets",
        "configmaps",
        "namespaces",
        "roles",
        "rolebindings",
        "clusterroles",
        "clusterrolebindings",
        "persistentvolumeclaims",
        "persistentvolumes",
        "nodes",
        "jobs",
        "cronjobs",
        "ingresses",
        "networkpolicies",
        "serviceaccounts",
    }
)
_APPROVED = frozenset({"approved", "scheduled", "implemented", "in_progress", "in-progress", "implement", "authorized"})
_SENSITIVE_BUCKET = re.compile(
    r"(?i)finance|prod|customer|pii|payroll|backup|export|secret|hr|billing|confidential|private"
)
_SCHEDULER = re.compile(r"(?i)(?:^|[\\/])(?:cron|crond|anacron|atd|systemd|taskeng\.exe|taskhostw\.exe|launchd)$")
#: Command kinds a scheduled job legitimately runs (backups, exports): explained when scheduled.
_ROUTINE_WHEN_SCHEDULED = frozenset({"database export", "data upload"})
_COMMANDS: tuple[tuple[str, Severity, re.Pattern[str]], ...] = (
    ("reverse shell", Severity.HIGH, re.compile(
        r"(?i)/dev/tcp/|\bnc(?:at)?\b[^|]*\s-e\s|bash\s+-i\s*>&|\bsh\s+-i\b.*>&|socat\b.*exec:|"
        r"python\d?\s+-c\s+.*socket.*connect")),
    ("download and execute", Severity.HIGH, re.compile(
        r"(?i)(?:curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|downloadstring\s*\(|"
        r"iex\s*\(\s*new-object|invoke-expression.*(?:http|downloadstring)|certutil(?:\.exe)?\s+.*-urlcache|"
        r"bitsadmin(?:\.exe)?\s+/transfer|mshta(?:\.exe)?\s+https?:|regsvr32(?:\.exe)?\s+/s\s+/n\s+/u\s+/i:https?")),
    ("credential dumping", Severity.HIGH, re.compile(
        r"(?i)mimikatz|sekurlsa|lsass(?:\.exe)?.*(?:dump|minidump)|procdump.*lsass|comsvcs\.dll.*minidump|"
        r"reg(?:\.exe)?\s+save\s+hklm\\\\?(?:sam|system|security)|ntdsutil.*ifm|/etc/shadow")),
    ("defense evasion", Severity.HIGH, re.compile(
        r"(?i)history\s+-c\b|unset\s+histfile|wevtutil(?:\.exe)?\s+cl\b|clear-eventlog|auditctl\s+-D\b|"
        r"setenforce\s+0|set-mppreference\s+.*-disable|systemctl\s+(?:stop|disable)\s+(?:auditd|falcon|wazuh)|"
        r"iptables\s+-F\b")),
    ("data upload", Severity.MEDIUM, re.compile(
        r"(?i)\bcurl\b[^|;]*(?:\s-T\s|--upload-file|\s-F\s+\S*@|--data-binary\s+@|\s-d\s+@)|"
        r"\bwget\b[^|;]*--post-file|\brclone\b\s+(?:copy|sync)\b|\bscp\b\s+\S+\s+\S+@[\w.-]+:")),
    ("database export", Severity.MEDIUM, re.compile(
        r"(?i)\bcopy\b.+\bto\s+'|\bpg_dump(?:all)?\b|\bmysqldump\b|\bmongodump\b|\binto\s+outfile\b|"
        r"\bbcp\b.+\bout\b|\bexpdp\b")),
    ("credential discovery", Severity.MEDIUM, re.compile(
        r"(?i)\bfind\b.*-i?name\s+['\"]?\*?\.?(?:env|pem|key|kdbx|ovpn|ppk)\b|"
        r"\bgrep\b.*-[a-z]*r[a-z]*\b.*\b(?:password|passwd|secret|token|api[_-]?key)\b|"
        r"\b(?:cat|less|more|head|tail|type|get-content)\b\s+\S*(?:\.env\b|id_(?:rsa|ed25519|ecdsa)\b|"
        r"\.aws/credentials|\.git-credentials|\.pgpass|\.netrc|kubeconfig)")),
    ("control bypass", Severity.MEDIUM, re.compile(
        r"(?i)--(?:skip|no|bypass)[-_](?:review|verify|approval|checks?|tests?|gates?|signing)\b|--force[-_]deploy\b")),
    ("encoded PowerShell", Severity.MEDIUM, re.compile(
        r"(?i)powershell(?:\.exe)?\b.*\s-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}")),
    ("persistence", Severity.MEDIUM, re.compile(
        r"(?i)schtasks(?:\.exe)?\s+/create|reg(?:\.exe)?\s+add\s+.*\\\\currentversion\\\\run|"
        r"crontab\s+-[lr]?\s*<|>>\s*/etc/crontab|authorized_keys")),
)  # fmt: skip


# --------------------------------------------------------------------------- results


class Explained(RafModel):
    rule: str
    title: str
    reason: str
    events: list[str] = Field(default_factory=list)
    at: datetime | None = None


class DetectedIncident(RafModel):
    id: str
    name: str
    title: str
    severity: Severity
    confidence: float
    findings: list[str]
    events: int
    start: datetime | None = None
    end: datetime | None = None
    narrative: list[str] = Field(default_factory=list)
    existing: bool = False  # the chain matches an incident that was already in the workspace


class DetectionReport(RafModel):
    scope: str
    generated_at: datetime
    events_examined: int
    findings: list[Finding] = Field(default_factory=list)
    explained: list[Explained] = Field(default_factory=list)
    incidents: list[DetectedIncident] = Field(default_factory=list)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_rule: dict[str, int] = Field(default_factory=dict)
    created: int = 0
    updated: int = 0
    resolved: int = 0
    notes: list[str] = Field(default_factory=list)


@dataclass(slots=True)
class Detection:
    rule: str
    subject: str  # stable identity of what was detected (finding ID)
    title: str
    severity: Severity
    confidence: float
    description: str
    events: list[str]
    affected: list[str]
    pivots: set[str]
    start: datetime
    end: datetime
    explanation: list[tuple[str, str]] = field(default_factory=list)
    stage: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- event view


@dataclass(slots=True)
class Ev:
    id: str
    ts: datetime
    type: str
    action: str
    outcome: str | None
    actor: str | None
    target: str | None
    attrs: dict[str, Any]
    roles: dict[str, list[str]]
    message: str
    incidents: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO

    @classmethod
    def of(cls, event: Event) -> Ev:
        roles: dict[str, list[str]] = {}
        for ref in event.objects:
            roles.setdefault(ref.role, []).append(ref.object_id)
        return cls(
            event.id,
            event.timestamp,
            event.event_type,
            event.action,
            event.outcome,
            event.actor,
            event.target,
            event.attributes or {},
            roles,
            event.message or "",
            list(event.incidents or []),
            event.severity,
        )

    def first(self, role: str) -> str | None:
        ids = self.roles.get(role)
        return ids[0] if ids else None

    def text(self, key: str) -> str | None:
        value = self.attrs.get(key)
        return None if value in (None, "") else str(value)

    def number(self, *keys: str) -> float | None:
        for key in keys:
            value = self.attrs.get(key)
            if isinstance(value, bool) or value is None:
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        return None

    @property
    def src_ip(self) -> str | None:
        value = self.text("src_ip")
        if value:
            return value
        actor = self.actor or ""
        return actor[3:] if actor.startswith("ip:") else None


def _key_name(object_id_: str | None) -> str:
    if not object_id_:
        return "-"
    return object_id_.split(":", 1)[1] if ":" in object_id_ else object_id_


def _size(value: float) -> str:
    if value >= 1000 * _MB:
        return f"{value / (1000 * _MB):.1f} GB"
    if value >= _MB:
        return f"{value / _MB:.1f} MB"
    if value >= 1000:
        return f"{value / 1000:.1f} kB"
    return f"{int(value)} B"


def _clock(ts: datetime) -> str:
    """``2026-10-07 20:06:12.126`` (UTC, milliseconds)."""
    text = (format_ts(ts) or "").replace("T", " ").replace("Z", "")
    return text[:23] if "." in text else text


def _span(start: datetime, end: datetime) -> str:
    seconds = (end - start).total_seconds()
    if seconds < 1:
        return "in under a second"
    if seconds < 120:
        return f"in {int(seconds)} s"
    if seconds < 7200:
        return f"in {int(seconds // 60)} min"
    return f"in {seconds / 3600:.1f} h"


def _bounded_append(store: dict[Any, list[Any]], key: Any, item: Any) -> None:
    if key not in store and len(store) >= _KEY_CAP:
        return
    items = store[key]
    if len(items) < _LIST_CAP:
        items.append(item)


def _max_window(times: Sequence[datetime], window: timedelta) -> tuple[int, int, int]:
    """Largest number of ``times`` (sorted) inside any ``window``: (count, first index, last index)."""
    best = (0, 0, 0)
    queue: deque[int] = deque()
    for index, ts in enumerate(times):
        queue.append(index)
        while times[queue[0]] < ts - window:
            queue.popleft()
        if len(queue) > best[0]:
            best = (len(queue), queue[0], index)
    return best


# --------------------------------------------------------------------------- collection


class _Collector:
    """One pass over the events: compact, bounded state for every rule."""

    def __init__(self, internal: tuple[Any, ...]) -> None:
        self.internal = internal
        self.examined = 0
        self.event_ids: set[str] = set()
        self.http_probes: dict[str, list[tuple[datetime, str, int | None, str]]] = defaultdict(list)
        self.http_buckets: dict[tuple[str, int], list[int]] = {}  # (ip, 15-min bucket) -> [total, errors]
        self.http_error_paths: dict[tuple[str, int], set[str]] = defaultdict(set)
        self.artifact_http: list[Ev] = []
        self.app_downloads: list[Ev] = []
        self.manifests: list[Ev] = []
        self.by_request: dict[str, list[Ev]] = defaultdict(list)
        self.cloud_total = 0
        self.cloud_internal = 0
        self.cloud_calls: dict[tuple[str, str], list[Ev]] = defaultdict(list)  # (actor, public ip)
        self.actor_internal: dict[str, list[Ev]] = defaultdict(list)  # actor -> calls from internal addresses
        self.storage: dict[tuple[str, str, str], list[Ev]] = defaultdict(list)  # (actor, bucket, ip)
        self.storage_bytes: dict[str, float] = {}  # request id -> bytes sent (server access logs)
        self.iam: list[Ev] = []
        self.flow_sizes: list[float] = []
        self.big_flows: list[tuple[float, Ev]] = []
        self.failures_by_actor: dict[str, list[Ev]] = defaultdict(list)
        self.failures_by_src: dict[str, list[Ev]] = defaultdict(list)
        self.logins_by_actor: dict[str, list[Ev]] = defaultdict(list)
        self.mfa_by_actor: dict[str, list[Ev]] = defaultdict(list)
        self.changes: list[Ev] = []
        self.destructive: list[Ev] = []
        self.tamper: list[Ev] = []
        self.commands: list[tuple[str, Severity, Ev]] = []
        self.sql: list[Ev] = []
        self.dns_long: dict[tuple[str, str], list[Ev]] = defaultdict(list)
        self.exports: list[Ev] = []
        self.secret_files: list[Ev] = []
        self.scheduled: dict[str, list[Ev]] = defaultdict(list)  # host -> processes started by a scheduler
        self.file_writes: dict[str, list[Ev]] = defaultdict(list)  # host -> large files written
        self.alerts: list[Ev] = []
        self.dns_answers: dict[str, list[Ev]] = defaultdict(list)  # answer IP -> queries
        self.first_ts: datetime | None = None
        self.last_ts: datetime | None = None
        self.capped = False

    def scope(self, address: str | None) -> str | None:
        return ip_scope(address, self.internal) if address else None

    def observe(self, ev: Ev) -> None:
        self.examined += 1
        if self.first_ts is None or ev.ts < self.first_ts:
            self.first_ts = ev.ts
        if self.last_ts is None or ev.ts > self.last_ts:
            self.last_ts = ev.ts
        alert = ev.type == "alert" or ev.type.startswith("alert.")
        if alert and ev.severity.rank >= Severity.MEDIUM.rank and len(self.alerts) < _LIST_CAP:
            self.alerts.append(ev)
        if len(self.event_ids) < 2_000_000:
            self.event_ids.add(ev.id)
        handler = _HANDLERS.get(ev.type)
        if ev.attrs.get("platform") in _CLOUD_PLATFORMS and ev.type.startswith(("cloud.", "iam.", "auth.")):
            self._cloud_use(ev)
        if handler is not None:
            handler(self, ev)
        elif ev.type.startswith("iam."):
            if len(self.iam) < _LIST_CAP:
                self.iam.append(ev)
        elif ev.type.startswith("network."):
            self._flow(ev)
        elif ev.type == "log.audit_log_cleared" and len(self.tamper) < _LIST_CAP:
            self.tamper.append(ev)
        if ev.attrs.get("entries") and len(self.manifests) < _LIST_CAP:
            self.manifests.append(ev)
        request = ev.text("request_id")
        interesting = ev.type in ("http.request", "file.read", "file.create") or ev.attrs.get("entries")
        if request and interesting and len(self.by_request) < _KEY_CAP:
            self.by_request[request].append(ev)

    # -- web
    def _http(self, ev: Ev) -> None:
        src = ev.src_ip
        if not src:
            return
        path = ev.text("path") or ""
        status = ev.number("status")
        code = int(status) if status is not None else None
        bucket = int(ev.ts.timestamp() // 900)
        key = (src, bucket)
        if key in self.http_buckets or len(self.http_buckets) < _KEY_CAP:
            counts = self.http_buckets.setdefault(key, [0, 0])
            counts[0] += 1
            if code is not None and code >= 400:
                counts[1] += 1
                if len(self.http_error_paths[key]) < 64:
                    self.http_error_paths[key].add(path)
        if _PROBE_PATH.search(path):
            _bounded_append(self.http_probes, src, (ev.ts, path, code, ev.id))
        if (
            code is not None
            and 200 <= code < 300
            and _ARTIFACT_PATH.search(path)
            and (ev.text("method") or "GET").upper() == "GET"
            and (self.scope(src) == "public" or not ev.text("user"))
            and len(self.artifact_http) < _LIST_CAP
        ):
            self.artifact_http.append(ev)

    # -- files and storage
    def _file(self, ev: Ev) -> None:
        if ev.type in ("file.read", "file.modify", "file.create") and not ev.text("bucket") and not ev.text("cache"):
            path = str((ev.target or "").split("|", 1)[-1] if ev.target and ev.target.startswith("file:") else "")
            if path and secret_bearing(path) and len(self.secret_files) < _LIST_CAP:
                self.secret_files.append(ev)
        written = ev.number("size", "bytes")
        host = ev.first("host")
        if ev.type == "file.create" and host and written is not None and written >= _MB and not ev.text("bucket"):
            _bounded_append(self.file_writes, host, ev)
        bucket = ev.text("bucket")
        if bucket:
            src = ev.src_ip or "-"
            _bounded_append(self.storage, (ev.actor or "-", bucket, src), ev)
            sent = ev.number("bytes_sent")
            request = ev.text("request_id")
            if sent is not None and request and len(self.storage_bytes) < _KEY_CAP:
                self.storage_bytes[request] = sent
            return
        actor_name = _key_name(ev.actor).lower()
        public = bool(_PUBLIC_LINK.search(str(ev.attrs.get("cache") or ""))) or actor_name in _ANONYMOUS
        if ev.type == "file.read" and public and len(self.app_downloads) < _LIST_CAP:
            self.app_downloads.append(ev)
        size = ev.number("bytes")
        if size is not None and size >= 100 * _MB and len(self.exports) < _LIST_CAP:
            self.exports.append(ev)

    # -- cloud
    def _cloud(self, ev: Ev) -> None:
        platform = ev.text("platform") or ""
        if platform == "kubernetes":
            verb = (ev.text("verb") or "").lower()
            if (
                verb in _K8S_DESTRUCTIVE
                and (ev.text("k8s_resource") or "") in _K8S_RESOURCES
                and len(self.destructive) < _LIST_CAP
            ):
                self.destructive.append(ev)
            return
        api = ev.text("api") or ev.action
        if api in _TAMPER_APIS:
            self.tamper.append(ev)
        elif _DESTRUCTIVE_APIS.match(api or "") and len(self.destructive) < _LIST_CAP:
            self.destructive.append(ev)
        if api in _PERSISTENCE_APIS and len(self.iam) < _LIST_CAP:
            self.iam.append(ev)
        bucket = ev.text("bucket")
        if bucket and api in _READ_APIS:
            _bounded_append(self.storage, (ev.actor or "-", bucket, ev.src_ip or "-"), ev)

    def _cloud_use(self, ev: Ev) -> None:
        """Who calls the cloud control plane from where (the baseline of the credential rule).
        Storage access log lines repeat calls the audit trail records, so they are not counted."""
        if ev.text("operation") or not ev.actor:
            return
        src = ev.src_ip
        scope = self.scope(src)
        if scope is None or src is None:
            return
        self.cloud_total += 1
        if scope in _INTERNAL_SCOPES:
            self.cloud_internal += 1
            _bounded_append(self.actor_internal, ev.actor, ev)
        elif scope == "public":
            _bounded_append(self.cloud_calls, (ev.actor, src), ev)

    # -- network
    def _flow(self, ev: Ev) -> None:
        size = ev.number("bytes")
        if size is None:
            parts = [ev.number("bytes_in"), ev.number("bytes_out")]
            present = [p for p in parts if p is not None]
            size = sum(present) if present else None
        if size is None:
            return
        if len(self.flow_sizes) < 500_000:
            self.flow_sizes.append(size)
        if size >= 10 * _MB and len(self.big_flows) < _LIST_CAP:
            self.big_flows.append((size, ev))

    # -- authentication
    def _auth_failure(self, ev: Ev) -> None:
        if ev.actor:
            _bounded_append(self.failures_by_actor, ev.actor, ev)
        if ev.src_ip:
            _bounded_append(self.failures_by_src, ev.src_ip, ev)

    def _auth_login(self, ev: Ev) -> None:
        if ev.actor:
            _bounded_append(self.logins_by_actor, ev.actor, ev)

    def _auth_mfa(self, ev: Ev) -> None:
        if ev.actor:
            _bounded_append(self.mfa_by_actor, ev.actor, ev)

    # -- other
    def _change(self, ev: Ev) -> None:
        if len(self.changes) < _LIST_CAP:
            self.changes.append(ev)

    def _process(self, ev: Ev) -> None:
        host = ev.first("host")
        if host and (ev.attrs.get("scheduler") or _SCHEDULER.search(str(ev.attrs.get("parent_image") or ""))):
            _bounded_append(self.scheduled, host, ev)
        command = str(ev.attrs.get("command_line") or ev.attrs.get("command") or "")
        if not command:
            return
        for label, severity, pattern in _COMMANDS:
            if pattern.search(command):
                if len(self.commands) < _LIST_CAP:
                    self.commands.append((label, severity, ev))
                return

    def _db(self, ev: Ev) -> None:
        if ev.attrs.get("sql_risk") and len(self.sql) < _LIST_CAP:
            self.sql.append(ev)

    def _dns(self, ev: Ev) -> None:
        for answer in ev.roles.get("answer", []):
            address = _key_name(answer)
            if len(self.dns_answers[address]) < 50 and (
                address in self.dns_answers or len(self.dns_answers) < _KEY_CAP
            ):
                self.dns_answers[address].append(ev)
        query = ev.text("query") or _key_name(ev.target)
        labels = query.rstrip(".").split(".")
        if len(labels) < 3:
            return
        longest = max(len(label) for label in labels[:-2])
        if longest < 30 and len(query) < 100:
            return
        base = ".".join(labels[-2:]).lower()
        client = ev.src_ip or ev.actor or "-"
        _bounded_append(self.dns_long, (client, base), ev)

    def _privilege(self, ev: Ev) -> None:
        self._process(ev)


_HANDLERS = {
    "http.request": _Collector._http,
    "file.read": _Collector._file,
    "file.create": _Collector._file,
    "file.delete": _Collector._file,
    "cloud.api": _Collector._cloud,
    "network.flow": _Collector._flow,
    "network.connection": _Collector._flow,
    "auth.failure": _Collector._auth_failure,
    "auth.login": _Collector._auth_login,
    "auth.mfa": _Collector._auth_mfa,
    "change.record": _Collector._change,
    "process.start": _Collector._process,
    "auth.privilege": _Collector._privilege,
    "db.query": _Collector._db,
    "dns.query": _Collector._dns,
}


# --------------------------------------------------------------------------- the engine


class DetectionEngine:
    def __init__(self, ctx: RafContext, scope_label: str) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.scope_label = scope_label
        raw = str(ctx.settings.get("detect.internal_networks") or "")
        self.internal = parse_networks(raw.replace(";", ",").split(","))
        self.c = _Collector(self.internal)
        self.detections: list[Detection] = []
        self.explained: list[Explained] = []
        self._names: dict[str, str] = {}
        self._hosts: dict[str, list[str]] = {}
        self.event_incidents: dict[str, list[str]] = {}
        self.flagged_actors: dict[str, Detection] = {}
        self.flagged_ips: set[str] = set()

    # -- helpers
    def name(self, oid: str | None) -> str:
        if not oid:
            return "-"
        if oid not in self._names:
            obj = self.store.objects.get(oid)
            self._names[oid] = obj.name if obj is not None else _key_name(oid)
        return self._names[oid]

    def public(self, address: str | None) -> bool:
        return self.c.scope(address) == "public"

    def scheduled_job(self, host: str, before: datetime, size: float | None = None) -> tuple[Ev, Ev | None] | None:
        """A scheduler-started process on ``host`` in the hour before ``before`` (and, with ``size``, a
        file of about that size it wrote): the context that makes an export or a transfer routine."""
        jobs = [e for e in self.c.scheduled.get(host, []) if before - timedelta(hours=1) <= e.ts <= before]
        if not jobs:
            return None
        job = jobs[-1]
        if size is None:
            return job, None
        for written in self.c.file_writes.get(host, []):
            amount = written.number("size", "bytes") or 0
            if job.ts <= written.ts <= before and amount and abs(amount - size) <= 0.05 * size:
                return job, written
        return None

    def hosts_of(self, address: str | None) -> list[str]:
        """Hosts that the graph knows hold ``address`` (HAS_ADDRESS), for correlating by machine."""
        if not address:
            return []
        oid = object_id(ObjectType.IP, address)
        if oid not in self._hosts:
            edges = self.store.relationships.edges([oid], direction="in", types=["HAS_ADDRESS"])
            self._hosts[oid] = sorted({e.source_object for e in edges})[:5]
        return self._hosts[oid]

    def add(self, detection: Detection) -> Detection:
        detection.events = list(dict.fromkeys(detection.events))[:_EVIDENCE_CAP]
        detection.affected = list(dict.fromkeys(a for a in detection.affected if a))
        detection.pivots = {p for p in detection.pivots if p}
        self.detections.append(detection)
        return detection

    # -- run
    def collect(self, events: Iterable[Event]) -> None:
        for event in events:
            view = Ev.of(event)
            if view.incidents and len(self.event_incidents) < _KEY_CAP:
                self.event_incidents[view.id] = view.incidents
            self.c.observe(view)

    def detect(self) -> None:
        self._web_recon()
        self._exposed_artifacts()
        self._cloud_credentials()
        self._bulk_storage()
        self._persistence()
        self._large_transfers()
        self._authentication()
        self._new_signins()
        self._destructive()
        self._tampering()
        self._credential_access()
        self._service_accounts()
        self._alerts()
        self._commands()
        self._sql()
        self._dns_tunneling()
        self._exports()

    # ------------------------------------------------------------------ web
    def _web_recon(self) -> None:
        sources = set(self.c.http_probes)
        for (src, _bucket), (total, errors) in self.c.http_buckets.items():
            if errors >= 30 and errors / max(total, 1) >= 0.7 and len(self.c.http_error_paths[(src, _bucket)]) >= 10:
                sources.add(src)
        for src in sorted(sources):
            probes = sorted(self.c.http_probes.get(src, []))
            count, lo, hi = _max_window([p[0] for p in probes], timedelta(minutes=15))
            bursts = [
                (bucket, counts)
                for (ip_, bucket), counts in self.c.http_buckets.items()
                if ip_ == src and counts[1] >= 30 and counts[1] / max(counts[0], 1) >= 0.7
            ]
            if count < 5 and not bursts:
                continue
            window = probes[lo : hi + 1] if count >= 5 else probes
            answered = [p for p in window if p[2] is not None and p[2] < 400]
            paths = Counter(p[1] for p in window)
            start = window[0][0] if window else datetime.fromtimestamp(min(b for b, _c in bursts) * 900, UTC)
            end = window[-1][0] if window else start
            severity = Severity.MEDIUM if answered else Severity.LOW
            listed = ", ".join(path for path, _n in paths.most_common(5))
            title = (
                f"Web reconnaissance from {src}: {len(window)} probes of sensitive paths ({listed}) {_span(start, end)}"
            )
            title += f"; {len(answered)} answered" if answered else "; all refused"
            errors_total = sum(c[1] for _b, c in bursts)
            self.add(
                Detection(
                    rule="web-recon",
                    subject=f"{src}|{start.date()}",
                    title=title,
                    severity=severity,
                    confidence=0.8,
                    description=(
                        f"{src} ({self.c.scope(src) or 'unknown'} address) requested {len(window)} well-known "
                        f"sensitive paths between {_clock(start)} and {_clock(end)}: "
                        + ", ".join(f"{p} ({n}x)" for p, n in paths.most_common(8))
                        + ". "
                        + (
                            f"{len(answered)} request(s) were answered with a non-error status: check those paths."
                            if answered
                            else "Every probe was refused (4xx): no evidence that anything was found."
                        )
                        + (f" Client-error bursts: {errors_total} errors in 15-minute windows." if bursts else "")
                    ),
                    events=[p[3] for p in window],
                    affected=[object_id(ObjectType.IP, src)],
                    pivots={object_id(ObjectType.IP, src)},
                    start=start,
                    end=end,
                    explanation=[
                        ("probes", f"{len(window)} requests to paths such as {listed}"),
                        ("outcome", "answered" if answered else "all refused with 4xx"),
                    ],
                    stage="reconnaissance",
                    metadata={"src_ip": src, "probes": len(window), "answered": len(answered)},
                )
            )

    def _artifact_contents(self, evs: Sequence[Ev]) -> tuple[list[str], list[str], list[str]]:
        """Entries and credential-bearing entries of the artifact, from manifest events joined by
        request ID or path, and the manifest event IDs."""
        requests = {e.text("request_id") for e in evs if e.text("request_id")}
        paths = {(e.text("path") or "").lstrip("/") for e in evs if e.text("path")}
        entries: list[str] = []
        secret: list[str] = []
        sources: list[str] = []
        for manifest in self.c.manifests:
            path = (manifest.text("path") or "").lstrip("/")
            joined = manifest.text("request_id") in requests or any(
                p and path and (p.endswith(path) or path.endswith(p)) for p in paths
            )
            if not joined:
                continue
            sources.append(manifest.id)
            for entry in manifest.attrs.get("entries") or []:
                if str(entry) not in entries:
                    entries.append(str(entry))
            for entry in manifest.attrs.get("secret_entries") or []:
                if str(entry) not in secret:
                    secret.append(str(entry))
        return entries, secret, sources

    def _exposed_artifacts(self) -> None:
        groups: dict[str, list[Ev]] = {}
        for ev in self.c.app_downloads + self.c.artifact_http:
            request = ev.text("request_id")
            key = f"rid|{request}" if request else f"ev|{ev.id}"
            groups.setdefault(key, []).append(ev)
        # requests that reached the application through the web tier share their ID: one download
        for key, evs in list(groups.items()):
            request = key.split("|", 1)[1] if key.startswith("rid|") else None
            if request:
                for other in self.c.by_request.get(request, []):
                    if other not in evs and other.type in ("http.request", "file.read"):
                        evs.append(other)
        merged: dict[tuple[str, str], list[Ev]] = {}
        for evs in groups.values():
            web = next((e for e in evs if e.type == "http.request"), None)
            app = next((e for e in evs if e.type == "file.read"), None)
            src = (web.src_ip if web else None) or (app.src_ip if app else None) or "-"
            path = ((app.text("path") if app else None) or (web.text("path") if web else "") or "").lstrip("/")
            merged.setdefault((path, src), []).extend(evs)
        for (path, src), evs in sorted(merged.items()):
            evs = sorted({e.id: e for e in evs}.values(), key=lambda e: e.ts)
            entries, secret, manifest_ids = self._artifact_contents(evs)
            web = next((e for e in evs if e.type == "http.request"), None)
            app = next((e for e in evs if e.type == "file.read"), None)
            link = str((app.attrs.get("cache") if app else None) or "")
            anonymous = app is not None and _key_name(app.actor).lower() in _ANONYMOUS
            public_src = self.public(src)
            if not (public_src or anonymous or _PUBLIC_LINK.search(link)):
                continue
            severity = Severity.HIGH if secret else Severity.MEDIUM
            confidence = 0.85 if secret else 0.7
            size = (app.number("bytes") if app else None) or (web.number("bytes") if web else None)
            name = path.rsplit("/", 1)[-1] or path
            how = ", ".join(
                x
                for x in (
                    f"public link ({link})" if link else "",
                    "no authentication" if anonymous or (web and not web.text("user")) else "",
                    f"from public address {src}" if public_src else "",
                )
                if x
            )
            title = f"Sensitive artifact served publicly: {name} downloaded by {src}"
            if secret:
                title += f"; it contains {', '.join(secret[:4])}"
            affected = [e.target for e in evs if e.target] + [object_id(ObjectType.IP, src) if src != "-" else ""]
            services = [e.first("service") for e in evs if e.first("service")]
            files = [e.target for e in evs if e.type == "file.read" and e.target]
            self.add(
                Detection(
                    rule="exposed-artifact",
                    subject=f"{path}|{src}",
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    description=(
                        f"{path} was downloaded at {_clock(evs[0].ts)} by {src}"
                        + (f" ({_size(size)})" if size else "")
                        + (f" via {how}" if how else "")
                        + "."
                        + (f" Its manifest lists {', '.join(entries)}." if entries else "")
                        + (
                            (
                                f" {secret[0]} conventionally holds credentials: treat them as disclosed."
                                if len(secret) == 1
                                else f" {', '.join(secret)} conventionally hold credentials: treat them as disclosed."
                            )
                            if secret
                            else ""
                        )
                    ),
                    events=[e.id for e in evs] + manifest_ids,
                    affected=affected + [s for s in services if s],
                    pivots={object_id(ObjectType.IP, src) if src != "-" else "", *files},
                    start=evs[0].ts,
                    end=evs[-1].ts,
                    explanation=[
                        ("exposure", how or "served without authentication"),
                        ("contents", ", ".join(entries) if entries else "unknown"),
                    ]
                    + ([("credential files", ", ".join(secret))] if secret else []),
                    stage="exposure",
                    metadata={"src_ip": src, "path": path, "secret_entries": secret, "entries": entries},
                )
            )
            if public_src:
                self.flagged_ips.add(src)

    # ------------------------------------------------------------------ cloud
    def _cloud_credentials(self) -> None:
        total, internal = self.c.cloud_total, self.c.cloud_internal
        mostly_internal = total >= 20 and internal / total >= 0.8
        for (actor, src), calls in sorted(self.c.cloud_calls.items()):
            calls.sort(key=lambda e: e.ts)
            credentials = sorted({c for e in calls for c in e.roles.get("credential", [])})
            long_term = any(self.name(c).startswith("AKIA") for c in credentials)
            name = self.name(actor)
            service_like = bool(_SERVICE_IDENTITY.search(name)) or actor.startswith("role:")
            internal_uses = sorted(self.c.actor_internal.get(actor, []), key=lambda e: e.ts)
            seen_internal = bool(internal_uses)
            same_key = [e for e in internal_uses if set(e.roles.get("credential", [])) & set(credentials)]
            if not (mostly_internal or seen_internal or long_term or service_like or src in self.flagged_ips):
                continue
            apis = Counter(str(e.text("api") or e.action) for e in calls)
            failed = [e for e in calls if e.outcome == "failure"]
            discovery = [a for a in apis if a in _DISCOVERY_APIS]
            severity = Severity.HIGH if (long_term or service_like or seen_internal) else Severity.MEDIUM
            confidence = 0.75 + (0.1 if discovery else 0.0) + (0.05 if failed else 0.0)
            confidence += 0.05 if src in self.flagged_ips else 0.0
            api_text = ", ".join(f"{a} x{n}" if n > 1 else a for a, n in apis.most_common(8))
            reasons = []
            if mostly_internal:
                reasons.append(f"{internal:,} of {total:,} cloud calls in scope come from internal addresses")
            if seen_internal:
                example = same_key[0] if same_key else internal_uses[0]
                reasons.append(
                    f"{name} also calls from internal addresses ({len(internal_uses)} call(s), e.g. "
                    f"{example.src_ip} at {_clock(example.ts)})"
                    + (
                        f"; {len(same_key)} of them with the same access key: one credential used from two networks"
                        if same_key
                        else ""
                    )
                )
            if long_term:
                reasons.append(
                    "signed with a long-term access key (" + ", ".join(self.name(c) for c in credentials) + ")"
                )
            if service_like:
                reasons.append(f"{name} is a service identity")
            if src in self.flagged_ips:
                reasons.append(f"{src} also downloaded an exposed artifact")
            detection = self.add(
                Detection(
                    rule="cloud-credential-public",
                    subject=f"{actor}|{src}",
                    title=f"Cloud identity {name} used from public address {src}: {len(calls)} API call(s) "
                    f"({api_text})" + (f", {len(failed)} denied" if failed else ""),
                    severity=severity,
                    confidence=min(confidence, 0.95),
                    description=(
                        f"Between {_clock(calls[0].ts)} and {_clock(calls[-1].ts)}, {len(calls)} call(s) signed by "
                        f"{name} came from {src}: {api_text}. "
                        + "; ".join(reasons)
                        + "."
                        + (f" Discovery calls first: {', '.join(discovery)}." if discovery else "")
                    ),
                    events=[e.id for e in calls] + [e.id for e in same_key[:3]],
                    affected=[actor, object_id(ObjectType.IP, src), *credentials],
                    pivots={actor, object_id(ObjectType.IP, src), *credentials},
                    start=calls[0].ts,
                    end=calls[-1].ts,
                    explanation=[("why", r) for r in reasons] + [("calls", api_text)],
                    stage="credential-misuse",
                    metadata={
                        "src_ip": src,
                        "apis": dict(apis),
                        "credentials": credentials,
                        "internal_uses": len(internal_uses),
                        "same_key_internal_uses": len(same_key),
                    },
                )
            )
            self.flagged_actors[actor] = detection
            self.flagged_ips.add(src)

    def _bulk_storage(self) -> None:
        for (actor, bucket, src), evs in sorted(self.c.storage.items()):
            evs.sort(key=lambda e: e.ts)
            requests: dict[str, Ev] = {}
            objects: set[str] = set()
            listed: set[str] = set()
            size = 0.0
            for ev in evs:
                request = ev.text("request_id") or ev.id
                key = ev.text("object_key")
                api = str(ev.text("api") or ev.text("operation") or ev.action)
                if key and ("GetObject" in api or "GET.OBJECT" in api or ev.type == "file.read"):
                    objects.add(key)
                elif ev.text("prefix") or "List" in api or "GET.BUCKET" in api:
                    listed.add(ev.text("prefix") or key or "/")
                if request not in requests:
                    requests[request] = ev
                    sent = self.c.storage_bytes.get(request)
                    if sent is None:
                        sent = ev.number("bytes_sent", "bytes_out")
                    size += sent or 0
            flagged = actor in self.flagged_actors
            public_src = self.public(src)
            if not (len(objects) >= 5 or size >= 100 * _MB):
                continue
            if not (public_src or flagged or size >= 1024 * _MB):
                continue
            sensitive = bool(_SENSITIVE_BUCKET.search(bucket))
            if public_src and (size >= 100 * _MB or sensitive):
                severity = Severity.CRITICAL
            elif public_src or flagged:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM
            prefixes = sorted({k.rsplit("/", 1)[0] + "/" for k in objects if "/" in k} | listed)
            start, end = evs[0].ts, evs[-1].ts
            name = self.name(actor)
            bucket_id = object_id(ObjectType.CLOUD_RESOURCE, f"aws/s3/{bucket}")
            self.add(
                Detection(
                    rule="bulk-storage-read",
                    subject=f"{actor}|{bucket}|{src}",
                    title=f"Bulk read from bucket {bucket} by {name} from {src}: {len(objects)} object(s), "
                    f"{_size(size)}" + (f" ({', '.join(prefixes[:2])})" if prefixes else ""),
                    severity=severity,
                    confidence=0.85 if (public_src or flagged) else 0.65,
                    description=(
                        f"{name} read {len(objects)} object(s) totalling {_size(size)} from {bucket} "
                        f"{_span(start, end)} ({_clock(start)} - {_clock(end)}), from {src}"
                        + (" (a public address)" if public_src else "")
                        + "."
                        + (f" Listed first: {', '.join(sorted(listed)[:3])}." if listed else "")
                        + (" The bucket name suggests sensitive data." if sensitive else "")
                        + (f" The identity is flagged: {self.flagged_actors[actor].title}." if flagged else "")
                        + " Sizes come from the storage access logs where they are present."
                    ),
                    events=[e.id for e in evs],
                    affected=[
                        actor,
                        bucket_id,
                        object_id(ObjectType.IP, src) if src != "-" else "",
                        *sorted({e.first("object") or (e.target or "") for e in evs if e.type == "file.read"} - {""})[
                            :20
                        ],
                    ],
                    pivots={actor, bucket_id, object_id(ObjectType.IP, src) if src != "-" else ""},
                    start=start,
                    end=end,
                    explanation=[
                        ("volume", f"{len(objects)} objects, {_size(size)}"),
                        ("source", f"{src} ({self.c.scope(src) or 'unknown'})"),
                    ],
                    stage="collection",
                    metadata={"src_ip": src, "bucket": bucket, "objects": len(objects), "bytes": int(size)},
                )
            )

    def _persistence(self) -> None:
        for ev in sorted(self.c.iam, key=lambda e: e.ts):
            api = str(ev.text("api") or ev.action)
            src = ev.src_ip
            actor = ev.actor
            if not actor:
                continue
            flagged = actor in self.flagged_actors
            public_src = self.public(src)
            name = self.name(actor)
            service_like = bool(_SERVICE_IDENTITY.search(name))
            failed = ev.outcome == "failure"
            if not (public_src or flagged or service_like or failed):
                continue
            if not (ev.type.startswith("iam.") or api in _PERSISTENCE_APIS):
                continue
            if failed:
                severity = Severity.MEDIUM
            elif public_src and flagged:
                severity = Severity.CRITICAL
            else:
                severity = Severity.HIGH
            target = self.name(ev.target) if ev.target and ev.target != actor else "itself"
            error = ev.text("error_code")
            self.add(
                Detection(
                    rule="cloud-persistence",
                    subject=f"{actor}|{api}|{ev.target}|{ev.ts.date()}",
                    title=(
                        f"Persistence attempt: {name} called {api} for {target}"
                        if failed
                        else f"Persistence: {name} called {api} for {target}"
                    )
                    + (f" from {src}" if src else "")
                    + (f" - denied ({error})" if failed and error else " - denied" if failed else ""),
                    severity=severity,
                    confidence=0.85 if (flagged or public_src) else 0.65,
                    description=(
                        f"At {_clock(ev.ts)} {name} called {api} for {target}"
                        + (f" from {src}" + (" (public)" if public_src else "") if src else "")
                        + (f"; the call failed with {error}, so nothing was created" if failed else "; it succeeded")
                        + "."
                        + (f" The identity is flagged: {self.flagged_actors[actor].title}." if flagged else "")
                    ),
                    events=[ev.id],
                    affected=[actor, ev.target or "", object_id(ObjectType.IP, src) if src else ""],
                    pivots={actor, object_id(ObjectType.IP, src) if src else ""},
                    start=ev.ts,
                    end=ev.ts,
                    explanation=[("call", f"{api} -> {'denied' if failed else 'success'}")],
                    stage="persistence",
                    metadata={"api": api, "outcome": ev.outcome, "error_code": error, "src_ip": src},
                )
            )

    # ------------------------------------------------------------------ network
    def _large_transfers(self) -> None:
        sizes = sorted(self.c.flow_sizes)
        if not self.c.big_flows:
            return
        if len(sizes) >= 30:
            p90 = sizes[min(len(sizes) - 1, int(len(sizes) * 0.9))]
            routine = [s for s in sizes if s < 10 * _MB] or sizes
            largest_routine = max(routine)
            threshold = max(10 * _MB, 20 * p90)
        else:
            largest_routine = 0.0
            threshold = 100 * _MB
        storage = {d.metadata.get("src_ip"): d for d in self.detections if d.rule == "bulk-storage-read"}
        for size, ev in sorted(self.c.big_flows, key=lambda x: x[1].ts):
            if size < threshold:
                continue
            src, dst = ev.text("src_ip") or _key_name(ev.actor), ev.text("dst_ip") or _key_name(ev.target)
            public = [a for a in (src, dst) if self.public(a)]
            source_hosts = [h for h in [ev.actor or "", *self.hosts_of(src)] if h.startswith("host:")]
            sent = ev.number("bytes_out") or size
            scheduled = next(
                (found for h in source_hosts if (found := self.scheduled_job(h, ev.ts, sent)) is not None), None
            )
            if scheduled is not None:
                job, written = scheduled
                self.explained.append(
                    Explained(
                        rule="large-transfer",
                        title=f"Transfer of {_size(sent)} from {src} to {dst}",
                        reason=f"follows the scheduled job '{str(job.attrs.get('command_line') or job.action)[:80]}' "
                        f"({_key_name(job.actor)}, started by {job.attrs.get('parent_image') or 'a scheduler'!s}) "
                        f"that wrote {self.name(written.target) if written else 'a file'} "
                        f"({_size(written.number('size', 'bytes') or 0) if written else '?'}) on "
                        f"{self.name(source_hosts[0])}: consistent with a scheduled backup or export",
                        events=[ev.id, job.id] + ([written.id] if written else []),
                        at=ev.ts,
                    )
                )
                continue
            severity = Severity.HIGH if public else Severity.MEDIUM
            ratio = size / largest_routine if largest_routine else None
            corroborates = [d for a in (src, dst) if (d := storage.get(a)) is not None]
            close = [
                d for d in corroborates if d.metadata.get("bytes") and abs(d.metadata["bytes"] - size) <= 0.02 * size
            ]
            port = ev.text("dst_port")
            proto = ev.text("protocol")
            duration = ev.number("duration_ms") or ((ev.number("duration_s") or 0) * 1000 or None)
            resolved = [
                q for a in public for q in self.c.dns_answers.get(a, []) if ev.ts - timedelta(hours=1) <= q.ts <= ev.ts
            ]
            domain = resolved[-1].text("query") or self.name(resolved[-1].target) if resolved else None
            endpoints = [ev.actor or "", *self.hosts_of(src)]
            self.add(
                Detection(
                    rule="large-transfer",
                    subject=f"{ev.id}",
                    title=f"Large transfer between {src} and {dst}"
                    + (f" ({domain})" if domain else "")
                    + f": {_size(size)}"
                    + (f" over {port}/{proto}" if port else "")
                    + (f" ({ratio:,.0f}x the largest routine flow)" if ratio and ratio >= 2 else ""),
                    severity=severity,
                    confidence=0.85 if close else 0.7,
                    description=(
                        f"At {_clock(ev.ts)} a flow {src} -> {dst} moved {_size(size)}"
                        + (f" in {duration / 1000:.0f} s" if duration else "")
                        + (f" (bytes in {_size(ev.number('bytes_in') or 0)}, out {_size(ev.number('bytes_out') or 0)})")
                        + "."
                        + (
                            f" The largest routine flow in scope is {_size(largest_routine)} "
                            f"(90th percentile {_size(sizes[min(len(sizes) - 1, int(len(sizes) * 0.9))])})."
                            if largest_routine
                            else ""
                        )
                        + (f" Public endpoint(s): {', '.join(public)}." if public else "")
                        + (
                            f" Its volume matches the bulk storage read by {close[0].metadata.get('src_ip')} "
                            f"({_size(close[0].metadata['bytes'])}) within 2%."
                            if close
                            else ""
                        )
                        + (f" Sensor: {ev.text('sensor')}." if ev.text("sensor") else "")
                        + (
                            f" The destination was resolved from {domain} at {_clock(resolved[-1].ts)}."
                            if domain
                            else ""
                        )
                    ),
                    events=[ev.id] + [q.id for q in resolved[-2:]],
                    affected=[object_id(ObjectType.IP, a) for a in (src, dst) if a and a != "-"] + endpoints,
                    pivots={object_id(ObjectType.IP, a) for a in public}
                    | {e for e in endpoints if e.startswith("host:")},
                    start=ev.ts,
                    end=ev.ts,
                    explanation=[("volume", _size(size)), ("baseline", f"threshold {_size(threshold)}")],
                    stage="exfiltration",
                    metadata={
                        "bytes": int(size),
                        "src_ip": src,
                        "dst_ip": dst,
                        "corroborates": [d.subject for d in close],
                    },
                )
            )

    # ------------------------------------------------------------------ authentication
    def _authentication(self) -> None:
        window = timedelta(minutes=10)
        span = 1
        if self.c.first_ts and self.c.last_ts:
            span = max(1, int((self.c.last_ts - self.c.first_ts).total_seconds() // 600) + 1)
        for actor, failures in sorted(self.c.failures_by_actor.items()):
            failures.sort(key=lambda e: e.ts)
            count, lo, hi = _max_window([e.ts for e in failures], window)
            if count < 5:
                continue
            buckets = Counter(int(e.ts.timestamp() // 600) for e in failures)
            counts = sorted([*buckets.values(), *([0] * max(0, span - len(buckets)))])
            typical = statistics.median(counts) if counts else 0
            if count < 3 * max(typical, 1):
                continue
            burst = failures[lo : hi + 1]
            sources = Counter(e.src_ip or "-" for e in burst)
            main_source, main_count = sources.most_common(1)[0]
            concentrated = main_count >= 0.8 * count
            if count < 10 and not (concentrated and self.public(main_source)):
                continue  # a handful of failures spread over internal clients is routine
            later = [
                e
                for e in self.c.logins_by_actor.get(actor, [])
                if burst[-1].ts <= e.ts <= burst[-1].ts + timedelta(minutes=30)
            ]
            same_source = [e for e in later if e.src_ip == main_source]
            success = same_source[0] if same_source else (later[0] if later else None)
            name = self.name(actor)
            public_sources = [s for s in sources if s != "-" and self.public(s)]
            self.add(
                Detection(
                    rule="brute-force",
                    subject=f"{actor}|{burst[0].ts.isoformat()}",
                    title=f"{count} failed sign-ins for {name} {_span(burst[0].ts, burst[-1].ts)}"
                    + (f" from {main_source}" if concentrated and main_source != "-" else "")
                    + (f", then a success from {success.src_ip or 'an unknown address'}" if success else ""),
                    severity=Severity.HIGH if success else Severity.MEDIUM,
                    confidence=0.85 if success and success in same_source else 0.75,
                    description=(
                        f"{count} authentication failures for {name} between {_clock(burst[0].ts)} and "
                        f"{_clock(burst[-1].ts)} from {', '.join(f'{s} ({n})' for s, n in sources.most_common(5))}; "
                        f"the account's typical rate in this scope is {typical:g} per 10 minutes."
                        + (
                            f" A successful sign-in followed at {_clock(success.ts)}"
                            + (" from the same address." if success in same_source else ".")
                            if success
                            else ""
                        )
                    ),
                    events=[e.id for e in burst] + ([success.id] if success else []),
                    affected=[actor] + [object_id(ObjectType.IP, s) for s in sources if s != "-"],
                    pivots={actor} | {object_id(ObjectType.IP, s) for s in public_sources},
                    start=burst[0].ts,
                    end=(success.ts if success else burst[-1].ts),
                    explanation=[
                        ("failures", f"{count} in 10 minutes"),
                        ("baseline", f"median {typical:g} per 10 minutes"),
                        ("source", f"{main_source} ({main_count} of {count})"),
                    ],
                    stage="credential-attack",
                    metadata={"src_ip": main_source if concentrated else None, "success": bool(success)},
                )
            )
        for src, failures in sorted(self.c.failures_by_src.items()):
            failures.sort(key=lambda e: e.ts)
            count, lo, hi = _max_window([e.ts for e in failures], window)
            burst = failures[lo : hi + 1]
            accounts = {e.actor for e in burst if e.actor}
            if count < 10 or len(accounts) < 3:
                continue
            successes = [
                e
                for a in accounts
                for e in self.c.logins_by_actor.get(a or "", [])
                if e.src_ip == src and burst[0].ts <= e.ts <= burst[-1].ts + timedelta(minutes=30)
            ]
            self.add(
                Detection(
                    rule="password-spray",
                    subject=f"{src}|{burst[0].ts.isoformat()}",
                    title=f"Password spraying from {src}: {count} failures across {len(accounts)} accounts"
                    + (f", {len(successes)} success(es)" if successes else ""),
                    severity=Severity.HIGH if successes else Severity.MEDIUM,
                    confidence=0.8,
                    description=(
                        f"{src} failed to authenticate {count} times as {len(accounts)} accounts between "
                        f"{_clock(burst[0].ts)} and {_clock(burst[-1].ts)}: "
                        + ", ".join(sorted(self.name(a) for a in accounts)[:10])
                        + "."
                    ),
                    events=[e.id for e in burst] + [e.id for e in successes[:5]],
                    affected=[object_id(ObjectType.IP, src), *sorted(a for a in accounts if a)],
                    pivots={object_id(ObjectType.IP, src)},
                    start=burst[0].ts,
                    end=burst[-1].ts,
                    stage="credential-attack",
                )
            )
        for actor, challenges in sorted(self.c.mfa_by_actor.items()):
            challenges.sort(key=lambda e: e.ts)
            count, lo, hi = _max_window([e.ts for e in challenges], window)
            if count < 5:
                continue
            burst = challenges[lo : hi + 1]
            name = self.name(actor)
            self.add(
                Detection(
                    rule="mfa-fatigue",
                    subject=f"{actor}|{burst[0].ts.isoformat()}",
                    title=f"{count} MFA challenges for {name} {_span(burst[0].ts, burst[-1].ts)}",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    description=f"{name} received {count} MFA challenges between {_clock(burst[0].ts)} and "
                    f"{_clock(burst[-1].ts)}.",
                    events=[e.id for e in burst],
                    affected=[actor],
                    pivots={actor},
                    start=burst[0].ts,
                    end=burst[-1].ts,
                    stage="credential-attack",
                )
            )

    def _new_signins(self) -> None:
        for actor, logins in sorted(self.c.logins_by_actor.items()):
            logins.sort(key=lambda e: e.ts)
            internal = [e for e in logins if self.c.scope(e.src_ip) in ("internal", "loopback")]
            if len(internal) < 3:
                continue
            seen: set[str] = set()
            reported: set[str] = set()
            for ev in logins:
                src = ev.src_ip
                if not src:
                    continue
                if src in seen or not self.public(src) or src in reported:
                    seen.add(src)
                    continue
                seen.add(src)
                reported.add(src)
                session = ev.first("session")
                mfa = [
                    m
                    for m in self.c.mfa_by_actor.get(actor, [])
                    if (session and m.first("session") == session)
                    or (m.src_ip == src and ev.ts - timedelta(minutes=10) <= m.ts <= ev.ts)
                ]
                others = [e for e in logins if e.src_ip == src and e.id != ev.id]
                flagged = src in self.flagged_ips
                name = self.name(actor)
                service = self.name(ev.target) if ev.target else "a service"
                severity = Severity.MEDIUM if (flagged or not mfa) else Severity.LOW
                self.add(
                    Detection(
                        rule="new-external-signin",
                        subject=f"{actor}|{src}",
                        title=f"Sign-in from a new public address: {name} from {src} to {service}"
                        + (" (MFA completed)" if mfa else " (no MFA seen)"),
                        severity=severity,
                        confidence=0.6,
                        description=(
                            f"{name} signed in to {service} from {src} at {_clock(ev.ts)}; their {len(internal)} other "
                            f"sign-ins in scope come from internal addresses."
                            + (
                                f" An MFA challenge preceded it at {_clock(mfa[0].ts)} in the same session."
                                if mfa
                                else " No MFA challenge was seen for it."
                            )
                            + (f" {len(others)} more sign-in(s) from that address." if others else "")
                            + (" The address also appears in other detections." if flagged else "")
                        ),
                        events=[ev.id] + [m.id for m in mfa[:3]] + [e.id for e in others[:5]],
                        affected=[actor, object_id(ObjectType.IP, src), ev.target or "", session or ""],
                        pivots={object_id(ObjectType.IP, src), *(s for s in [session] if s)},
                        start=min([ev.ts] + [m.ts for m in mfa]),
                        end=ev.ts,
                        explanation=[
                            ("baseline", f"{len(internal)} internal sign-ins"),
                            ("mfa", "yes" if mfa else "no"),
                        ],
                        stage="initial-access",
                        metadata={"src_ip": src, "mfa": bool(mfa), "session": session},
                    )
                )

    # ------------------------------------------------------------------ changes and control plane
    def _change_covering(self, ev: Ev) -> Ev | None:
        actor = self.name(ev.actor).lower()
        target = (self.name(ev.target) + " " + str(ev.attrs.get("name") or "")).lower()
        for change in self.c.changes:
            status = str(change.attrs.get("change_status") or change.outcome or "").lower()
            if status not in _APPROVED:
                continue
            start, end = change.attrs.get("window_start"), change.attrs.get("window_end")
            if not (start and end):
                continue
            stamp = format_ts(ev.ts) or ""
            if not (str(start) <= stamp <= str(end)):
                continue
            service = str(change.attrs.get("change_service") or "").lower()
            who = str(change.attrs.get("change_actor") or "").lower()
            if (service and service in target) or (who and who in actor):
                return change
        return None

    def _destructive(self) -> None:
        groups: dict[tuple[str, str], list[Ev]] = defaultdict(list)
        for ev in self.c.destructive:
            change = self._change_covering(ev)
            groups[(ev.actor or "-", change.id if change else "")].append(ev)
        for (actor, change_id), evs in sorted(groups.items()):
            evs.sort(key=lambda e: e.ts)
            name = self.name(actor)
            what = Counter(
                f"{e.text('verb') or e.text('api') or e.action} {e.text('k8s_resource') or self.name(e.target)}"
                for e in evs
            )
            summary = ", ".join(f"{k} x{n}" if n > 1 else k for k, n in what.most_common(5))
            if change_id:
                change = next(c for c in self.c.changes if c.id == change_id)
                ticket = change.attrs.get("ticket")
                self.explained.append(
                    Explained(
                        rule="destructive-change",
                        title=f"{len(evs)} destructive operation(s) by {name} ({summary})",
                        reason=f"covered by approved change {ticket} ({change.action}"
                        + (f" on {change.attrs.get('change_service')}" if change.attrs.get("change_service") else "")
                        + f", window {change.attrs.get('window') or change.attrs.get('window_start')})",
                        events=[*[e.id for e in evs][:_EVIDENCE_CAP], change.id],
                        at=evs[0].ts,
                    )
                )
                continue
            self.add(
                Detection(
                    rule="destructive-change",
                    subject=f"{actor}|{evs[0].ts.date()}|{summary}",
                    title=f"Destructive operation(s) by {name} outside any change: {summary}",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description=f"{name} ran {summary} between {_clock(evs[0].ts)} and {_clock(evs[-1].ts)}; no "
                    "approved change record in scope covers this actor or service at that time.",
                    events=[e.id for e in evs],
                    affected=[actor, *(e.target or "" for e in evs)],
                    pivots={actor},
                    start=evs[0].ts,
                    end=evs[-1].ts,
                    stage="impact",
                )
            )

    def _tampering(self) -> None:
        for ev in sorted(self.c.tamper, key=lambda e: e.ts):
            what = ev.text("api") or ev.action or ev.type
            name = self.name(ev.actor) if ev.actor else self.name(ev.first("host"))
            self.add(
                Detection(
                    rule="log-tampering",
                    subject=f"{ev.id}",
                    title=f"Audit logging tampered with: {what} by {name}"
                    + (" (failed)" if ev.outcome == "failure" else ""),
                    severity=Severity.MEDIUM if ev.outcome == "failure" else Severity.HIGH,
                    confidence=0.85,
                    description=f"At {_clock(ev.ts)} {name} ran {what}: {ev.message[:300]}",
                    events=[ev.id],
                    affected=[ev.actor or "", ev.target or "", ev.first("host") or ""],
                    pivots={ev.actor or "", object_id(ObjectType.IP, ev.src_ip) if ev.src_ip else ""},
                    start=ev.ts,
                    end=ev.ts,
                    stage="defense-evasion",
                )
            )

    def _credential_access(self) -> None:
        groups: dict[tuple[str, str], list[Ev]] = defaultdict(list)
        for ev in self.c.secret_files:
            groups[(ev.first("host") or "-", ev.ts.date().isoformat())].append(ev)
        for label, _severity, ev in self.c.commands:
            if label == "credential discovery":
                groups[(ev.first("host") or "-", ev.ts.date().isoformat())].append(ev)
        for (host, _day), evs in sorted(groups.items()):
            evs.sort(key=lambda e: e.ts)
            people = [e.actor for e in evs if e.actor and e.actor.split(":", 1)[0] in ("user", "identity")]
            actor = people[0] if people else (evs[0].actor or evs[0].first("process") or "-")
            files = [
                (e.target or "").split("|", 1)[-1] if (e.target or "").startswith("file:") else self.name(e.target)
                for e in evs
                if e.type.startswith("file.") and e.target
            ]
            commands = [str(e.attrs.get("command_line") or "")[:160] for e in evs if e.type == "process.start"]
            read = bool(files) or any(
                re.search(r"(?i)\b(?:cat|less|more|head|tail|type|get-content)\b", c) for c in commands
            )
            who = self.name(actor) if actor != "-" else "a process"
            where = self.name(host) if host != "-" else "an unknown host"
            what = ", ".join(dict.fromkeys(files)) or (commands[0] if commands else "credential files")
            self.add(
                Detection(
                    rule="credential-access",
                    subject=f"{host}|{evs[0].ts.date()}",
                    title=f"Credential access on {where} by {who}: {what[:100]}",
                    severity=Severity.HIGH if read else Severity.MEDIUM,
                    confidence=0.75 if read else 0.6,
                    description=(
                        f"Between {_clock(evs[0].ts)} and {_clock(evs[-1].ts)}, {who} on {where} "
                        + (f"read {', '.join(dict.fromkeys(files))}" if files else "searched for credential files")
                        + (f"; commands: {'; '.join(commands[:4])}" if commands else "")
                        + ". Files like these hold tokens, keys or passwords: treat their contents as exposed."
                    ),
                    events=[e.id for e in evs],
                    affected=[host, actor, *(e.target or "" for e in evs if e.type.startswith("file."))],
                    pivots={host, actor} - {"-"},
                    start=evs[0].ts,
                    end=evs[-1].ts,
                    explanation=[("files", what[:200])],
                    stage="credential-access",
                )
            )

    def _service_accounts(self) -> None:
        for actor, logins in sorted(self.c.logins_by_actor.items()):
            name = self.name(actor)
            if not _SERVICE_IDENTITY.search(name) or len(logins) < 4:
                continue
            logins.sort(key=lambda e: e.ts)
            seen: dict[str, int] = {}
            for index, ev in enumerate(logins):
                src = ev.src_ip
                if not src:
                    continue
                if src not in seen and index >= 3 and sum(seen.values()) >= 3:
                    usual = ", ".join(f"{s} ({n})" for s, n in sorted(seen.items(), key=lambda kv: -kv[1])[:3])
                    hosts = self.hosts_of(src)
                    target = self.name(ev.target) if ev.target else "a host"
                    self.add(
                        Detection(
                            rule="service-account-new-source",
                            subject=f"{actor}|{src}",
                            title=f"Service account {name} signed in to {target} from a new source {src}"
                            + (f" ({', '.join(self.name(h) for h in hosts)})" if hosts else ""),
                            severity=Severity.HIGH,
                            confidence=0.7,
                            description=(
                                f"At {_clock(ev.ts)} {name} authenticated to {target} from {src}"
                                + (f" ({', '.join(self.name(h) for h in hosts)})" if hosts else "")
                                + f"; its {sum(seen.values())} earlier sign-ins in scope came from {usual}."
                            ),
                            events=[ev.id] + [e.id for e in logins[:index][-3:]],
                            affected=[actor, ev.target or "", object_id(ObjectType.IP, src), *hosts],
                            pivots={actor, object_id(ObjectType.IP, src), *hosts},
                            start=ev.ts,
                            end=ev.ts,
                            explanation=[("usual sources", usual), ("new source", src)],
                            stage="lateral-movement",
                            metadata={"src_ip": src},
                        )
                    )
                seen[src] = seen.get(src, 0) + 1

    def _alerts(self) -> None:
        groups: dict[tuple[str, str, str], list[Ev]] = defaultdict(list)
        for ev in self.c.alerts:
            signature = str(ev.attrs.get("rule") or ev.attrs.get("signature") or ev.message or ev.action)[:200]
            groups[(signature, ev.actor or "-", ev.target or "-")].append(ev)
        for (signature, actor, target), evs in sorted(groups.items()):
            evs.sort(key=lambda e: e.ts)
            worst = max((e.severity for e in evs), key=lambda s: s.rank)
            detector = str(
                evs[0].attrs.get("detector") or evs[0].attrs.get("vendor") or evs[0].attrs.get("product") or ""
            )
            message = evs[0].message or signature
            self.add(
                Detection(
                    rule="security-alert",
                    subject=f"{signature}|{actor}|{target}",
                    title=f"Alert{' from ' + detector if detector else ''}: {message[:140]}"
                    + (f" (x{len(evs)})" if len(evs) > 1 else ""),
                    severity=worst,
                    confidence=0.6,
                    description=(
                        f"{len(evs)} alert(s) '{signature}' between {_clock(evs[0].ts)} and {_clock(evs[-1].ts)}"
                        + (f", reported by {detector}" if detector else "")
                        + f": {message[:400]}. The severity is the reporting tool's."
                    ),
                    events=[e.id for e in evs],
                    affected=[actor, target],
                    pivots={actor, target} - {"-"},
                    start=evs[0].ts,
                    end=evs[-1].ts,
                    stage="detection",
                )
            )

    def _commands(self) -> None:
        groups: dict[tuple[str, str], list[tuple[Severity, Ev]]] = defaultdict(list)
        for label, severity, ev in self.c.commands:
            if label == "credential discovery":
                continue
            parent = str(ev.attrs.get("parent_image") or "")
            if label in _ROUTINE_WHEN_SCHEDULED and (ev.attrs.get("scheduler") or _SCHEDULER.search(parent)):
                command = str(ev.attrs.get("command_line") or ev.attrs.get("command") or "")[:120]
                self.explained.append(
                    Explained(
                        rule="suspicious-command",
                        title=f"{label.capitalize()} on {self.name(ev.first('host'))}: {command}",
                        reason=f"run by {self.name(ev.actor) if ev.actor else 'a service'} from a scheduler "
                        f"({parent or ev.attrs.get('scheduler')}): a scheduled job",
                        events=[ev.id],
                        at=ev.ts,
                    )
                )
                continue
            groups[(ev.first("host") or "-", label)].append((severity, ev))
        for (host, label), items in sorted(groups.items()):
            items.sort(key=lambda x: x[1].ts)
            evs = [e for _s, e in items]
            first = str(evs[0].attrs.get("command_line") or evs[0].attrs.get("command") or "")[:200]
            self.add(
                Detection(
                    rule="suspicious-command",
                    subject=f"{host}|{label}",
                    title=f"Suspicious command ({label}) on {self.name(host)}: {first[:90]}",
                    severity=max((s for s, _e in items), key=lambda s: s.rank),
                    confidence=0.75,
                    description=f"{len(evs)} command line(s) matching {label} on {self.name(host)}, first at "
                    f"{_clock(evs[0].ts)}: {first}",
                    events=[e.id for e in evs],
                    affected=[host, *(e.actor or "" for e in evs), *(e.target or "" for e in evs)],
                    pivots={host, *(e.actor or "" for e in evs)},
                    start=evs[0].ts,
                    end=evs[-1].ts,
                    stage="execution",
                )
            )

    def _sql(self) -> None:
        groups: dict[tuple[str, str], list[Ev]] = defaultdict(list)
        for ev in self.c.sql:
            for risk in ev.attrs.get("sql_risk") or []:
                groups[(ev.actor or "-", str(risk))].append(ev)
        for (actor, risk), evs in sorted(groups.items()):
            evs.sort(key=lambda e: e.ts)
            severity = Severity.HIGH if risk in ("file-export", "file-read", "command-execution") else Severity.MEDIUM
            statement = str(evs[0].attrs.get("statement") or "")[:160]
            self.add(
                Detection(
                    rule="risky-sql",
                    subject=f"{actor}|{risk}",
                    title=f"Risky database statement ({risk}) by {self.name(actor)}: {statement[:80]}",
                    severity=severity,
                    confidence=0.7,
                    description=f"{len(evs)} statement(s) by {self.name(actor)} flagged {risk}, first at "
                    f"{_clock(evs[0].ts)}: {statement}",
                    events=[e.id for e in evs],
                    affected=[actor, *(e.target or "" for e in evs)],
                    pivots={actor},
                    start=evs[0].ts,
                    end=evs[-1].ts,
                    stage="collection",
                )
            )

    def _dns_tunneling(self) -> None:
        for (client, base), evs in sorted(self.c.dns_long.items()):
            names = {e.text("query") or _key_name(e.target) for e in evs}
            if len(names) < 30:
                continue
            evs.sort(key=lambda e: e.ts)
            self.add(
                Detection(
                    rule="dns-tunneling",
                    subject=f"{client}|{base}",
                    title=f"DNS tunneling pattern: {client} queried {len(names)} long unique names under {base}",
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    description=f"{client} queried {len(names)} distinct names with long labels under {base} between "
                    f"{_clock(evs[0].ts)} and {_clock(evs[-1].ts)}.",
                    events=[e.id for e in evs],
                    affected=[object_id(ObjectType.DOMAIN, base)]
                    + ([object_id(ObjectType.IP, client)] if ip_scope(client) else []),
                    pivots={object_id(ObjectType.IP, client) if ip_scope(client) else ""},
                    start=evs[0].ts,
                    end=evs[-1].ts,
                    stage="command-and-control",
                )
            )

    def _exports(self) -> None:
        for ev in sorted(self.c.exports, key=lambda e: e.ts):
            size = ev.number("bytes") or 0
            ticket = ev.text("ticket")
            name = self.name(ev.actor) if ev.actor else "an application"
            what = self.name(ev.target) if ev.target else (ev.text("path") or "data")
            title = f"Large export of {what} ({_size(size)}) by {name}"
            if ticket:
                self.explained.append(
                    Explained(
                        rule="large-export",
                        title=title,
                        reason=f"carries its own reference ticket {ticket}"
                        + (f" ({ev.text('path')})" if ev.text("path") else ""),
                        events=[ev.id],
                        at=ev.ts,
                    )
                )
                continue
            self.add(
                Detection(
                    rule="large-export",
                    subject=f"{ev.id}",
                    title=title,
                    severity=Severity.MEDIUM,
                    confidence=0.55,
                    description=f"At {_clock(ev.ts)} {name} exported {what} ({_size(size)}) with no ticket or "
                    "change reference on the record.",
                    events=[ev.id],
                    affected=[ev.actor or "", ev.target or ""],
                    pivots={ev.actor or ""},
                    start=ev.ts,
                    end=ev.ts,
                    stage="exfiltration",
                )
            )

    # ------------------------------------------------------------------ correlation
    def chains(self) -> list[list[Detection]]:
        """Detections linked by a shared entity within two hours of each other (connected components)."""
        items = sorted(self.detections, key=lambda d: d.start)
        parent = list(range(len(items)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        by_entity: dict[str, list[int]] = defaultdict(list)
        for index, detection in enumerate(items):
            for pivot in detection.pivots:
                by_entity[pivot].append(index)
        for members in by_entity.values():
            for a, b in pairwise(members):
                da, db = items[a], items[b]
                if db.start - da.end <= _CHAIN_GAP and da.start - db.end <= _CHAIN_GAP:
                    parent[find(b)] = find(a)
        groups: dict[int, list[Detection]] = defaultdict(list)
        for index, detection in enumerate(items):
            groups[find(index)].append(detection)
        result: list[list[Detection]] = []
        for group in groups.values():
            if len(group) >= 2 and max(d.severity.rank for d in group) >= Severity.HIGH.rank:
                result.append(sorted(group, key=lambda d: d.start))
        return sorted(result, key=lambda g: g[0].start)


_SEVERITIES = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
_STAGE_LABELS = {
    "reconnaissance": "reconnaissance",
    "exposure": "exposed credentials",
    "initial-access": "suspicious sign-in",
    "credential-attack": "credential attack",
    "credential-misuse": "credential misuse",
    "collection": "data collection",
    "exfiltration": "exfiltration",
    "persistence": "persistence attempt",
    "defense-evasion": "defense evasion",
    "execution": "malicious execution",
    "impact": "destructive change",
    "credential-access": "credential access",
    "lateral-movement": "lateral movement",
    "detection": "security alert",
    "command-and-control": "command and control",
}


# --------------------------------------------------------------------------- service


class DetectionService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.store = ctx.store

    def run(self, query: EventQuery, *, scope_label: str = "workspace", persist: bool = True) -> DetectionReport:
        engine = DetectionEngine(self.ctx, scope_label)
        engine.collect(self.store.events.iter(query))
        engine.detect()
        now = utcnow()
        findings = [self._finding(engine, d, now) for d in engine.detections]
        incidents: list[DetectedIncident] = []
        chain_findings: list[Finding] = []
        incident_links: list[tuple[str, list[str]]] = []
        for chain in engine.chains():
            incident, finding, events = self._chain(engine, chain, now)
            incidents.append(incident)
            chain_findings.append(finding)
            incident_links.append((incident.id, events))
        findings += chain_findings
        findings.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.id))
        report = DetectionReport(
            scope=scope_label,
            generated_at=now,
            events_examined=engine.c.examined,
            findings=findings,
            explained=engine.explained,
            incidents=incidents,
            by_severity=dict(Counter(f.severity.value for f in findings)),
            by_rule=dict(Counter(f.rule_id for f in findings)),
        )
        if persist:
            stats = self.store.findings.upsert(findings)
            report.created, report.updated = stats.created, stats.updated
            candidates = self._candidates(engine.c.event_ids)
            report.resolved = self.store.findings.resolve_absent(
                PRODUCT, list(RULES), [f.id for f in findings], candidates=candidates
            )
            for incident, (incident_id, events) in zip(incidents, incident_links, strict=True):
                if incident.existing:
                    continue  # an incident the workspace already had: it is cited, never rewritten
                self.store.incidents.upsert(
                    incident.name,
                    title=incident.title,
                    status="suspected",
                    severity=incident.severity,
                    description="\n".join(incident.narrative),
                    start=incident.start,
                    end=incident.end,
                    source="raf detections",
                    tags=["detected"],
                    metadata={
                        "created_by": "raf detections",
                        "confidence": incident.confidence,
                        "findings": incident.findings,
                    },
                )
                self.store.events.link_incident(incident_id, events)
        return report

    def _candidates(self, scope_events: set[str]) -> list[str]:
        """Open findings of these rules whose evidence lies entirely in the examined events: a re-run of
        the same data resolves them when they are no longer produced; findings about other data stay."""
        out: list[str] = []
        offset = 0
        while True:
            page = self.store.findings.list(
                product=PRODUCT, statuses=[FindingStatus.OPEN.value], limit=500, offset=offset
            )
            for finding in page:
                events = [e.id for e in finding.evidence if e.kind == "event"]
                if events and all(e in scope_events for e in events):
                    out.append(finding.id)
            if len(page) < 500:
                return out
            offset += 500

    def _finding(self, engine: DetectionEngine, d: Detection, now: datetime) -> Finding:
        info = RULES[d.rule]
        evidence = [EvidenceRef(kind="event", id=e) for e in d.events]
        evidence.append(EvidenceRef(kind="rule", id=f"{PRODUCT}.{d.rule}", note=info.description))
        return Finding(
            id=finding_id(PRODUCT, d.rule, d.subject),
            title=d.title[:512],
            description=d.description,
            severity=d.severity,
            confidence=round(min(max(d.confidence, 0.05), 0.99), 4),
            product=PRODUCT,
            rule_id=d.rule,
            affected_objects=[a for a in d.affected if ":" in a],
            evidence=evidence,
            recommendation=info.recommendation,
            explanation=[{"sign": "+", "factor": factor, "label": label} for factor, label in d.explanation],
            created_at=now,
            updated_at=now,
            tags=["detection", info.tactic.lower().replace(" ", "-"), *info.techniques],
            metadata={
                "start": format_ts(d.start),
                "end": format_ts(d.end),
                "tactic": info.tactic,
                "attack": list(info.techniques),
                "stage": d.stage,
                "scope": engine.scope_label,
                **{k: v for k, v in d.metadata.items() if v not in (None, "", [], {})},
            },
        )

    def _chain(
        self, engine: DetectionEngine, chain: list[Detection], now: datetime
    ) -> tuple[DetectedIncident, Finding, list[str]]:
        shared = Counter(p for d in chain for p in d.pivots)
        primary = [p for p, n in shared.most_common() if n >= 2]
        lead = next((p for p in primary if p.startswith("ip:")), primary[0] if primary else "")
        stages: list[str] = []
        for d in chain:
            label = _STAGE_LABELS.get(d.stage, d.stage)
            if label and label not in stages:
                stages.append(label)
        lead_name = engine.name(lead) if lead else ""
        title = "Suspected " + " → ".join(stages) + (f" ({lead_name})" if lead_name else "")
        severity = max((d.severity for d in chain), key=lambda s: s.rank)
        if len(chain) >= 4:  # four or more stages of one chain: one level above its worst step
            severity = _SEVERITIES[min(severity.rank + 1, len(_SEVERITIES) - 1)]
        confidence = round(min(0.95, statistics.mean(d.confidence for d in chain) + 0.1), 4)
        start, end = min(d.start for d in chain), max(d.end for d in chain)
        name = "CASE-" + digest(*sorted(f"{d.rule}|{d.subject}" for d in chain), length=6).upper()
        incident_id = object_id(ObjectType.INCIDENT, name)
        narrative = [f"{_clock(d.start)}  [{d.severity.value}] {RULES[d.rule].tactic}: {d.title}" for d in chain]
        explained = [
            e
            for e in engine.explained
            if e.at is not None and start - timedelta(hours=1) <= e.at <= end + timedelta(hours=1)
        ]
        if explained:
            narrative.append("Ruled out (no finding):")
            narrative += [f"  {e.title}: {e.reason}" for e in explained]
        events = list(dict.fromkeys(e for d in chain for e in d.events))
        member_ids = [finding_id(PRODUCT, d.rule, d.subject) for d in chain]
        lo, hi = self.store.events.bounds(EventQuery(event_ids=events)) if events else (None, None)
        start, end = min(filter(None, [start, lo])), max(filter(None, [end, hi]))
        existing = Counter(
            i for e in events for i in engine.event_incidents.get(e, []) if not i.startswith("incident:case-")
        )
        known = existing.most_common(1)[0] if existing else None
        matched = known is not None and known[1] >= 0.5 * len(events)
        if matched and known is not None:
            incident_id = known[0]
            current = self.store.incidents.get(incident_id)
            name = current.name if current is not None else _key_name(incident_id).upper()
            narrative.insert(
                0, f"Matches existing incident {name}: {known[1]} of {len(events)} cited events belong to it."
            )
        incident = DetectedIncident(
            id=incident_id,
            name=name,
            title=title,
            severity=severity,
            confidence=confidence,
            findings=member_ids,
            events=len(events),
            start=start,
            end=end,
            narrative=narrative,
            existing=matched,
        )
        finding = Finding(
            id=finding_id(PRODUCT, "attack-chain", "|".join(sorted(f"{d.rule}|{d.subject}" for d in chain))),
            title=f"{title}: {len(chain)} correlated detections" + (f", matching {name}" if matched else ""),
            description="\n".join(narrative),
            severity=severity,
            confidence=confidence,
            product=PRODUCT,
            rule_id="attack-chain",
            affected_objects=list(dict.fromkeys(a for d in chain for a in d.affected if ":" in a))[:60],
            evidence=[EvidenceRef(kind="finding", id=f) for f in member_ids]
            + [EvidenceRef(kind="object", id=incident_id, note="suspected incident")]
            + [EvidenceRef(kind="event", id=e) for e in events[:_EVIDENCE_CAP]],
            recommendation=RULES["attack-chain"].recommendation
            + (f" Shared entities: {', '.join(engine.name(p) for p in primary[:5])}." if primary else ""),
            explanation=[
                {
                    "sign": "+",
                    "factor": "correlation",
                    "label": f"{len(chain)} detections share {', '.join(engine.name(p) for p in primary[:4])}",
                }
            ],
            created_at=now,
            updated_at=now,
            tags=["detection", "attack-chain"],
            metadata={
                "start": format_ts(start),
                "end": format_ts(end),
                "incident": name,
                "stages": stages,
                "scope": engine.scope_label,
            },
        )
        return incident, finding, events


__all__ = ["RULES", "DetectionReport", "DetectionService", "Explained"]
