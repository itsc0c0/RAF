"""R$F Vault detection rules.

Every rule has a stable id, a severity (impact if the match is a live secret)
and a base confidence (the documented precision of its pattern). Severity and
confidence are independent. Detectors look at one line at a time (a private
key may look ahead to the end of its PEM block) and return candidates with the
exact span of the secret value. The value never leaves the scanner: callers
keep only its keyed fingerprint and its redacted form.
"""

from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field

from raf.core.objects.types import Severity

# --------------------------------------------------------------------------- model


@dataclass(frozen=True, slots=True)
class Factor:
    """One explained adjustment of a candidate's confidence (points = percentage points)."""

    label: str
    points: int


@dataclass(frozen=True, slots=True)
class FileKind:
    config: bool  # config-like file: unquoted assignments are accepted
    test_like: bool  # tests, fixtures, examples or docs (confidence penalty)


@dataclass(frozen=True, slots=True)
class LineView:
    lines: Sequence[str]
    index: int  # 0-based
    kind: FileKind
    entropy_threshold: float

    @property
    def text(self) -> str:
        return self.lines[self.index]

    @property
    def number(self) -> int:
        return self.index + 1


@dataclass(slots=True)
class Candidate:
    rule: str
    value: str  # the secret itself: never persisted, printed or logged
    line: int  # 1-based
    start: int  # column span of the value on its first line
    end: int
    end_line: int
    label: str | None = None  # non-secret context such as the assignment key
    display: str | None = None  # material to redact for display (defaults to value)
    severity: Severity | None = None  # per-match override of the rule severity
    factors: list[Factor] = field(default_factory=list)


Finder = Callable[[LineView], Iterator[Candidate]]


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    severity: Severity
    confidence: float
    precision: str  # high | medium | low (documented in docs/products/vault.md)
    priority: int  # lower wins when matches overlap
    description: str
    recommendation: str
    find: Finder
    prefilter: tuple[str, ...] = ()  # cheap substring test before running the pattern
    redact_keep: tuple[int, int] = (3, 4)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "precision": self.precision,
            "description": self.description,
            "recommendation": self.recommendation,
        }


# --------------------------------------------------------------------------- helpers


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in Counter(text).values())


def _has_classes(text: str, *, upper: bool = True, lower: bool = True, digit: bool = True) -> bool:
    return (
        (not upper or any(c.isupper() for c in text))
        and (not lower or any(c.islower() for c in text))
        and (not digit or any(c.isdigit() for c in text))
    )


def _candidate(
    rule: str,
    view: LineView,
    match: re.Match[str],
    group: int = 1,
    *,
    label: str | None = None,
    factors: list[Factor] | None = None,
) -> Candidate:
    return Candidate(
        rule=rule,
        value=match.group(group),
        line=view.number,
        start=match.start(group),
        end=match.end(group),
        end_line=view.number,
        label=label,
        factors=list(factors or []),
    )


_PLACEHOLDER_WORDS = frozenset(
    {
        "changeme",
        "change_me",
        "change-me",
        "password",
        "passwd",
        "pass",
        "secret",
        "token",
        "apikey",
        "api_key",
        "example",
        "sample",
        "dummy",
        "placeholder",
        "redacted",
        "none",
        "null",
        "nil",
        "true",
        "false",
        "undefined",
        "todo",
        "tbd",
        "fixme",
        "empty",
        "string",
        "required",
        "optional",
        "your_password",
        "yourpassword",
        "mypassword",
        "my_password",
        "foo",
        "bar",
        "foobar",
    }
)
_PLACEHOLDER_SUBSTRINGS = (
    "changeme",
    "change_me",
    "change-me",
    "replace_me",
    "replace-me",
    "replaceme",
    "your_",
    "your-",
    "yourpass",
    "_here",
    "-here",
    "example",
    "placeholder",
    "dummy",
    "redacted",
    "xxxx",
    "****",
)
_PLACEHOLDER_RES = (
    re.compile(r"^\$\{[^}]*\}$"),  # ${VAR}
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),  # $VAR
    re.compile(r"^\$\(.*\)?$"),  # $(command)
    re.compile(r"\{\{.*\}\}"),  # {{ template }}
    re.compile(r"^%\(.+\)s$|^%s$"),  # %(name)s
    re.compile(r"^#\{.*\}$|^%\{.*\}$"),  # #{expr} / %{expr}
    re.compile(r"^@[\w.\-]+@$"),  # @maven.filter@
    re.compile(r"^__\w+__$"),  # __PLACEHOLDER__
    re.compile(r"^<[^<>]*>$"),  # <password>
    re.compile(r"^\[[^\[\]]*\]$"),  # [password]
    re.compile(r"^[xX*•._#\-]+$"),  # masks: xxxx, ****, ....
    re.compile(r"^(?:ENC\[|vault:|op://|ref\+|arn:aws:|secretsmanager:|sm://|env:|ENV\[)", re.IGNORECASE),
    re.compile(r"^[*&!]"),  # YAML aliases, anchors and tags (!vault, !secret, !ENV)
)


def is_placeholder(value: str, key: str | None = None) -> bool:
    """True for template variables, references and obvious placeholder values."""
    text = value.strip().strip("\"'")
    lowered = text.lower()
    if len(text) < 4 or lowered in _PLACEHOLDER_WORDS:
        return True
    if key is not None and lowered in {key.lower(), key.lower().rsplit("_", 1)[-1]}:
        return True
    if any(part in lowered for part in _PLACEHOLDER_SUBSTRINGS):
        return True
    if "EXAMPLE" in text:  # documentation keys such as the AWS examples
        return True
    return any(pattern.search(text) for pattern in _PLACEHOLDER_RES)


# --------------------------------------------------------------------------- token formats

_AWS_KEY_ID_RE = re.compile(r"(?<![A-Za-z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Za-z0-9])")
_AWS_SECRET_RE = re.compile(r"(?<![A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])")
_AWS_CONTEXT_RE = re.compile(r"(?i)(?:aws|amazon)[\w.\-]{0,30}?secret|secret[_\-. ]?access[_\-. ]?key")
_GITHUB_RE = re.compile(
    r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])"
)
_GITLAB_RE = re.compile(r"(?<![A-Za-z0-9_\-])(glpat-[A-Za-z0-9_\-]{20,255})(?![A-Za-z0-9_\-])")
_SLACK_RE = re.compile(r"(?<![A-Za-z0-9\-])(xox[baprs]-[A-Za-z0-9\-]{10,255})(?![A-Za-z0-9\-])")
_STRIPE_RE = re.compile(r"(?<![A-Za-z0-9_])((?:sk|rk)_live_[A-Za-z0-9]{16,255})(?![A-Za-z0-9])")
_OPENAI_RE = re.compile(r"(?<![A-Za-z0-9_\-])(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,255})(?![A-Za-z0-9_\-])")
_OPENAI_MARKER = "T3BlbkFJ"  # base64 of "OpenAI", embedded in OpenAI keys
_GOOGLE_RE = re.compile(r"(?<![A-Za-z0-9_\-])(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])")
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{5,2048}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{8,})(?![A-Za-z0-9_\-])"
)


def _find_aws_key_id(view: LineView) -> Iterator[Candidate]:
    for match in _AWS_KEY_ID_RE.finditer(view.text):
        if not is_placeholder(match.group(1)):
            yield _candidate("aws-access-key-id", view, match)


def _find_aws_secret(view: LineView) -> Iterator[Candidate]:
    if not _AWS_CONTEXT_RE.search(view.text):
        return
    for match in _AWS_SECRET_RE.finditer(view.text):
        value = match.group(1)
        if not _has_classes(value) or shannon_entropy(value) < 3.5 or is_placeholder(value):
            continue
        yield _candidate(
            "aws-secret-access-key", view, match, factors=[Factor("AWS secret keyword on the same line", 10)]
        )


def _simple_finder(rule: str, pattern: re.Pattern[str]) -> Finder:
    def find(view: LineView) -> Iterator[Candidate]:
        for match in pattern.finditer(view.text):
            if not is_placeholder(match.group(1)):
                yield _candidate(rule, view, match)

    return find


def _find_openai(view: LineView) -> Iterator[Candidate]:
    for match in _OPENAI_RE.finditer(view.text):
        value = match.group(1)
        if not _has_classes(value[3:]) or is_placeholder(value):
            continue
        factors = [Factor("contains the OpenAI key marker", 30)] if _OPENAI_MARKER in value else []
        yield _candidate("openai-style", view, match, factors=factors)


def _jwt_header_ok(token: str) -> bool:
    head = token.split(".", 1)[0]
    try:
        data = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    except (ValueError, TypeError, RecursionError):  # untrusted bytes: malformed or deeply nested
        return False
    return isinstance(data, dict) and "alg" in data


def _find_jwt(view: LineView) -> Iterator[Candidate]:
    for match in _JWT_RE.finditer(view.text):
        if _jwt_header_ok(match.group(1)):
            yield _candidate("jwt", view, match, factors=[Factor("header decodes to a JWT header", 10)])


# --------------------------------------------------------------------------- private keys

_PEM_BEGIN_RE = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY(?: BLOCK)?-----")
_PEM_END_RE = re.compile(r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_PEM_HEADER_RE = re.compile(r"^(?:Proc-Type|DEK-Info|Comment|Version|Hash|Charset):.*$", re.MULTILINE)
_NON_B64_RE = re.compile(r"[^A-Za-z0-9+/=]")
_MAX_PEM_LINES = 400


def _pem_block(lines: Sequence[str], index: int, column: int) -> tuple[list[str], int]:
    """Lines of the PEM block starting at ``lines[index][column:]`` and the index of its last line."""
    first = lines[index][column:]
    end = _PEM_END_RE.search(first)
    if end is not None:
        return [first[: end.end()]], index
    block = [first]
    last = min(len(lines) - 1, index + _MAX_PEM_LINES)
    for position in range(index + 1, last + 1):
        text = lines[position]
        end = _PEM_END_RE.search(text)
        if end is not None:
            block.append(text[: end.end()])
            return block, position
        block.append(text)
    return block, last


def _pem_body(material: str) -> str:
    text = material.replace("\\n", "\n").replace("\\r", "\n")
    text = _PEM_BEGIN_RE.sub("", _PEM_END_RE.sub("", text))
    text = _PEM_HEADER_RE.sub("", text)
    return _NON_B64_RE.sub("", text)


def _find_private_key(view: LineView) -> Iterator[Candidate]:
    match = _PEM_BEGIN_RE.search(view.text)
    if match is None:
        return
    block, last = _pem_block(view.lines, view.index, match.start())
    material = "\n".join(block)
    body = _pem_body(material)
    if len(body) < 32 or len(set(body.rstrip("="))) < 8:
        return  # a marker without key material (key-handling code, documentation placeholder)
    encrypted = "ENCRYPTED" in (match.group(1) or "") or "Proc-Type: 4,ENCRYPTED" in material
    factors = [Factor("PEM block with key material", 5)]
    if encrypted:
        factors.append(Factor("key is encrypted with a passphrase (severity lowered)", 0))
    yield Candidate(
        rule="private-key",
        value=material,
        line=view.number,
        start=match.start(),
        end=len(view.text) if last > view.index else match.start() + len(block[0]),
        end_line=last + 1,
        label=((match.group(1) or "").strip() + " private key").strip(),
        display=body,
        severity=Severity.HIGH if encrypted else None,
        factors=factors,
    )


# --------------------------------------------------------------------------- credentials in URLs

_URL_CRED_RE = re.compile(
    r"(?i)\b([a-z][a-z0-9+.\-]{1,20})://([^\s:/?#@\"'<>]{1,128}):([^\s@/?#\"'<>]{1,256})@([a-z0-9.\-_~%\[\]]+)"
)
_LOCAL_HOST_RE = re.compile(
    r"(?i)^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[?::1\]?|[\w.\-]*\.(?:example|test|invalid|local|localhost)"
    r"|(?:[\w\-]+\.)*example\.(?:com|org|net))$"
)


def _find_url_credentials(view: LineView) -> Iterator[Candidate]:
    for match in _URL_CRED_RE.finditer(view.text):
        password = match.group(3)
        if is_placeholder(password):
            continue
        factors = []
        if _LOCAL_HOST_RE.match(match.group(4)):
            factors.append(Factor("points at a local or documentation host", -20))
        yield _candidate(
            "url-credentials", view, match, group=3, label=f"{match.group(1).lower()} URL password", factors=factors
        )


# --------------------------------------------------------------------------- assignments

_QUOTED = r"\"(?:[^\"\\\n]|\\.){1,512}\"|'(?:[^'\\\n]|\\.){1,512}'"
_ASSIGN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<q>[\"']?)(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,80})(?P=q)\s*(?P<op>:=|=>|=|:)\s*"
    rf"(?P<value>{_QUOTED}|[^\s\"'`,;#()\[\]{{}}<>]{{1,512}})"
)
_ANNOTATED_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<key>[A-Za-z_][A-Za-z0-9_]{0,80})\s*:\s*[A-Za-z_][\w.\[\], |]{0,60}?\s*=\s*"
    rf"(?P<value>{_QUOTED})"
)
_XML_RE = re.compile(r"<(?P<key>[A-Za-z_][\w.\-]{0,80})>(?P<value>[^<>\s][^<>]{0,255})</(?P=key)>")
_CAMEL_1 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")
_KEY_SPLIT = re.compile(r"[\s_.\-]+")
_LAST_EXACT = frozenset({"password", "passwd", "pwd", "pass", "passphrase", "secret", "token", "apikey"})
_LAST_SUFFIX = ("password", "passwd", "secret", "token", "apikey")
_PAIRS = frozenset(
    {
        ("api", "key"),
        ("secret", "key"),
        ("app", "key"),
        ("master", "key"),
        ("encryption", "key"),
        ("signing", "key"),
    }
)


def key_parts(key: str) -> list[str]:
    """Split an identifier into lowercase words (snake, kebab, dotted and camelCase)."""
    spaced = _CAMEL_2.sub(r"\1 \2", _CAMEL_1.sub(r"\1 \2", key))
    return [part for part in _KEY_SPLIT.split(spaced.lower()) if part]


def is_secret_key(key: str) -> bool:
    """True when an assignment key names a credential (``DB_PASSWORD``, ``apiKey``, ``client_secret``)."""
    parts = key_parts(key)
    if not parts:
        return False
    last = parts[-1]
    if last in _LAST_EXACT or last.endswith(_LAST_SUFFIX):
        return True
    return len(parts) >= 2 and (parts[-2], last) in _PAIRS


def _unquote(raw: str) -> tuple[str, int, bool]:
    """Return (value, offset of the value inside ``raw``, quoted)."""
    if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
        return raw[1:-1], 1, True
    return raw, 0, False


def _looks_like_path_or_url(value: str) -> bool:
    return "://" in value or (value.startswith(("/", "./", "../", "~/")) and "/" in value[1:])


def _assignment_candidate(view: LineView, key: str, raw: str, raw_start: int) -> Candidate | None:
    value, offset, quoted = _unquote(raw)
    if not quoted and not view.kind.config:
        return None  # in source code only string literals are credentials, not expressions
    if not is_secret_key(key) or is_placeholder(value, key_parts(key)[-1]):
        return None
    if value.isdigit() or _looks_like_path_or_url(value) or not value.strip():
        return None
    factors = [Factor("config-like file" if view.kind.config else "string literal in source code", 0)]
    if not view.kind.config:
        factors.append(Factor("source code assignment (often test data)", -10))
    if len(value) >= 10 and shannon_entropy(value) >= 3.0:
        factors.append(Factor("value looks random", 10))
    start = raw_start + offset
    return Candidate(
        rule="password-assignment",
        value=value,
        line=view.number,
        start=start,
        end=start + len(value),
        end_line=view.number,
        label=key[-80:],
        factors=factors,
    )


def _overlapping(pattern: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """Matches that may start inside a previous match's value (``f(api_key="...")`` inside ``x = f(...)``)."""
    position = 0
    while position < len(text):
        match = pattern.search(text, position)
        if match is None:
            return
        yield match
        position = max(match.start("value"), match.start() + 1)


def _find_assignments(view: LineView) -> Iterator[Candidate]:
    text = view.text
    seen: set[int] = set()
    matches: list[tuple[str, str, int]] = []
    for pattern in (_ASSIGN_RE, _ANNOTATED_RE, _XML_RE):
        for match in _overlapping(pattern, text):
            matches.append((match.group("key"), match.group("value"), match.start("value")))
    for key, raw, start in matches:
        if start in seen:
            continue
        candidate = _assignment_candidate(view, key, raw, start)
        if candidate is not None:
            seen.add(start)
            yield candidate


# --------------------------------------------------------------------------- generic high entropy

_ENTROPY_KEYWORD_RE = re.compile(
    r"(?i)secret|token|passw(?:or)?d|\bpwd\b|credential|api[_\-.]?key|apikey|access[_\-.]?key|private[_\-.]?key"
    r"|\bauth(?:[_\-.]?(?:key|token))?\b|authorization|bearer|signing[_\-.]?key|encryption[_\-.]?key"
    r"|master[_\-.]?key"
)
_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/_\-])([A-Za-z0-9+/_\-]{20,512}={0,2})(?![A-Za-z0-9+/=_\-])")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_PATHLIKE_RE = re.compile(r"[a-z0-9._\-]+(?:/[a-z0-9._\-]+){2,}")
#: A hex alphabet carries at most 4 bits per character (base64: 6), so the threshold is scaled by 4/6.
HEX_THRESHOLD_SCALE = 4 / 6


def _find_high_entropy(view: LineView) -> Iterator[Candidate]:
    if not _ENTROPY_KEYWORD_RE.search(view.text):
        return
    for match in _TOKEN_RE.finditer(view.text):
        core = match.group(1).rstrip("=")
        if len(core) < 20 or _PATHLIKE_RE.fullmatch(core) or is_placeholder(core):
            continue
        is_hex = _HEX_RE.fullmatch(core) is not None
        if is_hex and not _has_classes(core, upper=False, lower=False):
            continue
        if not is_hex and not _has_classes(core):
            continue
        threshold = view.entropy_threshold * (HEX_THRESHOLD_SCALE if is_hex else 1.0)
        entropy = shannon_entropy(core)
        if entropy < threshold:
            continue
        bonus = min(20, int((entropy - threshold) * 20))
        factors = [Factor(f"{'hex' if is_hex else 'base64'} entropy {entropy:.2f} >= {threshold:.2f}", bonus)]
        yield _candidate("high-entropy", view, match, factors=factors)


# --------------------------------------------------------------------------- registry

_ROTATE = "Revoke or rotate the credential now, remove it from the file and from version-control history, "
_STORE = "and load it at runtime from a secret manager or environment instead of committing it."

RULES: tuple[Rule, ...] = (
    Rule(
        "private-key",
        "Private key",
        Severity.CRITICAL,
        0.95,
        "high",
        1,
        "PEM private key block (-----BEGIN ... PRIVATE KEY-----) with key material.",
        "Treat the key as compromised: replace the key pair, revoke certificates or authorized_keys entries that "
        "trust it, remove it from the repository history and keep keys in a secret store or agent.",
        _find_private_key,
        prefilter=("PRIVATE KEY",),
    ),
    Rule(
        "aws-access-key-id",
        "AWS access key ID",
        Severity.HIGH,
        0.9,
        "high",
        2,
        "AKIA (long-term) or ASIA (temporary) followed by 16 uppercase letters or digits.",
        "Deactivate and delete the access key in IAM (check CloudTrail for its use), "
        + _STORE.replace("and load", "load"),
        _find_aws_key_id,
        prefilter=("AKIA", "ASIA"),
    ),
    Rule(
        "aws-secret-access-key",
        "AWS secret access key",
        Severity.CRITICAL,
        0.7,
        "medium",
        2,
        "40-character base64 string on a line that mentions an AWS secret key.",
        "Deactivate the matching access key in IAM, review CloudTrail for its use, "
        + _STORE.replace("and load", "load"),
        _find_aws_secret,
    ),
    Rule(
        "github-token",
        "GitHub token",
        Severity.HIGH,
        0.95,
        "high",
        2,
        "ghp_/gho_/ghu_/ghs_/ghr_ followed by 36+ characters, or a fine-grained github_pat_ token.",
        "Revoke the token in GitHub settings (or the owning app), audit its recent use, " + _STORE,
        _simple_finder("github-token", _GITHUB_RE),
        prefilter=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    ),
    Rule(
        "gitlab-token",
        "GitLab personal access token",
        Severity.HIGH,
        0.95,
        "high",
        2,
        "glpat- followed by 20+ characters.",
        "Revoke the token in GitLab, audit its recent use, " + _STORE,
        _simple_finder("gitlab-token", _GITLAB_RE),
        prefilter=("glpat-",),
    ),
    Rule(
        "slack-token",
        "Slack token",
        Severity.HIGH,
        0.9,
        "high",
        2,
        "xoxb-/xoxa-/xoxp-/xoxr-/xoxs- tokens.",
        "Revoke the token in the Slack app configuration, " + _STORE,
        _simple_finder("slack-token", _SLACK_RE),
        prefilter=("xox",),
    ),
    Rule(
        "stripe-key",
        "Stripe live key",
        Severity.HIGH,
        0.95,
        "high",
        2,
        "sk_live_ (secret) or rk_live_ (restricted) keys. Test-mode keys are not reported.",
        "Roll the key in the Stripe dashboard, review recent API activity, " + _STORE,
        _simple_finder("stripe-key", _STRIPE_RE),
        prefilter=("_live_",),
    ),
    Rule(
        "google-api-key",
        "Google API key",
        Severity.HIGH,
        0.9,
        "high",
        2,
        "AIza followed by 35 characters.",
        "Delete or regenerate the key in the Google Cloud console and restrict keys by API and referrer, " + _STORE,
        _simple_finder("google-api-key", _GOOGLE_RE),
        prefilter=("AIza",),
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        Severity.HIGH,
        0.6,
        "medium",
        3,
        "Three base64url segments whose header decodes to a JWT header. May be expired or public (anon keys).",
        "If the token is long-lived, revoke it or rotate the signing key; never commit bearer tokens.",
        _find_jwt,
        prefilter=("eyJ",),
    ),
    Rule(
        "openai-style",
        "OpenAI-style API key",
        Severity.HIGH,
        0.6,
        "medium",
        4,
        "sk- (or sk-proj-) followed by 20+ mixed-case alphanumerics; higher confidence with the OpenAI marker.",
        "Revoke the key in the provider console, review usage, " + _STORE,
        _find_openai,
        prefilter=("sk-",),
    ),
    Rule(
        "url-credentials",
        "Credentials in URL",
        Severity.HIGH,
        0.8,
        "high",
        5,
        "scheme://user:password@host with a non-placeholder password.",
        "Change the password, remove it from the URL and pass credentials separately from a secret store.",
        _find_url_credentials,
        prefilter=("://",),
        redact_keep=(1, 2),
    ),
    Rule(
        "password-assignment",
        "Hardcoded password or secret",
        Severity.MEDIUM,
        0.55,
        "medium",
        6,
        "password/passwd/pwd/secret/token/api_key = literal in config-like files (quoted literals in source "
        "code); placeholders such as changeme, ${VAR}, <password> and xxxx are ignored.",
        "Change the credential, remove the literal and read it from the environment or a secret manager.",
        _find_assignments,
        prefilter=("=", ":", "<"),
        redact_keep=(1, 2),
    ),
    Rule(
        "high-entropy",
        "High-entropy string near a secret keyword",
        Severity.LOW,
        0.3,
        "low",
        7,
        "Base64/hex string of 20+ characters with Shannon entropy >= vault.entropy_threshold (scaled by 4/6 for "
        "hex) on a line that mentions a secret keyword.",
        "Check whether the value is a credential; if so rotate it and move it to a secret manager, otherwise "
        "allowlist its fingerprint.",
        _find_high_entropy,
        redact_keep=(2, 3),
    ),
)

RULE_INDEX: dict[str, Rule] = {rule.id: rule for rule in RULES}
RULE_IDS: tuple[str, ...] = tuple(RULE_INDEX)
_BY_PRIORITY: tuple[Rule, ...] = tuple(sorted(RULES, key=lambda r: r.priority))


def detect_line(view: LineView) -> list[Candidate]:
    """Run every rule on one line; overlapping matches keep the most specific rule."""
    text = view.text
    accepted: list[Candidate] = []
    for rule in _BY_PRIORITY:
        if rule.prefilter and not any(token in text for token in rule.prefilter):
            continue
        for candidate in rule.find(view):
            if any(candidate.start < other.end and other.start < candidate.end for other in accepted):
                continue
            accepted.append(candidate)
    return accepted
