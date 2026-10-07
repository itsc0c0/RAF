"""Secret redaction shared by logging, Vault output and Oracle prompts.

R$F never prints full secrets by default. ``redact_secret`` keeps a short
prefix (for recognizability, e.g. the ``sk-`` scheme) and the last four
characters: ``sk-****91a2``.
"""

from __future__ import annotations

import re

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/-]{12,}=*)"),
    re.compile(
        r"(?i)((?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|access[_-]?key)\s*[=:]\s*[\"']?)"
        r"([^\s\"',;]{4,})"
    ),
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,20}://[^:/\s@]{1,64}:)([^@\s/]{1,128})(@)"),
)


def redact_secret(value: str, keep_prefix: int = 3, keep_suffix: int = 4) -> str:
    """Redact a secret value: ``sk-****91a2``. Short values are fully masked."""
    text = value.strip()
    if len(text) <= keep_prefix + keep_suffix + 4:
        return "*" * min(len(text), 8) if text else ""
    return f"{text[:keep_prefix]}****{text[-keep_suffix:]}"


def redact_text(text: str) -> str:
    """Replace secret-looking substrings in free text (used for logs and prompts)."""
    result = text
    for pattern in _PATTERNS:

        def _sub(match: re.Match[str]) -> str:
            groups = match.groups()
            if len(groups) >= 3 and groups[2] == "@":  # credentials in URL
                return f"{groups[0]}****{groups[2]}"
            if len(groups) >= 2 and groups[0] and groups[1]:
                return f"{groups[0]}{redact_secret(groups[1])}"
            return "[REDACTED]" if "PRIVATE KEY" in match.group(0) else redact_secret(match.group(0))

        result = pattern.sub(_sub, result)
    return result
