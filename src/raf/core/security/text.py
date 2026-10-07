"""Rendering untrusted text safely in a terminal.

Imported data (log lines, user agents, file names, container output) may contain terminal escape
sequences or bidirectional overrides that rewrite what an analyst sees. Everything R$F prints from
imported data goes through :func:`terminal_safe`.
"""

from __future__ import annotations

import re

#: C0/C1 control characters except tab and newline, zero-width characters, line/paragraph
#: separators and bidirectional overrides (code point ranges, inclusive).
_UNSAFE_RANGES = (
    (0x00, 0x08),
    (0x0B, 0x1F),
    (0x7F, 0x9F),
    (0x200B, 0x200F),
    (0x2028, 0x2029),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)
_UNSAFE_CHARS_RE = re.compile("[" + "".join(f"\\u{a:04x}-\\u{b:04x}" for a, b in _UNSAFE_RANGES) + "]")


def _escape_char(match: re.Match[str]) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def terminal_safe(text: str) -> str:
    """Escape control characters, terminal escape sequences and bidi overrides (keeps \\n and \\t)."""
    return _UNSAFE_CHARS_RE.sub(_escape_char, text.replace("\r\n", "\n"))


def has_unsafe_chars(text: str) -> bool:
    return _UNSAFE_CHARS_RE.search(text) is not None
