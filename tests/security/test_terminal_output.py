"""Imported data must never be able to emit terminal control sequences through the CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

HOSTILE = "pwn \x1b]0;owned-title\x07 \x1b[2J\x1b[31mred ‮evil‬ \x08\x08x"


def test_hostile_text_is_escaped_in_every_view(raf_home: Path, cli: Any, tmp_path: Path) -> None:
    records = [
        {
            "timestamp": "2026-10-06T10:00:00Z",
            "event_type": "auth.login",
            "actor": "mallory",
            "target": "WS-66",
            "message": HOSTILE,
            "incident": "INC-666",
        },
        {
            "timestamp": "2026-10-06T10:01:00Z",
            "event_type": "process.start",
            "actor": "mallory",
            "host": "WS-66",
            "message": HOSTILE,
            "attributes": {"command_line": HOSTILE, "image": "/usr/bin/sh", "pid": 4242},
            "incident": "INC-666",
        },
    ]
    data = tmp_path / "hostile.jsonl"
    data.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    assert cli("import", str(data)).exit_code == 0
    for args in (("timeline", "INC-666"), ("replay", "INC-666"), ("lens", "INC-666"), ("trace", "mallory")):
        result = cli(*args)
        assert result.exit_code == 0, result.stderr
        output = result.stdout + result.stderr
        assert "\x1b" not in output and "‮" not in output and "\x08" not in output, args
    shown = cli("timeline", "INC-666").stdout
    assert "\\x1b" in shown  # the sequence is visible, escaped, instead of being executed
