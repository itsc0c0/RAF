#!/usr/bin/env python3
"""Regenerate the deterministic Raven Industries fixtures under fixtures/.

Usage: python scripts/generate_fixtures.py [--check]

--check verifies that the committed fixtures match what the generator produces
(used in CI so fixtures never drift from src/raf/data/raven.py).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from raf.data import raven  # noqa: E402


def jsonl(records: Iterable[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in records)


def outputs() -> dict[str, Callable[[], str]]:
    files: dict[str, Callable[[], str]] = {
        "raven-events.jsonl": lambda: jsonl(raven.raven_event_file_records()),
        "raven/inventory.jsonl": lambda: jsonl(raven.inventory_records()),
        "evidence/auth.log": raven.evidence_auth_log,
        "evidence/edr-process-events.jsonl": lambda: jsonl(raven.evidence_edr_events()),
        "evidence/proxy.csv": raven.evidence_proxy_csv,
        "evidence/analyst-notes.txt": lambda: raven.EVIDENCE_NOTES,
        "policies/raven-policies.json": lambda: json.dumps(raven.policy_document(), indent=2) + "\n",
        "policies/raven-policies-2026-09.json": lambda: (
            json.dumps(raven.policy_document(raven.PREVIOUS_POLICY_REVISION), indent=2) + "\n"
        ),
        "policies/raven-fw-export.csv": raven.firewall_csv,
    }
    try:
        from raf.data import raven_extra
    except ImportError:
        return files
    files.update(raven_extra.fixture_outputs())
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if fixtures are out of date")
    args = parser.parse_args()
    stale = []
    for relative, produce in sorted(outputs().items()):
        target = ROOT / "fixtures" / relative
        content = produce()
        data = content.encode("utf-8") if isinstance(content, str) else content
        if args.check:
            if not target.exists() or target.read_bytes() != data:
                stale.append(relative)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        print(f"wrote fixtures/{relative} ({len(data):,} bytes)")
    if stale:
        print("stale fixtures: " + ", ".join(stale) + " (run scripts/generate_fixtures.py)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
