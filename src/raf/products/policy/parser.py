"""Ingestion parser so ``raf import`` / ``raf analyze`` recognize policy documents.

Policies become ``policy`` objects carrying the normalized policy in ``metadata.policy``.
``raf policy import`` additionally links each policy to the workspace objects it references.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any, ClassVar

from raf.core.errors import InvalidInputError
from raf.core.ingestion.base import ParseContext, Parser, RawRecord
from raf.products.policy.formats import MAX_POLICY_FILE_BYTES, POLICY_SUFFIXES, parse_policy_text, sniff_policy
from raf.products.policy.model import Policy


def policy_object_record(policy: Policy, source_label: str) -> dict[str, Any]:
    return {
        "kind": "object",
        "type": "policy",
        "name": policy.name,
        "key": policy.id,
        "metadata": {
            "domain": policy.domain,
            "evaluation": policy.evaluation,
            "default": policy.default,
            "revision": policy.revision,
            "rules": len(policy.rules),
            "digest": policy.digest(),
            "source": policy.source or source_label,
            "policy": policy.model_dump(mode="json"),
        },
        "tags": ["policy", policy.domain],
    }


class PolicyFileParser(Parser):
    name: ClassVar[str] = "raf-policy"
    version: ClassVar[str] = "1.0"
    description: ClassVar[str] = (
        "Policy documents: raf-policy/1 (JSON/YAML), AWS-style IAM JSON, CSV firewall exports, iptables-save"
    )
    extensions: ClassVar[tuple[str, ...]] = POLICY_SUFFIXES
    normalizer: ClassVar[str] = "raf-native"

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        return sniff_policy(head, path.suffix.lower())

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        data = stream.read(MAX_POLICY_FILE_BYTES + 1)
        if len(data) > MAX_POLICY_FILE_BYTES:
            yield RawRecord.rejected("document", f"Policy document exceeds {MAX_POLICY_FILE_BYTES:,} bytes.")
            return
        path = ctx.source.path
        name = path.name if path else ctx.source.name
        try:
            policy_set = parse_policy_text(
                data.decode("utf-8-sig", "replace"),
                source=name,
                suffix=path.suffix if path and path.suffix else ".json",
            )
        except InvalidInputError as exc:
            yield RawRecord.rejected("document", exc.message)
            return
        for warning in policy_set.warnings:
            ctx.warnings.append(f"{name}: {warning}")
        for policy in policy_set.policies:
            yield RawRecord(policy_object_record(policy, name), f"policy {policy.id}", parser_label=self.label)
