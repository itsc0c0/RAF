"""Policy file formats -> the normalized :mod:`raf.products.policy.model`.

Supported (auto-detected):

* ``raf-policy/1`` - R$F native JSON or YAML (network rules and identity statements)
* ``aws-iam``      - AWS-IAM-style JSON documents (``Version``/``Statement``)
* ``csv-firewall`` - firewall rule exports as CSV (id, action, source, destination, protocol, port, ...)

Policy files are untrusted input: parsed with safe loaders only, size- and count-limited, and
every identifier is normalized; nothing is ever executed or interpolated into commands.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import yaml

from raf.core.errors import InvalidInputError
from raf.core.ids import slugify
from raf.products.policy.model import (
    ANY,
    MAX_RULES_PER_POLICY,
    Policy,
    PolicyRule,
    PolicySet,
    default_evaluation,
    normalize_action,
    normalize_address,
    normalize_ports,
    normalize_principal,
    normalize_resource,
)

MAX_POLICY_FILE_BYTES = 5 * 1024 * 1024
POLICY_SUFFIXES = (".json", ".yaml", ".yml", ".csv")
_CSV_ALIASES = {
    "id": ("id", "rule", "rule_id", "name", "rule_name"),
    "effect": ("action", "effect", "decision", "verdict"),
    "source": ("source", "src", "from", "source_zone", "src_zone", "source_address"),
    "destination": ("destination", "dst", "to", "destination_zone", "dst_zone", "destination_address"),
    "protocol": ("protocol", "proto"),
    "port": ("port", "ports", "dport", "service", "destination_port"),
    "description": ("description", "comment", "remark", "note"),
    "enabled": ("enabled", "status", "state"),
    "policy": ("policy", "ruleset", "table", "chain"),
}


class _NoAliasLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses anchors/aliases (prevents alias-expansion resource exhaustion)."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()  # type: ignore[no-untyped-call]
            raise yaml.composer.ComposerError(
                None, None, "YAML aliases are not allowed in policy files", event.start_mark
            )
        return super().compose_node(parent, index)


def _as_list(value: Any) -> list[Any]:
    """Selector lists: a scalar or a list of scalars (nested structures are rejected)."""
    if value is None:
        return []
    items = list(value) if isinstance(value, list | tuple) else [value]
    for item in items:
        if not isinstance(item, str | int | float | bool):
            raise InvalidInputError("Policy selectors must be strings (or lists of strings).")
    return items


def _effect(value: Any, where: str) -> str:
    text = str(value or "").strip().lower()
    if text in ("allow", "accept", "permit", "pass"):
        return "allow"
    if text in ("deny", "drop", "reject", "block"):
        return "deny"
    raise InvalidInputError(f"{where}: unknown action/effect '{value}'.", hint="Use allow or deny.")


def _enabled(value: Any) -> bool:
    if value is None or value == "":
        return True
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("false", "no", "0", "disabled", "off", "inactive")


def _rule_id(raw: Any, index: int) -> str:
    text = slugify(str(raw)) if raw not in (None, "") else ""
    return text or f"rule-{index + 1}"


# --------------------------------------------------------------------------- native


def _native_rule(policy_id: str, domain: str, raw: dict[str, Any], index: int) -> PolicyRule:
    where = f"{policy_id} rule {index + 1}"
    if not isinstance(raw, dict):
        raise InvalidInputError(f"{where}: each rule must be an object.")
    effect = _effect(raw.get("effect", raw.get("action")), where)
    common = {
        "id": _rule_id(raw.get("id") or raw.get("name"), index),
        "policy": policy_id,
        "order": index,
        "effect": effect,
        "description": str(raw.get("description") or "")[:500],
        "enabled": _enabled(raw.get("enabled")),
        "metadata": dict(raw["metadata"]) if isinstance(raw.get("metadata"), dict) else {},
    }
    if domain == "network":
        sources = _as_list(raw.get("sources", raw.get("source", ANY))) or [ANY]
        destinations = _as_list(raw.get("destinations", raw.get("destination", ANY))) or [ANY]
        ports = raw.get("ports", raw.get("port", ANY))
        return PolicyRule(
            **common,
            sources=sorted({normalize_address(s) for s in sources}),
            destinations=sorted({normalize_address(d) for d in destinations}),
            ports=normalize_ports(ports),
            actions=["*"],
        )
    principals = _as_list(raw.get("principals", raw.get("principal", "*"))) or ["*"]
    resources = _as_list(raw.get("resources", raw.get("resource", "*"))) or ["*"]
    actions = _as_list(raw.get("actions", raw.get("action_names", "*"))) or ["*"]
    return PolicyRule(
        **common,
        sources=sorted({normalize_principal(p) for p in principals}),
        destinations=sorted({normalize_resource(r) for r in resources}),
        ports=[ANY],
        actions=sorted({normalize_action(a) for a in actions}),
    )


def _native_policy(raw: dict[str, Any], index: int, revision: str | None, source: str | None) -> Policy:
    if not isinstance(raw, dict):
        raise InvalidInputError(f"policies[{index}] must be an object.")
    policy_id = slugify(str(raw.get("id") or raw.get("name") or f"policy-{index + 1}"))
    domain = str(raw.get("domain") or ("identity" if "statements" in raw else "network")).lower()
    if domain not in ("network", "identity", "service"):
        raise InvalidInputError(
            f"Policy '{policy_id}': unknown domain '{domain}'.", hint="Use network, identity or service."
        )
    rules_raw = raw.get("rules", raw.get("statements", []))
    if not isinstance(rules_raw, list):
        raise InvalidInputError(f"Policy '{policy_id}': rules must be a list.")
    if len(rules_raw) > MAX_RULES_PER_POLICY:
        raise InvalidInputError(f"Policy '{policy_id}' has {len(rules_raw)} rules (limit {MAX_RULES_PER_POLICY}).")
    evaluation = str(raw.get("evaluation") or default_evaluation(domain))
    if evaluation not in ("first-match", "deny-overrides"):
        raise InvalidInputError(f"Policy '{policy_id}': unknown evaluation '{evaluation}'.")
    rules = [_native_rule(policy_id, domain, r, i) for i, r in enumerate(rules_raw)]
    _dedupe_rule_ids(rules)
    scope = sorted({normalize_address(s) for s in _as_list(raw.get("scope"))}) if domain == "network" else []
    return Policy(
        id=policy_id,
        name=str(raw.get("name") or policy_id)[:200],
        domain=domain,
        evaluation=evaluation,
        default=_effect(raw.get("default", "deny"), f"policy {policy_id} default"),
        revision=str(raw.get("revision") or revision) if (raw.get("revision") or revision) else None,
        description=str(raw.get("description") or "")[:1000],
        source=source,
        scope=scope,
        rules=rules,
    )


def _dedupe_rule_ids(rules: list[PolicyRule]) -> None:
    seen: dict[str, int] = {}
    for rule in rules:
        if rule.id in seen:
            seen[rule.id] += 1
            rule.id = f"{rule.id}-{seen[rule.id]}"
        else:
            seen[rule.id] = 1


def parse_native(doc: dict[str, Any], source: str | None) -> PolicySet:
    revision = str(doc["revision"]) if doc.get("revision") else None
    policies_raw = doc.get("policies")
    if policies_raw is None and ("rules" in doc or "statements" in doc):
        policies_raw = [doc]
    if not isinstance(policies_raw, list) or not policies_raw:
        raise InvalidInputError(
            "Policy document has no 'policies' list.", hint="See docs/products/policy.md for the raf-policy/1 format."
        )
    policies = [_native_policy(p, i, revision, source) for i, p in enumerate(policies_raw)]
    ids = [p.id for p in policies]
    if len(set(ids)) != len(ids):
        raise InvalidInputError("Policy IDs must be unique within a document.")
    return PolicySet(
        name=str(doc.get("name") or (Path(source).stem if source else "policies"))[:200],
        format="raf-policy/1",
        revision=revision,
        source=source,
        policies=policies,
    )


# --------------------------------------------------------------------------- AWS-style IAM


def _aws_resource(value: Any) -> str:
    text = str(value).strip()
    if text == "*":
        return "*"
    if ":" in text and text.split(":", 1)[0] in (
        "host",
        "service",
        "cloud_resource",
        "network",
        "identity",
        "role",
        "group",
        "user",
        "project",
        "container",
        "secret",
    ):
        return normalize_resource(text)
    return "cloud_resource:" + text[:400]


def parse_aws(doc: dict[str, Any], source: str | None, *, principal: str | None = None) -> PolicySet:
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise InvalidInputError("AWS-style policy has no Statement list.")
    if len(statements) > MAX_RULES_PER_POLICY:
        raise InvalidInputError(f"Policy has {len(statements)} statements (limit {MAX_RULES_PER_POLICY}).")
    stem = Path(source).stem if source else "iam-policy"
    policy_id = slugify(str(doc.get("Id") or stem)) or "iam-policy"
    warnings: list[str] = []
    rules: list[PolicyRule] = []
    for index, st in enumerate(statements):
        if not isinstance(st, dict):
            raise InvalidInputError(f"Statement {index + 1} must be an object.")
        if "NotAction" in st or "NotResource" in st or "NotPrincipal" in st:
            warnings.append(f"statement {index + 1}: NotAction/NotResource/NotPrincipal are not modeled; skipped")
            continue
        principals: list[str]
        unspecified = False
        raw_principal = st.get("Principal")
        if raw_principal in (None, ""):
            principals = [normalize_principal(principal)] if principal else ["*"]
            unspecified = principal is None
        elif raw_principal == "*":
            principals = ["*"]
        else:
            values = raw_principal.values() if isinstance(raw_principal, dict) else [raw_principal]
            principals = sorted({"identity:" + str(v)[:300] for vs in values for v in _as_list(vs)})
        metadata: dict[str, Any] = {}
        if unspecified:
            metadata["principal_unspecified"] = True
        if st.get("Condition"):
            metadata["conditional"] = True
            warnings.append(f"statement {index + 1}: conditions are recorded but not evaluated")
        rules.append(
            PolicyRule(
                id=_rule_id(st.get("Sid"), index),
                policy=policy_id,
                order=index,
                effect=_effect(st.get("Effect"), f"statement {index + 1}"),
                sources=principals,
                destinations=sorted({_aws_resource(r) for r in _as_list(st.get("Resource", "*"))}) or ["*"],
                ports=[ANY],
                actions=sorted({normalize_action(a) for a in _as_list(st.get("Action", "*"))}) or ["*"],
                metadata=metadata,
            )
        )
    _dedupe_rule_ids(rules)
    policy = Policy(
        id=policy_id,
        name=stem,
        domain="identity",
        evaluation="deny-overrides",
        default="deny",
        revision=str(doc.get("Version")) if doc.get("Version") else None,
        source=source,
        rules=rules,
    )
    return PolicySet(
        name=stem, format="aws-iam", revision=policy.revision, source=source, policies=[policy], warnings=warnings
    )


# --------------------------------------------------------------------------- CSV firewall


def _csv_column(header: list[str], key: str) -> int | None:
    lowered = [h.strip().lower().replace(" ", "_") for h in header]
    for alias in _CSV_ALIASES[key]:
        if alias in lowered:
            return lowered.index(alias)
    return None


def parse_csv(text: str, source: str | None) -> PolicySet:
    reader = csv.reader(io.StringIO(text))
    rows = [row for row in reader if any(cell.strip() for cell in row)]
    if not rows:
        raise InvalidInputError("Empty CSV policy file.")
    header, body = rows[0], rows[1:]
    columns = {key: _csv_column(header, key) for key in _CSV_ALIASES}
    if columns["effect"] is None or columns["source"] is None or columns["destination"] is None:
        raise InvalidInputError(
            "CSV firewall export needs action, source and destination columns.",
            hint="Recognized headers: id, action, source, destination, protocol, port, description, enabled, policy.",
        )
    if len(body) > MAX_RULES_PER_POLICY:
        raise InvalidInputError(f"CSV has {len(body)} rules (limit {MAX_RULES_PER_POLICY}).")
    default_policy = slugify(Path(source).stem if source else "firewall") or "firewall"

    def cell(row: list[str], key: str) -> str:
        idx = columns[key]
        return row[idx].strip() if idx is not None and idx < len(row) else ""

    grouped: dict[str, list[PolicyRule]] = {}
    for index, row in enumerate(body):
        policy_id = slugify(cell(row, "policy")) if cell(row, "policy") else default_policy
        protocol = cell(row, "protocol").lower()
        ports_raw = [p.strip() for p in cell(row, "port").replace(";", ",").split(",") if p.strip()] or [ANY]
        if protocol and protocol not in (ANY, "*", "ip", "all"):
            ports_raw = [p if "/" in p or p.lower() in (ANY, "*") else f"{protocol}/{p}" for p in ports_raw]
            ports_raw = [protocol if p.lower() in (ANY, "*") else p for p in ports_raw]
        where = f"row {index + 2}"
        rules = grouped.setdefault(policy_id, [])
        rules.append(
            PolicyRule(
                id=_rule_id(cell(row, "id"), index),
                policy=policy_id,
                order=len(rules),
                effect=_effect(cell(row, "effect"), where),
                sources=sorted(
                    {normalize_address(s) for s in cell(row, "source").replace(";", ",").split(",") if s.strip()}
                    or {ANY}
                ),
                destinations=sorted(
                    {normalize_address(d) for d in cell(row, "destination").replace(";", ",").split(",") if d.strip()}
                    or {ANY}
                ),
                ports=normalize_ports(ports_raw),
                description=cell(row, "description")[:500],
                enabled=_enabled(cell(row, "enabled")),
            )
        )
    policies = []
    for policy_id, rules in grouped.items():
        _dedupe_rule_ids(rules)
        policies.append(
            Policy(
                id=policy_id,
                name=policy_id,
                domain="network",
                evaluation="first-match",
                default="deny",
                source=source,
                rules=rules,
            )
        )
    return PolicySet(
        name=default_policy,
        format="csv-firewall",
        source=source,
        policies=policies,
        warnings=["CSV exports carry no default action; 'deny' is assumed"],
    )


# --------------------------------------------------------------------------- entry points


def sniff_policy(head: bytes, suffix: str) -> float:
    text = head[:65536].decode("utf-8", "replace")
    lowered = text.lower()
    if "raf-policy/" in lowered:
        return 0.98
    if suffix in (".json", ".yaml", ".yml"):
        if '"statement"' in lowered and '"effect"' in lowered:
            return 0.93
        if (
            "policies" in lowered
            and ("rules" in lowered or "statements" in lowered)
            and ("allow" in lowered or "deny" in lowered)
        ):
            return 0.9
    if suffix == ".csv":
        first = lowered.splitlines()[0] if lowered else ""
        cells = {c.strip().replace(" ", "_") for c in first.split(",")}
        if (
            cells & set(_CSV_ALIASES["effect"])
            and cells & set(_CSV_ALIASES["source"])
            and cells & set(_CSV_ALIASES["destination"])
        ):
            return 0.95
    return 0.0


def parse_policy_text(
    text: str, *, source: str | None = None, suffix: str = ".json", principal: str | None = None
) -> PolicySet:
    if len(text.encode("utf-8", "replace")) > MAX_POLICY_FILE_BYTES:
        raise InvalidInputError(f"Policy document exceeds {MAX_POLICY_FILE_BYTES // (1024 * 1024)} MB.")
    suffix = suffix.lower()
    if suffix == ".csv":
        return parse_csv(text, source)
    try:
        doc = yaml.load(text, Loader=_NoAliasLoader) if suffix in (".yaml", ".yml") else json.loads(text)  # noqa: S506
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise InvalidInputError(
            f"Policy document is not valid {'YAML' if suffix != '.json' else 'JSON'}: {str(exc).splitlines()[0][:200]}"
        ) from exc
    except RecursionError as exc:
        raise InvalidInputError("Policy document nesting is too deep.") from exc
    if not isinstance(doc, dict):
        raise InvalidInputError("Policy document must be a JSON/YAML object.")
    if "Statement" in doc:
        return parse_aws(doc, source, principal=principal)
    return parse_native(doc, source)


def load_policy_file(path: Path, *, principal: str | None = None) -> PolicySet:
    if not path.is_file():
        raise InvalidInputError(f"{path} is not a file.")
    size = path.stat().st_size
    if size > MAX_POLICY_FILE_BYTES:
        raise InvalidInputError(
            f"{path.name} is {size:,} bytes; policy files are limited to {MAX_POLICY_FILE_BYTES // (1024 * 1024)} MB."
        )
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    return parse_policy_text(text, source=path.name, suffix=path.suffix or ".json", principal=principal)


def load_policy_path(path: Path, *, principal: str | None = None) -> list[PolicySet]:
    """A policy file, or every policy file (json/yaml/yml/csv) directly inside a directory."""
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() in POLICY_SUFFIXES)
        if not files:
            raise InvalidInputError(f"No policy files (.json, .yaml, .yml, .csv) in {path}.")
        return [load_policy_file(f, principal=principal) for f in files]
    return [load_policy_file(path, principal=principal)]
