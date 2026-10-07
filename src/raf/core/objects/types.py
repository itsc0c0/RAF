"""Canonical enumerations of the R$F Security Object Model."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from raf.core.errors import InvalidInputError


class ObjectType(StrEnum):
    """Canonical object types. Every product speaks these types."""

    HOST = "host"
    USER = "user"
    IDENTITY = "identity"
    GROUP = "group"
    ROLE = "role"
    PERMISSION = "permission"
    ORGANIZATION = "organization"
    PROCESS = "process"
    FILE = "file"
    DIRECTORY = "directory"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    SERVICE = "service"
    PORT = "port"
    SESSION = "session"
    CONNECTION = "connection"
    CERTIFICATE = "certificate"
    SECRET = "secret"  # noqa: S105 - object type name, not a credential
    VULNERABILITY = "vulnerability"
    PACKAGE = "package"
    DEPENDENCY = "dependency"
    PROJECT = "project"
    POLICY = "policy"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    NETWORK = "network"
    EVENT = "event"
    ALERT = "alert"
    INCIDENT = "incident"
    EVIDENCE = "evidence"
    FINDING = "finding"
    SNAPSHOT = "snapshot"


#: Types whose canonical record lives in a dedicated table rather than ``objects``.
#: They are still addressable through the universal ``<type>:<key>`` ID scheme.
DEDICATED_TABLE_TYPES = frozenset({ObjectType.EVENT, ObjectType.FINDING, ObjectType.SNAPSHOT})

#: Types that represent "assets" for exposure and blast-radius accounting.
ASSET_TYPES = frozenset(
    {
        ObjectType.HOST,
        ObjectType.SERVICE,
        ObjectType.CLOUD_RESOURCE,
        ObjectType.CONTAINER,
        ObjectType.NETWORK,
        ObjectType.PROJECT,
    }
)

#: Types that represent principals (things that can act / hold access).
PRINCIPAL_TYPES = frozenset({ObjectType.USER, ObjectType.IDENTITY, ObjectType.GROUP, ObjectType.ROLE})

_CUSTOM_TYPE_RE = re.compile(r"^x-[a-z][a-z0-9_-]{1,40}$")


def validate_object_type(value: str) -> str:
    """Accept canonical types and plugin-defined ``x-<name>`` types."""
    text = value.strip().lower()
    if text in ObjectType.__members__.values() or _CUSTOM_TYPE_RE.match(text):
        return text
    aliases = {
        "hostname": "host",
        "account": "identity",
        "ipaddress": "ip",
        "ip_address": "ip",
        "fqdn": "domain",
        "cloudresource": "cloud_resource",
        "vuln": "vulnerability",
        "cve": "vulnerability",
        "proc": "process",
        "dir": "directory",
        "cert": "certificate",
        "net": "network",
    }
    if text in aliases:
        return aliases[text]
    raise InvalidInputError(
        f"Unknown object type '{value}'.",
        hint="Use a canonical type (raf help objects) or a plugin type prefixed with 'x-'.",
        details={"valid_types": [t.value for t in ObjectType]},
    )


class RelationshipType(StrEnum):
    """Canonical relationship types. Semantics are documented in docs/object-model.md."""

    # Identity and access
    LOGGED_INTO = "LOGGED_INTO"
    MEMBER_OF = "MEMBER_OF"
    HAS_ROLE = "HAS_ROLE"
    HAS_PERMISSION = "HAS_PERMISSION"
    HAS_IDENTITY = "HAS_IDENTITY"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_ASSUME = "CAN_ASSUME"
    ADMIN_OF = "ADMIN_OF"
    TRUSTS = "TRUSTS"
    OWNS = "OWNS"
    USES = "USES"
    AUTHENTICATES_AS = "AUTHENTICATES_AS"
    # Activity
    SPAWNED = "SPAWNED"
    STARTED = "STARTED"
    EXECUTED = "EXECUTED"
    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    READ = "READ"
    CONNECTED_TO = "CONNECTED_TO"
    RESOLVED = "RESOLVED"
    REQUESTED = "REQUESTED"
    # Infrastructure
    RESOLVES_TO = "RESOLVES_TO"
    RUNS = "RUNS"
    LISTENS_ON = "LISTENS_ON"
    HAS_ADDRESS = "HAS_ADDRESS"
    CAN_REACH = "CAN_REACH"
    DEPLOYS_TO = "DEPLOYS_TO"
    CONTAINS = "CONTAINS"
    CONTAINS_SECRET = "CONTAINS_SECRET"  # noqa: S105 - relationship type name
    PRESENTS = "PRESENTS"
    ISSUED_FOR = "ISSUED_FOR"
    # Software supply chain
    DEPENDS_ON = "DEPENDS_ON"
    DECLARES = "DECLARES"
    AFFECTS = "AFFECTS"
    # Policy
    ALLOWS = "ALLOWS"
    DENIES = "DENIES"
    APPLIES_TO = "APPLIES_TO"
    # Investigation
    INVOLVES = "INVOLVES"
    PART_OF = "PART_OF"
    SUPPORTS = "SUPPORTS"
    DERIVED_FROM = "DERIVED_FROM"
    RELATED_TO = "RELATED_TO"


_REL_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,48}$")


def validate_relationship_type(value: str) -> str:
    """Accept canonical relationship types and custom UPPER_SNAKE types (plugins)."""
    text = value.strip().upper().replace("-", "_").replace(" ", "_")
    if _REL_TYPE_RE.match(text):
        return text
    raise InvalidInputError(
        f"Invalid relationship type '{value}'.",
        hint="Relationship types are UPPER_SNAKE_CASE, e.g. LOGGED_INTO.",
    )


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: Any) -> Severity:
        if isinstance(value, Severity):
            return value
        if value is None:
            return cls.INFO
        if isinstance(value, int | float) and not isinstance(value, bool):
            # Numeric severities (0-10 CVSS-like or syslog 0-7 are ambiguous); map CVSS-like.
            number = float(value)
            if number >= 9:
                return cls.CRITICAL
            if number >= 7:
                return cls.HIGH
            if number >= 4:
                return cls.MEDIUM
            if number > 0:
                return cls.LOW
            return cls.INFO
        text = str(value).strip().upper()
        mapping = {
            "INFORMATIONAL": "INFO",
            "INFORMATION": "INFO",
            "NOTICE": "INFO",
            "DEBUG": "INFO",
            "NONE": "INFO",
            "WARN": "MEDIUM",
            "WARNING": "MEDIUM",
            "MODERATE": "MEDIUM",
            "ERROR": "HIGH",
            "IMPORTANT": "HIGH",
            "SEVERE": "HIGH",
            "CRIT": "CRITICAL",
            "ALERT": "CRITICAL",
            "EMERGENCY": "CRITICAL",
            "EMERG": "CRITICAL",
        }
        text = mapping.get(text, text)
        try:
            return cls(text)
        except ValueError as exc:
            raise InvalidInputError(
                f"Unknown severity '{value}'.", hint="Use INFO, LOW, MEDIUM, HIGH or CRITICAL."
            ) from exc


_SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


class ConfidenceLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


def confidence_level(value: float) -> ConfidenceLevel:
    if value >= 0.8:
        return ConfidenceLevel.HIGH
    if value >= 0.5:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def parse_confidence(value: Any, default: float = 0.8) -> float:
    """Accept floats in [0, 1], percentages, or LOW/MEDIUM/HIGH labels."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise InvalidInputError(f"Invalid confidence {value!r}.")
    if isinstance(value, int | float):
        number = float(value)
        if 1.0 < number <= 100.0:
            number /= 100.0
        if not 0.0 <= number <= 1.0:
            raise InvalidInputError(f"Confidence {value!r} must be between 0 and 1.")
        return round(number, 4)
    text = str(value).strip().upper()
    labels = {"LOW": 0.3, "MEDIUM": 0.6, "MED": 0.6, "HIGH": 0.9, "CONFIRMED": 1.0, "CERTAIN": 1.0}
    if text in labels:
        return labels[text]
    try:
        return parse_confidence(float(text), default)
    except ValueError as exc:
        raise InvalidInputError(f"Invalid confidence {value!r}.", hint="Use 0..1 or LOW/MEDIUM/HIGH.") from exc


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUPPRESSED = "SUPPRESSED"


class Criticality(StrEnum):
    """Business criticality of an asset (``metadata.criticality``)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    @classmethod
    def of(cls, metadata: dict[str, Any] | None, tags: list[str] | None = None) -> Criticality | None:
        raw = (metadata or {}).get("criticality")
        if isinstance(raw, str):
            try:
                return cls(raw.strip().lower())
            except ValueError:
                return None
        if tags and "critical" in tags:
            return cls.CRITICAL
        return None
