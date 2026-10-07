"""Deterministic identifiers.

Object IDs are ``<type>:<normalized-key>`` (for example ``host:ws-04`` or
``ip:10.0.0.5``). Because IDs are derived from content rather than generated
randomly, re-importing the same data is idempotent and every product refers to
the same entity with the same ID.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from raf.core.errors import InvalidInputError
from raf.core.objects.types import ObjectType, validate_object_type

MAX_KEY_LENGTH = 200

_CASE_INSENSITIVE = frozenset(
    {
        ObjectType.HOST,
        ObjectType.USER,
        ObjectType.IDENTITY,
        ObjectType.GROUP,
        ObjectType.ROLE,
        ObjectType.PERMISSION,
        ObjectType.ORGANIZATION,
        ObjectType.DOMAIN,
        ObjectType.NETWORK,
        ObjectType.SERVICE,
        ObjectType.INCIDENT,
        ObjectType.CERTIFICATE,
        ObjectType.PACKAGE,
        ObjectType.DEPENDENCY,
        ObjectType.POLICY,
        ObjectType.SNAPSHOT,
    }
)
_WS_RE = re.compile(r"\s+")


def digest(*parts: object, length: int = 24) -> str:
    """Stable short SHA-256 digest of the given parts."""
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(str(part).encode("utf-8", "surrogatepass"))
        hasher.update(b"\x1f")
    return hasher.hexdigest()[:length]


def normalize_key(obj_type: str, key: str) -> str:
    """Normalize a natural key for the given object type."""
    otype = validate_object_type(obj_type)
    text = _WS_RE.sub(" ", str(key)).strip()
    if not text:
        raise InvalidInputError(f"Empty key for object type '{otype}'.")
    if otype == ObjectType.IP:
        candidate = text.strip("[]")
        if "%" in candidate:
            candidate = candidate.split("%", 1)[0]
        try:
            text = ipaddress.ip_address(candidate).compressed
        except ValueError as exc:
            raise InvalidInputError(f"'{key}' is not a valid IP address.") from exc
    elif otype == ObjectType.DOMAIN:
        text = text.lower().rstrip(".")
    elif otype == ObjectType.URL:
        try:
            parts = urlsplit(text)
        except ValueError as exc:
            raise InvalidInputError(f"'{key}' is not a valid URL.") from exc
        text = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, ""))
    elif otype in _CASE_INSENSITIVE:
        text = text.lower()
    if len(text) > MAX_KEY_LENGTH:
        text = text[:MAX_KEY_LENGTH] + "~" + digest(text, length=16)
    return text


def object_id(obj_type: str, key: str) -> str:
    otype = validate_object_type(obj_type)
    return f"{otype}:{normalize_key(otype, key)}"


def split_id(entity_id: str) -> tuple[str, str]:
    """Split ``type:key``. Raises :class:`InvalidInputError` when the prefix is not a type."""
    if ":" not in entity_id:
        raise InvalidInputError(f"'{entity_id}' is not a typed R$F ID.")
    prefix, key = entity_id.split(":", 1)
    return validate_object_type(prefix), key


def try_split_id(entity_id: str) -> tuple[str, str] | None:
    try:
        return split_id(entity_id)
    except InvalidInputError:
        return None


def relationship_id(source_id: str, rel_type: str, target_id: str) -> str:
    return "rel:" + digest(source_id, rel_type, target_id)


def event_id(*parts: object) -> str:
    return "event:" + digest(*parts)


def finding_id(product: str, rule: str, subject: str) -> str:
    return f"finding:{product}:{rule}:{digest(subject, length=12)}"


_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def slugify(text: str, max_length: int = 64) -> str:
    slug = _SLUG_RE.sub("-", text.strip().lower()).strip("-.")
    return slug[:max_length] or "item"
