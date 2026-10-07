"""A small, safe filter language for events.

    type:auth.* actor:alice severity>=medium after:2026-10-06T22:00Z "exfil"

Terms combine with AND. Values become bound parameters in SQLAlchemy
expressions - nothing is ever interpolated into SQL text.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from raf.core.errors import InvalidInputError
from raf.core.objects.types import Severity
from raf.core.query.resolve import Resolver
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import parse_timestamp

KEYS = (
    "type",
    "category",
    "actor",
    "target",
    "object",
    "severity",
    "outcome",
    "source",
    "after",
    "before",
    "incident",
    "job",
    "synthetic",
)
_TERM = re.compile(r"^(?P<key>[a-z_]+)(?P<op>:|>=|<=|=)(?P<value>.*)$")


@dataclass(slots=True)
class ParsedFilter:
    query: EventQuery
    terms: list[str] = field(default_factory=list)


def parse_filter(text: str, *, resolver: Resolver | None = None, base: EventQuery | None = None) -> ParsedFilter:
    query = base.with_(**{}) if base is not None else EventQuery()
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise InvalidInputError(f"Could not parse filter: {exc}.") from exc
    free: list[str] = []
    terms: list[str] = []
    types: list[str] = list(query.event_types or [])
    categories: list[str] = list(query.categories or [])
    objects: list[str] = list(query.object_ids or [])

    def resolve(ref: str) -> str:
        if resolver is None:
            return ref
        return resolver.resolve(ref).id

    for token in tokens:
        match = _TERM.match(token)
        if not match or match["key"] not in KEYS:
            if match and ":" in token and match["key"] not in KEYS and not token.startswith(("http:", "https:")):
                raise InvalidInputError(f"Unknown filter key '{match['key']}'.", hint="Keys: " + ", ".join(KEYS))
            free.append(token)
            continue
        key, op, value = match["key"], match["op"], match["value"].strip()
        if not value:
            raise InvalidInputError(f"Filter '{token}' has no value.")
        terms.append(token)
        if key == "type":
            types.append(value)
        elif key == "category":
            categories.append(value.lower())
        elif key == "actor":
            query.actor = resolve(value)
        elif key == "target":
            query.target = resolve(value)
        elif key == "object":
            objects.append(resolve(value))
        elif key == "severity":
            if op not in (">=", ":", "="):
                raise InvalidInputError("Use severity>=LEVEL or severity:LEVEL.")
            query.min_severity = Severity.parse(value)
        elif key == "outcome":
            query.outcome = value.lower()
        elif key == "source":
            query.source = value
        elif key == "after":
            query.start = parse_timestamp(value)
        elif key == "before":
            query.end = parse_timestamp(value)
        elif key == "incident":
            query.incident_id = resolver.resolve(value, types=["incident"]).id if resolver else value
        elif key == "job":
            query.job_ids = [value]
        elif key == "synthetic":
            query.synthetic = value.lower() in ("1", "true", "yes")
    query.event_types = types or None
    query.categories = categories or None
    query.object_ids = objects or None
    if free:
        query.text = " ".join(free)
        terms.append(f'"{query.text}"')
    return ParsedFilter(query=query, terms=terms)
