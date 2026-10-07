"""A small, safe filter language for events.

    type:auth.* actor:alice severity>=medium time>=2026-10-06T22:00:00Z "exfil"

A filter is a list of terms separated by spaces and quoted like a shell command line. A term is
``key:value`` (``key=value`` means the same) or, for the ordered keys ``severity`` and ``time``, a
comparison such as ``time>=T``. A token that starts with a quote is always free text, whatever it
contains; an unquoted ``word:...`` or ``word=...`` whose word is not a key is an error.

Terms combine with AND and **narrow** what the command already selected - its scope (an object,
an incident, an analysis or a job) and its options (``--from``/``--to``, ``--type``, ``--source``
...). They never widen it: when the event store cannot express a combination (events that involve
two different objects, for example), the filter is rejected with an explanation instead of being
approximated. Repeated ``type:``, ``category:``, ``object:`` and ``job:`` terms are alternatives
(any of them); a filter holds at most one free-text term (a word or a quoted phrase).

Values become bound parameters in SQLAlchemy expressions - nothing is ever interpolated into SQL.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

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
    "time",
    "after",
    "before",
    "incident",
    "job",
    "synthetic",
)
_TERM = re.compile(r"^(?P<key>[a-z_]+)(?P<op>>=|<=|>|<|:|=)(?P<value>.*)$", re.DOTALL)
_JOB_ID = re.compile(r"^job-\d+$")
_WHITESPACE = " \t\r\n"
_TRUE = ("1", "true", "yes")
_FALSE = ("0", "false", "no")
#: Stored timestamps have microsecond precision: ``time>T`` is ``time>=T+1µs``.
_TICK = timedelta(microseconds=1)


@dataclass(slots=True)
class ParsedFilter:
    query: EventQuery
    terms: list[str] = field(default_factory=list)


def parse_filter(text: str, *, resolver: Resolver | None = None, base: EventQuery | None = None) -> ParsedFilter:
    """The events of ``base`` (the command's scope and options) that match every term of ``text``."""
    base = base if base is not None else EventQuery()
    terms: list[str] = []
    texts: list[str] = []
    types: list[str] = []
    categories: list[str] = []
    objects: list[str] = []
    jobs: list[str] = []
    incidents: list[str] = []
    sources: list[str] = []
    equal: dict[str, list[str | bool]] = {"actor": [], "target": [], "outcome": [], "synthetic": []}
    severities: list[Severity] = []
    starts: list[datetime] = []
    ends: list[datetime] = []
    nothing = False  # a term no event can satisfy (severity>critical, two different outcomes, ...)

    def resolve(key: str, ref: str, types: list[str] | None = None) -> str:
        if resolver is None:
            return ref
        resolved = resolver.resolve(ref, types=types)
        if resolved.kind != "object":  # an event:, finding: or snapshot: ID
            raise InvalidInputError(f"{key}: takes an object, and '{ref}' is not one ({resolved.kind}).")
        return resolved.id

    for token, quoted in split_terms(text):
        match = None if quoted else _TERM.match(token)
        if match is None or (match["op"] == ":" and match["value"].startswith("//")):  # free text; URLs
            if token.strip():
                texts.append(token)
            continue
        key, op, value = match["key"], match["op"], match["value"].strip()
        if key not in KEYS:
            raise InvalidInputError(
                f"Unknown filter key '{key}'.",
                hint="Keys: " + ", ".join(KEYS) + ". Quote free text that contains ':' or '=' "
                '(for example "error: disk full").',
            )
        _check_operator(key, op)
        if not value:
            raise InvalidInputError(f"Filter '{token}' has no value.")
        terms.append(token)
        if key == "type":
            types.append(value)
        elif key == "category":
            categories.append(value.lower())
        elif key in ("actor", "target"):
            equal[key].append(resolve(key, value))
        elif key == "object":
            objects.append(resolve(key, value))
        elif key == "outcome":
            equal["outcome"].append(value.lower())
        elif key == "synthetic":
            equal["synthetic"].append(_boolean(value))
        elif key == "source":
            sources.append(value)
        elif key == "severity":
            level = Severity.parse(value)
            if op == ">":
                above = [s for s in Severity if s.rank > level.rank]
                if not above:
                    nothing = True
                    continue
                level = above[0]
            severities.append(level)
        elif key in ("time", "after", "before"):
            moment = parse_timestamp(value)
            if key == "after" or op == ">=":
                starts.append(moment)
            elif op == ">":
                starts.append(moment + _TICK)
            elif key == "before" or op == "<=":
                ends.append(moment)
            else:
                ends.append(moment - _TICK)
        elif key == "incident":
            incidents.append(resolve(key, value, ["incident"]))
        elif key == "job":
            jobs.append(_job_id(value, resolver))
    if len(texts) > 1:
        raise InvalidInputError(
            "A filter holds one free-text term.",
            reason="Free text found: " + ", ".join(f"'{t}'" for t in texts) + ".",
            hint='Quote the words to search for them as one phrase: "' + " ".join(texts) + '".',
        )

    query = base.with_()
    if types:
        query.event_types = _types_in_both(base.event_types, types)
    if categories:
        query.categories = _in_both(base.categories, categories)
    if jobs:
        query.job_ids = _in_both(base.job_ids, jobs)
    for wanted, name in ((types, "event_types"), (categories, "categories"), (jobs, "job_ids")):
        if wanted and not getattr(query, name):
            nothing = True  # none of the filter's alternatives is inside the scope and options
    if objects:
        query.object_ids = _objects_in_both(base.object_ids, objects)
    for name, values in equal.items():
        current = getattr(base, name)
        distinct = list(dict.fromkeys([*([current] if current is not None else []), *values]))
        if len(distinct) > 1:
            nothing = True  # an event has one actor, one target, one outcome
        elif distinct:
            setattr(query, name, distinct[0])
    if incidents:
        query.incident_id = _one_incident(base.incident_id, incidents)
    if sources:
        query.source = contains_all("source", [base.source, *sources])
    if texts:
        query.text = contains_all("text", [base.text, *texts])
    if severities:
        query.min_severity = max([*severities, *_present(base.min_severity)], key=lambda s: s.rank)
    if starts:
        query.start = max([*starts, *_present(base.start)])
    if ends:
        query.end = min([*ends, *_present(base.end)])
    if nothing:
        query.event_ids = []
    if texts:
        terms.append(f'"{texts[0]}"')
    return ParsedFilter(query=query, terms=terms)


def split_terms(text: str) -> list[tuple[str, bool]]:
    """Split like a POSIX shell (the rules of ``shlex.split``); each token says whether it began with a quote."""
    tokens: list[tuple[str, bool]] = []
    current: list[str] = []
    started = quoted = False
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char in _WHITESPACE:
            if started:
                tokens.append(("".join(current), quoted))
                current, started, quoted = [], False, False
            i += 1
            continue
        if not started:
            started, quoted = True, char in "'\""
        if char == "'":
            end = text.find("'", i + 1)
            if end < 0:
                raise InvalidInputError("Could not parse filter: No closing quotation.")
            current.append(text[i + 1 : end])
            i = end + 1
        elif char == '"':
            i += 1
            while True:
                if i >= n:
                    raise InvalidInputError("Could not parse filter: No closing quotation.")
                inner = text[i]
                if inner == '"':
                    i += 1
                    break
                if inner == "\\" and i + 1 < n and text[i + 1] in '"\\':
                    current.append(text[i + 1])
                    i += 2
                    continue
                current.append(inner)
                i += 1
        elif char == "\\":
            if i + 1 >= n:
                raise InvalidInputError("Could not parse filter: No escaped character.")
            current.append(text[i + 1])
            i += 2
        else:
            current.append(char)
            i += 1
    if started:
        tokens.append(("".join(current), quoted))
    return tokens


def contains_all(name: str, values: Iterable[str | None]) -> str:
    """AND of several "contains this text" conditions on one field, as the single text that implies them all.

    The event store matches one text per field (case-insensitively), so the conditions can only be combined
    when one of the texts contains every other one.
    """
    unique = list(dict.fromkeys(v for v in values if v))
    for candidate in sorted(unique, key=len, reverse=True):
        if all(other.lower() in candidate.lower() for other in unique):
            return candidate
    shown = " and ".join(f"'{v}'" for v in unique)
    if name == "text":
        raise InvalidInputError(
            f"Cannot search for {shown} at once.",
            reason="Events are searched for one text (a word or a phrase) at a time.",
            hint="Search for one phrase, and narrow further with keys such as type:, actor: or source:.",
        )
    raise InvalidInputError(
        f"Cannot select events whose {name} contains both {shown}.",
        reason=f"Events are matched against one {name} text at a time.",
        hint=f"Use one {name} text (the scope or --{name} may already set one).",
    )


def _check_operator(key: str, op: str) -> None:
    if key == "time":
        if op in (":", "="):
            raise InvalidInputError(
                f"time{op} is not a comparison.", hint="Use time>=T, time>T, time<=T or time<T (or after:T, before:T)."
            )
        return
    if op in (":", "="):
        return
    if key == "severity":
        if op in (">=", ">"):
            return
        raise InvalidInputError(
            f"severity{op} is not supported: events are selected by a minimum severity.",
            hint="Use severity>=LEVEL or severity>LEVEL.",
        )
    raise InvalidInputError(
        f"'{key}{op}' compares, but {key} is not an ordered value.",
        hint=f"Use {key}:VALUE (or {key}=VALUE); comparisons apply to severity (>=, >) and time (>=, >, <=, <).",
    )


def _boolean(value: str) -> bool:
    text = value.lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise InvalidInputError(f"synthetic takes true or false, not '{value}'.")


def _job_id(value: str, resolver: Resolver | None) -> str:
    if value.startswith("@") and resolver is not None:
        return resolver.resolve(value, accept=("job",)).id
    text = value.lower()
    if not _JOB_ID.match(text):
        raise InvalidInputError(f"'{value}' is not a job ID.", hint="Use a job ID such as job:job-4 (raf jobs).")
    return text


def _present[T](value: T | None) -> list[T]:
    return [value] if value is not None else []


def _in_both(current: Sequence[str] | None, wanted: list[str]) -> list[str]:
    """Alternatives allowed both by the scope or options (``None`` or empty: anything) and by the filter."""
    unique = list(dict.fromkeys(wanted))
    if not current:
        return unique
    return [v for v in unique if v in set(current)]


def _type_pattern(text: str) -> tuple[str, bool]:
    """``(stem, is_prefix)`` as the event store reads a type: ``auth.*`` and ``auth`` match ``auth.<action>``."""
    value = text.strip()
    if value.endswith(".*"):
        return value[:-2], True
    return value, "." not in value


def _type_overlap(a: str, b: str) -> str | None:
    """The type term that matches exactly the event types both ``a`` and ``b`` match, or None."""
    (stem_a, prefix_a), (stem_b, prefix_b) = _type_pattern(a), _type_pattern(b)
    if prefix_a and (stem_b == stem_a or stem_b.startswith(stem_a + ".")):
        return b
    if prefix_b and (stem_a == stem_b or stem_a.startswith(stem_b + ".")):
        return a
    return a if stem_a == stem_b else None


def _types_in_both(current: Sequence[str] | None, wanted: list[str]) -> list[str]:
    unique = list(dict.fromkeys(wanted))
    if not current:
        return unique
    both = (_type_overlap(have, want) for have in current for want in unique)
    return list(dict.fromkeys(t for t in both if t is not None))


def _objects_in_both(current: Sequence[str] | None, wanted: list[str]) -> list[str]:
    unique = list(dict.fromkeys(wanted))
    if not current:
        return unique
    scope, chosen = set(current), set(unique)
    if scope <= chosen:  # every event of the scope already involves one of the filter's objects
        return list(current)
    if chosen <= scope:
        return unique
    raise InvalidInputError(
        "object: cannot narrow a scope that is already an object.",
        reason=f"The events would have to involve both {', '.join(current)} and {' or '.join(unique)}; "
        "R$F selects events by one object at a time.",
        hint="Narrow with actor: or target: instead (for example target:DEV-01), or use the other object as the scope.",
    )


def _one_incident(current: str | None, wanted: list[str]) -> str:
    distinct = list(dict.fromkeys([*([current] if current else []), *wanted]))
    if len(distinct) > 1:
        raise InvalidInputError(
            "Events can be selected for one incident at a time.",
            reason="The filter would need events linked to " + " and ".join(distinct) + ".",
            hint="Use one incident: term, or the incident as the scope without an incident: term.",
        )
    return distinct[0]
