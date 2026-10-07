"""Time handling.

All timestamps inside R$F are timezone-aware UTC :class:`datetime` objects.
Parsing is strict about what it accepts and explicit about what it assumed
(callers receive warnings for naive values or year-less syslog timestamps).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from email.utils import parsedate_to_datetime
from typing import Any

from raf.core.errors import InvalidInputError

__all__ = [
    "UTC",
    "ParsedTime",
    "TimestampError",
    "ensure_utc",
    "format_ts",
    "parse_duration",
    "parse_timestamp",
    "parse_timestamp_ex",
    "resolve_time_spec",
    "utcnow",
]


class TimestampError(InvalidInputError):
    code = "raf.invalid_timestamp"


@dataclass(slots=True)
class ParsedTime:
    value: datetime
    warnings: list[str] = field(default_factory=list)


_MONTHS = {
    m: i
    for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)
}

_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d{1,6}))?$"
)
_APACHE_RE = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
    r"\s*(?P<tz>[+-]\d{4})?$"
)
_US_RE = re.compile(
    r"^(?P<mo>\d{1,2})/(?P<d>\d{1,2})/(?P<y>\d{4})\s+(?P<h>\d{1,2}):(?P<mi>\d{2}):(?P<s>\d{2})\s*(?P<ampm>[AaPp][Mm])?$"
)
_DURATION_RE = re.compile(r"^(?P<sign>[+-])?(?P<num>\d+(?:\.\d+)?)(?P<unit>ms|s|m|h|d|w)$")
_TIME_OF_DAY_RE = re.compile(r"^(?P<h>\d{1,2}):(?P<m>\d{2})(?::(?P<s>\d{2})(?:\.(?P<frac>\d{1,6}))?)?$")
_ISO_SPACE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}")

# Plausible range for security telemetry. Values outside are almost always unit mistakes.
_MIN_TS = datetime(1990, 1, 1, tzinfo=UTC)
_MAX_TS = datetime(2200, 1, 1, tzinfo=UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime, default_tz: tzinfo = UTC) -> datetime:
    """Attach ``default_tz`` to naive datetimes and convert to UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=default_tz)
    return value.astimezone(UTC)


def format_ts(value: datetime | None) -> str | None:
    """Canonical serialization: ISO-8601 UTC with ``Z`` suffix, microseconds only if non-zero."""
    if value is None:
        return None
    value = ensure_utc(value)
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    if value.microsecond:
        text += f".{value.microsecond:06d}"
    return text + "Z"


def _from_epoch(number: float) -> datetime:
    magnitude = abs(number)
    if magnitude >= 1e17:
        seconds = number / 1e9
    elif magnitude >= 1e14:
        seconds = number / 1e6
    elif magnitude >= 1e11:
        seconds = number / 1e3
    else:
        seconds = number
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise TimestampError(f"Epoch value {number!r} is out of range.") from exc


def _check_range(value: datetime, raw: Any) -> datetime:
    if not (_MIN_TS <= value < _MAX_TS):
        raise TimestampError(
            f"Timestamp {raw!r} resolves to {value.isoformat()}, outside the plausible range 1990-2200.",
            hint="Check the unit of epoch values (seconds vs. milliseconds).",
        )
    return value


def parse_timestamp_ex(
    value: Any,
    *,
    default_tz: tzinfo = UTC,
    reference: datetime | None = None,
) -> ParsedTime:
    """Parse a timestamp from many common formats.

    Supported: ``datetime``, epoch seconds/ms/us/ns (number or numeric string),
    ISO-8601 (``Z`` or offsets, ``T`` or space separator, comma fractions),
    RFC 2822, Apache/NCSA ``07/Oct/2026:09:14:11 +0000``, RFC 3164 syslog
    ``Oct  7 09:14:11`` (year inferred from ``reference``) and US
    ``10/07/2026 09:14:11 PM``.
    """
    warnings: list[str] = []
    if value is None or (isinstance(value, str) and not value.strip()):
        raise TimestampError("Timestamp is missing.")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            warnings.append("naive timestamp interpreted in default timezone")
        return ParsedTime(_check_range(ensure_utc(value, default_tz), value), warnings)
    if isinstance(value, date):
        return ParsedTime(datetime(value.year, value.month, value.day, tzinfo=UTC), warnings)
    if isinstance(value, bool):
        raise TimestampError(f"Boolean {value!r} is not a timestamp.")
    if isinstance(value, int | float):
        return ParsedTime(_check_range(_from_epoch(float(value)), value), warnings)
    if not isinstance(value, str):
        raise TimestampError(f"Unsupported timestamp type {type(value).__name__}.")

    text = value.strip()
    if len(text) > 64:
        raise TimestampError("Timestamp text is implausibly long.", details={"length": len(text)})

    # Numeric epoch strings.
    try:
        number = float(text)
    except ValueError:
        pass
    else:
        if re.fullmatch(r"-?\d+(\.\d+)?", text):
            return ParsedTime(_check_range(_from_epoch(number), value), warnings)

    # ISO-8601 variants.
    if _ISO_SPACE_RE.match(text):
        iso = text.replace(",", ".", 1) if re.search(r":\d{2},\d", text) else text
        if iso.endswith(("Z", "z")):
            iso = iso[:-1] + "+00:00"
        iso = re.sub(r"\s+(?=[+-]\d{2}:?\d{2}$)", "", iso)
        iso = re.sub(r" UTC$", "+00:00", iso)
        # Python's fromisoformat accepts at most 6 fractional digits.
        iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
        try:
            parsed = datetime.fromisoformat(iso)
        except ValueError:
            pass
        else:
            if parsed.tzinfo is None:
                warnings.append("naive timestamp interpreted in default timezone")
            return ParsedTime(_check_range(ensure_utc(parsed, default_tz), value), warnings)

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        d = date.fromisoformat(text)
        return ParsedTime(datetime(d.year, d.month, d.day, tzinfo=UTC), ["date without time interpreted as 00:00 UTC"])

    match = _APACHE_RE.match(text.strip("[]"))
    if match:
        month = _MONTHS.get(match["mon"].lower())
        if month is None:
            raise TimestampError(f"Unknown month in {value!r}.")
        tz: tzinfo = default_tz
        if match["tz"]:
            sign = 1 if match["tz"][0] == "+" else -1
            tz = timezone(sign * timedelta(hours=int(match["tz"][1:3]), minutes=int(match["tz"][3:5])))
        else:
            warnings.append("timestamp without offset interpreted in default timezone")
        parsed = datetime(
            int(match["year"]), month, int(match["day"]), int(match["h"]), int(match["m"]), int(match["s"]), tzinfo=tz
        )
        return ParsedTime(_check_range(parsed.astimezone(UTC), value), warnings)

    match = _SYSLOG_RE.match(text)
    if match:
        month = _MONTHS.get(match["mon"].lower())
        if month is None:
            raise TimestampError(f"Unknown month in {value!r}.")
        ref = ensure_utc(reference) if reference else utcnow()
        year = ref.year
        frac = int((match["frac"] or "0").ljust(6, "0"))
        try:
            parsed = datetime(
                year,
                month,
                int(match["day"]),
                int(match["h"]),
                int(match["m"]),
                int(match["s"]),
                frac,
                tzinfo=default_tz,
            )
        except ValueError as exc:
            raise TimestampError(f"Invalid syslog timestamp {value!r}.") from exc
        # A year-less date more than a day in the future belongs to the previous year.
        if parsed - timedelta(days=1) > ref:
            parsed = parsed.replace(year=year - 1)
        warnings.append(f"syslog timestamp without year; assumed {parsed.year}")
        return ParsedTime(_check_range(parsed.astimezone(UTC), value), warnings)

    match = _US_RE.match(text)
    if match:
        hour = int(match["h"])
        if match["ampm"]:
            hour = hour % 12 + (12 if match["ampm"].lower() == "pm" else 0)
        try:
            parsed = datetime(
                int(match["y"]),
                int(match["mo"]),
                int(match["d"]),
                hour,
                int(match["mi"]),
                int(match["s"]),
                tzinfo=default_tz,
            )
        except ValueError as exc:
            raise TimestampError(f"Invalid date {value!r}.") from exc
        warnings.append("US-style date (month/day/year) assumed")
        return ParsedTime(_check_range(parsed.astimezone(UTC), value), warnings)

    if re.search(r"[A-Za-z]{3},? \d{1,2} [A-Za-z]{3} \d{4}", text):
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            pass
        else:
            return ParsedTime(_check_range(ensure_utc(parsed, default_tz), value), warnings)

    raise TimestampError(
        f"Could not determine a timestamp from {value!r}.",
        hint="Use ISO-8601 (2026-10-07T09:14:11Z) or epoch seconds.",
    )


def parse_timestamp(value: Any, *, default_tz: tzinfo = UTC, reference: datetime | None = None) -> datetime:
    return parse_timestamp_ex(value, default_tz=default_tz, reference=reference).value


def parse_duration(text: str) -> timedelta:
    """Parse ``90s``, ``15m``, ``2h``, ``7d``, ``1w``, ``250ms`` (optionally signed)."""
    match = _DURATION_RE.match(text.strip())
    if not match:
        raise InvalidInputError(f"Invalid duration {text!r}.", hint="Use forms like 30s, 15m, 2h, 7d.")
    number = float(match["num"])
    unit = match["unit"]
    seconds = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit] * number
    delta = timedelta(seconds=seconds)
    return -delta if match["sign"] == "-" else delta


def resolve_time_spec(
    spec: str,
    *,
    anchor: datetime | None = None,
    window: tuple[datetime, datetime] | None = None,
) -> datetime:
    """Resolve a user-supplied time specification.

    * full timestamps are parsed normally;
    * ``HH:MM[:SS]`` is placed on the anchor's date (choosing the occurrence that
      falls inside ``window`` when the window spans midnight);
    * ``+15m`` / ``-2h`` are offsets from the anchor;
    * ``now`` is the current time.
    """
    text = spec.strip()
    if text.lower() == "now":
        return utcnow()
    if text[:1] in "+-" and _DURATION_RE.match(text):
        if anchor is None:
            raise InvalidInputError(f"Relative time {spec!r} needs an anchor (incident or dataset start).")
        return ensure_utc(anchor) + parse_duration(text)
    match = _TIME_OF_DAY_RE.match(text)
    if match:
        base = ensure_utc(anchor) if anchor else utcnow()
        frac = int((match["frac"] or "0").ljust(6, "0"))
        try:
            candidate = base.replace(
                hour=int(match["h"]), minute=int(match["m"]), second=int(match["s"] or 0), microsecond=frac
            )
        except ValueError as exc:
            raise InvalidInputError(f"Invalid time of day {spec!r}.") from exc
        if window is not None:
            start, end = (ensure_utc(window[0]), ensure_utc(window[1]))
            for offset in (0, 1, -1):
                shifted = candidate + timedelta(days=offset)
                if start <= shifted <= end:
                    return shifted
        return candidate
    return parse_timestamp(text)
