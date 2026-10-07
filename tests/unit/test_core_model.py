from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from raf.core.errors import InvalidInputError
from raf.core.ids import event_id, normalize_key, object_id, relationship_id, split_id
from raf.core.objects.models import ObjectDraft, RelationshipDraft, merge_metadata
from raf.core.objects.types import (
    ConfidenceLevel,
    Criticality,
    Severity,
    confidence_level,
    parse_confidence,
    validate_object_type,
    validate_relationship_type,
)
from raf.core.timeutil import format_ts, parse_duration, parse_timestamp, parse_timestamp_ex, resolve_time_spec


class TestIds:
    def test_deterministic_and_normalized(self) -> None:
        assert object_id("host", "WS-04") == "host:ws-04"
        assert object_id("Host", " ws-04 ") == "host:ws-04"
        assert object_id("ip", "10.0.0.5") == "ip:10.0.0.5"
        assert object_id("ip", "2001:0db8:0000::1") == "ip:2001:db8::1"
        assert object_id("domain", "Example.COM.") == "domain:example.com"
        assert object_id("url", "HTTPS://Example.com/Path?q=1#frag") == "url:https://example.com/Path?q=1"
        # file paths keep their case
        assert object_id("file", "ws-01|C:\\Users\\Alice") == "file:ws-01|C:\\Users\\Alice"

    def test_invalid_ip_rejected(self) -> None:
        with pytest.raises(InvalidInputError):
            object_id("ip", "999.1.1.1")

    def test_long_keys_are_hashed(self) -> None:
        key = normalize_key("file", "x" * 1000)
        assert len(key) < 230 and "~" in key
        assert normalize_key("file", "x" * 1000) == key

    def test_relationship_and_event_ids_stable(self) -> None:
        assert relationship_id("user:a", "LOGGED_INTO", "host:b") == relationship_id("user:a", "LOGGED_INTO", "host:b")
        assert relationship_id("user:a", "LOGGED_INTO", "host:b") != relationship_id("host:b", "LOGGED_INTO", "user:a")
        assert event_id("src", 1).startswith("event:")

    def test_split_id(self) -> None:
        assert split_id("ip:fe80::1") == ("ip", "fe80::1")
        with pytest.raises(InvalidInputError):
            split_id("nonsense")


class TestTypes:
    def test_object_types_and_aliases(self) -> None:
        assert validate_object_type("HOST") == "host"
        assert validate_object_type("hostname") == "host"
        assert validate_object_type("x-custom") == "x-custom"
        with pytest.raises(InvalidInputError):
            validate_object_type("spaceship")

    def test_relationship_type_normalization(self) -> None:
        assert validate_relationship_type("logged-into") == "LOGGED_INTO"
        with pytest.raises(InvalidInputError):
            validate_relationship_type("1bad")

    def test_severity_parsing_and_rank(self) -> None:
        assert Severity.parse("warning") is Severity.MEDIUM
        assert Severity.parse(9.8) is Severity.CRITICAL
        assert Severity.HIGH.rank > Severity.MEDIUM.rank
        with pytest.raises(InvalidInputError):
            Severity.parse("catastrophic")

    def test_confidence_distinct_from_severity(self) -> None:
        assert parse_confidence("low") == 0.3
        assert parse_confidence(80) == 0.8
        assert confidence_level(0.85) is ConfidenceLevel.HIGH
        with pytest.raises(InvalidInputError):
            parse_confidence(-1)

    def test_criticality(self) -> None:
        assert Criticality.of({"criticality": "HIGH"}) is Criticality.HIGH
        assert Criticality.of({}, ["critical"]) is Criticality.CRITICAL
        assert Criticality.of({"criticality": "bogus"}) is None


class TestDraftMerge:
    def test_object_merge_semantics(self) -> None:
        t1 = datetime(2026, 10, 7, 9, tzinfo=UTC)
        t2 = t1 + timedelta(hours=2)
        a = ObjectDraft.make(
            "host",
            "ws-04",
            first_seen=t2,
            last_seen=t2,
            confidence=0.5,
            tags={"a"},
            metadata={"os": "linux", "aliases": ["x"]},
        )
        b = ObjectDraft.make(
            "host",
            "WS-04",
            first_seen=t1,
            last_seen=t1,
            confidence=0.9,
            tags={"b"},
            metadata={"os": "windows", "aliases": ["y"], "nested": {"k": 1}},
        )
        a.merge(b)
        assert a.name == "WS-04"  # higher confidence name wins
        assert a.first_seen == t1 and a.last_seen == t2
        assert a.tags == {"a", "b"}
        assert a.metadata["os"] == "windows"
        assert a.metadata["aliases"] == ["x", "y"]
        assert a.observations == 2

    def test_relationship_reactivation(self) -> None:
        t0 = datetime(2026, 1, 1, tzinfo=UTC)
        ended = RelationshipDraft.make("user:a", "HAS_ROLE", "role:admin", first_seen=t0, valid_to=t0 + timedelta(1))
        again = RelationshipDraft.make(
            "user:a", "HAS_ROLE", "role:admin", first_seen=t0 + timedelta(5), last_seen=t0 + timedelta(5)
        )
        ended.merge(again)
        assert ended.valid_to is None

    def test_merge_metadata_nested(self) -> None:
        assert merge_metadata({"a": {"b": 1}}, {"a": {"c": 2}}) == {"a": {"b": 1, "c": 2}}


class TestTime:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("2026-10-07T09:14:11Z", "2026-10-07T09:14:11Z"),
            ("2026-10-07 09:14:11,250", "2026-10-07T09:14:11.250000Z"),
            ("2026-10-07T11:14:11+02:00", "2026-10-07T09:14:11Z"),
            ("07/Oct/2026:09:14:11 +0000", "2026-10-07T09:14:11Z"),
            (1791364451, "2026-10-07T09:14:11Z"),
            (1791364451000, "2026-10-07T09:14:11Z"),
            ("1791364451", "2026-10-07T09:14:11Z"),
            ("Wed, 07 Oct 2026 09:14:11 +0000", "2026-10-07T09:14:11Z"),
        ],
    )
    def test_formats(self, value: object, expected: str) -> None:
        assert format_ts(parse_timestamp(value)) == expected

    def test_syslog_year_inference(self) -> None:
        ref = datetime(2026, 1, 2, tzinfo=UTC)
        parsed = parse_timestamp_ex("Dec 31 23:59:59", reference=ref)
        assert parsed.value.year == 2025
        assert parsed.warnings

    def test_rejects_garbage_and_implausible(self) -> None:
        for bad in ["", "yesterday-ish", "99999999999999999999", True]:
            with pytest.raises(InvalidInputError):
                parse_timestamp(bad)

    def test_time_specs(self) -> None:
        anchor = datetime(2026, 10, 7, 14, 30, tzinfo=UTC)
        assert resolve_time_spec("14:32:41", anchor=anchor) == anchor.replace(minute=32, second=41)
        assert resolve_time_spec("+5m", anchor=anchor) == anchor + timedelta(minutes=5)
        window = (datetime(2026, 10, 7, 23, 0, tzinfo=UTC), datetime(2026, 10, 8, 1, 0, tzinfo=UTC))
        assert resolve_time_spec("00:30", anchor=window[0], window=window).day == 8
        assert parse_duration("2h") == timedelta(hours=2)
