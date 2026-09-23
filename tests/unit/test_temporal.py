"""Unit tests for the Phase 1 temporal versioning helpers."""

from datetime import UTC, datetime, timedelta

import pytest

from core.graph.exceptions import TemporalValidationError
from core.graph.temporal import (
    default_temporal_fields,
    derive_version_id,
    from_iso,
    get_root_id,
    is_valid_at,
    now_utc,
    temporal_filter_clause,
    to_iso,
    validate_temporal_consistency,
)

# ── now_utc ────────────────────────────────────────────────────────────────


def test_now_utc_returns_utc_datetime() -> None:
    """now_utc returns a timezone-aware datetime in UTC."""
    dt = now_utc()
    assert dt.tzinfo is not None
    assert dt.tzinfo == UTC


def test_now_utc_is_recent() -> None:
    """now_utc returns a timestamp close to the actual current time."""
    before = datetime.now(UTC)
    dt = now_utc()
    after = datetime.now(UTC)
    assert before <= dt <= after


# ── to_iso / from_iso ──────────────────────────────────────────────────────


def test_to_iso_round_trips_with_from_iso() -> None:
    """to_iso and from_iso are inverse operations."""
    dt = datetime(2024, 6, 15, 12, 30, 0, tzinfo=UTC)
    assert from_iso(to_iso(dt)) == dt


def test_from_iso_parses_utc_suffix() -> None:
    """from_iso handles +00:00 timezone correctly."""
    dt = from_iso("2024-01-01T00:00:00+00:00")
    assert dt.year == 2024
    assert dt.tzinfo is not None


def test_from_iso_assumes_utc_for_naive() -> None:
    """from_iso treats naive timestamps as UTC."""
    dt = from_iso("2024-01-01T12:00:00")
    assert dt.tzinfo == UTC


def test_from_iso_raises_on_garbage() -> None:
    """from_iso raises TemporalValidationError on unparseable input."""
    with pytest.raises(TemporalValidationError):
        from_iso("not-a-date")


# ── default_temporal_fields ────────────────────────────────────────────────


def test_default_temporal_fields_has_all_keys() -> None:
    """default_temporal_fields returns all four required keys."""
    fields = default_temporal_fields()
    assert "created_at" in fields
    assert "updated_at" in fields
    assert "valid_from" in fields
    assert "valid_to" in fields


def test_default_temporal_fields_valid_to_is_none() -> None:
    """valid_to defaults to None (entity is still active)."""
    fields = default_temporal_fields()
    assert fields["valid_to"] is None


def test_default_temporal_fields_timestamps_are_iso() -> None:
    """created_at and valid_from are valid ISO-8601 strings."""
    fields = default_temporal_fields()
    dt = from_iso(fields["created_at"])
    assert isinstance(dt, datetime)


# ── is_valid_at ────────────────────────────────────────────────────────────


def test_is_valid_at_returns_true_for_active_entity() -> None:
    """Entity with valid_to=None is valid at any future timestamp."""
    now = now_utc()
    props = {"valid_from": to_iso(now - timedelta(hours=1)), "valid_to": None}
    assert is_valid_at(props, now) is True


def test_is_valid_at_returns_false_before_valid_from() -> None:
    """Entity is not valid before its valid_from timestamp."""
    now = now_utc()
    props = {"valid_from": to_iso(now + timedelta(hours=1)), "valid_to": None}
    assert is_valid_at(props, now) is False


def test_is_valid_at_returns_false_after_valid_to() -> None:
    """Entity is not valid after its valid_to timestamp."""
    now = now_utc()
    props = {
        "valid_from": to_iso(now - timedelta(hours=2)),
        "valid_to": to_iso(now - timedelta(hours=1)),
    }
    assert is_valid_at(props, now) is False


def test_is_valid_at_returns_true_within_window() -> None:
    """Entity is valid between valid_from and valid_to."""
    now = now_utc()
    props = {
        "valid_from": to_iso(now - timedelta(hours=1)),
        "valid_to": to_iso(now + timedelta(hours=1)),
    }
    assert is_valid_at(props, now) is True


def test_is_valid_at_returns_false_no_valid_from() -> None:
    """Entity with no valid_from is not valid."""
    assert is_valid_at({}, now_utc()) is False


# ── temporal_filter_clause ─────────────────────────────────────────────────


def test_temporal_filter_clause_contains_alias() -> None:
    """temporal_filter_clause embeds the alias correctly."""
    clause = temporal_filter_clause("n")
    assert "n.valid_from" in clause
    assert "n.valid_to" in clause
    assert "$timestamp" in clause


def test_temporal_filter_clause_different_alias() -> None:
    """temporal_filter_clause works with relationship alias."""
    clause = temporal_filter_clause("r")
    assert "r.valid_from" in clause


# ── validate_temporal_consistency ─────────────────────────────────────────


def test_validate_temporal_consistency_valid_window() -> None:
    """Valid window (valid_to > valid_from) raises no exception."""
    now = now_utc()
    props = {
        "valid_from": to_iso(now - timedelta(hours=1)),
        "valid_to": to_iso(now + timedelta(hours=1)),
    }
    validate_temporal_consistency(props)  # should not raise


def test_validate_temporal_consistency_raises_when_vt_before_vf() -> None:
    """valid_to <= valid_from raises TemporalValidationError."""
    now = now_utc()
    props = {
        "valid_from": to_iso(now),
        "valid_to": to_iso(now - timedelta(seconds=1)),
    }
    with pytest.raises(TemporalValidationError, match="valid_to"):
        validate_temporal_consistency(props)


def test_validate_temporal_consistency_raises_when_equal() -> None:
    """valid_to == valid_from raises TemporalValidationError."""
    now = now_utc()
    ts = to_iso(now)
    with pytest.raises(TemporalValidationError):
        validate_temporal_consistency({"valid_from": ts, "valid_to": ts})


def test_validate_temporal_consistency_no_valid_to_ok() -> None:
    """No valid_to (None) is always valid."""
    props = {"valid_from": to_iso(now_utc()), "valid_to": None}
    validate_temporal_consistency(props)  # no raise


def test_validate_temporal_consistency_bad_string_raises() -> None:
    """Unparseable valid_from raises TemporalValidationError."""
    with pytest.raises(TemporalValidationError):
        validate_temporal_consistency({"valid_from": "not-a-date", "valid_to": None})


# ── derive_version_id / get_root_id ───────────────────────────────────────


def test_derive_version_id() -> None:
    """derive_version_id creates correct versioned IDs."""
    assert derive_version_id("CVE-2021-44228", 1) == "CVE-2021-44228::v1"
    assert derive_version_id("CVE-2021-44228", 3) == "CVE-2021-44228::v3"


def test_get_root_id_strips_version() -> None:
    """get_root_id extracts the root from a versioned ID."""
    assert get_root_id("CVE-2021-44228::v3") == "CVE-2021-44228"


def test_get_root_id_passthrough_for_plain() -> None:
    """get_root_id returns plain IDs unchanged."""
    assert get_root_id("CVE-2021-44228") == "CVE-2021-44228"
