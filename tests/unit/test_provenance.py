"""Unit tests for the Phase 1 provenance enforcement helpers."""

import pytest

from core.graph.exceptions import ProvenanceValidationError
from core.graph.provenance import (
    AGENT_NAME_PATTERN,
    DEFAULT_KNOWN_AGENTS,
    default_provenance,
    parse_known_agents,
    validate_provenance,
)

# ── validate_provenance — flexible mode (default) ─────────────────────────


def test_validate_provenance_valid_fields() -> None:
    """Valid provenance fields pass without exception."""
    validate_provenance({"source_agent": "system", "confidence": 1.0})


def test_validate_provenance_custom_agent_name() -> None:
    """Any regex-compliant agent name passes in flexible mode."""
    validate_provenance({"source_agent": "vuln_agent_v2", "confidence": 0.9})


def test_validate_provenance_missing_source_agent_raises() -> None:
    """Missing source_agent raises ProvenanceValidationError."""
    with pytest.raises(ProvenanceValidationError, match="source_agent"):
        validate_provenance({"confidence": 1.0})


def test_validate_provenance_empty_source_agent_raises() -> None:
    """Empty source_agent raises ProvenanceValidationError."""
    with pytest.raises(ProvenanceValidationError, match="source_agent"):
        validate_provenance({"source_agent": "", "confidence": 1.0})


def test_validate_provenance_none_source_agent_raises() -> None:
    """None source_agent raises ProvenanceValidationError."""
    with pytest.raises(ProvenanceValidationError, match="source_agent"):
        validate_provenance({"source_agent": None, "confidence": 1.0})


def test_validate_provenance_agent_starts_with_digit_raises() -> None:
    """Agent name starting with a digit violates the regex."""
    with pytest.raises(ProvenanceValidationError, match="pattern"):
        validate_provenance({"source_agent": "1agent", "confidence": 1.0})


def test_validate_provenance_agent_too_short_raises() -> None:
    """Agent name of two characters (too short) raises."""
    with pytest.raises(ProvenanceValidationError, match="pattern"):
        validate_provenance({"source_agent": "ab", "confidence": 1.0})


def test_validate_provenance_agent_with_uppercase_raises() -> None:
    """Agent name with uppercase letters violates the regex."""
    with pytest.raises(ProvenanceValidationError, match="pattern"):
        validate_provenance({"source_agent": "MyAgent", "confidence": 1.0})


def test_validate_provenance_agent_minimum_length() -> None:
    """Agent name of exactly 3 characters passes."""
    validate_provenance({"source_agent": "abc", "confidence": 0.5})


def test_validate_provenance_missing_confidence_raises() -> None:
    """Missing confidence raises ProvenanceValidationError."""
    with pytest.raises(ProvenanceValidationError, match="confidence"):
        validate_provenance({"source_agent": "system"})


def test_validate_provenance_confidence_zero_valid() -> None:
    """Confidence of 0.0 is valid."""
    validate_provenance({"source_agent": "system", "confidence": 0.0})


def test_validate_provenance_confidence_one_valid() -> None:
    """Confidence of 1.0 is valid."""
    validate_provenance({"source_agent": "system", "confidence": 1.0})


def test_validate_provenance_confidence_above_one_raises() -> None:
    """Confidence > 1.0 raises ProvenanceValidationError."""
    with pytest.raises(ProvenanceValidationError, match="confidence"):
        validate_provenance({"source_agent": "system", "confidence": 1.01})


def test_validate_provenance_confidence_negative_raises() -> None:
    """Confidence < 0.0 raises ProvenanceValidationError."""
    with pytest.raises(ProvenanceValidationError, match="confidence"):
        validate_provenance({"source_agent": "system", "confidence": -0.1})


def test_validate_provenance_confidence_string_raises() -> None:
    """Non-numeric confidence raises ProvenanceValidationError."""
    with pytest.raises(ProvenanceValidationError, match="confidence"):
        validate_provenance({"source_agent": "system", "confidence": "high"})


def test_validate_provenance_source_artifact_id_optional() -> None:
    """source_artifact_id is optional — absence is fine."""
    validate_provenance({"source_agent": "system", "confidence": 0.8})


# ── validate_provenance — strict mode ─────────────────────────────────────


def test_validate_provenance_strict_known_agent_passes() -> None:
    """Known agent passes strict mode."""
    validate_provenance(
        {"source_agent": "system", "confidence": 1.0},
        strict=True,
        known_agents=["system", "manual"],
    )


def test_validate_provenance_strict_unknown_agent_raises() -> None:
    """Unknown agent raises ProvenanceValidationError in strict mode."""
    with pytest.raises(ProvenanceValidationError, match="allowlist"):
        validate_provenance(
            {"source_agent": "vuln_agent", "confidence": 1.0},
            strict=True,
            known_agents=["system", "manual"],
        )


def test_validate_provenance_strict_uses_default_known_agents() -> None:
    """Strict mode with no explicit list uses DEFAULT_KNOWN_AGENTS."""
    validate_provenance(
        {"source_agent": DEFAULT_KNOWN_AGENTS[0], "confidence": 1.0},
        strict=True,
    )


def test_validate_provenance_flexible_allows_unknown_agent() -> None:
    """Flexible mode (default) allows any regex-compliant agent."""
    validate_provenance(
        {"source_agent": "new_agent_phase2", "confidence": 0.7},
        strict=False,
    )


# ── default_provenance ────────────────────────────────────────────────────


def test_default_provenance_defaults() -> None:
    """default_provenance returns correct default values."""
    p = default_provenance()
    assert p["source_agent"] == "system"
    assert p["source_artifact_id"] is None
    assert p["confidence"] == 1.0


def test_default_provenance_custom() -> None:
    """default_provenance accepts custom values."""
    p = default_provenance("manual", "artifact-123", 0.75)
    assert p["source_agent"] == "manual"
    assert p["source_artifact_id"] == "artifact-123"
    assert p["confidence"] == 0.75


# ── parse_known_agents ────────────────────────────────────────────────────


def test_parse_known_agents_basic() -> None:
    """parse_known_agents splits comma-separated string."""
    assert parse_known_agents("system,manual") == ["system", "manual"]


def test_parse_known_agents_strips_whitespace() -> None:
    """parse_known_agents strips surrounding whitespace."""
    assert parse_known_agents(" system , manual ") == ["system", "manual"]


def test_parse_known_agents_empty_string() -> None:
    """parse_known_agents on empty string returns empty list."""
    assert parse_known_agents("") == []


def test_parse_known_agents_single_agent() -> None:
    """parse_known_agents handles a single agent name."""
    assert parse_known_agents("system") == ["system"]


# ── Regex pattern ─────────────────────────────────────────────────────────


def test_agent_name_pattern_accepts_valid() -> None:
    """AGENT_NAME_PATTERN matches valid agent names."""
    valid_names = ["system", "manual", "vuln_agent", "abc", "a123_b456_c"]
    for name in valid_names:
        assert AGENT_NAME_PATTERN.match(name), f"Should match: {name}"


def test_agent_name_pattern_rejects_invalid() -> None:
    """AGENT_NAME_PATTERN rejects invalid agent names."""
    invalid_names = ["1abc", "AB", "", "my-agent", "a b", "ab"]
    for name in invalid_names:
        assert not AGENT_NAME_PATTERN.match(name), f"Should NOT match: {name}"
