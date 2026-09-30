"""Tests for normalize_agent_name and its integration with the ingestion pipeline.

Covers the requirements:
- integration-test  → integration_test
- integration_test  → integration_test  (already valid, passthrough)
- uppercase identifiers  → lowercased
- identifiers with spaces  → underscored
- identifiers starting with a digit  → leading digits stripped
- valid identifiers  → unchanged
- empty / whitespace-only  → fallback
- determinism  → same input always produces same output
"""

import pytest

from core.graph.provenance import (
    AGENT_NAME_PATTERN,
    normalize_agent_name,
)

# ── Hyphen normalization (the original bug) ───────────────────────────────


class TestNormalizeAgentNameHyphen:
    """Hyphens must be converted to underscores."""

    def test_integration_test_hyphen(self) -> None:
        assert normalize_agent_name("integration-test") == "integration_test"

    def test_multiple_hyphens(self) -> None:
        result = normalize_agent_name("my-custom-agent")
        assert result == "my_custom_agent"
        assert AGENT_NAME_PATTERN.match(result)

    def test_trailing_hyphen(self) -> None:
        result = normalize_agent_name("agent-")
        assert AGENT_NAME_PATTERN.match(result)
        assert "-" not in result


# ── Already-valid identifiers (passthrough) ───────────────────────────────


class TestNormalizeAgentNamePassthrough:
    """Valid identifiers must be returned unchanged."""

    def test_integration_test_underscore(self) -> None:
        assert normalize_agent_name("integration_test") == "integration_test"

    def test_system(self) -> None:
        assert normalize_agent_name("system") == "system"

    def test_vulnerability_intelligence(self) -> None:
        assert (
            normalize_agent_name("vulnerability_intelligence")
            == "vulnerability_intelligence"
        )

    def test_three_char_minimum(self) -> None:
        assert normalize_agent_name("abc") == "abc"


# ── Uppercase normalization ───────────────────────────────────────────────


class TestNormalizeAgentNameUppercase:
    """Uppercase letters must be lowercased."""

    def test_mixed_case(self) -> None:
        assert normalize_agent_name("MyAgent") == "myagent"

    def test_all_caps(self) -> None:
        result = normalize_agent_name("SYSTEM")
        assert result == "system"
        assert AGENT_NAME_PATTERN.match(result)

    def test_camel_case_with_underscores(self) -> None:
        result = normalize_agent_name("Vuln_Agent_V2")
        assert result == "vuln_agent_v2"
        assert AGENT_NAME_PATTERN.match(result)


# ── Spaces ────────────────────────────────────────────────────────────────


class TestNormalizeAgentNameSpaces:
    """Spaces must be converted to underscores."""

    def test_spaces_replaced(self) -> None:
        assert normalize_agent_name("my agent") == "my_agent"

    def test_multiple_spaces_collapsed(self) -> None:
        result = normalize_agent_name("my   agent   v2")
        assert result == "my_agent_v2"
        assert AGENT_NAME_PATTERN.match(result)

    def test_leading_trailing_spaces_stripped(self) -> None:
        result = normalize_agent_name("  system  ")
        assert result == "system"


# ── Leading digits ────────────────────────────────────────────────────────


class TestNormalizeAgentNameLeadingDigits:
    """Identifiers starting with a digit must have leading digits stripped."""

    def test_starts_with_digit(self) -> None:
        result = normalize_agent_name("1agent")
        assert result == "agent"
        assert AGENT_NAME_PATTERN.match(result)

    def test_all_digits(self) -> None:
        result = normalize_agent_name("12345")
        assert result == "unknown_agent"
        assert AGENT_NAME_PATTERN.match(result)

    def test_digits_then_valid(self) -> None:
        result = normalize_agent_name("123numeric")
        assert result == "numeric"
        assert AGENT_NAME_PATTERN.match(result)


# ── Edge cases and fallbacks ──────────────────────────────────────────────


class TestNormalizeAgentNameEdgeCases:
    """Edge cases: empty, whitespace-only, special characters."""

    def test_empty_string(self) -> None:
        assert normalize_agent_name("") == "unknown_agent"

    def test_whitespace_only(self) -> None:
        assert normalize_agent_name("   ") == "unknown_agent"

    def test_special_characters_only(self) -> None:
        result = normalize_agent_name("@#$%^&*()")
        assert result == "unknown_agent"
        assert AGENT_NAME_PATTERN.match(result)

    def test_dots_replaced(self) -> None:
        result = normalize_agent_name("agent.v2.1")
        assert result == "agent_v2_1"
        assert AGENT_NAME_PATTERN.match(result)

    def test_mixed_separators(self) -> None:
        result = normalize_agent_name("My Agent v2.1")
        assert result == "my_agent_v2_1"
        assert AGENT_NAME_PATTERN.match(result)

    def test_short_name_padded(self) -> None:
        """Single valid letter is padded to minimum 3 characters."""
        result = normalize_agent_name("a")
        assert len(result) >= 3
        assert AGENT_NAME_PATTERN.match(result)

    def test_two_char_name_padded(self) -> None:
        result = normalize_agent_name("ab")
        assert len(result) >= 3
        assert AGENT_NAME_PATTERN.match(result)


# ── Determinism ───────────────────────────────────────────────────────────


class TestNormalizeAgentNameDeterminism:
    """Same input always produces the same output (critical for forensic use)."""

    def test_deterministic_hyphen(self) -> None:
        results = [normalize_agent_name("integration-test") for _ in range(100)]
        assert all(r == "integration_test" for r in results)

    def test_deterministic_complex(self) -> None:
        raw = "My Complex-Agent.v3 (Test)"
        results = [normalize_agent_name(raw) for _ in range(100)]
        assert len(set(results)) == 1
        assert AGENT_NAME_PATTERN.match(results[0])


# ── Output always matches AGENT_NAME_PATTERN ──────────────────────────────


class TestNormalizeAgentNameAlwaysValid:
    """Every possible output must match the required pattern."""

    @pytest.mark.parametrize(
        "raw",
        [
            "integration-test",
            "integration_test",
            "INTEGRATION-TEST",
            "INTEGRATION-TEST-RUNNER",
            "MyAgent",
            "SYSTEM",
            "my agent",
            "Incident Responder (Tier-2)",
            "special.agent@domain.com",
            "agent-007",
            "1agent",
            "12345",
            "---",
            "___",
            "123_456",
            "",
            "   ",
            "a",
            "ab",
            "abc",
            "@#$",
            "agent.v2.1",
            "My Agent v2.1",
            "threat_reconstruction",
            "vulnerability_intelligence",
            "Chief Forensic Examiner",
            "EvidenceGraphAI Section 65B Digital Evidence Authority - Very Long Extended Organization Name For Forensic Lab",
        ],
    )
    def test_output_always_matches_pattern(self, raw: str) -> None:
        result = normalize_agent_name(raw)
        assert AGENT_NAME_PATTERN.match(
            result
        ), f"normalize_agent_name({raw!r}) = {result!r} does not match pattern"
        assert len(result) <= 64
        assert len(result) >= 3


class TestNormalizeAgentNameSpecialCases:
    """Explicit checks for specific expected transformations."""

    def test_all_caps_hyphenated(self) -> None:
        assert normalize_agent_name("INTEGRATION-TEST") == "integration_test"

    def test_agent_with_numbers(self) -> None:
        assert normalize_agent_name("agent-007") == "agent_007"

    def test_special_characters_with_name(self) -> None:
        assert normalize_agent_name("special.agent@unit") == "special_agentunit"

    def test_truncation_to_64_chars(self) -> None:
        long_input = "a" * 100
        result = normalize_agent_name(long_input)
        assert len(result) == 64
        assert result == "a" * 64
