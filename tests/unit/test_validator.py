"""Unit tests for core/graph/validator.py (GraphValidator)."""

from unittest.mock import MagicMock, patch

import pytest

from core.graph.validator import (
    GraphValidator,
    ValidationReport,
    Violation,
    main,
)


def _make_validator(query_results: dict[str, list] | None = None) -> GraphValidator:
    """Creates a GraphValidator with a mocked GraphClient.

    Args:
        query_results: Optional dict mapping Cypher fragments to result lists.
                       If None, all queries return [].
    """
    client = MagicMock()
    if query_results is None:
        client.query.return_value = []
    else:

        def _side_effect(cypher: str, *args, **kwargs) -> list:
            for fragment, results in query_results.items():
                if fragment in cypher:
                    return results
            return []

        client.query.side_effect = _side_effect
    return GraphValidator(client)


# ── ValidationReport / Violation ──────────────────────────────────────────


def test_violation_to_dict_keys() -> None:
    """Violation.to_dict returns correct keys."""
    v = Violation("error", "orphan_nodes", "n-1", "node", "msg")
    d = v.to_dict()
    assert set(d.keys()) == {"severity", "rule", "entity_id", "entity_type", "message"}


def test_violation_severity_level() -> None:
    """Severity levels are correctly ordered."""
    assert Violation("info", "r", "i", "node", "m").severity_level() == 0
    assert Violation("warning", "r", "i", "node", "m").severity_level() == 1
    assert Violation("error", "r", "i", "node", "m").severity_level() == 2


def test_validation_report_summary() -> None:
    """ValidationReport.summary counts violations by severity."""
    report = ValidationReport()
    report.add(Violation("error", "r", "i", "node", "m"))
    report.add(Violation("warning", "r", "i", "node", "m"))
    report.add(Violation("warning", "r", "i", "node", "m"))
    s = report.summary()
    assert s["error"] == 1
    assert s["warning"] == 2
    assert s["info"] == 0


def test_validation_report_has_violations_at_error() -> None:
    """has_violations_at('error') returns True only with error violations."""
    report = ValidationReport()
    report.add(Violation("warning", "r", "i", "node", "m"))
    assert not report.has_violations_at("error")
    report.add(Violation("error", "r", "i", "node", "m"))
    assert report.has_violations_at("error")


def test_validation_report_to_dict_structure() -> None:
    """ValidationReport.to_dict contains expected keys."""
    report = ValidationReport()
    d = report.to_dict()
    assert "violations" in d
    assert "total" in d
    assert "summary" in d


# ── Rule: orphan_nodes ────────────────────────────────────────────────────


def test_orphan_nodes_detected() -> None:
    """Orphan nodes are detected and reported as warnings."""
    validator = _make_validator(
        {
            "NOT (n)--()": [{"props": {"id": "orphan-1"}, "label": "CVE"}],
        }
    )
    report = validator.validate(rules=["orphan_nodes"])
    assert len(report.violations) == 1
    assert report.violations[0].rule == "orphan_nodes"
    assert report.violations[0].severity == "warning"


def test_no_orphan_nodes_clean() -> None:
    """No violations when graph has no orphan nodes."""
    validator = _make_validator()
    report = validator.validate(rules=["orphan_nodes"])
    assert report.violations == []


# ── Rule: invalid_edge_types ──────────────────────────────────────────────


def test_invalid_edge_type_detected() -> None:
    """Edges with unknown types are reported as errors."""
    validator = _make_validator(
        {
            "MATCH (a)-[r]->(b)": [
                {
                    "rel_type": "GHOST_EDGE",
                    "from_label": "CVE",
                    "to_label": "Malware",
                    "edge_id": "e-bad",
                }
            ]
        }
    )
    report = validator.validate(rules=["invalid_edge_types"])
    errors = [v for v in report.violations if v.rule == "invalid_edge_types"]
    assert len(errors) == 1
    assert errors[0].severity == "error"


def test_valid_edge_type_no_violation() -> None:
    """Valid edge type with correct endpoint types produces no violations."""
    validator = _make_validator(
        {
            "MATCH (a)-[r]->(b)": [
                {
                    "rel_type": "EXPLOITS",
                    "from_label": "Attacker",
                    "to_label": "CVE",
                    "edge_id": "e-good",
                }
            ]
        }
    )
    report = validator.validate(rules=["invalid_edge_types"])
    assert report.violations == []


# ── Rule: confidence_range ────────────────────────────────────────────────


def test_confidence_out_of_range_node_detected() -> None:
    """Nodes with out-of-range confidence are reported as errors."""
    validator = _make_validator(
        {
            "n.confidence": [{"props": {"id": "n-bad", "confidence": 1.5}}],
        }
    )
    report = validator.validate(rules=["confidence_range"])
    assert any(v.rule == "confidence_range" for v in report.violations)


def test_confidence_in_range_no_violation() -> None:
    """Nodes with valid confidence produce no violations."""
    validator = _make_validator()
    report = validator.validate(rules=["confidence_range"])
    assert report.violations == []


# ── Rule: temporal_consistency ────────────────────────────────────────────


def test_temporal_inconsistency_detected() -> None:
    """Nodes with valid_to <= valid_from are reported as errors."""
    validator = _make_validator(
        {
            "n.valid_to IS NOT NULL": [
                {
                    "props": {
                        "id": "n-bad",
                        "valid_from": "2024-01-02T00:00:00+00:00",
                        "valid_to": "2024-01-01T00:00:00+00:00",
                    },
                    "label": "CVE",
                }
            ]
        }
    )
    report = validator.validate(rules=["temporal_consistency"])
    assert any(v.rule == "temporal_consistency" for v in report.violations)


# ── validate() full run ────────────────────────────────────────────────────


def test_validate_all_rules_runs_without_error() -> None:
    """validate() with no rule filter runs all rules on an empty graph."""
    validator = _make_validator()
    report = validator.validate()
    assert isinstance(report, ValidationReport)
    assert report.violations == []


def test_validate_unknown_rule_skips_gracefully() -> None:
    """Unknown rule names are skipped without raising."""
    validator = _make_validator()
    report = validator.validate(rules=["nonexistent_rule"])
    assert report.violations == []


# ── CLI ───────────────────────────────────────────────────────────────────


def test_main_exit_code_0_on_clean_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI exits 0 when there are no violations."""
    monkeypatch.setattr("sys.argv", ["validator"])
    with (
        patch("core.graph.validator.GraphClient"),
        patch("core.graph.validator.GraphValidator") as mock_validator_cls,
    ):
        mock_report = ValidationReport()
        mock_validator_cls.return_value.validate.return_value = mock_report
        code = main()
    assert code == 0


def test_main_exit_code_1_on_violations(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI exits 1 when there are error violations and --fail-on=error."""
    monkeypatch.setattr("sys.argv", ["validator", "--fail-on", "error"])
    with (
        patch("core.graph.validator.GraphClient"),
        patch("core.graph.validator.GraphValidator") as mock_validator_cls,
    ):
        mock_report = ValidationReport()
        mock_report.add(Violation("error", "orphan_nodes", "n-1", "node", "bad"))
        mock_validator_cls.return_value.validate.return_value = mock_report
        code = main()
    assert code == 1


def test_main_exit_code_2_on_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI exits 2 on an unexpected runtime exception."""
    monkeypatch.setattr("sys.argv", ["validator"])
    with patch("core.graph.validator.GraphClient", side_effect=RuntimeError("db gone")):
        code = main()
    assert code == 2
