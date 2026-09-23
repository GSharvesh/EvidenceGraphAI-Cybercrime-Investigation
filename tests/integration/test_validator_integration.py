"""Integration tests for GraphValidator against live Neo4j."""

from core.graph.client import GraphClient
from core.graph.validator import GraphValidator
from tests.integration.conftest import neo4j_required

_NODE_ID = "TestPhase1_Validator-orphan-001"
_NODE2_ID = "TestPhase1_Validator-orphan-002"
_CVE_ID = "TestPhase1_CVE-validator-001"
_ATTACKER_ID = "TestPhase1_Attacker-validator-001"


@neo4j_required
def test_validator_clean_graph_no_errors(
    test_client: GraphClient, clean_test_graph
) -> None:
    """Clean graph (only connected, properly typed nodes) has no error violations."""
    test_client.create_node(
        "CVE", {"id": _CVE_ID, "cvss_score": 9.0, "severity": "CRITICAL"}
    )
    test_client.create_node("Attacker", {"id": _ATTACKER_ID, "name": "Validator Test"})
    test_client.create_edge(_ATTACKER_ID, _CVE_ID, "EXPLOITS", {"vector": "RCE"})

    validator = GraphValidator(test_client)
    report = validator.validate()
    errors = [v for v in report.violations if v.severity == "error"]
    assert len(errors) == 0, f"Unexpected errors: {errors}"


@neo4j_required
def test_validator_detects_orphan_node(
    test_client: GraphClient, clean_test_graph
) -> None:
    """Orphan nodes (no edges) are detected as warnings."""
    test_client.create_node("CVE", {"id": _NODE_ID, "cvss_score": 5.0})

    validator = GraphValidator(test_client)
    report = validator.validate(rules=["orphan_nodes"])

    orphan_warnings = [
        v
        for v in report.violations
        if v.rule == "orphan_nodes" and _NODE_ID in v.entity_id
    ]
    assert len(orphan_warnings) >= 1


@neo4j_required
def test_validator_detects_temporal_inconsistency(
    test_client: GraphClient, clean_test_graph
) -> None:
    """Nodes with valid_to < valid_from are detected as temporal errors."""
    # Insert a node with invalid temporal state directly (bypass client enforcement)
    test_client.query(
        "CREATE (n:CVE {id: $id, valid_from: '2024-01-02T00:00:00+00:00', "
        "valid_to: '2024-01-01T00:00:00+00:00', created_at: '2024-01-02T00:00:00+00:00', "
        "updated_at: '2024-01-02T00:00:00+00:00', source_agent: 'system', "
        "source_artifact_id: null, confidence: 1.0})",
        {"id": _NODE_ID},
    )

    validator = GraphValidator(test_client)
    report = validator.validate(rules=["temporal_consistency"])

    temporal_errors = [
        v
        for v in report.violations
        if v.rule == "temporal_consistency" and _NODE_ID in v.entity_id
    ]
    assert len(temporal_errors) >= 1
    assert temporal_errors[0].severity == "error"


@neo4j_required
def test_validator_detects_out_of_range_confidence(
    test_client: GraphClient, clean_test_graph
) -> None:
    """Nodes with confidence > 1.0 are detected as errors."""
    # Insert directly with invalid confidence
    test_client.query(
        "CREATE (n:CVE {id: $id, confidence: 2.5, valid_from: '2024-01-01T00:00:00+00:00', "
        "valid_to: null, created_at: '2024-01-01T00:00:00+00:00', "
        "updated_at: '2024-01-01T00:00:00+00:00', source_agent: 'system', "
        "source_artifact_id: null})",
        {"id": _NODE_ID},
    )

    validator = GraphValidator(test_client)
    report = validator.validate(rules=["confidence_range"])

    conf_errors = [
        v
        for v in report.violations
        if v.rule == "confidence_range" and _NODE_ID in v.entity_id
    ]
    assert len(conf_errors) >= 1


@neo4j_required
def test_validator_report_to_dict_serialisable(
    test_client: GraphClient, clean_test_graph
) -> None:
    """ValidationReport.to_dict() returns JSON-serialisable data."""
    import json

    validator = GraphValidator(test_client)
    report = validator.validate()
    data = report.to_dict()
    # Should not raise
    serialised = json.dumps(data)
    assert "violations" in serialised
