"""Unit tests for ontology validator."""

import pytest

from core.graph.exceptions import GraphValidationError
from core.ontology.validator import OntologyValidator


def test_valid_node_passes(ontology_validator: OntologyValidator) -> None:
    """Verifies valid node properties pass validation."""
    props = {"id": "CVE-2024-9999", "cvss_score": 9.8, "severity": "CRITICAL"}
    # Should not raise exception
    ontology_validator.validate_node("CVE", props)


def test_missing_required_property_raises(
    ontology_validator: OntologyValidator,
) -> None:
    """Verifies missing required node property raises GraphValidationError."""
    props = {"cvss_score": 8.5}  # Missing 'id'
    with pytest.raises(GraphValidationError) as exc_info:
        ontology_validator.validate_node("CVE", props)
    assert "Missing required property 'id'" in str(exc_info.value)


def test_unknown_node_type_raises(ontology_validator: OntologyValidator) -> None:
    """Verifies unknown node type raises GraphValidationError."""
    props = {"id": "test-123"}
    with pytest.raises(GraphValidationError) as exc_info:
        ontology_validator.validate_node("InvalidType", props)
    assert "Unknown node type 'InvalidType'" in str(exc_info.value)


def test_valid_edge_passes(ontology_validator: OntologyValidator) -> None:
    """Verifies valid relationship type passes validation."""
    props = {"vector": "Network"}
    # Should not raise exception
    ontology_validator.validate_edge("EXPLOITS", props)


def test_unknown_edge_type_raises(ontology_validator: OntologyValidator) -> None:
    """Verifies unknown relationship type raises GraphValidationError."""
    with pytest.raises(GraphValidationError) as exc_info:
        ontology_validator.validate_edge("INVALID_RELATION", {})
    assert "Unknown relationship type 'INVALID_RELATION'" in str(exc_info.value)
