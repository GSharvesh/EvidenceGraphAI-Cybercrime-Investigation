"""Unit tests for GraphClient library with mocked Neo4j driver."""

from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import ConstraintError, Neo4jError

from core.graph.client import GraphClient
from core.graph.exceptions import (
    GraphConstraintError,
    GraphQueryError,
    GraphValidationError,
)


def test_connect_and_close(mock_graph_client: GraphClient) -> None:
    """Verifies driver connection and close lifecycle."""
    mock_graph_client.connect()
    assert mock_graph_client._driver is not None
    mock_graph_client.close()
    assert mock_graph_client._driver is None


def test_health_check_success(mock_graph_client: GraphClient) -> None:
    """Verifies health_check returns True when driver connectivity succeeds."""
    assert mock_graph_client.health_check() is True


def test_health_check_failure(mock_graph_client: GraphClient) -> None:
    """Verifies health_check returns False when driver raises error."""
    mock_graph_client._driver.verify_connectivity.side_effect = Exception(
        "Connection refused"
    )
    assert mock_graph_client.health_check() is False


def test_create_node_adds_metadata(mock_graph_client: GraphClient) -> None:
    """Verifies create_node validates schema and injects temporal & provenance fields."""
    session = mock_graph_client._driver.session.return_value.__enter__.return_value
    session.run.return_value = [MagicMock(data=lambda: {"id": "CVE-2024-1000"})]

    node_id = mock_graph_client.create_node(
        node_type="CVE",
        properties={"id": "CVE-2024-1000", "cvss_score": 9.1},
    )

    assert node_id == "CVE-2024-1000"
    assert session.run.called
    params_arg = session.run.call_args[0][1]
    props_arg = params_arg["props"]

    assert props_arg["id"] == "CVE-2024-1000"
    assert "valid_from" in props_arg
    assert "created_at" in props_arg
    assert "updated_at" in props_arg
    assert props_arg["source_agent"] == "system"
    assert props_arg["confidence"] == 1.0


def test_create_node_validation_failure(mock_graph_client: GraphClient) -> None:
    """Verifies invalid node type raises GraphValidationError before query execution."""
    with pytest.raises(GraphValidationError):
        mock_graph_client.create_node("UnknownType", {"id": "123"})


def test_create_edge_adds_metadata(mock_graph_client: GraphClient) -> None:
    """Verifies create_edge validates schema and executes parameterized Cypher."""
    session = mock_graph_client._driver.session.return_value.__enter__.return_value
    session.run.return_value = [MagicMock(data=lambda: {"id": "edge-123"})]

    edge_id = mock_graph_client.create_edge(
        from_id="attacker-1",
        to_id="cve-1",
        edge_type="EXPLOITS",
        properties={"vector": "Remote"},
    )

    assert edge_id is not None
    assert session.run.called
    params = session.run.call_args[0][1]
    assert params["from_id"] == "attacker-1"
    assert params["to_id"] == "cve-1"
    assert "created_at" in params["props"]


def test_get_node_found(mock_graph_client: GraphClient) -> None:
    """Verifies get_node returns properties dictionary when node is found."""
    session = mock_graph_client._driver.session.return_value.__enter__.return_value
    session.run.return_value = [
        MagicMock(data=lambda: {"props": {"id": "cve-1", "severity": "HIGH"}})
    ]

    res = mock_graph_client.get_node("cve-1")
    assert res == {"id": "cve-1", "severity": "HIGH", "valid_to": None}


def test_get_node_not_found(mock_graph_client: GraphClient) -> None:
    """Verifies get_node returns None when node does not exist."""
    session = mock_graph_client._driver.session.return_value.__enter__.return_value
    session.run.return_value = []

    res = mock_graph_client.get_node("nonexistent-node")
    assert res is None


def test_constraint_error_translation(mock_graph_client: GraphClient) -> None:
    """Verifies ConstraintError is re-raised as GraphConstraintError."""
    session = mock_graph_client._driver.session.return_value.__enter__.return_value
    session.run.side_effect = ConstraintError("Already exists")

    with pytest.raises(GraphConstraintError) as exc_info:
        mock_graph_client.query("CREATE (n:CVE {id: 'dup'})")
    assert "Already exists" in str(exc_info.value)


def test_query_error_translation(mock_graph_client: GraphClient) -> None:
    """Verifies generic Neo4jError is re-raised as GraphQueryError."""
    session = mock_graph_client._driver.session.return_value.__enter__.return_value
    session.run.side_effect = Neo4jError("Syntax error")

    with pytest.raises(GraphQueryError) as exc_info:
        mock_graph_client.query("INVALID CYAN QUERY")
    assert "Syntax error" in str(exc_info.value)


def test_transaction_rollback_on_error(mock_graph_client: GraphClient) -> None:
    """Verifies transaction context manager rolls back on exception."""
    session = mock_graph_client._driver.session.return_value
    tx_mock = MagicMock()
    session.begin_transaction.return_value = tx_mock

    with (
        pytest.raises(ValueError, match="Simulated error"),
        mock_graph_client.transaction(),
    ):
        raise ValueError("Simulated error")

    assert tx_mock.rollback.called
    assert not tx_mock.commit.called
