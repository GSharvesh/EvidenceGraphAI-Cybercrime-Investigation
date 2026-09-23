"""Shared fixtures for Phase 1 integration tests.

All integration tests must:
- Prefix test data labels with ``TestPhase1_``
- Use the ``clean_test_graph`` fixture for before/after cleanup
- Support ``NEO4J_TEST_DATABASE`` env var for a separate test database
- Be fully idempotent

The tests skip automatically when Neo4j is not reachable.
"""

import os

import pytest

from core.config.settings import get_settings
from core.graph.client import GraphClient


def _test_settings():
    """Returns settings with the test database applied if configured."""
    settings = get_settings()
    test_db = os.environ.get("NEO4J_TEST_DATABASE", settings.neo4j_test_database)
    # Return settings but override the database name
    # We use model_copy for pydantic v2
    return settings.model_copy(update={"neo4j_database": test_db})


def is_neo4j_reachable() -> bool:
    """Returns True if the Neo4j container is accepting connections."""
    try:
        client = GraphClient(settings=_test_settings())
        return client.health_check()
    except Exception:
        return False


_NEO4J_UP = is_neo4j_reachable()

neo4j_required = pytest.mark.skipif(
    not _NEO4J_UP,
    reason="Neo4j container not reachable — skipping integration test",
)


@pytest.fixture(scope="function")
def test_client() -> GraphClient:
    """Provides a connected GraphClient using the test database."""
    settings = _test_settings()
    client = GraphClient(settings=settings)
    client.connect()
    yield client
    client.close()


@pytest.fixture(scope="function", autouse=False)
def clean_test_graph(test_client: GraphClient) -> None:
    """Deletes all TestPhase1_* labelled nodes before and after each test.

    This ensures full test isolation and idempotency.
    """
    _cleanup(test_client)
    yield
    _cleanup(test_client)


def _cleanup(client: GraphClient) -> None:
    """Removes all nodes whose ID starts with 'TestPhase1_'."""
    client.query("MATCH (n) WHERE n.id STARTS WITH 'TestPhase1_' DETACH DELETE n")
