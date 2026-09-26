"""Shared fixtures for Phase 1 and Phase 2 integration tests.

All integration tests must:
- Prefix test data labels/IDs with ``TestPhase2_`` or ``TestPhase1_``
- Use cleanup fixtures for before/after cleanup
- Be fully idempotent
- Skip gracefully if underlying Docker services (Neo4j, PostgreSQL, MinIO) are not running
"""

import os
import socket
from collections.abc import Generator

import pytest

from core.config.settings import Settings, get_settings
from core.custody.ledger import CustodyLedger
from core.db.postgres import PostgresClient
from core.graph.client import GraphClient
from core.storage.minio_client import MinioClient
from scripts.migrate_postgres import apply_migrations


def _test_settings() -> Settings:
    """Returns settings with test database applied."""
    settings = get_settings()
    test_db = os.environ.get("NEO4J_TEST_DATABASE", settings.neo4j_test_database)
    return settings.model_copy(update={"neo4j_database": test_db})


def _check_tcp(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def is_neo4j_reachable() -> bool:
    """Returns True if Neo4j is reachable."""
    try:
        client = GraphClient(settings=_test_settings())
        return client.health_check()
    except Exception:
        return False


def is_postgres_reachable() -> bool:
    """Returns True if PostgreSQL is reachable."""
    try:
        settings = get_settings()
        client = PostgresClient(settings=settings)
        return client.health_check()
    except Exception:
        return False


def is_minio_reachable() -> bool:
    """Returns True if MinIO is reachable."""
    try:
        settings = get_settings()
        client = MinioClient(settings=settings)
        return client.health_check()
    except Exception:
        return False


_NEO4J_UP = is_neo4j_reachable()
_POSTGRES_UP = is_postgres_reachable()
_MINIO_UP = is_minio_reachable()

neo4j_required = pytest.mark.skipif(
    not _NEO4J_UP,
    reason="Neo4j container not reachable — skipping integration test",
)

postgres_required = pytest.mark.skipif(
    not _POSTGRES_UP,
    reason="PostgreSQL container not reachable — skipping integration test",
)

minio_required = pytest.mark.skipif(
    not _MINIO_UP,
    reason="MinIO container not reachable — skipping integration test",
)


@pytest.fixture(scope="function")
def test_client() -> Generator[GraphClient, None, None]:
    """Provides a connected GraphClient using the test database."""
    settings = _test_settings()
    client = GraphClient(settings=settings)
    client.connect()
    yield client
    client.close()


@pytest.fixture(scope="session", autouse=True)
def init_test_databases() -> None:
    """Ensures database schemas and migrations are applied before running integration tests."""
    if _POSTGRES_UP:
        settings = get_settings()
        client = PostgresClient(settings=settings)
        apply_migrations(client)


@pytest.fixture(scope="function")
def test_postgres() -> PostgresClient:
    """Provides a PostgresClient instance for integration tests."""
    settings = get_settings()
    client = PostgresClient(settings=settings)
    apply_migrations(client)
    return client


@pytest.fixture(scope="function")
def test_ledger(test_postgres: PostgresClient) -> CustodyLedger:
    """Provides a CustodyLedger instance for integration tests."""
    return CustodyLedger(db_client=test_postgres)


@pytest.fixture(scope="function")
def test_storage() -> MinioClient:
    """Provides a MinioClient instance for integration tests."""
    settings = get_settings()
    client = MinioClient(settings=settings)
    client.ensure_bucket_exists()
    return client


@pytest.fixture(scope="function", autouse=False)
def clean_test_graph(test_client: GraphClient) -> Generator[None, None, None]:
    """Deletes all TestPhase1_* / TestPhase2_* labelled nodes before and after each test."""
    _cleanup_graph(test_client)
    yield
    _cleanup_graph(test_client)


def _cleanup_graph(client: GraphClient) -> None:
    client.query(
        "MATCH (n) WHERE n.id STARTS WITH 'TestPhase1_' OR n.id STARTS WITH 'TestPhase2_' DETACH DELETE n"
    )
