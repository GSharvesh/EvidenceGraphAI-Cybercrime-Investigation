"""Shared pytest fixtures for unit and integration tests."""

from collections.abc import Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from api.main import app
from core.config.settings import Settings
from core.graph.client import GraphClient
from core.ontology.loader import OntologyLoader
from core.ontology.validator import OntologyValidator


@pytest.fixture
def mock_settings() -> Settings:
    """Returns test application settings."""
    return Settings(
        app_name="EvidenceGraphAI-Test",
        app_env="testing",
        log_level="DEBUG",
        neo4j_uri="bolt://localhost:7687",
        neo4j_user="neo4j",
        neo4j_password="devpassword123",
    )


@pytest.fixture
def mock_driver() -> MagicMock:
    """Returns a mocked Neo4j Driver instance."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    driver.verify_connectivity.return_value = True
    return driver


@pytest.fixture
def mock_graph_client(mock_settings: Settings, mock_driver: MagicMock) -> GraphClient:
    """Returns a GraphClient initialized with mocked driver."""
    client = GraphClient(settings=mock_settings, driver=mock_driver)
    return client


@pytest.fixture
def ontology_loader() -> OntologyLoader:
    """Returns an OntologyLoader instance."""
    return OntologyLoader()


@pytest.fixture
def ontology_validator(ontology_loader: OntologyLoader) -> OntologyValidator:
    """Returns an OntologyValidator instance."""
    return OntologyValidator(loader=ontology_loader)


@pytest.fixture
def api_client() -> Generator[TestClient, None, None]:
    """Returns a FastAPI TestClient."""
    with TestClient(app) as client:
        yield client
