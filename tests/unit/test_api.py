"""Unit tests for FastAPI REST API endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient


def test_root_endpoint(api_client: TestClient) -> None:
    """Verifies GET / returns application metadata."""
    response = api_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data
    assert "environment" in data
    assert data["name"] == "EvidenceGraphAI"


def test_health_endpoint_healthy(api_client: TestClient) -> None:
    """Verifies GET /health returns HTTP 200 when all service checks pass."""
    with (
        patch("api.routes.health._check_tcp_port", return_value=True),
        patch("core.graph.client.GraphClient.health_check", return_value=True),
    ):
        response = api_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["services"]["neo4j"] == "healthy"
        assert data["services"]["postgres"] == "healthy"
        assert data["services"]["redis"] == "healthy"
        assert data["services"]["minio"] == "healthy"


def test_health_endpoint_unhealthy(api_client: TestClient) -> None:
    """Verifies GET /health returns HTTP 503 when a service check fails."""
    with (
        patch("api.routes.health._check_tcp_port", return_value=False),
        patch("core.graph.client.GraphClient.health_check", return_value=False),
    ):
        response = api_client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["services"]["neo4j"] == "unhealthy"


def test_metrics_endpoint(api_client: TestClient) -> None:
    """Verifies GET /metrics returns Prometheus formatted metric data."""
    response = api_client.get("/metrics")
    assert response.status_code == 200
    assert (
        "evidencegraph_http_requests_total" in response.text
        or "python_gc_objects_collected_total" in response.text
    )


def test_correlation_id_header(api_client: TestClient) -> None:
    """Verifies request receives X-Correlation-ID header in response."""
    response = api_client.get("/")
    assert response.status_code == 200
    assert "x-correlation-id" in response.headers
