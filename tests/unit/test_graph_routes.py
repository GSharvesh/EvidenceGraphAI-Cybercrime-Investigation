"""Unit tests for graph API routes and developer endpoint security guard."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.dependencies import get_app_settings, get_graph_client
from api.main import app
from api.routes.graph import _get_client_ip, _is_localhost
from core.graph.exceptions import GraphQueryError
from core.graph.validator import ValidationReport, Violation


@pytest.fixture
def mock_graph_client():
    """Provides a mocked GraphClient for API route tests."""
    mock = MagicMock()
    return mock


@pytest.fixture
def client(mock_graph_client):
    """FastAPI TestClient with overridden get_graph_client dependency."""
    app.dependency_overrides[get_graph_client] = lambda: mock_graph_client
    with TestClient(app, base_url="http://127.0.0.1") as tc:
        yield tc
    app.dependency_overrides.clear()


# --- Localhost Guard Helper Tests ---


def test_is_localhost_ipv4():
    """Verifies IPv4 loopback addresses are recognized as localhost."""
    assert _is_localhost("127.0.0.1") is True
    assert _is_localhost("127.0.0.2") is True
    assert _is_localhost("127.255.255.255") is True


def test_is_localhost_ipv6():
    """Verifies IPv6 loopback address ::1 is recognized as localhost."""
    assert _is_localhost("::1") is True


def test_is_localhost_remote_ips():
    """Verifies non-loopback IPs are recognized as remote."""
    assert _is_localhost("192.168.1.100") is False
    assert _is_localhost("10.0.0.1") is False
    assert _is_localhost("8.8.8.8") is False
    assert _is_localhost("2001:db8::1") is False
    assert _is_localhost("invalid-ip") is False
    assert _is_localhost("unknown") is False


def test_get_client_ip_forwarded_for():
    """Verifies X-Forwarded-For header takes precedence for real client IP."""
    req = MagicMock()
    req.headers = {"X-Forwarded-For": "203.0.113.195, 70.41.3.18, 150.172.238.178"}
    req.client = MagicMock(host="127.0.0.1")
    assert _get_client_ip(req) == "203.0.113.195"


def test_get_client_ip_direct_client():
    """Verifies client host is used when X-Forwarded-For is absent."""
    req = MagicMock()
    req.headers = {}
    req.client = MagicMock(host="127.0.0.1")
    assert _get_client_ip(req) == "127.0.0.1"


def test_get_client_ip_fallback():
    """Verifies fallback when no client info is present."""
    req = MagicMock()
    req.headers = {}
    req.client = None
    assert _get_client_ip(req) == "unknown"


# --- /graph/export Endpoint Tests ---


def test_export_graph_localhost_success(client, mock_graph_client):
    """Verifies /graph/export returns nodes and edges from localhost."""
    mock_graph_client.query.side_effect = [
        [
            {
                "props": {"id": "CVE-2021-44228", "severity": "CRITICAL"},
                "labels": ["CVE"],
            }
        ],
        [
            {
                "id": "e1",
                "from_id": "CVE-2021-44228",
                "to_id": "a1",
                "type": "EXPLOITS",
                "properties": {},
            }
        ],
    ]
    response = client.get("/graph/export")
    assert response.status_code == 200
    data = response.json()
    assert data["node_count"] == 1
    assert data["edge_count"] == 1
    assert data["nodes"][0]["id"] == "CVE-2021-44228"
    assert data["nodes"][0]["_labels"] == ["CVE"]


def test_export_graph_with_node_type_filter(client, mock_graph_client):
    """Verifies /graph/export filters by node_type query param."""
    mock_graph_client.query.side_effect = [
        [{"props": {"id": "m1", "family": "Emotet"}, "labels": ["Malware"]}],
        [],
    ]
    response = client.get("/graph/export?node_type=Malware&limit=50")
    assert response.status_code == 200
    data = response.json()
    assert data["node_count"] == 1


def test_export_graph_remote_forbidden(client):
    """Verifies /graph/export rejects remote IP requests with 403."""
    response = client.get(
        "/graph/export",
        headers={"X-Forwarded-For": "198.51.100.25"},
    )
    assert response.status_code == 403
    assert "restricted to localhost" in response.json()["detail"]


def test_export_graph_disabled_service_unavailable(client):
    """Verifies /graph/export returns 503 when dev viewer is disabled in settings."""
    settings_mock = MagicMock(dev_viewer_enabled=False, dev_viewer_allow_remote=False)
    app.dependency_overrides[get_app_settings] = lambda: settings_mock
    try:
        response = client.get("/graph/export")
        assert response.status_code == 503
        assert "disabled" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_app_settings, None)


def test_export_graph_error_handling(client, mock_graph_client):
    """Verifies /graph/export returns 500 on database query errors."""
    mock_graph_client.query.side_effect = GraphQueryError("Database unavailable")
    response = client.get("/graph/export")
    assert response.status_code == 500
    assert response.json()["detail"] == "Graph export failed."


# --- /graph/stats Endpoint Tests ---


def test_graph_stats_success(client, mock_graph_client):
    """Verifies /graph/stats returns aggregate statistics without localhost restriction."""
    mock_graph_client.query.side_effect = [
        [{"label": "CVE", "cnt": 10}, {"label": "Malware", "cnt": 5}],
        [{"rel_type": "EXPLOITS", "cnt": 8}],
        [{"cnt": 15}],
    ]
    response = client.get("/graph/stats", headers={"X-Forwarded-For": "198.51.100.25"})
    assert response.status_code == 200
    data = response.json()
    assert "node_counts" in data
    assert "edge_counts" in data
    assert data["totals"]["nodes"] == 15
    assert data["totals"]["edges"] == 8


def test_graph_stats_error_handling(client, mock_graph_client):
    """Verifies /graph/stats returns 500 when query fails."""
    mock_graph_client.query.side_effect = GraphQueryError("DB error")
    response = client.get("/graph/stats")
    assert response.status_code == 500
    assert "Failed to retrieve graph statistics" in response.json()["detail"]


# --- /graph/validate Endpoint Tests ---


def test_validate_graph_localhost_success(client, mock_graph_client):
    """Verifies /graph/validate runs validator and returns violations."""
    mock_report = ValidationReport()
    mock_report.violations = [
        Violation(
            severity="warning",
            rule="confidence_range",
            entity_id="n1",
            entity_type="CVE",
            message="Low confidence",
        )
    ]
    with patch("api.routes.graph.GraphValidator") as mock_val_cls:
        val_instance = MagicMock()
        val_instance.validate.return_value = mock_report
        mock_val_cls.return_value = val_instance

        response = client.get("/graph/validate?severity=warning")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["violations"][0]["rule"] == "confidence_range"


def test_validate_graph_remote_forbidden(client):
    """Verifies /graph/validate rejects remote IP requests with 403."""
    response = client.get(
        "/graph/validate",
        headers={"X-Forwarded-For": "203.0.113.50"},
    )
    assert response.status_code == 403
    assert "restricted to localhost" in response.json()["detail"]


def test_validate_graph_invalid_severity(client):
    """Verifies /graph/validate returns 400 on invalid severity parameter."""
    response = client.get("/graph/validate?severity=catastrophic")
    assert response.status_code == 400
    assert "severity must be one of" in response.json()["detail"]


# --- /dev/viewer Route Tests ---


def test_dev_viewer_page(client):
    """Verifies GET /dev/viewer serves the HTML visualizer."""
    response = client.get("/dev/viewer")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Developer Graph Viewer" in response.text
