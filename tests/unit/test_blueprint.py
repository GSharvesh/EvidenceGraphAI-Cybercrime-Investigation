"""Unit tests for the threat blueprint generator — FR-4."""

from __future__ import annotations

from core.agents.threat_reconstruction.blueprint import (
    _phase_decay,
    generate_blueprint,
)
from core.agents.threat_reconstruction.models import Blueprint


class TestPhaseDecay:
    def test_phase_0_no_decay(self):
        result = _phase_decay(phase=0, base=0.95)
        assert result == 0.95  # 1.0 * 0.95

    def test_later_phases_decay(self):
        p0 = _phase_decay(phase=0, base=0.9)
        p5 = _phase_decay(phase=5, base=0.9)
        assert p0 > p5

    def test_minimum_confidence_floor(self):
        result = _phase_decay(phase=100, base=0.5)
        assert result >= 0.05

    def test_rounds_to_3_decimal_places(self):
        result = _phase_decay(phase=2, base=0.85)
        assert len(str(result).split(".")[-1]) <= 3


class TestGenerateBlueprint:
    def _network_unauth_profile(self) -> dict:
        return {
            "attack_vector": "NETWORK",
            "cvss_score": 10.0,
            "cwe_id": "CWE-917",
            "requires_auth": False,
            "requires_user_interaction": False,
            "remote_exploitable": True,
            "availability_impact": "HIGH",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
        }

    def _local_priv_esc_profile(self) -> dict:
        return {
            "attack_vector": "LOCAL",
            "cvss_score": 7.8,
            "cwe_id": "CWE-269",
            "requires_auth": False,
            "requires_user_interaction": False,
            "remote_exploitable": False,
            "availability_impact": "HIGH",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
        }

    def _dos_profile(self) -> dict:
        return {
            "attack_vector": "NETWORK",
            "cvss_score": 7.5,
            "cwe_id": "CWE-400",
            "requires_auth": False,
            "requires_user_interaction": False,
            "remote_exploitable": True,
            "availability_impact": "HIGH",
            "confidentiality_impact": "NONE",
            "integrity_impact": "NONE",
        }

    def test_returns_blueprint_model(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        assert isinstance(bp, Blueprint)

    def test_blueprint_id_includes_cve_id(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        assert "CVE-2021-44228" in bp.blueprint_id

    def test_network_unauth_includes_t1190(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        technique_ids = [t.technique_id for t in bp.techniques]
        assert "T1190" in technique_ids

    def test_local_priv_esc_includes_t1068(self):
        profile = self._local_priv_esc_profile()
        bp = generate_blueprint("CVE-2021-99999", profile)
        technique_ids = [t.technique_id for t in bp.techniques]
        assert "T1068" in technique_ids

    def test_dos_profile_includes_t1499(self):
        profile = self._dos_profile()
        bp = generate_blueprint("CVE-2021-99998", profile)
        technique_ids = [t.technique_id for t in bp.techniques]
        assert "T1499" in technique_ids

    def test_techniques_sorted_by_phase(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        phases = [t.tactic_phase for t in bp.techniques]
        assert phases == sorted(phases)

    def test_edges_connect_consecutive_techniques(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        if len(bp.techniques) > 1 and bp.edges:
            first_edge = bp.edges[0]
            assert first_edge.from_technique_id == bp.techniques[0].technique_id
            assert first_edge.to_technique_id == bp.techniques[1].technique_id

    def test_all_techniques_hypothesized(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        for tech in bp.techniques:
            assert tech.status == "hypothesized"

    def test_all_edges_hypothesized(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        for edge in bp.edges:
            assert edge.status == "hypothesized"

    def test_edge_probability_is_geometric_mean(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        if len(bp.techniques) >= 2 and bp.edges:
            t0 = bp.techniques[0]
            t1 = bp.techniques[1]
            expected_prob = round((t0.confidence * t1.confidence) ** 0.5, 3)
            actual_prob = bp.edges[0].probability
            assert abs(actual_prob - expected_prob) < 0.001

    def test_total_confidence_is_average(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        if bp.techniques:
            expected = round(
                sum(t.confidence for t in bp.techniques) / len(bp.techniques), 3
            )
            assert abs(bp.total_confidence - expected) < 0.001

    def test_empty_profile_returns_blueprint(self):
        """An empty/unknown profile should still return a Blueprint (may have 0 techniques)."""
        bp = generate_blueprint("CVE-0000-00000", {})
        assert isinstance(bp, Blueprint)
        # All techniques default to hypothesized
        for t in bp.techniques:
            assert t.status == "hypothesized"

    def test_no_duplicate_techniques(self):
        profile = self._network_unauth_profile()
        bp = generate_blueprint("CVE-2021-44228", profile)
        ids = [t.technique_id for t in bp.techniques]
        assert len(ids) == len(set(ids))


class TestThreatReconstructionAgent:
    def test_raises_cve_not_analyzed_if_node_missing(self):
        from unittest.mock import MagicMock

        from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent
        from core.agents.threat_reconstruction.exceptions import CVENotAnalyzedError

        mock_graph = MagicMock()
        mock_graph.get_node.return_value = None
        mock_graph.get_latest_version.return_value = None

        agent = ThreatReconstructionAgent(
            graph_client=mock_graph, ledger=MagicMock(), db_client=MagicMock()
        )
        import pytest

        with pytest.raises(CVENotAnalyzedError):
            agent.blueprint("CVE-2021-44228")

    def test_generates_and_persists_blueprint_when_cve_exists(self):
        from unittest.mock import MagicMock

        from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent

        mock_node = {
            "id": "CVE-2021-44228",
            "attack_vector": "NETWORK",
            "cvss_score": 10.0,
            "cwe_id": "CWE-917",
            "requires_auth": False,
            "requires_user_interaction": False,
            "remote_exploitable": True,
            "availability_impact": "HIGH",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "confidence": 0.9,
        }
        mock_graph = MagicMock()
        mock_graph.get_latest_version.return_value = mock_node
        mock_graph.get_node.side_effect = lambda nid, **kwargs: (
            mock_node if nid.startswith("CVE-") else None
        )
        mock_ledger = MagicMock()
        mock_db = MagicMock()

        agent = ThreatReconstructionAgent(
            graph_client=mock_graph, ledger=mock_ledger, db_client=mock_db
        )
        bp = agent.blueprint("CVE-2021-44228")

        assert bp.cve_id == "CVE-2021-44228"
        assert len(bp.techniques) > 0
        assert mock_graph.create_node.called or mock_graph.create_edge.called
        assert mock_ledger.append_entry.called

    def test_handles_graph_edge_creation_and_update_errors(self):
        from unittest.mock import MagicMock

        from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent

        mock_node = {
            "id": "CVE-2021-44228",
            "attack_vector": "NETWORK",
            "cvss_score": 10.0,
            "cwe_id": "CWE-917",
        }
        mock_graph = MagicMock()
        mock_graph.get_latest_version.return_value = mock_node
        mock_graph.get_node.return_value = mock_node
        mock_graph.update_node.side_effect = Exception("Neo4j update timeout")
        mock_graph.create_edge.side_effect = Exception("Neo4j edge error")

        mock_ledger = MagicMock()
        mock_ledger.append_entry.side_effect = Exception("Ledger down")

        agent = ThreatReconstructionAgent(
            graph_client=mock_graph, ledger=mock_ledger, db_client=MagicMock()
        )
        bp = agent.blueprint("CVE-2021-44228")
        assert bp.cve_id == "CVE-2021-44228"
