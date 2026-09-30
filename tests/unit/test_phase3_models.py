"""Unit tests for Phase 3 Pydantic models and event types."""

from __future__ import annotations

import pytest

from core.agents.attack_mapper.models import MappingResult
from core.agents.sandbox_replay.models import (
    ReplayReport,
    ReplaySession,
    TechniqueResult,
)
from core.agents.threat_reconstruction.models import (
    Blueprint,
    BlueprintEdge,
    BlueprintTechnique,
)
from core.agents.vulnerability.models import (
    CVEAnalysis,
    CVSSMetrics,
    TechniqueMapping,
)
from core.events.types import (
    BlueprintGeneratedEvent,
    CVEAnalyzedEvent,
    ReplaySessionEvent,
)


class TestCVSSMetrics:
    def test_valid_metrics(self):
        m = CVSSMetrics(
            version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            base_score=10.0,
            base_severity="CRITICAL",
            attack_vector="NETWORK",
            attack_complexity="LOW",
            privileges_required="NONE",
            user_interaction="NONE",
            scope="CHANGED",
            confidentiality_impact="HIGH",
            integrity_impact="HIGH",
            availability_impact="HIGH",
        )
        assert m.base_score == 10.0
        assert m.version == "3.1"

    def test_exploitability_score_optional(self):
        m = CVSSMetrics(
            version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            base_score=10.0,
            base_severity="CRITICAL",
            attack_vector="NETWORK",
            attack_complexity="LOW",
            privileges_required="NONE",
            user_interaction="NONE",
            scope="CHANGED",
            confidentiality_impact="HIGH",
            integrity_impact="HIGH",
            availability_impact="HIGH",
        )
        assert m.exploitability_score is None


class TestCVEAnalysis:
    def test_defaults(self):
        a = CVEAnalysis(cve_id="CVE-2021-44228", node_id="")
        assert a.technique_mappings == []
        assert a.cpe_matches == []
        assert a.source_agent == "vulnerability_intelligence"

    def test_analyzed_at_set(self):
        a = CVEAnalysis(cve_id="CVE-2021-44228", node_id="")
        assert "T" in a.analyzed_at  # ISO-8601 contains T

    def test_serialization_excludes_raw_nvd_data(self):
        a = CVEAnalysis(
            cve_id="CVE-2021-44228", node_id="", raw_nvd_data={"big": "blob"}
        )
        data = a.model_dump(exclude={"raw_nvd_data"})
        assert "raw_nvd_data" not in data


class TestTechniqueMapping:
    def test_confidence_bounds(self):
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            TechniqueMapping(
                technique_id="T1190",
                technique_name="Test",
                tactic="initial-access",
                confidence=1.5,  # > 1.0 — invalid
                rationale="test",
            )

    def test_valid_mapping(self):
        m = TechniqueMapping(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            confidence=0.95,
            rationale="Network accessible",
        )
        assert m.technique_id == "T1190"


class TestBlueprintModels:
    def test_blueprint_defaults(self):
        bp = Blueprint(
            blueprint_id="BP-CVE-2021-44228-ABCD1234",
            cve_id="CVE-2021-44228",
        )
        assert bp.techniques == []
        assert bp.edges == []
        assert bp.source_agent == "threat_reconstruction"

    def test_blueprint_technique_status(self):
        t = BlueprintTechnique(
            technique_id="T1190",
            technique_name="Exploit",
            tactic="initial-access",
            tactic_phase=0,
            confidence=0.9,
            rationale="test",
        )
        assert t.status == "hypothesized"

    def test_blueprint_edge_defaults(self):
        e = BlueprintEdge(
            from_technique_id="T1190",
            to_technique_id="T1059",
            probability=0.8,
        )
        assert e.status == "hypothesized"


class TestReplayModels:
    def test_replay_session_defaults(self):
        s = ReplaySession(
            session_id="RS-ABCDEF123456",
            blueprint_id="BP-CVE-TEST-AAAA1111",
            cve_id="CVE-2021-44228",
        )
        assert s.status == "pending"
        assert s.telemetry_artifacts == []

    def test_technique_result_confidence_bounds(self):
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            TechniqueResult(
                technique_id="T1190",
                technique_name="Test",
                status="confirmed",
                confidence=1.5,
            )

    def test_replay_report_model(self):
        r = ReplayReport(
            session_id="RS-ABCDEF123456",
            blueprint_id="BP-CVE-TEST-AAAA1111",
            cve_id="CVE-2021-44228",
        )
        assert r.telemetry_count == 0
        assert r.confirmed_techniques == []


class TestMappingResult:
    def test_defaults(self):
        r = MappingResult(
            evidence_id="EV-001",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            confidence=0.8,
            rule_name="shell_execution",
            rationale="bash detected",
        )
        assert r.edge_id == ""
        assert r.session_id is None
        assert "T" in r.mapped_at


class TestPhase3EventTypes:
    def test_cve_analyzed_event(self):
        e = CVEAnalyzedEvent(
            cve_id="CVE-2021-44228",
            node_id="CVE-2021-44228",
            cvss_score=10.0,
            severity="CRITICAL",
            technique_ids=["T1190", "T1059"],
        )
        assert e.event_type == "cve_analyzed"
        assert e.cve_id == "CVE-2021-44228"
        assert len(e.technique_ids) == 2

    def test_blueprint_generated_event(self):
        e = BlueprintGeneratedEvent(
            blueprint_id="BP-CVE-2021-44228-ABCD1234",
            cve_id="CVE-2021-44228",
            technique_count=5,
        )
        assert e.event_type == "blueprint_generated"
        assert e.technique_count == 5

    def test_replay_session_event(self):
        e = ReplaySessionEvent(
            session_id="RS-ABCDEF123456",
            blueprint_id="BP-CVE-2021-44228-ABCD1234",
            cve_id="CVE-2021-44228",
            status="completed",
            confirmed_count=3,
            refuted_count=1,
        )
        assert e.event_type == "replay_session"
        assert e.status == "completed"
        assert e.confirmed_count == 3

    def test_events_have_event_id(self):
        e = CVEAnalyzedEvent(cve_id="CVE-2021-44228", node_id="test")
        assert len(e.event_id) > 0

    def test_events_have_timestamp(self):
        e = BlueprintGeneratedEvent(
            blueprint_id="BP-1",
            cve_id="CVE-2021-44228",
        )
        assert e.timestamp is not None
