"""Unit tests for the Sandbox Replay Agent — FR-5, FR-6."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.agents.sandbox_replay.agent import SandboxReplayAgent
from core.agents.sandbox_replay.exceptions import (
    SandboxCleanupError,
    SandboxIsolationError,
    SandboxStartError,
    SandboxStopError,
    TelemetryIngestError,
)
from core.agents.sandbox_replay.orchestrator import (
    SandboxOrchestrator,
    sandbox_cleanup,
)
from core.agents.sandbox_replay.telemetry import (
    collect_telemetry,
    create_synthetic_telemetry,
)
from core.agents.threat_reconstruction.models import (
    Blueprint,
    BlueprintEdge,
    BlueprintTechnique,
)
from core.config.settings import Settings


def _make_blueprint(cve_id: str = "CVE-2021-44228") -> Blueprint:
    return Blueprint(
        blueprint_id=f"BP-{cve_id}-ABCD1234",
        cve_id=cve_id,
        techniques=[
            BlueprintTechnique(
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic="initial-access",
                tactic_phase=0,
                confidence=0.95,
                status="hypothesized",
                rationale="Network unauth",
            ),
            BlueprintTechnique(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactic="execution",
                tactic_phase=1,
                confidence=0.80,
                status="hypothesized",
                rationale="RCE leads to shell",
            ),
        ],
        edges=[
            BlueprintEdge(
                from_technique_id="T1190",
                to_technique_id="T1059",
                probability=0.87,
                status="hypothesized",
            )
        ],
        total_confidence=0.875,
    )


@pytest.fixture
def mock_graph() -> MagicMock:
    g = MagicMock()
    g.create_node.return_value = "node-001"
    g.create_edge.return_value = "edge-001"
    g.get_node.return_value = None
    g.query.return_value = []
    return g


@pytest.fixture
def mock_ledger() -> MagicMock:
    ledger = MagicMock()
    entry = MagicMock()
    entry.id = 1
    ledger.append_entry.return_value = entry
    return ledger


@pytest.fixture
def mock_db() -> MagicMock:
    db = MagicMock()
    return db


@pytest.fixture
def dry_run_agent(mock_graph, mock_ledger, mock_db) -> SandboxReplayAgent:
    return SandboxReplayAgent(
        settings=Settings(
            app_env="testing", sandbox_telemetry_dir="/tmp/evidencegraphai_test_sandbox"
        ),
        graph_client=mock_graph,
        ledger=mock_ledger,
        db_client=mock_db,
        dry_run=True,
    )


# ---------------------------------------------------------------------------
# SandboxReplayAgent Dry-Run Tests
# ---------------------------------------------------------------------------


class TestSandboxReplayAgentDryRun:
    def test_returns_replay_session(self, dry_run_agent):
        bp = _make_blueprint()
        with (
            patch(
                "core.agents.sandbox_replay.agent.collect_telemetry", return_value=[]
            ),
            patch("core.agents.sandbox_replay.agent.create_synthetic_telemetry"),
        ):
            session = dry_run_agent.replay(bp)
        assert session.cve_id == "CVE-2021-44228"
        assert session.blueprint_id == bp.blueprint_id
        assert session.status == "completed"

    def test_updates_node_with_session(self, dry_run_agent, mock_db):
        bp = _make_blueprint()
        with (
            patch(
                "core.agents.sandbox_replay.agent.collect_telemetry", return_value=[]
            ),
            patch("core.agents.sandbox_replay.agent.create_synthetic_telemetry"),
        ):
            dry_run_agent.replay(bp)
        assert mock_db.execute.called

    def test_creates_ledger_entry(self, dry_run_agent, mock_ledger):
        bp = _make_blueprint()
        with (
            patch(
                "core.agents.sandbox_replay.agent.collect_telemetry", return_value=[]
            ),
            patch("core.agents.sandbox_replay.agent.create_synthetic_telemetry"),
        ):
            dry_run_agent.replay(bp)
        assert mock_ledger.append_entry.called

    def test_publishes_event(self, dry_run_agent):
        bp = _make_blueprint()
        with (
            patch(
                "core.agents.sandbox_replay.agent.collect_telemetry", return_value=[]
            ),
            patch("core.agents.sandbox_replay.agent.create_synthetic_telemetry"),
            patch("core.agents.sandbox_replay.agent.get_event_bus") as mock_bus,
        ):
            mock_bus.return_value = MagicMock()
            dry_run_agent.replay(bp)
            mock_bus.return_value.publish.assert_called_once()

    def test_handles_telemetry_collection_failure(self, dry_run_agent):
        bp = _make_blueprint()
        with (
            patch(
                "core.agents.sandbox_replay.agent.collect_telemetry",
                side_effect=Exception("Telemetry error"),
            ),
            patch("core.agents.sandbox_replay.agent.create_synthetic_telemetry"),
        ):
            session = dry_run_agent.replay(bp)
        assert session.status in ("completed", "failed")

    def test_live_replay_flow_with_mocked_orchestrator(
        self, mock_graph, mock_ledger, mock_db
    ):
        agent = SandboxReplayAgent(
            settings=Settings(app_env="testing"),
            graph_client=mock_graph,
            ledger=mock_ledger,
            db_client=mock_db,
            dry_run=False,
        )
        bp = _make_blueprint()
        with (
            patch.object(agent.orchestrator, "start") as mock_start,
            patch.object(agent.orchestrator, "verify_isolation", return_value=True),
            patch.object(agent, "_execute_attack") as mock_exec,
            patch.object(agent, "_collect_pcap"),
            patch.object(agent.orchestrator, "teardown") as mock_down,
            patch(
                "core.agents.sandbox_replay.agent.collect_telemetry", return_value=[]
            ),
        ):
            session = agent.replay(bp)
            assert session.status == "completed"
            assert mock_start.called
            assert mock_exec.called
            assert mock_down.called


# ---------------------------------------------------------------------------
# Synthetic telemetry Tests
# ---------------------------------------------------------------------------


class TestCreateSyntheticTelemetry:
    def test_creates_directory(self, tmp_path):
        session_dir = tmp_path / "test_session"
        result = create_synthetic_telemetry(
            session_dir, "CVE-2021-44228", "test_script.sh"
        )
        assert result.is_dir()

    def test_creates_log_file(self, tmp_path):
        session_dir = tmp_path / "test_session"
        create_synthetic_telemetry(session_dir, "CVE-2021-44228", "test_script.sh")
        log_files = list(session_dir.glob("*.log"))
        assert len(log_files) > 0

    def test_creates_json_events_file(self, tmp_path):
        session_dir = tmp_path / "test_session"
        create_synthetic_telemetry(session_dir, "CVE-2021-44228", "test_script.sh")
        json_files = list(session_dir.glob("*.json"))
        assert len(json_files) > 0

    def test_log_contains_technique_hints(self, tmp_path):
        session_dir = tmp_path / "test_session"
        create_synthetic_telemetry(session_dir, "CVE-2021-44228", "test_script.sh")
        log_files = list(session_dir.glob("*.log"))
        content = log_files[0].read_text(encoding="utf-8")
        assert "T1190" in content

    def test_json_events_are_valid(self, tmp_path):
        import json

        session_dir = tmp_path / "test_session"
        create_synthetic_telemetry(session_dir, "CVE-2021-44228", "test_script.sh")
        json_files = list(session_dir.glob("*.json"))
        data = json.loads(json_files[0].read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) > 0


# ---------------------------------------------------------------------------
# Telemetry Collection Tests
# ---------------------------------------------------------------------------


class TestCollectTelemetry:
    def test_raises_when_directory_missing(self, tmp_path):
        missing = tmp_path / "does_not_exist"
        with pytest.raises(TelemetryIngestError):
            collect_telemetry(missing, session_id="RS-001")

    def test_returns_empty_when_directory_empty(self, tmp_path):
        empty_dir = tmp_path / "empty_session"
        empty_dir.mkdir()
        artifacts = collect_telemetry(empty_dir, session_id="RS-001")
        assert artifacts == []

    def test_ingests_pcap_and_logs(self, tmp_path):
        session_dir = tmp_path / "session_with_files"
        session_dir.mkdir()
        (session_dir / "traffic.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        (session_dir / "audit.log").write_text("user logged in\n", encoding="utf-8")
        (session_dir / "unknown.bin").write_bytes(b"\x00\x01\x02")

        mock_ingestor = MagicMock()
        mock_result = MagicMock()
        mock_result.evidence_id = "EV-001"
        mock_result.artifact_type = "pcap"
        mock_result.sha256 = "abc123"
        mock_result.file_size_bytes = 24
        mock_ingestor.ingest.return_value = mock_result

        artifacts = collect_telemetry(
            session_dir,
            session_id="RS-001",
            ingestor=mock_ingestor,
        )
        assert len(artifacts) == 2
        assert mock_ingestor.ingest.call_count == 2


# ---------------------------------------------------------------------------
# Sandbox Orchestrator Unit Tests
# ---------------------------------------------------------------------------


class TestSandboxOrchestrator:
    def test_start_raises_if_compose_file_missing(self):
        orch = SandboxOrchestrator(
            settings=Settings(sandbox_compose_file="nonexistent_compose.yml")
        )
        with pytest.raises(SandboxStartError):
            orch.start()

    def test_start_success_with_mocked_compose(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("services: {}", encoding="utf-8")
        orch = SandboxOrchestrator(
            settings=Settings(sandbox_compose_file=str(compose_file))
        )

        mock_ps = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='[{"State": "running", "Health": "healthy"}]',
            stderr="",
        )
        mock_up = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ok", stderr=""
        )

        with patch.object(orch, "_run_compose", side_effect=[mock_up, mock_ps]):
            orch.start(timeout=5)

    def test_start_raises_on_compose_failure(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("services: {}", encoding="utf-8")
        orch = SandboxOrchestrator(
            settings=Settings(sandbox_compose_file=str(compose_file))
        )

        mock_up = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Compose error"
        )
        with (
            patch.object(orch, "_run_compose", return_value=mock_up),
            pytest.raises(SandboxStartError),
        ):
            orch.start()

    def test_stop_and_teardown(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("services: {}", encoding="utf-8")
        orch = SandboxOrchestrator(
            settings=Settings(sandbox_compose_file=str(compose_file))
        )

        mock_res = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="stopped", stderr=""
        )
        with patch.object(orch, "_run_compose", return_value=mock_res):
            orch.stop()
            orch.teardown()

    def test_stop_raises_on_failure(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("services: {}", encoding="utf-8")
        orch = SandboxOrchestrator(
            settings=Settings(sandbox_compose_file=str(compose_file))
        )

        mock_fail = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Stop failed"
        )
        with (
            patch.object(orch, "_run_compose", return_value=mock_fail),
            pytest.raises(SandboxStopError),
        ):
            orch.stop()

    def test_verify_isolation_passed_when_blocked(self):
        orch = SandboxOrchestrator()
        mock_blocked = subprocess.CompletedProcess(
            args=[], returncode=28, stdout="", stderr="Connection timed out"
        )
        with patch.object(orch, "_run_compose", return_value=mock_blocked):
            assert orch.verify_isolation() is True

    def test_verify_isolation_raises_when_traffic_leaks(self):
        orch = SandboxOrchestrator()
        mock_leak = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="HTTP/1.1 200 OK", stderr=""
        )
        with (
            patch.object(orch, "_run_compose", return_value=mock_leak),
            pytest.raises(SandboxIsolationError),
        ):
            orch.verify_isolation()

    def test_is_running_check(self):
        orch = SandboxOrchestrator()
        mock_running = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="attacker\nvictim", stderr=""
        )
        with patch.object(orch, "_run_compose", return_value=mock_running):
            assert orch.is_running() is True

        mock_stopped = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        with patch.object(orch, "_run_compose", return_value=mock_stopped):
            assert orch.is_running() is False

    def test_sandbox_cleanup(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("services: {}", encoding="utf-8")
        settings = Settings(sandbox_compose_file=str(compose_file))

        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            result = sandbox_cleanup(settings=settings)
            assert "removed_containers" in result

    def test_sandbox_cleanup_raises_on_errors(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("services: {}", encoding="utf-8")
        settings = Settings(sandbox_compose_file=str(compose_file))

        with (
            patch("subprocess.run") as mock_sub,
            pytest.raises(SandboxCleanupError),
        ):
            mock_sub.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="docker error"
            )
            sandbox_cleanup(settings=settings)

    def test_wait_for_healthy_timeout(self):
        orch = SandboxOrchestrator()
        with (
            patch.object(
                orch, "get_service_status", return_value=[{"Health": "unhealthy"}]
            ),
            patch("time.sleep"),
            pytest.raises(SandboxStartError),
        ):
            orch._wait_for_healthy(timeout=0)

    def test_get_service_status_multiline_json(self):
        orch = SandboxOrchestrator()
        stdout = '{"Service": "attacker", "State": "running"}\n{"Service": "victim", "State": "running"}'
        mock_res = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with patch.object(orch, "_run_compose", return_value=mock_res):
            statuses = orch.get_service_status()
            assert len(statuses) == 2

    def test_execute_attack_and_pcap_collection(self, dry_run_agent):
        with patch("subprocess.run") as mock_sub:
            # Test success
            mock_sub.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="ok", stderr=""
            )
            dry_run_agent._execute_attack("/scripts/test.sh")

            # Test timeout
            mock_sub.side_effect = subprocess.TimeoutExpired(cmd="bash", timeout=5)
            from core.agents.sandbox_replay.exceptions import (
                ReplayScriptError,
                SandboxTimeoutError,
            )

            with pytest.raises(SandboxTimeoutError):
                dry_run_agent._execute_attack("/scripts/test.sh", timeout=5)

            # Test script failure
            mock_sub.side_effect = None
            mock_sub.return_value = subprocess.CompletedProcess(
                args=[], returncode=2, stdout="", stderr="Script failed"
            )
            with pytest.raises(ReplayScriptError):
                dry_run_agent._execute_attack("/scripts/test.sh")

            # Test collect pcap warning
            mock_sub.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="cp failed"
            )
            dry_run_agent._collect_pcap(Path("/tmp"))

    def test_update_edge_statuses(self, dry_run_agent, mock_graph):
        bp = _make_blueprint()
        bp.edges[0].edge_id = "edge-123"
        # Test confirmed
        dry_run_agent._update_edge_statuses(
            bp, confirmed_ids=["T1190", "T1059"], refuted_ids=[], actor="test"
        )
        assert mock_graph.query.called

        # Test refuted
        dry_run_agent._update_edge_statuses(
            bp, confirmed_ids=[], refuted_ids=["T1190"], actor="test"
        )
        assert mock_graph.query.called

        # Test graph exception handling
        mock_graph.query.side_effect = Exception("Graph query failed")
        dry_run_agent._update_edge_statuses(
            bp, confirmed_ids=["T1190", "T1059"], refuted_ids=[], actor="test"
        )

    def test_replay_with_telemetry_artifacts_and_mapping(self, dry_run_agent):
        from core.agents.attack_mapper.models import MappingResult
        from core.agents.sandbox_replay.models import TelemetryArtifact

        bp = _make_blueprint()
        mock_artifact = TelemetryArtifact(
            artifact_id="EA-001",
            artifact_type="text",
            sha256="abc123",
            size_bytes=100,
            path="/tmp/test.log",
        )
        mock_mapping_high = MappingResult(
            evidence_id="EA-001",
            technique_id="T1190",
            technique_name="Exploit Public-Facing App",
            tactic="initial-access",
            confidence=0.95,
            rule_name="rule-1",
            rationale="Matched log",
        )
        mock_mapping_low = MappingResult(
            evidence_id="EA-001",
            technique_id="T1059",
            technique_name="Command Interpreter",
            tactic="execution",
            confidence=0.5,
            rule_name="rule-2",
            rationale="Low confidence",
        )

        with (
            patch("core.agents.sandbox_replay.agent.create_synthetic_telemetry"),
            patch(
                "core.agents.sandbox_replay.agent.collect_telemetry",
                return_value=[mock_artifact],
            ),
            patch(
                "core.agents.attack_mapper.mapper.ATTACKMapper.map_artifact",
                return_value=[mock_mapping_high, mock_mapping_low],
            ),
        ):
            session = dry_run_agent.replay(bp)
            assert session.status == "completed"
            assert len(session.technique_results) == 2
            confirmed = [
                r for r in session.technique_results if r.status == "confirmed"
            ]
            inconclusive = [
                r for r in session.technique_results if r.status == "inconclusive"
            ]
            assert len(confirmed) == 1
            assert len(inconclusive) == 1

    def test_replay_timeout_and_isolation_failure(
        self, mock_graph, mock_ledger, mock_db
    ):
        from core.agents.sandbox_replay.exceptions import (
            SandboxIsolationError,
            SandboxTimeoutError,
        )

        agent = SandboxReplayAgent(
            settings=Settings(app_env="testing"),
            graph_client=mock_graph,
            ledger=mock_ledger,
            db_client=mock_db,
            dry_run=False,
        )
        bp = _make_blueprint()

        # Test timeout handling in replay
        with (
            patch.object(agent.orchestrator, "start"),
            patch.object(agent.orchestrator, "verify_isolation"),
            patch.object(
                agent, "_execute_attack", side_effect=SandboxTimeoutError("Timeout")
            ),
            patch.object(agent.orchestrator, "teardown"),
        ):
            session = agent.replay(bp)
            assert session.status == "failed"
            assert "timed out" in (session.error_message or "")

        # Test isolation failure in live replay
        with (
            patch.object(agent.orchestrator, "start"),
            patch.object(
                agent.orchestrator,
                "verify_isolation",
                side_effect=SandboxIsolationError("Leak detected"),
            ),
            patch.object(
                agent.orchestrator, "teardown", side_effect=Exception("Teardown fail")
            ),
        ):
            session = agent.replay(bp)
            assert session.status == "failed"

    def test_replay_db_and_ledger_exception_tolerance(
        self, dry_run_agent, mock_ledger, mock_db
    ):
        bp = _make_blueprint()
        mock_ledger.append_entry.side_effect = Exception("Ledger down")
        mock_db.execute.side_effect = Exception("DB down")

        with (
            patch("core.agents.sandbox_replay.agent.create_synthetic_telemetry"),
            patch(
                "core.agents.sandbox_replay.agent.collect_telemetry", return_value=[]
            ),
        ):
            session = dry_run_agent.replay(bp)
            assert session.status == "completed"
