"""Sandbox Replay Agent — orchestrates end-to-end attack replay.

Given a ``Blueprint`` and an optional attack script path, this agent:

1. Creates a ``ReplaySession`` record in PostgreSQL (status=pending).
2. Starts the sandbox Docker environment (via ``SandboxOrchestrator``).
3. Verifies isolation (no internet access).
4. Executes the attack script inside the attacker container.
5. Collects telemetry from the shared volume.
6. Ingests telemetry via Phase 2's ``ArtifactIngestor``.
7. Maps telemetry to ATT&CK techniques via the ``ATTACKMapper``.
8. Updates ``EXPECTED_TO_LEAD_TO`` edge statuses (confirmed/refuted).
9. Updates the PostgreSQL ``replay_sessions`` record (status=completed).
10. Appends a ledger entry.
11. Publishes a ``ReplaySessionEvent``.
12. Returns the ``ReplaySession`` model.

Provenance contract: ``source_agent = "sandbox_replay"``
"""

from __future__ import annotations

import json
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from core.agents.sandbox_replay.exceptions import (
    ReplayScriptError,
    SandboxTimeoutError,
)
from core.agents.sandbox_replay.models import (
    ReplayReport,
    ReplaySession,
    TechniqueResult,
)
from core.agents.sandbox_replay.orchestrator import SandboxOrchestrator
from core.agents.sandbox_replay.telemetry import (
    collect_telemetry,
    create_synthetic_telemetry,
)
from core.agents.threat_reconstruction.models import Blueprint
from core.config.settings import Settings, get_settings
from core.custody.ledger import CustodyLedger
from core.db.postgres import PostgresClient
from core.events.bus import get_event_bus
from core.events.types import ReplaySessionEvent
from core.graph.client import GraphClient
from core.logging.logger import get_logger

logger = get_logger("core.agents.sandbox_replay.agent")

_SOURCE_AGENT = "sandbox_replay"


class SandboxReplayAgent:
    """Orchestrates attack replay and telemetry mapping.

    Parameters
    ----------
    settings:
        Application settings.
    graph_client:
        Neo4j client for updating edge statuses.
    ledger:
        Chain-of-custody ledger.
    db_client:
        PostgreSQL client for session tracking.
    orchestrator:
        Sandbox Docker orchestrator (injectable for testing).
    dry_run:
        If True, skip actual Docker operations and use synthetic telemetry.
        Useful for unit tests and CI environments without Docker.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        graph_client: GraphClient | None = None,
        ledger: CustodyLedger | None = None,
        db_client: PostgresClient | None = None,
        orchestrator: SandboxOrchestrator | None = None,
        dry_run: bool = False,
    ) -> None:
        self.settings = settings or get_settings()
        self.db = db_client or PostgresClient(settings=self.settings)
        self.graph = graph_client or GraphClient(settings=self.settings)
        self.ledger = ledger or CustodyLedger(db_client=self.db)
        self.orchestrator = orchestrator or SandboxOrchestrator(settings=self.settings)
        self.dry_run = dry_run

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def replay(
        self,
        blueprint: Blueprint,
        attack_script: str | None = None,
        actor: str = _SOURCE_AGENT,
    ) -> ReplaySession:
        """Executes a full sandbox replay of a threat blueprint.

        Args:
            blueprint: ``Blueprint`` from the Threat Reconstruction Agent.
            attack_script: Path to the attack script inside the attacker container.
                Defaults to the CVE-specific script in ``infra/sandbox/scripts/``.
            actor: Provenance actor string.

        Returns:
            Completed ``ReplaySession`` model.

        Raises:
            SandboxError: On unrecoverable sandbox failures.
        """
        session_id = f"RS-{uuid.uuid4().hex[:12].upper()}"
        cve_id = blueprint.cve_id
        logger.info(
            "Starting sandbox replay",
            session_id=session_id,
            blueprint_id=blueprint.blueprint_id,
            cve_id=cve_id,
            dry_run=self.dry_run,
        )

        session = ReplaySession(
            session_id=session_id,
            blueprint_id=blueprint.blueprint_id,
            cve_id=cve_id,
            status="pending",
            attack_script=attack_script,
        )

        # Step 1: Persist session to PostgreSQL (status=pending)
        self._upsert_session(session)

        try:
            session.status = "running"
            session.started_at = datetime.now(UTC).isoformat()
            self._upsert_session(session)

            # Steps 2–4: Sandbox lifecycle
            telemetry_dir = Path(self.settings.sandbox_telemetry_dir) / session_id
            telemetry_dir.mkdir(parents=True, exist_ok=True)

            if not self.dry_run:
                self.orchestrator.start(timeout=120)
                try:
                    self.orchestrator.verify_isolation()
                except Exception as exc:
                    logger.error("Isolation check failed", error=str(exc))
                    raise

                effective_script = attack_script or self._default_script(cve_id)
                self._execute_attack(
                    effective_script, timeout=self.settings.sandbox_replay_timeout
                )
                self._collect_pcap(telemetry_dir)
            else:
                # Dry-run: produce synthetic telemetry for testing
                create_synthetic_telemetry(
                    session_dir=telemetry_dir,
                    cve_id=cve_id,
                    attack_script=attack_script or "synthetic",
                )
                logger.info(
                    "Dry-run: synthetic telemetry created", dir=str(telemetry_dir)
                )

            # Steps 5–6: Collect and ingest telemetry
            artifacts = collect_telemetry(
                telemetry_dir=telemetry_dir,
                session_id=session_id,
                actor=actor,
                anonymize=False,
            )
            session.telemetry_artifacts = artifacts

            # Step 7: ATT&CK mapping (lazy import to avoid circular deps)
            from core.agents.attack_mapper.mapper import ATTACKMapper  # noqa: PLC0415

            mapper = ATTACKMapper(graph_client=self.graph)
            all_results: list[TechniqueResult] = []

            for artifact in artifacts:
                mappings = mapper.map_artifact(
                    evidence_id=artifact.artifact_id,
                    content=None,  # mapper reads from file if needed
                    session_id=session_id,
                    actor=actor,
                )
                for m in mappings:
                    tr = TechniqueResult(
                        technique_id=m.technique_id,
                        technique_name=m.technique_name,
                        status="confirmed" if m.confidence >= 0.7 else "inconclusive",
                        confidence=m.confidence,
                        evidence_artifact_ids=[artifact.artifact_id],
                        rationale=m.rationale,
                    )
                    all_results.append(tr)

            session.technique_results = all_results

            # Step 8: Update EXPECTED_TO_LEAD_TO edges
            confirmed_ids = [
                r.technique_id for r in all_results if r.status == "confirmed"
            ]
            refuted_ids = [
                t.technique_id
                for t in blueprint.techniques
                if t.technique_id not in confirmed_ids
            ]
            self._update_edge_statuses(blueprint, confirmed_ids, refuted_ids, actor)

            # Build report
            completed_at = datetime.now(UTC).isoformat()
            duration = (
                (
                    datetime.fromisoformat(completed_at)
                    - datetime.fromisoformat(session.started_at)
                ).total_seconds()
                if session.started_at
                else 0.0
            )

            report = ReplayReport(
                session_id=session_id,
                blueprint_id=blueprint.blueprint_id,
                cve_id=cve_id,
                duration_seconds=duration,
                telemetry_count=len(artifacts),
                confirmed_techniques=[
                    r for r in all_results if r.status == "confirmed"
                ],
                refuted_techniques=[
                    TechniqueResult(
                        technique_id=rid,
                        technique_name=next(
                            (
                                t.technique_name
                                for t in blueprint.techniques
                                if t.technique_id == rid
                            ),
                            rid,
                        ),
                        status="refuted",
                        confidence=0.0,
                        rationale="No telemetry evidence found for this technique",
                    )
                    for rid in refuted_ids
                ],
            )
            session.report = report
            session.status = "completed"
            session.completed_at = completed_at

        except SandboxTimeoutError as exc:
            session.status = "failed"
            session.error_message = f"Replay timed out: {exc}"
            logger.error("Replay timed out", session_id=session_id, error=str(exc))
        except Exception as exc:
            session.status = "failed"
            session.error_message = str(exc)
            logger.error("Replay failed", session_id=session_id, error=str(exc))
        finally:
            if not self.dry_run:
                try:
                    self.orchestrator.teardown()
                except Exception as exc:
                    logger.warning("Sandbox teardown error", error=str(exc))

        # Step 9: Update PostgreSQL
        self._upsert_session(session)

        # Step 10: Ledger
        try:
            import hashlib

            self.ledger.append_entry(
                evidence_id=session_id,
                action="DERIVE",
                actor=actor,
                sha256=hashlib.sha256(session_id.encode()).hexdigest(),
                metadata={
                    "blueprint_id": blueprint.blueprint_id,
                    "cve_id": cve_id,
                    "status": session.status,
                    "telemetry_count": len(session.telemetry_artifacts),
                },
            )
        except Exception as exc:
            logger.warning("Ledger append failed for replay session", error=str(exc))

        # Step 11: Publish event
        try:
            rep = session.report
            confirmed_count = len(rep.confirmed_techniques) if rep else 0
            refuted_count = len(rep.refuted_techniques) if rep else 0
            get_event_bus().publish(
                ReplaySessionEvent(
                    session_id=session_id,
                    blueprint_id=blueprint.blueprint_id,
                    cve_id=cve_id,
                    status=session.status,
                    confirmed_count=confirmed_count,
                    refuted_count=refuted_count,
                    actor=actor,
                )
            )
        except Exception as exc:
            logger.warning("Failed to publish ReplaySessionEvent", error=str(exc))

        logger.info(
            "Replay complete",
            session_id=session_id,
            status=session.status,
            artifacts=len(session.telemetry_artifacts),
        )
        return session

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute_attack(self, script: str, timeout: int = 300) -> None:
        """Runs the attack script inside the attacker container."""
        cmd = [
            "docker",
            "compose",
            "-f",
            str(self.orchestrator.compose_file),
            "exec",
            "-T",
            "attacker",
            "bash",
            script,
        ]
        logger.info("Executing attack script", script=script)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode not in (0, 1):  # 1 = partial — tolerated
                raise ReplayScriptError(
                    f"Attack script exited with code {result.returncode}: {result.stderr}"
                )
        except subprocess.TimeoutExpired as exc:
            raise SandboxTimeoutError(
                f"Attack script timed out after {timeout}s"
            ) from exc

    def _collect_pcap(self, telemetry_dir: Path) -> None:
        """Copies PCAP output from the tcpdump sidecar container."""
        cmd = [
            "docker",
            "cp",
            "evidencegraphai_sandbox-tcpdump-1:/captures/.",
            str(telemetry_dir),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            logger.warning("Could not copy PCAP captures", error=result.stderr)

    @staticmethod
    def _default_script(cve_id: str) -> str:
        """Returns the default attack script path for a CVE."""
        slug = cve_id.lower().replace("-", "_")
        return f"/scripts/{slug}_attack.sh"

    def _upsert_session(self, session: ReplaySession) -> None:
        """Persists the replay session to PostgreSQL."""
        report_json = None
        if session.report:
            report_json = json.dumps(session.report.model_dump())

        confirmed = json.dumps(
            [
                r.technique_id
                for r in session.technique_results
                if r.status == "confirmed"
            ]
        )
        refuted = json.dumps(
            [r.technique_id for r in session.technique_results if r.status == "refuted"]
        )

        try:
            self.db.execute(
                """
                INSERT INTO replay_sessions (
                    session_id, blueprint_id, cve_id, status, started_at,
                    completed_at, created_at, attack_script, telemetry_paths,
                    artifact_ids, confirmed_techniques, refuted_techniques,
                    replay_report, error_message
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (session_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    started_at = EXCLUDED.started_at,
                    completed_at = EXCLUDED.completed_at,
                    telemetry_paths = EXCLUDED.telemetry_paths,
                    artifact_ids = EXCLUDED.artifact_ids,
                    confirmed_techniques = EXCLUDED.confirmed_techniques,
                    refuted_techniques = EXCLUDED.refuted_techniques,
                    replay_report = EXCLUDED.replay_report,
                    error_message = EXCLUDED.error_message
                """,
                (
                    session.session_id,
                    session.blueprint_id,
                    session.cve_id,
                    session.status,
                    session.started_at,
                    session.completed_at,
                    session.created_at,
                    session.attack_script,
                    json.dumps([a.path for a in session.telemetry_artifacts]),
                    json.dumps([a.artifact_id for a in session.telemetry_artifacts]),
                    confirmed,
                    refuted,
                    report_json,
                    session.error_message,
                ),
            )
        except Exception as exc:
            logger.warning(
                "Failed to persist replay session to PostgreSQL", error=str(exc)
            )

    def _update_edge_statuses(
        self,
        blueprint: Blueprint,
        confirmed_ids: list[str],
        refuted_ids: list[str],
        actor: str,
    ) -> None:
        """Updates EXPECTED_TO_LEAD_TO edge statuses based on replay results."""
        now = datetime.now(UTC).isoformat()
        for edge in blueprint.edges:
            if (
                edge.from_technique_id in confirmed_ids
                and edge.to_technique_id in confirmed_ids
            ):
                new_status = "confirmed"
            elif (
                edge.from_technique_id in refuted_ids
                or edge.to_technique_id in refuted_ids
            ):
                new_status = "refuted"
            else:
                continue

            if edge.edge_id:
                try:
                    self.graph.query(
                        "MATCH ()-[r {id: $eid}]->() SET r.status = $status, r.updated_at = $now",
                        {"eid": edge.edge_id, "status": new_status, "now": now},
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to update edge status",
                        edge_id=edge.edge_id,
                        error=str(exc),
                    )
