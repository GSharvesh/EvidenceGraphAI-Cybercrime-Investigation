"""Telemetry collector for the Sandbox Replay Agent.

Scans the sandbox telemetry output directory for captured artifacts
(PCAPs, logs, JSON events) and ingests them via Phase 2's ``ArtifactIngestor``.

This module is intentionally stateless: it receives a telemetry directory
path and returns a list of ``TelemetryArtifact`` models.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.agents.sandbox_replay.exceptions import TelemetryIngestError
from core.agents.sandbox_replay.models import TelemetryArtifact
from core.ingestion.ingestor import ArtifactIngestor, IngestResult
from core.logging.logger import get_logger

logger = get_logger("core.agents.sandbox_replay.telemetry")

# File extension → artifact type hint mapping
_EXT_TYPE_MAP: dict[str, str] = {
    ".pcap": "pcap",
    ".pcapng": "pcap",
    ".log": "text",
    ".txt": "text",
    ".json": "json",
}


def collect_telemetry(
    telemetry_dir: str | Path,
    session_id: str,
    actor: str = "sandbox_replay",
    ingestor: ArtifactIngestor | None = None,
    anonymize: bool = False,
) -> list[TelemetryArtifact]:
    """Scans the telemetry directory, ingests each file, and returns artifacts.

    Args:
        telemetry_dir: Path to the directory containing captured telemetry files.
        session_id: Replay session ID (used as metadata tag).
        actor: Provenance actor string.
        ingestor: Optional ``ArtifactIngestor`` (created from settings if None).
        anonymize: Whether to apply DPDP anonymization on PCAP/log files.

    Returns:
        List of ``TelemetryArtifact`` models for each successfully ingested file.

    Raises:
        TelemetryIngestError: If the telemetry directory is invalid.
    """
    tel_path = Path(telemetry_dir)
    if not tel_path.exists():
        raise TelemetryIngestError(f"Telemetry directory does not exist: {tel_path}")

    _ingestor = ingestor or ArtifactIngestor()
    artifacts: list[TelemetryArtifact] = []

    telemetry_files = sorted(tel_path.rglob("*"))
    if not telemetry_files:
        logger.warning("No telemetry files found", telemetry_dir=str(tel_path))
        return []

    for file_path in telemetry_files:
        if not file_path.is_file():
            continue

        ext = file_path.suffix.lower()
        type_hint = _EXT_TYPE_MAP.get(ext)
        if type_hint is None:
            logger.debug("Skipping unknown file type", path=str(file_path), ext=ext)
            continue

        try:
            result: IngestResult = _ingestor.ingest(
                data_or_stream_or_path=file_path,
                filename=file_path.name,
                evidence_type_hint=type_hint,
                actor=actor,
                anonymize=anonymize,
                source_metadata={
                    "session_id": session_id,
                    "telemetry_source": "sandbox_replay",
                    "original_path": str(file_path),
                },
            )
            artifacts.append(
                TelemetryArtifact(
                    artifact_id=result.evidence_id,
                    path=str(file_path),
                    artifact_type=result.artifact_type,
                    sha256=result.sha256,
                    size_bytes=result.file_size_bytes,
                )
            )
            logger.info(
                "Telemetry artifact ingested",
                evidence_id=result.evidence_id,
                file=file_path.name,
                type=result.artifact_type,
            )
        except Exception as exc:
            logger.error(
                "Failed to ingest telemetry file",
                path=str(file_path),
                error=str(exc),
            )
            # Non-fatal: continue with other files

    logger.info(
        "Telemetry collection complete",
        session_id=session_id,
        total_files=len(artifacts),
    )
    return artifacts


def create_synthetic_telemetry(
    session_dir: str | Path,
    cve_id: str,
    attack_script: str,
) -> Path:
    """Creates synthetic telemetry files for testing when Docker is unavailable.

    Produces a minimal PCAP-compatible placeholder and a log file for
    unit-test and CI environments where real sandbox containers cannot run.

    Args:
        session_dir: Directory to write synthetic files to.
        cve_id: CVE ID for labelling.
        attack_script: Name of the attack script used.

    Returns:
        Path to the session directory.
    """
    session_path = Path(session_dir)
    session_path.mkdir(parents=True, exist_ok=True)

    # Synthetic log
    log_file = session_path / f"replay_{cve_id.replace('-', '_')}.log"
    log_content = (
        f"[REPLAY] CVE={cve_id} script={attack_script}\n"
        f"[REPLAY] Synthetic telemetry generated for CI/testing\n"
        f"[REPLAY] T1190: Exploitation of public-facing application detected\n"
        f"[REPLAY] T1059: Command interpreter invocation observed\n"
    )
    log_file.write_text(log_content, encoding="utf-8")

    # Synthetic event JSON
    events_file = session_path / "events.json"
    import json

    events: list[dict[str, Any]] = [
        {
            "timestamp": "2026-01-01T00:00:01Z",
            "event_type": "network_connection",
            "src": "10.0.0.5",
            "dst": "10.0.0.100",
            "port": 8080,
            "technique_hint": "T1190",
        },
        {
            "timestamp": "2026-01-01T00:00:05Z",
            "event_type": "process_execution",
            "process": "/bin/sh",
            "args": ["-c", "id"],
            "technique_hint": "T1059",
        },
    ]
    events_file.write_text(json.dumps(events, indent=2), encoding="utf-8")

    return session_path
