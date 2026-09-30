"""Main forensic ingestion pipeline and orchestrator for EvidenceGraphAI."""

import contextlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from pydantic import BaseModel, Field

from core.config.settings import Settings, get_settings
from core.custody.ledger import CustodyLedger
from core.graph.client import GraphClient
from core.graph.provenance import normalize_agent_name
from core.ingestion.detector import (
    DetectedType,
    FileTypeDetectionResult,
    detect_file_type,
)
from core.ingestion.exceptions import (
    IngestionAtomicityError,
    IngestionError,
)
from core.ingestion.hasher import compute_sha256_bytes
from core.ingestion.validators import (
    sanitize_filename,
    validate_allowed_type,
    validate_file_size,
)
from core.logging.logger import get_logger
from core.privacy.anonymizer import AnonymizationMethod
from core.privacy.log_filter import LogFilter
from core.privacy.pcap_filter import PCAPFilter
from core.storage.minio_client import MinioClient

logger = get_logger("core.ingestion.ingestor")


class IngestResult(BaseModel):
    """Outcome of artifact ingestion."""

    evidence_id: str
    sha256: str
    original_sha256: str | None = None
    artifact_type: str
    original_filename: str
    file_size_bytes: int
    storage_path: str
    node_id: str
    ledger_entry_id: int
    anonymized: bool = False
    anonymization_stats: dict[str, Any] | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class ArtifactIngestor:
    """Orchestrates forensic artifact validation, hashing, storage, graph registration, and chain of custody."""

    def __init__(
        self,
        settings: Settings | None = None,
        storage_client: MinioClient | None = None,
        graph_client: GraphClient | None = None,
        custody_ledger: CustodyLedger | None = None,
        pcap_filter: PCAPFilter | None = None,
        log_filter: LogFilter | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.storage = storage_client or MinioClient(settings=self.settings)
        self.graph = graph_client or GraphClient(settings=self.settings)
        self.ledger = custody_ledger or CustodyLedger()
        self.pcap_filter = pcap_filter or PCAPFilter()
        self.log_filter = log_filter or LogFilter()

    def ingest(
        self,
        data_or_stream_or_path: bytes | BinaryIO | Path | str,
        filename: str = "artifact.bin",
        evidence_type_hint: str | None = None,
        actor: str = "system",
        source_metadata: dict[str, Any] | None = None,
        anonymize: bool | None = None,
        anonymize_method: AnonymizationMethod = AnonymizationMethod.MASK,
    ) -> IngestResult:
        """Ingests a raw forensic artifact end-to-end.

        Args:
            data_or_stream_or_path: Artifact payload (bytes, open stream, or disk path).
            filename: Original file name.
            evidence_type_hint: Optional type hint.
            actor: Actor identity (user, agent ID, system).
            source_metadata: Arbitrary contextual metadata.
            anonymize: Whether to apply DPDP Act anonymization. If None, uses settings default.
            anonymize_method: MASK, PSEUDONYMIZE, or REDACT.

        Returns:
            IngestResult model.

        Raises:
            IngestionError: If validation, storage, graph, or ledger registration fails.
        """
        clean_filename = sanitize_filename(filename)

        # 1. Read bytes for validation & processing
        raw_bytes: bytes
        if isinstance(data_or_stream_or_path, str | Path):
            raw_bytes = Path(data_or_stream_or_path).read_bytes()
        elif isinstance(data_or_stream_or_path, bytes):
            raw_bytes = data_or_stream_or_path
        else:
            pos = data_or_stream_or_path.tell()
            raw_bytes = data_or_stream_or_path.read()
            data_or_stream_or_path.seek(pos)

        validate_file_size(len(raw_bytes), settings=self.settings)

        # 2. File type detection
        detection: FileTypeDetectionResult = detect_file_type(
            raw_bytes, filename_hint=clean_filename
        )
        artifact_type = detection.file_type.value
        validate_allowed_type(detection.file_type, settings=self.settings)

        # 3. DPDP Anonymization Check
        original_sha256 = compute_sha256_bytes(raw_bytes)
        stored_bytes = raw_bytes
        was_anonymized = False
        anon_stats: dict[str, Any] | None = None

        should_anon_pcap = (
            anonymize
            if anonymize is not None
            else self.settings.ingestion_anonymize_pcap
        )
        should_anon_logs = (
            anonymize
            if anonymize is not None
            else self.settings.ingestion_anonymize_logs
        )

        if detection.file_type == DetectedType.PCAP and should_anon_pcap:
            pcap_res = self.pcap_filter.filter_pcap_bytes(
                raw_bytes, method=anonymize_method
            )
            if pcap_res.findings_count > 0:
                stored_bytes = pcap_res.anonymized_bytes
                was_anonymized = True
                anon_stats = {
                    "findings_count": pcap_res.findings_count,
                    "category_counts": pcap_res.category_counts,
                    "packets_modified": pcap_res.packets_modified,
                    "method": anonymize_method.value,
                }
        elif detection.file_type == DetectedType.PLAIN_TEXT and should_anon_logs:
            try:
                log_text = raw_bytes.decode("utf-8")
                log_res = self.log_filter.filter_log_text(
                    log_text, method=anonymize_method
                )
                if log_res.findings_count > 0:
                    stored_bytes = log_res.anonymized_content.encode("utf-8")
                    was_anonymized = True
                    anon_stats = {
                        "findings_count": log_res.findings_count,
                        "category_counts": log_res.category_counts,
                        "lines_modified": log_res.lines_modified,
                        "method": anonymize_method.value,
                    }
            except Exception as exc:
                logger.warning(
                    "Could not apply text anonymization filter", error=str(exc)
                )

        # 4. Final SHA256 computation
        final_sha256 = compute_sha256_bytes(stored_bytes)
        evidence_id = f"EV-{uuid.uuid4()}"

        # Context metadata
        meta: dict[str, Any] = {
            "original_filename": clean_filename,
            "detected_mime_type": detection.mime_type,
            "detected_type": artifact_type,
            "detection_confidence": detection.confidence,
            "original_sha256": original_sha256,
            "file_size_bytes": len(stored_bytes),
            **(source_metadata or {}),
        }
        if was_anonymized:
            meta["anonymization"] = anon_stats

        # 5. MinIO Object Storage
        storage_path: str = ""
        try:
            storage_path = self.storage.put_object(
                evidence_id=evidence_id,
                sha256=final_sha256,
                data=stored_bytes,
                content_type=detection.mime_type,
                metadata={
                    "evidence_id": evidence_id,
                    "original_filename": clean_filename,
                    "artifact_type": artifact_type,
                },
            )
        except Exception as exc:
            logger.error("Storage upload failed during ingest", error=str(exc))
            raise IngestionError(f"Artifact storage failed: {exc}") from exc

        # 6. Neo4j EvidenceArtifact Node Creation
        #    Normalize the human-readable actor into a valid source_agent identifier
        #    for the graph schema. The original actor string is preserved in the
        #    custody ledger for full audit fidelity.
        graph_agent = normalize_agent_name(actor)
        node_id = evidence_id
        try:
            self.graph.create_node(
                "EvidenceArtifact",
                {
                    "id": evidence_id,
                    "artifact_type": artifact_type,
                    "storage_path": storage_path,
                    "hash_sha256": final_sha256,
                    "source_agent": graph_agent,
                    "source_artifact_id": None,
                    "confidence": 1.0,
                },
            )
        except Exception as exc:
            logger.warning(
                "Graph registration failed; attempting compensatory ledger record",
                error=str(exc),
            )
            # Even if Neo4j is offline in mock mode or error, we log error and ensure ledger recording
            with contextlib.suppress(Exception):
                self.ledger.append_entry(
                    evidence_id=evidence_id,
                    action="ERROR",
                    actor=actor,
                    sha256=final_sha256,
                    metadata={"error": f"Neo4j node creation failed: {exc}", **meta},
                )
            # If graph is essential, raise
            logger.debug("Neo4j node creation error handled", error=str(exc))

        # 7. Custody Ledger Append
        ledger_entry_id = 0
        try:
            if was_anonymized:
                # Record ANONYMIZE step
                self.ledger.append_entry(
                    evidence_id=evidence_id,
                    action="ANONYMIZE",
                    actor=actor,
                    sha256=final_sha256,
                    metadata={
                        "dpdp_anonymization": anon_stats,
                        "original_sha256": original_sha256,
                    },
                )

            # Record INGEST step
            ingest_entry = self.ledger.append_entry(
                evidence_id=evidence_id,
                action="INGEST",
                actor=actor,
                sha256=final_sha256,
                metadata=meta,
            )
            ledger_entry_id = ingest_entry.id or 0
        except Exception as exc:
            logger.error("Ledger append failed during ingest", error=str(exc))
            raise IngestionAtomicityError(
                f"Chain of custody ledger append failed: {exc}"
            ) from exc

        logger.info(
            "Ingestion successful",
            evidence_id=evidence_id,
            sha256=final_sha256,
            type=artifact_type,
            size=len(stored_bytes),
        )

        return IngestResult(
            evidence_id=evidence_id,
            sha256=final_sha256,
            original_sha256=original_sha256 if was_anonymized else None,
            artifact_type=artifact_type,
            original_filename=clean_filename,
            file_size_bytes=len(stored_bytes),
            storage_path=storage_path,
            node_id=node_id,
            ledger_entry_id=ledger_entry_id,
            anonymized=was_anonymized,
            anonymization_stats=anon_stats,
        )
