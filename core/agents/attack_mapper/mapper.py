"""ATT&CK Mapper — maps evidence text to ATT&CK techniques via rule-based matching.

This module implements the ``ATTACKMapper`` class which:
1. Applies the compiled regex rules from :mod:`rules` against evidence text.
2. Deduplicates overlapping technique matches.
3. Writes ``MAPS_TO`` edges in Neo4j between the evidence node and technique nodes.
4. Persists mapping records to the ``attack_mappings`` PostgreSQL table.
5. Returns a list of ``MappingResult`` models.

Design (ADR 0020): Rule-based only. No ML model. Rules are in ``rules.py``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from core.agents.attack_mapper.models import MappingResult
from core.agents.attack_mapper.rules import COMPILED_RULES
from core.config.settings import Settings, get_settings
from core.db.postgres import PostgresClient
from core.graph.client import GraphClient
from core.logging.logger import get_logger

logger = get_logger("core.agents.attack_mapper.mapper")

_SOURCE_AGENT = "attack_mapper"


class ATTACKMapper:
    """Maps evidence artifacts and log entries to ATT&CK techniques.

    Parameters
    ----------
    settings:
        Application settings.
    graph_client:
        Neo4j client for creating MAPS_TO edges.
    db_client:
        PostgreSQL client for persisting mapping records.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        graph_client: GraphClient | None = None,
        db_client: PostgresClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.graph = graph_client or GraphClient(settings=self.settings)
        self.db = db_client or PostgresClient(settings=self.settings)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def map_text(
        self,
        text: str,
        evidence_id: str,
        session_id: str | None = None,
        actor: str = _SOURCE_AGENT,
    ) -> list[MappingResult]:
        """Maps raw text evidence to matching ATT&CK techniques.

        Args:
            text: Evidence text to scan (log lines, command output, etc.).
            evidence_id: ID of the evidence node in Neo4j.
            session_id: Optional sandbox replay session ID.
            actor: Provenance actor string.

        Returns:
            List of ``MappingResult`` models, sorted by descending confidence.

        Raises:
            MappingError: If the mapping pipeline encounters an unrecoverable error.
        """
        if not text or not text.strip():
            return []

        results: list[MappingResult] = []
        seen_techniques: set[str] = set()

        for rule in COMPILED_RULES:
            matched, snippet = rule.matches(text)
            if matched and rule.technique_id not in seen_techniques:
                seen_techniques.add(rule.technique_id)
                result = MappingResult(
                    evidence_id=evidence_id,
                    technique_id=rule.technique_id,
                    technique_name=rule.technique_name,
                    tactic=rule.tactic,
                    confidence=rule.confidence,
                    rule_name=rule.rule_name,
                    rationale=f"Pattern '{rule.rule_name}' matched: {snippet}",
                    matched_text=snippet,
                    session_id=session_id,
                )
                results.append(result)

        # Sort by confidence descending
        results.sort(key=lambda r: r.confidence, reverse=True)

        # Persist edges and DB records
        now = datetime.now(UTC).isoformat()
        for result in results:
            self._upsert_technique_node(result, actor, now)
            result.edge_id = self._create_maps_to_edge(result, actor, now)
            self._persist_mapping(result)

        logger.info(
            "ATT&CK mapping complete",
            evidence_id=evidence_id,
            techniques_matched=len(results),
        )
        return results

    def map_artifact(
        self,
        evidence_id: str,
        content: str | None = None,
        session_id: str | None = None,
        actor: str = _SOURCE_AGENT,
    ) -> list[MappingResult]:
        """Maps an artifact by its stored evidence content to ATT&CK techniques.

        If ``content`` is None, attempts to load it from the Neo4j node description.
        For binary artifacts (PCAP) this returns empty — PCAP analysis requires
        proper packet parsing (Phase 4).

        Args:
            evidence_id: Neo4j evidence artifact node ID.
            content: Optional pre-loaded text content.
            session_id: Optional sandbox replay session ID.
            actor: Provenance actor string.

        Returns:
            List of ``MappingResult`` models.
        """
        text = content or ""

        if not text:
            # Try to load description from Neo4j node
            try:
                node = self.graph.get_node(evidence_id)
                if node:
                    text = node.get("description") or node.get("message") or ""
            except Exception:
                pass

        if not text:
            logger.debug(
                "No text content for artifact — skipping mapping",
                evidence_id=evidence_id,
            )
            return []

        return self.map_text(text, evidence_id, session_id=session_id, actor=actor)

    def map_log_file(
        self,
        log_path: str,
        evidence_id: str,
        session_id: str | None = None,
        actor: str = _SOURCE_AGENT,
        max_bytes: int = 10 * 1024 * 1024,
    ) -> list[MappingResult]:
        """Maps a log file's content to ATT&CK techniques.

        Args:
            log_path: Path to the log file on disk.
            evidence_id: Associated evidence node ID.
            session_id: Optional sandbox replay session ID.
            actor: Provenance actor string.
            max_bytes: Maximum bytes to read (default 10 MB).

        Returns:
            List of ``MappingResult`` models.
        """
        try:
            from pathlib import Path  # noqa: PLC0415

            text = Path(log_path).read_text(encoding="utf-8", errors="replace")[
                :max_bytes
            ]
        except Exception as exc:
            logger.warning(
                "Failed to read log file for ATT&CK mapping",
                path=log_path,
                error=str(exc),
            )
            return []

        return self.map_text(text, evidence_id, session_id=session_id, actor=actor)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _upsert_technique_node(
        self, result: MappingResult, actor: str, now: str
    ) -> None:
        """Ensures the ATT&CKTechnique node exists in Neo4j."""
        existing = self.graph.get_node(result.technique_id)
        if existing:
            return
        try:
            self.graph.create_node(
                "ATT&CKTechnique",
                {
                    "id": result.technique_id,
                    "name": result.technique_name,
                    "tactic": result.tactic,
                    "source_agent": actor,
                    "confidence": 1.0,
                    "created_at": now,
                    "valid_from": now,
                },
            )
        except Exception as exc:
            logger.debug(
                "ATT&CKTechnique create skipped (likely exists)",
                technique_id=result.technique_id,
                error=str(exc),
            )

    def _create_maps_to_edge(self, result: MappingResult, actor: str, now: str) -> str:
        """Creates a MAPS_TO edge from the evidence artifact to the technique."""
        try:
            return self.graph.create_edge(
                from_id=result.evidence_id,
                to_id=result.technique_id,
                edge_type="MAPS_TO",
                properties={
                    "mapping_confidence": result.confidence,
                    "source_agent": actor,
                    "confidence": result.confidence,
                    "valid_from": now,
                    "rule_name": result.rule_name,
                },
            )
        except Exception as exc:
            logger.warning(
                "MAPS_TO edge creation failed",
                evidence_id=result.evidence_id,
                technique_id=result.technique_id,
                error=str(exc),
            )
            return ""

    def _persist_mapping(self, result: MappingResult) -> None:
        """Writes a mapping record to the ``attack_mappings`` PostgreSQL table."""
        try:
            self.db.execute(
                """
                INSERT INTO attack_mappings (
                    evidence_id, technique_id, technique_name, tactic,
                    confidence, rule_name, rule_pattern, mapped_at,
                    session_id, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    result.evidence_id,
                    result.technique_id,
                    result.technique_name,
                    result.tactic,
                    result.confidence,
                    result.rule_name,
                    result.matched_text,
                    result.mapped_at,
                    result.session_id,
                    json.dumps({"rationale": result.rationale}),
                ),
            )
        except Exception as exc:
            logger.warning(
                "Failed to persist attack mapping to PostgreSQL",
                evidence_id=result.evidence_id,
                technique_id=result.technique_id,
                error=str(exc),
            )
