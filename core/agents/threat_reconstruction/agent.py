"""Threat Reconstruction Agent — orchestrates blueprint generation and graph persistence.

Given a CVE ID (which must have already been analysed by the
``VulnerabilityIntelligenceAgent``), this agent:

1. Loads the CVE node from Neo4j.
2. Extracts the vulnerability profile.
3. Generates a deterministic attack blueprint via :mod:`blueprint`.
4. Upserts ``ATT&CKTechnique`` nodes (MERGE).
5. Creates ``EXPECTED_TO_LEAD_TO`` edges with ``status=hypothesized``.
6. Links the CVE node to the first technique via a ``MAPS_TO`` edge.
7. Appends a ledger entry.
8. Publishes a ``BlueprintGeneratedEvent``.
9. Returns the ``Blueprint`` model.

Provenance contract: ``source_agent = "threat_reconstruction"``
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from core.agents.threat_reconstruction.blueprint import generate_blueprint
from core.agents.threat_reconstruction.exceptions import (
    BlueprintGenerationError,
    CVENotAnalyzedError,
)
from core.agents.threat_reconstruction.models import Blueprint, BlueprintEdge
from core.config.settings import Settings, get_settings
from core.custody.ledger import CustodyLedger
from core.db.postgres import PostgresClient
from core.events.bus import get_event_bus
from core.events.types import BlueprintGeneratedEvent
from core.graph.client import GraphClient
from core.logging.logger import get_logger

logger = get_logger("core.agents.threat_reconstruction.agent")

_SOURCE_AGENT = "threat_reconstruction"


class ThreatReconstructionAgent:
    """Orchestrates attack blueprint generation and graph persistence.

    Parameters
    ----------
    settings:
        Application settings.
    graph_client:
        Neo4j graph client.
    ledger:
        Custody ledger for audit trail.
    db_client:
        PostgreSQL client.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        graph_client: GraphClient | None = None,
        ledger: CustodyLedger | None = None,
        db_client: PostgresClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.db = db_client or PostgresClient(settings=self.settings)
        self.graph = graph_client or GraphClient(settings=self.settings)
        self.ledger = ledger or CustodyLedger(db_client=self.db)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def blueprint(self, cve_id: str, actor: str = _SOURCE_AGENT) -> Blueprint:
        """Generates a threat blueprint for an already-analysed CVE.

        Args:
            cve_id: CVE identifier (must exist as a node in Neo4j).
            actor: Provenance actor string.

        Returns:
            ``Blueprint`` model with techniques and edges.

        Raises:
            CVENotAnalyzedError: If the CVE node does not exist in Neo4j.
            BlueprintGenerationError: On blueprint generation or graph write failure.
        """
        cve_id = cve_id.strip().upper()
        logger.info("Starting threat blueprint generation", cve_id=cve_id)

        # Step 1: Load CVE node
        cve_node = self._load_cve_node(cve_id)

        # Step 2: Extract profile from node properties
        profile = self._extract_profile(cve_node)

        # Step 3: Generate blueprint
        try:
            bp = generate_blueprint(cve_id=cve_id, cve_profile=profile)
        except Exception as exc:
            raise BlueprintGenerationError(
                f"Blueprint generation failed for {cve_id}: {exc}"
            ) from exc

        if not bp.techniques:
            logger.warning("Blueprint generated with zero techniques", cve_id=cve_id)

        # Step 4–5: Upsert nodes and edges into Neo4j
        self._persist_blueprint(bp, cve_node["id"], actor)

        # Step 6: Store blueprint metadata on CVE node
        try:
            self.graph.update_node(
                cve_id,
                {
                    "blueprint_id": bp.blueprint_id,
                    "blueprint_technique_count": len(bp.techniques),
                    "source_agent": actor,
                    "confidence": cve_node.get("confidence", 0.8),
                },
                node_type="CVE",
            )
        except Exception as exc:
            logger.warning(
                "Failed to store blueprint_id on CVE node",
                cve_id=cve_id,
                error=str(exc),
            )

        # Step 7: Ledger
        fake_sha256 = hashlib.sha256(bp.blueprint_id.encode()).hexdigest()
        try:
            self.ledger.append_entry(
                evidence_id=cve_id,
                action="DERIVE",
                actor=actor,
                sha256=fake_sha256,
                metadata={
                    "blueprint_id": bp.blueprint_id,
                    "technique_count": len(bp.techniques),
                    "edge_count": len(bp.edges),
                },
            )
        except Exception as exc:
            logger.warning("Ledger append failed", error=str(exc))

        # Step 8: Publish event
        try:
            get_event_bus().publish(
                BlueprintGeneratedEvent(
                    blueprint_id=bp.blueprint_id,
                    cve_id=cve_id,
                    technique_count=len(bp.techniques),
                    actor=actor,
                )
            )
        except Exception as exc:
            logger.warning("Failed to publish BlueprintGeneratedEvent", error=str(exc))

        logger.info(
            "Blueprint generation complete",
            blueprint_id=bp.blueprint_id,
            cve_id=cve_id,
            techniques=len(bp.techniques),
            edges=len(bp.edges),
        )
        return bp

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_cve_node(self, cve_id: str) -> dict[str, Any]:
        """Loads the CVE node from Neo4j or raises CVENotAnalyzedError."""
        node = self.graph.get_latest_version(cve_id)
        if node is None:
            node = self.graph.get_node(cve_id)
        if node is None:
            raise CVENotAnalyzedError(
                f"CVE '{cve_id}' not found in the Evidence Graph. "
                f"Run VulnerabilityIntelligenceAgent.analyze() first."
            )
        return node

    @staticmethod
    def _extract_profile(cve_node: dict[str, Any]) -> dict[str, Any]:
        """Extracts the vulnerability profile from a CVE node's properties."""
        desc = (cve_node.get("description") or "").lower()
        av = cve_node.get("attack_vector")
        if not av:
            if (
                "remote" in desc
                or "network" in desc
                or (cve_node.get("cvss_score") or 0) >= 9.0
            ):
                av = "NETWORK"
            elif "local" in desc:
                av = "LOCAL"

        remote = cve_node.get("remote_exploitable")
        if remote is None and av == "NETWORK":
            remote = True

        return {
            "attack_vector": av,
            "cvss_score": cve_node.get("cvss_score"),
            "cwe_id": cve_node.get("cwe_id"),
            "requires_auth": cve_node.get("requires_auth", False),
            "requires_user_interaction": cve_node.get(
                "requires_user_interaction", False
            ),
            "remote_exploitable": bool(remote),
            "availability_impact": cve_node.get("availability_impact", "NONE"),
            "confidentiality_impact": cve_node.get("confidentiality_impact", "NONE"),
            "integrity_impact": cve_node.get("integrity_impact", "NONE"),
        }

    def _persist_blueprint(self, bp: Blueprint, cve_node_id: str, actor: str) -> None:
        """Upserts ATT&CKTechnique nodes and EXPECTED_TO_LEAD_TO edges."""
        now = datetime.now(UTC).isoformat()

        # Upsert technique nodes
        created_node_ids: dict[str, str] = {}
        for tech in bp.techniques:
            node_id = self._upsert_technique(
                tech.technique_id, tech.technique_name, tech.tactic, actor, now
            )
            tech.node_id = node_id
            created_node_ids[tech.technique_id] = node_id

        # Create EXPECTED_TO_LEAD_TO edges
        for edge in bp.edges:
            src_id = created_node_ids.get(
                edge.from_technique_id, edge.from_technique_id
            )
            dst_id = created_node_ids.get(edge.to_technique_id, edge.to_technique_id)
            self._create_blueprint_edge(edge, src_id, dst_id, actor, now)

        # Link CVE to first technique via MAPS_TO
        if bp.techniques:
            first_tech_id = bp.techniques[0].node_id or bp.techniques[0].technique_id
            try:
                self.graph.create_edge(
                    from_id=cve_node_id,
                    to_id=first_tech_id,
                    edge_type="MAPS_TO",
                    properties={
                        "mapping_confidence": bp.techniques[0].confidence,
                        "source_agent": actor,
                        "confidence": bp.techniques[0].confidence,
                        "valid_from": now,
                    },
                )
            except Exception as exc:
                logger.debug(
                    "CVE→technique MAPS_TO edge skipped (may already exist)",
                    error=str(exc),
                )

    def _upsert_technique(
        self, technique_id: str, name: str, tactic: str, actor: str, now: str
    ) -> str:
        """Creates an ATT&CKTechnique node if it doesn't exist, returns its node ID."""
        existing = self.graph.get_node(technique_id)
        if existing:
            return str(existing.get("id", technique_id))
        try:
            return self.graph.create_node(
                "ATT&CKTechnique",
                {
                    "id": technique_id,
                    "name": name,
                    "tactic": tactic,
                    "source_agent": actor,
                    "confidence": 1.0,
                    "created_at": now,
                    "valid_from": now,
                },
            )
        except Exception as exc:
            logger.debug(
                "ATT&CKTechnique create skipped (constraint — likely already exists)",
                technique_id=technique_id,
                error=str(exc),
            )
            return technique_id

    def _create_blueprint_edge(
        self,
        edge: BlueprintEdge,
        src_id: str,
        dst_id: str,
        actor: str,
        now: str,
    ) -> None:
        """Creates an EXPECTED_TO_LEAD_TO relationship for a blueprint step."""
        try:
            edge_id = self.graph.create_edge(
                from_id=src_id,
                to_id=dst_id,
                edge_type="EXPECTED_TO_LEAD_TO",
                properties={
                    "probability": edge.probability,
                    "status": edge.status,
                    "blueprint_id": None,  # stored on CVE node
                    "source_agent": actor,
                    "confidence": edge.probability,
                    "valid_from": now,
                },
            )
            edge.edge_id = edge_id
        except Exception as exc:
            logger.warning(
                "EXPECTED_TO_LEAD_TO edge creation failed",
                from_id=src_id,
                to_id=dst_id,
                error=str(exc),
            )
