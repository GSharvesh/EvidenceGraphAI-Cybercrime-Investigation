"""Programmatic Neo4j schema initialization script seeding constraints and indexes."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.graph.client import GraphClient
from core.logging.logger import get_logger

logger = get_logger("infra.scripts.seed_ontology")

CONSTRAINTS = [
    "CREATE CONSTRAINT cve_id_unique IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT victim_id_unique IF NOT EXISTS FOR (n:Victim) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT attacker_id_unique IF NOT EXISTS FOR (n:Attacker) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT malware_id_unique IF NOT EXISTS FOR (n:Malware) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT apksample_id_unique IF NOT EXISTS FOR (n:APKSample) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT domain_id_unique IF NOT EXISTS FOR (n:Domain) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT ipaddress_id_unique IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT certificate_id_unique IF NOT EXISTS FOR (n:Certificate) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT attacktechnique_id_unique IF NOT EXISTS FOR (n:`ATT&CKTechnique`) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT logentry_id_unique IF NOT EXISTS FOR (n:LogEntry) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT evidenceartifact_id_unique IF NOT EXISTS FOR (n:EvidenceArtifact) REQUIRE n.id IS UNIQUE",
]

INDEXES = [
    "CREATE INDEX malware_sha256_idx IF NOT EXISTS FOR (n:Malware) ON (n.sha256)",
    "CREATE INDEX apksample_sha256_idx IF NOT EXISTS FOR (n:APKSample) ON (n.sha256)",
    "CREATE INDEX domain_name_idx IF NOT EXISTS FOR (n:Domain) ON (n.name)",
    "CREATE INDEX ipaddress_addr_idx IF NOT EXISTS FOR (n:IPAddress) ON (n.addr)",
    "CREATE INDEX logentry_timestamp_idx IF NOT EXISTS FOR (n:LogEntry) ON (n.timestamp)",
]


def seed_ontology() -> None:
    """Executes Cypher constraints and indexes via GraphClient."""
    logger.info("Initializing Neo4j ontology constraints and indexes...")
    client = GraphClient()
    client.connect()

    for statement in CONSTRAINTS:
        logger.info("Executing constraint", query=statement)
        client.query(statement)

    for statement in INDEXES:
        logger.info("Executing index", query=statement)
        client.query(statement)

    # Verification
    constraints_result = client.query("SHOW CONSTRAINTS")
    logger.info(
        "Successfully verified Neo4j constraints",
        count=len(constraints_result),
    )
    client.close()


if __name__ == "__main__":
    seed_ontology()
