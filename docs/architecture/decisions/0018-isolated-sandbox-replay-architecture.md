# 18. Isolated Docker Sandbox Replay Architecture

Date: 2026-09-28
Status: Accepted

## Context

To validate hypothetical threat blueprints generated from CVE data, the framework needs to safely simulate or replay exploit sequences and capture empirical forensic evidence (PCAP network traces, system audit logs). Executing exploit payloads on open networks poses severe security and contamination risks.

## Decision

We designed a fully isolated Docker Compose sandbox topology (`infra/sandbox/docker-compose.yml`):

1. **Air-Gapped Network Topology:**
   - Dedicated Docker bridge network with `internal: true`.
   - Zero outbound WAN connectivity; strictly intra-container traffic between `attacker`, `victim`, and `collector`.

2. **Sidecar Passive Telemetry Collector:**
   - A dedicated `collector` container running `tcpdump` attaches to the network namespace, recording all packets directly into timestamped `.pcap` files on a mounted volume.

3. **Multi-Mode Execution:**
   - **Live Replay:** Deploys containers, executes templated reproduction scripts (`generic_attack.sh`), collects PCAPs and syslog files, and invokes Phase 2 `ArtifactIngestor`.
   - **Dry-Run Mode:** Synthesizes realistic telemetry artifacts without Docker socket dependencies for fast local development and CI testing.

4. **Forensic Custody Integration:**
   - Generated telemetry files are hashed (SHA-256), stored in MinIO (`replay-telemetry/` prefix), registered in the Immutable Custody Ledger, and mapped into Neo4j graph nodes.

## Consequences

- **Positive:** Complete isolation prevents accidental external data leakage or compromised infrastructure.
- **Positive:** Telemetry artifacts undergo standard Phase 2 anonymization and chain-of-custody verification.
- **Negative:** Requires Docker daemon with container privileges for full live replays.
