# Sandbox Replay Agent

## Overview

The `SandboxReplayAgent` orchestrates safe attack simulations in an isolated Docker environment to validate hypothetical threat blueprints and generate verifiable forensic telemetry.

## Operational Modes

1. **Dry-Run Mode (`dry_run=True`):**
   - Synthesizes realistic PCAP and system log artifacts deterministically.
   - Ideal for CI pipelines, automated integration testing, and development without container runtime dependencies.

2. **Live Sandbox Execution (`dry_run=False`):**
   - Spins up an air-gapped Docker Compose stack (`infra/sandbox/docker-compose.yml`).
   - Executes parameterized attack scripts (`generic_attack.sh`) inside an attacker container against a victim container.
   - Sidecar collector records continuous network traffic (`tcpdump`).

## Telemetry Ingestion & Custody

All generated artifacts are ingested through the Phase 2 `ArtifactIngestor` pipeline:
- SHA-256 fingerprinting
- MinIO artifact storage under `replay-telemetry/{session_id}/`
- Immutable Custody Ledger entry appending
- Neo4j graph linkage to the associated `ReplaySession`

## Usage Example

```python
from core.agents.sandbox_replay.agent import SandboxReplayAgent
from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent

tr_agent = ThreatReconstructionAgent()
bp = tr_agent.blueprint(cve_id="CVE-2021-44228")

replay_agent = SandboxReplayAgent(dry_run=True)
session = replay_agent.replay(blueprint=bp, actor="sandbox_replay")

print(f"Session ID: {session.session_id}")
print(f"Status: {session.status}")
print(f"Artifacts: {session.telemetry_artifacts}")
```
