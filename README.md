# EvidenceGraphAI

**EvidenceGraphAI** is a graph-based multi-agent framework designed for AI-assisted cybercrime investigation and threat reconstruction. It ingests heterogeneous forensic artifacts (network captures, vulnerability records, malware samples, Android APKs, logs, certificates), reconstructs the full attack lifecycle as a temporally ordered knowledge graph, correlates cases across multiple behavioral dimensions, preserves legal chain of custody, generates detection rules, and provides a GraphRAG-powered natural language investigation interface.

---

## Current Status: Phase 3 Completed (Vulnerability Intelligence & Threat Reconstruction)

Phase 3 establishes the **Vulnerability Intelligence, Threat Blueprint Reconstruction, and Sandbox Replay** subsystem:
- **Vulnerability Intelligence Agent**: Full NVD REST API v2.0 ingest with rate-limiting, exponential backoff, PostgreSQL `cve_cache`, CVSS v3.1 vector parsing, CWE identification, and automated Git patch analysis.
- **Threat Reconstruction Agent**: Deterministic multi-stage attack lifecycle blueprint generation with exponential phase confidence decay and graph materialization (`EXPECTED_TO_LEAD_TO` with `status="hypothesized"`).
- **Isolated Sandbox Replay Agent**: Air-gapped Docker Compose attack sandbox (`internal: true`), automated sidecar PCAP packet capture (`tcpdump`), dry-run synthetic execution mode, and automated forensic custody ingestion.
- **MITRE ATT&CK Mapper**: High-precision compiled regex pattern engine for automated mapping of unstructured logs, commands, and payloads to ATT&CK techniques (`MAPS_TO`).
- **Vulnerability Intelligence Dashboard**: Modern Single-Page Application at `/dev/vulnerability-dashboard` (or `/vulnerability/dashboard`) with live SSE stream, interactive CVE explorer, blueprint visualizer, dry-run replay console, and ATT&CK mapper.
- **Forensic Ingest Console & Graph Viewer**: Full integration across `/dev/ingestion-portal` and `/dev/viewer`.

For detailed roadmap status, see [Phases Roadmap](docs/roadmap/phases.md) and [Phase 3 Completion Report](docs/reports/phase3_completion_report.md).

---

## Technology Stack

- **Language**: Python 3.11+
- **Graph Database**: Neo4j 5.20
- **Metadata & Ledger**: PostgreSQL 16
- **Cache & Queue**: Redis 7
- **Artifact Storage**: MinIO / S3
- **Vulnerability Data**: NVD REST API v2.0
- **Ontology & Framework**: MITRE ATT&CK Enterprise Matrix
- **API Layer**: FastAPI + Uvicorn
- **Validation & Models**: Pydantic 2.x & pydantic-settings 2.x
- **Logging**: Structlog (Structured JSON)
- **Observability**: Prometheus client
- **Code Quality**: Ruff, Black, MyPy, PyTest

---

## Quick Start (Developer Setup)

### 1. Environment Requirements
- Python 3.11 installed
- Docker Engine and Docker Compose running

### 2. Installation
```bash
# Create virtual environment
py -3.11 -m venv .venv

# Activate environment (Windows)
.\.venv\Scripts\activate

# Activate environment (Linux/macOS)
source .venv/bin/activate

# Install package in editable mode with development dependencies
pip install -e .[dev]
```

### 3. Running Local Orchestrator
```bash
# Start all infrastructure, run migrations, seed sample CVEs, and launch all frontends
python scripts/start_local.py --seed
```

### 4. Running Validation Suite
```bash
# Run unit tests and integration tests
pytest tests/unit tests/integration -v --cov=core

# Run code format and lint checks
black --check .
ruff check .
mypy core api
```

---

## Documentation Links

- [Architecture Overview](docs/architecture/overview.md)
- [Architecture Decision Records (ADRs)](docs/architecture/decisions/)
- [Vulnerability Intelligence Agent](docs/agents/vulnerability-intelligence.md)
- [Threat Reconstruction Agent](docs/agents/threat-reconstruction.md)
- [Sandbox Replay Agent](docs/agents/sandbox-replay.md)
- [ATT&CK Mapper Agent](docs/agents/attack-mapper.md)
- [Sandbox Architecture](docs/sandbox/architecture.md)
- [Vulnerability Dashboard](docs/frontend/vulnerability-dashboard.md)
- [Forensic Ingest Portal](docs/frontend/ingestion-portal.md)
- [Developer Graph Viewer](docs/graph/developer-viewer.md)
- [Phases Roadmap](docs/roadmap/phases.md)

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
