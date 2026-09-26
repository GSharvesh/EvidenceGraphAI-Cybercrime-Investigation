# EvidenceGraphAI

**EvidenceGraphAI** is a graph-based multi-agent framework designed for AI-assisted cybercrime investigation and threat reconstruction. It ingests heterogeneous forensic artifacts (network captures, vulnerability records, malware samples, Android APKs, logs, certificates), reconstructs the full attack lifecycle as a temporally ordered knowledge graph, correlates cases across multiple behavioral dimensions, preserves legal chain of custody, generates detection rules, and provides a GraphRAG-powered natural language investigation interface.

---

## Current Status: Phase 2 Completed (Ingestion & Chain of Custody)

Phase 2 establishes the production-grade **Ingestion & Chain of Custody** subsystem:
- **Heterogeneous Forensic Ingest Pipeline**: Ingests PCAPs, JSON vulnerability records, PE/ELF/APK binaries, logs, and X.509 certificates.
- **Append-Only PostgreSQL Custody Ledger**: Database-trigger enforced immutable audit trail with sequential SHA256 cryptographic hash chaining.
- **Section 65B Evidence Manifest Generator**: Digitally signed electronic evidence certificates complying with Section 65B of the Indian Evidence Act.
- **DPDP Act 2023 Privacy Filters**: Automated detection and masking/pseudonymization of Aadhaar, PAN, phone, email, and payment cards across PCAPs and logs.
- **Forensic Ingest Console**: Modern developer UI with live Web Crypto hashing, timeline visualization, and Cytoscape.js graph rendering at `/dev/ingestion-portal`.
- **Developer Viewer**: Interactive graph visualizer with localhost security gating at `/dev/viewer`.

For detailed roadmap status, see [Phases Roadmap](docs/roadmap/phases.md) and [Phase 2 Completion Report](docs/reports/phase2_completion_report.md).

---

## Technology Stack

- **Language**: Python 3.11+
- **Graph Database**: Neo4j 5.20
- **Metadata & Ledger**: PostgreSQL 16
- **Cache & Queue**: Redis 7
- **Artifact Storage**: MinIO / S3
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

### 3. Running Local Infrastructure
```bash
# Start Docker Compose services (Neo4j, Postgres, Redis, MinIO)
make docker-up

# Seed Neo4j ontology constraints and indexes
python infra/scripts/seed_ontology.py
```

### 4. Running API Server
```bash
uvicorn api.main:app --reload --port 8000
```

Access API documentation at `http://localhost:8000/docs`.

### 5. Running Validation Suite
```bash
make validate
```

---

## Documentation Links

- [Architecture Overview](docs/architecture/overview.md)
- [Architecture Decision Records (ADRs)](docs/architecture/decisions/)
- [Ontology Reference](docs/ontology/reference.md)
- [Developer Setup Guide](docs/setup/development.md)
- [Phases Roadmap](docs/roadmap/phases.md)
- [Future Requirements](docs/roadmap/future-requirements.md)

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
