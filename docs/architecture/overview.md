# EvidenceGraphAI Architecture Overview

## Architectural Principles

EvidenceGraphAI follows **Clean Architecture** and **Domain-Driven Design (DDD)** principles.

### Key Architectural Layers

1. **Domain Layer (`core/ontology/`, `core/graph/models.py`)**:
   - Machine-readable YAML ontology (`schema.yaml`).
   - Pydantic models for 11 node types and 15 edge types.
   - Core temporal versioning (`valid_from`, `valid_to`, `created_at`, `updated_at`) and provenance tracking (`source_agent`, `source_artifact_id`, `confidence`).

2. **Infrastructure / Persistence Layer (`core/graph/client.py`, `core/db/postgres.py`, `core/storage/minio_client.py`, `infra/docker/`)**:
   - Neo4j Bolt driver wrapper `GraphClient`.
   - PostgreSQL 16 append-only `CustodyLedger` with database triggers preventing mutation.
   - MinIO S3-compatible immutable forensic artifact vault.
   - Redis 7 for distributed caching and coordination.

3. **Ingestion & Chain of Custody Subsystem (`core/ingestion/`, `core/custody/`, `core/privacy/`)**:
   - `ArtifactIngestor`: Orchestrates validation, hashing, storage, graph registration, and ledger append.
   - `FileTypeDetector`: Multi-layered magic byte and format detection for PCAP, JSON, PE/ELF/APK, Logs, Certs.
   - `CustodyLedger` & `Chain`: Cryptographic SHA256 hash chaining with mathematical tamper evidence.
   - `ArtifactVerifier`: On-demand cryptographic hash recomputation and ledger verification.
   - `DPDP Anonymization`: Privacy filter for PCAPs and logs complying with Indian DPDP Act 2023.
   - `ManifestGenerator`: Indian Evidence Act Section 65B certified manifest generator and digital signature verifier.

4. **API / Interface Layer (`api/`)**:
   - FastAPI HTTP endpoints (`/ingest`, `/evidence/*`, `/ledger/*`, `/manifests/*`, `/dev/ingestion-portal`, `/dev/viewer`, `/health`, `/metrics`).
   - Correlation ID middleware (`X-Correlation-ID`) for distributed context tracing.
   - Self-contained single-page Forensic Ingest Console (`/dev/ingestion-portal`).

5. **Agents Layer (`agents/`)**:
   - Autonomous, decoupled agent components writing to the central Neo4j evidence graph.

6. **Observability Layer (`core/observability/metrics.py`, `core/logging/logger.py`)**:
   - Prometheus metrics for database and API performance.
   - Structlog structured JSON logger.
