# EvidenceGraphAI Architecture Overview

## Architectural Principles

EvidenceGraphAI follows **Clean Architecture** and **Domain-Driven Design (DDD)** principles.

### Key Architectural Layers

1. **Domain Layer (`core/ontology/`, `core/graph/models.py`)**:
   - Machine-readable YAML ontology (`schema.yaml`).
   - Pydantic models for 11 node types and 15 edge types.
   - Core temporal versioning (`valid_from`, `valid_to`, `created_at`, `updated_at`) and provenance tracking (`source_agent`, `source_artifact_id`, `confidence`).

2. **Infrastructure / Persistence Layer (`core/graph/client.py`, `infra/docker/`)**:
   - Neo4j Bolt driver wrapper `GraphClient`.
   - Docker Compose managing Neo4j 5.20, PostgreSQL 16, Redis 7, and MinIO.

3. **API / Interface Layer (`api/`)**:
   - FastAPI HTTP endpoints (`/`, `/health`, `/metrics`).
   - Correlation ID middleware (`X-Correlation-ID`) for distributed context tracing.

4. **Agents Layer (`agents/`)**:
   - Autonomous, decoupled agent components writing to the central Neo4j evidence graph.

5. **Observability Layer (`core/observability/metrics.py`, `core/logging/logger.py`)**:
   - Prometheus metrics for database and API performance.
   - Structlog structured JSON logger.
