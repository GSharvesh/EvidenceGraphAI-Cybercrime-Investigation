# ADR 0004: Use Docker Compose for Local Infrastructure Orchestration

## Status
Accepted

## Context
Developers require a reproducible environment providing Neo4j 5.x, PostgreSQL 16, Redis 7, and MinIO storage without manual installation steps.

## Decision
We select **Docker Compose** as the local container orchestration standard.

## Consequences
- Single command `make docker-up` starts all infrastructure services.
- Container healthchecks ensure dependent services are fully ready before seeding or testing.
- Named persistent volumes prevent data loss between restarts.
