# ADR 0003: Use Structlog for Structured JSON Logging

## Status
Accepted

## Context
High-volume investigation platforms require structured log entries that can be ingested into centralized observability suites (e.g. ELK, Grafana Loki) with correlation IDs for tracing request lifecycles.

## Decision
We select **structlog 24.x** for application logging.

## Consequences
- Produces clean structured JSON output in production environments.
- Formats colorized human-readable text logs during local development.
- Automatically injects `timestamp`, `level`, `logger`, `message`, and `correlation_id` into every log record.
