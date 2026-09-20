# ADR 0005: Clean Modular Directory Layout

## Status
Accepted

## Context
The repository layout must maintain strict separation of concerns between core graph domain models (`core/`), agent logic (`agents/`), API routes (`api/`), infrastructure scripts (`infra/`), test suites (`tests/`), and documentation (`docs/`).

## Decision
We adopt a standard top-level package layout separating `core`, `api`, `agents`, `infra`, `tests`, `scripts`, and `docs`.

## Consequences
- Clean dependency flow inward from API and Agents to Core.
- Allows independent module testing and packaging.
- Supports adding new agent subdirectories without modifying core domain models.
