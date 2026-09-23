# ADR 0007 — Temporal Versioning Strategy

**Status:** Accepted
**Date:** 2024-12-01
**Deciders:** EvidenceGraphAI Core Team
**Technical Story:** Phase 1 — Evidence Graph Core

---

## Context and Problem Statement

Forensic evidence graphs must preserve a complete, auditable history of every
piece of information.  In a cybercrime investigation, the understanding of a
vulnerability, attacker, or artefact changes over time as new evidence is
discovered.  If graph entities are mutated in place, this historical record
is destroyed.

We need a temporal model that satisfies three constraints:
1. **Completeness** — every historical state of every entity is retrievable.
2. **Point-in-time queries** — "what did the graph look like at time T?"
3. **Immutable audit trail** — nothing is ever destroyed; only soft-closed.

---

## Decision Drivers

* Legal defensibility of forensic data requires an immutable audit trail.
* Investigators need to replay the state of the graph at any past timestamp.
* Integration with external threat-intel feeds requires change tracking.
* The database (Neo4j) does not have native temporal table support, so we must implement the model in the application layer.

---

## Considered Options

### Option A — In-place mutation with `updated_at`
Update node properties in place and record `updated_at`.

**Pros:** Simple. Standard CRUD pattern.
**Cons:** History is lost. No point-in-time queries. Audit trail is impossible.
**Decision: Rejected.**

### Option B — Separate audit log table
Store every write event in a separate audit table with a JSON diff.

**Pros:** Preserves history without duplicating nodes.
**Cons:** Two sources of truth (current state vs. audit log). Complex reconstruction. No direct graph traversal of historical states.
**Decision: Rejected.**

### Option C — Append-only node versioning with SUPERSEDES ✅
Every "update" creates a new node version and soft-closes the existing one.
A `SUPERSEDES` relationship links new → old.  Temporal fields (`valid_from`,
`valid_to`) define the active window.

**Pros:**
- Full history is first-class graph data — traversable with Cypher.
- Point-in-time queries are a single `WHERE` clause filter.
- Immutable audit trail by construction — nothing is ever deleted.
- `SUPERSEDES` chain enables forensic lineage tracing.

**Cons:**
- ID management is more complex (versioned IDs: `{root_id}::v{n}`).
- Node count grows with every update (mitigated with indexes).
- Queries for "current" state must filter on `valid_to IS NULL`.

**Decision: Accepted.**

### Option D — Neo4j temporal extensions (3rd-party plugin)
Use a Neo4j temporal graph plugin.

**Pros:** Native support.
**Cons:** Not available in Neo4j Community Edition. Adds an external dependency. Not portable.
**Decision: Rejected.**

---

## Decision Outcome

**Chosen option: Option C — Append-only node versioning with SUPERSEDES.**

### Positive Consequences

- Every historical state of every node is recoverable by traversing `SUPERSEDES`.
- Point-in-time queries use a standard temporal filter clause:
  `n.valid_from <= $timestamp AND (n.valid_to IS NULL OR n.valid_to > $timestamp)`
- `created_at` is immutable across all versions — it records when the fact
  was first ingested, not when it was last updated.
- Investigations can be "replayed" to any past timestamp without any
  additional infrastructure.

### Negative Consequences / Mitigations

- Node count grows: **mitigated** by the `valid_from` and `source_agent`
  indexes added in Phase 1.
- Versioned IDs (`{root_id}::v{n}`) must be handled: **mitigated** by
  `get_root_id()` and `get_latest_version()` helpers in `core/graph/temporal.py`.
- Queries for "current" data must filter `valid_to IS NULL`: **mitigated** by
  `temporal_filter_clause()` helper and by `QueryLibrary.get_latest_version()`.

---

## Implementation Details

Temporal fields on every node and edge:

| Field | Type | Description |
|-------|------|-------------|
| `created_at` | ISO-8601 string | First insertion timestamp. **Immutable.** |
| `updated_at` | ISO-8601 string | Last write timestamp. Updated on every version. |
| `valid_from` | ISO-8601 string | Domain validity start. Defaults to `created_at`. |
| `valid_to` | ISO-8601 string \| null | Domain validity end. `null` = still active. |

Versioned node IDs: `{original_id}::v{n}` (e.g. `CVE-2021-44228::v2`).

---

## Deviation from Phase 1 Specification

The original Phase 1 specification proposed an in-place mutation / soft-deletion model using `valid_from` and `valid_to` timestamps directly on existing nodes.

During architectural design, we explicitly chose an **append-only** model featuring:
1. Versioned entity identifiers (`{original_id}::v{n}`).
2. A formal `SUPERSEDES` edge (the 15th relationship type in the ontology) linking each new version to its predecessor.
3. Immutability of past nodes, marking superseded nodes with `valid_to = now()`.

### Rationale
- **Legal Chain of Custody & Auditability**: In criminal forensics, mutating existing records destroys non-repudiation and chain-of-custody integrity. An append-only graph guarantees an immutable audit log.
- **Point-in-Time Traversal**: Point-in-time queries (`get_version_at(node_id, timestamp)`) can be answered with simple Cypher graph traversal along `SUPERSEDES` edges without relying on external relational logs.
- **Forensic Lineage**: Relationships between specific entity versions (e.g. which vulnerability definition was associated with an exploit at timestamp $T$) are preserved.

### Trade-offs & Mitigations
- **Storage Growth**: Node and edge count increases linearly with edits. Mitigated by composite indexes on `valid_from`, `valid_to`, and `root_id`.
- **Query Complexity for Current State**: Retrieving latest versions requires filtering on `valid_to IS NULL`. Mitigated by standard query helpers in `core/graph/temporal.py` and `QueryLibrary`.

**Precedence**: This ADR explicitly supersedes the original soft-deletion specification from the Phase 1 prompt.

---

## References

- [Temporal Data Management in Neo4j (neo4j.com)](https://neo4j.com/blog/temporal-graphs/)
- `core/graph/temporal.py`
- `core/graph/client.py` — `update_node()`
- `core/ontology/schema.yaml` — `SUPERSEDES` relationship type
