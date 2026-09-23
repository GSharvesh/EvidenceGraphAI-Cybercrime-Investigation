# Temporal Versioning

This document describes EvidenceGraphAI's append-only temporal versioning model.

---

## Overview

**Nodes are never mutated in place.**  Every "update" to a node:

1. Soft-closes the existing node (`valid_to = now`).
2. Creates a new node version with a derived ID (`{original_id}::v{n}`).
3. Copies all old properties, applies the patch, sets `valid_from = now`, `valid_to = null`.
4. Creates a `SUPERSEDES` edge from the new version to the old version.

This means the full history of every node is always available as first-class graph data.

---

## Temporal Fields

Every node and relationship carries these four fields:

| Field | Type | Mutable | Description |
|-------|------|---------|-------------|
| `created_at` | ISO-8601 string | ❌ No | First insertion timestamp. Preserved across all versions. |
| `updated_at` | ISO-8601 string | ✅ Yes | Last write timestamp. Updated on every version. |
| `valid_from` | ISO-8601 string | ✅ Yes | Domain validity start. Defaults to `created_at`. |
| `valid_to` | ISO-8601 string \| null | ✅ Yes | Domain validity end. `null` means "still active". |

---

## Versioned IDs

Versioned nodes use the pattern `{original_id}::v{n}`:

```
CVE-2021-44228         → original (v0)
CVE-2021-44228::v1     → first update
CVE-2021-44228::v2     → second update
```

Use `get_root_id(node_id)` to extract the root from any versioned ID.

---

## Point-in-Time Queries

To query the graph as it appeared at a given timestamp, use the temporal filter
clause:

```cypher
MATCH (n:CVE)
WHERE n.valid_from <= $timestamp
  AND (n.valid_to IS NULL OR n.valid_to > $timestamp)
RETURN n
```

In Python, use the helpers:

```python
from core.graph.temporal import temporal_filter_clause, to_iso
from core.graph.queries import QueryLibrary

ts = datetime(2021, 12, 10, 8, 0, 0, tzinfo=UTC)
nodes = ql.get_nodes_at(ts, node_type="CVE")
```

---

## Programmatic Usage

### Creating a node
```python
node_id = client.create_node("CVE", {
    "id": "CVE-2021-44228",
    "cvss_score": 10.0,
    "severity": "CRITICAL",
})
```
`valid_from`, `valid_to`, `created_at`, `updated_at` are set automatically.

### Updating a node (append-only)
```python
new_id = client.update_node("CVE-2021-44228", {"cvss_score": 9.8})
# new_id == "CVE-2021-44228::v1"
```

### Soft-deleting a node
```python
client.soft_delete("CVE-2021-44228")  # sets valid_to = now
```

### Querying the full version history
```python
history = client.get_node_history("CVE-2021-44228")
# Returns all versions oldest-first
```

### Getting the currently active version
```python
latest = client.get_latest_version("CVE-2021-44228")
# Returns the version with valid_to IS NULL
```

### Getting the version at a specific time
```python
from datetime import UTC, datetime
ts = datetime(2021, 12, 10, tzinfo=UTC)
version = client.get_node_at("CVE-2021-44228", ts)
```

---

## SUPERSEDES Relationship

Every update creates a `SUPERSEDES` edge from the new version to the old:

```
(CVE-2021-44228::v1) -[:SUPERSEDES]-> (CVE-2021-44228)
```

To traverse the full version chain:
```cypher
MATCH (latest {id: 'CVE-2021-44228::v1'})-[:SUPERSEDES*]->(ancestor)
RETURN ancestor
```

---

## Worked Example: Version Evolution Walkthrough

Consider an initial vulnerability report that is subsequently enriched with CVSS score updates and then mitigated.

### 1. Initial Insertion (v0)
```cypher
CREATE (n:CVE {
  id: "CVE-2024-9999",
  severity: "MEDIUM",
  created_at: "2024-01-01T10:00:00Z",
  updated_at: "2024-01-01T10:00:00Z",
  valid_from: "2024-01-01T10:00:00Z",
  valid_to: null,
  source_agent: "system",
  confidence: 1.0
})
```

### 2. First Update (v1 — Append New Node, Close Old)
When `client.update_node("CVE-2024-9999", {"cvss_score": 9.8, "severity": "CRITICAL"})` is called:
```cypher
// Close original node
MATCH (n:CVE {id: "CVE-2024-9999"})
SET n.valid_to = "2024-01-02T12:00:00Z", n.updated_at = "2024-01-02T12:00:00Z";

// Insert new version
CREATE (v1:CVE {
  id: "CVE-2024-9999::v1",
  severity: "CRITICAL",
  cvss_score: 9.8,
  created_at: "2024-01-01T10:00:00Z",
  updated_at: "2024-01-02T12:00:00Z",
  valid_from: "2024-01-02T12:00:00Z",
  valid_to: null,
  source_agent: "system",
  confidence: 1.0
});

// Link version chain
MATCH (v1:CVE {id: "CVE-2024-9999::v1"}), (v0:CVE {id: "CVE-2024-9999"})
CREATE (v1)-[:SUPERSEDES {superseded_at: "2024-01-02T12:00:00Z"}]->(v0);
```

### 3. Querying History vs Latest
```cypher
// Query full version chain
MATCH (n:CVE) WHERE n.id = 'CVE-2024-9999' OR n.id STARTS WITH 'CVE-2024-9999::v'
RETURN n.id, n.severity, n.valid_from, n.valid_to
ORDER BY n.valid_from ASC;

// Result:
// ┌───────────────────────┬────────────┬──────────────────────┬──────────────────────┐
// │ n.id                  │ n.severity │ n.valid_from         │ n.valid_to           │
// ├───────────────────────┼────────────┼──────────────────────┼──────────────────────┤
// │ "CVE-2024-9999"       │ "MEDIUM"   │ 2024-01-01T10:00:00Z │ 2024-01-02T12:00:00Z │
// │ "CVE-2024-9999::v1"   │ "CRITICAL" │ 2024-01-02T12:00:00Z │ null                 │
// └───────────────────────┴────────────┴──────────────────────┴──────────────────────┘
```

---

## References

- `core/graph/temporal.py` — pure utility functions
- `core/graph/client.py` — `update_node()`, `get_node_history()`, `get_latest_version()`
- `core/graph/queries.py` — `QueryLibrary.get_nodes_at()`
- `core/ontology/schema.yaml` — `SUPERSEDES` relationship type
- `docs/architecture/decisions/0007-temporal-versioning-strategy.md`
