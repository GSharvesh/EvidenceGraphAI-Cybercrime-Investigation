# Provenance

This document describes EvidenceGraphAI's provenance model for graph entities.

---

## Overview

Every node and relationship in the graph carries three provenance fields:

| Field | Required | Description |
|-------|----------|-------------|
| `source_agent` | ✅ Yes | Name of the agent that created this entity |
| `source_artifact_id` | ❌ No | Evidence artefact ID that produced this entity |
| `confidence` | ✅ Yes | Float in `[0.0, 1.0]` indicating confidence |

These fields are automatically validated on every write via `GraphClient`.

---

## Validation Modes

### Flexible mode (default)

`source_agent` must match the regex `^[a-z][a-z0-9_]{2,63}$`.

Any valid agent name is accepted — no allowlist is consulted.

### Strict mode (opt-in)

Set `PROVENANCE_STRICT_MODE=true` in your environment.

`source_agent` must additionally be in the `KNOWN_AGENTS` comma-separated list.

```env
PROVENANCE_STRICT_MODE=true
KNOWN_AGENTS=system,manual,vuln_agent,network_agent
```

To add a new Phase 2 agent: add its name to `KNOWN_AGENTS` without any code changes.

---

## Agent Name Rules

Agent names must:
- Start with a lowercase letter (`a-z`).
- Contain only lowercase letters, digits, and underscores.
- Be 3–64 characters long.

Valid: `system`, `vuln_agent`, `network_scanner_v2`
Invalid: `MyAgent`, `1agent`, `ab`, `my-agent`

---

## Usage

### Default provenance (system agent)
```python
node_id = client.create_node("CVE", {
    "id": "CVE-2021-44228",
    "cvss_score": 10.0,
    # source_agent, confidence default to "system", 1.0
})
```

### Custom provenance
```python
node_id = client.create_node("Malware", {
    "id": "malware-xyz",
    "sha256": "abc...",
    "source_agent": "network_agent",
    "source_artifact_id": "pcap-capture-001",
    "confidence": 0.85,
})
```

### Querying by provenance
```python
from core.graph.queries import QueryLibrary

ql = QueryLibrary(client)

# All nodes from a specific agent
nodes = ql.get_nodes_by_agent("network_agent")

# All nodes derived from a specific evidence artefact
nodes = ql.get_nodes_by_source_artifact("pcap-capture-001")

# Full provenance chain (follows DERIVED_FROM edges)
chain = ql.get_full_provenance_chain("cve-node-id")
```

---

## References

- `core/graph/provenance.py` — validation utilities
- `core/graph/client.py` — `_enforce_provenance()`
- `core/config/settings.py` — `provenance_strict_mode`, `known_agents`
- `docs/architecture/decisions/0008-provenance-enforcement.md`
