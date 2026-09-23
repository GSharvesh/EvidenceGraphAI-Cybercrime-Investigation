# Graph Validation

This document describes the `GraphValidator` — a read-only tool that checks
the live graph against the ontology schema.

---

## Overview

`GraphValidator` runs 7 rules against Neo4j and returns a structured
`ValidationReport`.  It never writes to the database.

---

## Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `orphan_nodes` | warning | Nodes with no incoming or outgoing edges |
| `invalid_edge_types` | error | Edges with undefined types or wrong endpoint labels |
| `missing_required_properties` | error | Nodes/edges missing schema-required properties |
| `invalid_property_types` | warning | Properties whose values don't match the declared type |
| `dangling_references` | error | Edges pointing to non-existent nodes |
| `confidence_range` | error | `confidence` outside `[0.0, 1.0]` |
| `temporal_consistency` | error | `valid_to` not after `valid_from` |

---

## Python API

```python
from core.graph.client import GraphClient
from core.graph.validator import GraphValidator

validator = GraphValidator(GraphClient())
report = validator.validate()

# Run a single rule
report = validator.validate(rules=["temporal_consistency"])

print(report.summary())
# {"error": 0, "warning": 2, "info": 0}

for v in report.violations:
    print(v.severity, v.rule, v.entity_id, v.message)
```

---

## CLI

```bash
# Run all rules, show warnings and above
python -m core.graph.validator

# Only show errors; exit 1 if any found
python -m core.graph.validator --severity error --fail-on error

# Run a single rule, output as JSON
python -m core.graph.validator --rule temporal_consistency --json

# Exit codes
# 0 → no violations at or above --fail-on level
# 1 → violations found
# 2 → runtime error
```

### Full CLI reference

```
usage: python -m core.graph.validator [options]

  --severity {error,warning,info}   Minimum severity to display (default: warning)
  --rule RULE_NAME                  Run only this rule (default: all rules)
  --json                            Output as JSON
  --fail-on {error,warning}         Exit 1 if violations at this level exist (default: error)
```

---

## API Endpoint

```
GET /graph/validate?severity=warning&rule=temporal_consistency
```

Localhost-only by default. Returns:
```json
{
  "violations": [...],
  "total": 3,
  "summary": {"error": 1, "warning": 2, "info": 0}
}
```

---

## References

- `core/graph/validator.py`
- `api/routes/graph.py` — `/graph/validate`
