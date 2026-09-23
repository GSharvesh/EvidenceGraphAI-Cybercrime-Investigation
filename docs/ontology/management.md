# Ontology Management

This document describes how to introspect, diff, and migrate the EvidenceGraphAI schema.

---

## Introspection

Use `core.ontology.introspection` to query schema metadata without hitting the database:

```python
from core.ontology.loader import load_ontology_schema
from core.ontology.introspection import (
    list_node_types, list_edge_types,
    list_required_properties, get_allowed_sources,
)

schema = load_ontology_schema()

# List all node types (sorted)
print(list_node_types(schema))

# List all 15 relationship types (including SUPERSEDES)
print(list_edge_types(schema))

# Required properties for CVE
print(list_required_properties(schema, "CVE"))
# → ['id']

# Allowed source node types for EXPLOITS
print(get_allowed_sources(schema, "EXPLOITS"))
# → ['Attacker', 'Malware']
```

---

## Diffing Schemas

Compare two schema YAML files to identify additions, removals, and modifications:

```python
from core.ontology.loader import OntologyLoader
from core.ontology.diff import diff_schemas

old = OntologyLoader("core/ontology/schema_v1.yaml").load()
new = OntologyLoader("core/ontology/schema.yaml").load()

diff = diff_schemas(old, new)
print(diff.summary())
# "+1 edge type(s)"

print(diff.added_edge_types)
# ['SUPERSEDES']
```

---

## Generating Migrations

Given a diff, generate idempotent Cypher migration statements:

```python
from core.ontology.migration import generate_migration

statements = generate_migration(diff)
for stmt in statements:
    print(stmt)

# Execute (review first!)
for stmt in statements:
    if not stmt.startswith("//"):
        client.query(stmt)
```

Generated statements use `IF NOT EXISTS` / `IF EXISTS` for idempotency.

---

## Adding a New Node Type

1. Add the type definition to `core/ontology/schema.yaml`.
2. Run `python infra/scripts/seed_ontology.py` (idempotent — safe to re-run).
3. Diff the schemas and apply the generated migration.
4. Update `docs/ontology/reference.md`.

---

## Adding a New Relationship Type

1. Add the type definition to `core/ontology/schema.yaml`.
2. No DDL is needed for relationship types in Neo4j.
3. Diff and document.

---

## References

- `core/ontology/introspection.py`
- `core/ontology/diff.py`
- `core/ontology/migration.py`
- `core/ontology/schema.yaml`
- `docs/ontology/reference.md`
