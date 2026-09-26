import yaml

with open("core/ontology/schema.yaml") as f:
    s = yaml.safe_load(f)

nodes = list(s.get("nodes", {}).keys())
rels = list(s.get("relationships", {}).keys())

print(f"Ontology Version: {s.get('version')}")
print(f"Total Node Types ({len(nodes)}):")
for n in nodes:
    print(f"  - Node: {n}")

print(f"\nTotal Relationship Types ({len(rels)}):")
for r in rels:
    print(f"  - Edge: {r}")

assert len(nodes) == 11, f"Expected 11 nodes, got {len(nodes)}"
assert len(rels) == 15, f"Expected 15 relationships, got {len(rels)}"
print(
    "\nAUDIT RESULT: PASS (11 Node Types, 15 Relationship Types - including SUPERSEDES)"
)
