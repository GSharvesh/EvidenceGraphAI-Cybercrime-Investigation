# QueryLibrary Reference

Complete reference for all 22 methods in `core.graph.queries.QueryLibrary`.

---

## Usage

```python
from core.graph.client import GraphClient
from core.graph.queries import QueryLibrary

client = GraphClient()
ql = QueryLibrary(client)
```

---

## Node Retrieval

### `get_node_by_id(node_id)`
Returns the properties of a single node by ID, or `None` if not found.

### `get_nodes_by_type(node_type)`
Returns all nodes with the given label (e.g. `"CVE"`).

### `get_nodes_by_property(node_type, property_name, value)`
Returns nodes of a given type where `property_name == value`.

### `get_nodes_by_agent(source_agent)`
Returns all nodes whose `source_agent` matches.

---

## Edge Retrieval

### `get_edge_by_id(edge_id)`
Returns properties of a single relationship, or `None`.

### `get_edges_by_type(edge_type)`
Returns all relationships of the given type with endpoint IDs.
Returns: `[{"id", "from_id", "to_id", "type", "properties"}, ...]`

### `get_edges_from(node_id, edge_type=None)`
Returns outgoing relationships from `node_id`.  Optionally filtered by type.

### `get_edges_to(node_id, edge_type=None)`
Returns incoming relationships to `node_id`.  Optionally filtered by type.

---

## Neighborhood Traversal

### `get_neighbors(node_id, depth=1)`
Returns `{"nodes": [...], "edges": [...]}` for the neighbourhood of a node.

### `get_subgraph(node_ids, depth=1)`
Returns the subgraph spanning multiple seed nodes at a given depth.

---

## Temporal

### `get_nodes_at(timestamp, node_type=None)`
Returns nodes that were valid at the given timestamp (timezone-aware `datetime`).

### `get_edges_at(timestamp, edge_type=None)`
Returns relationships that were valid at the given timestamp.

### `get_node_history(node_id)`
Returns all versions of a node, oldest-first.

### `get_latest_version(node_id)`
Returns the currently active (valid_to IS NULL) version of a node.

---

## Provenance

### `get_nodes_by_source_artifact(artifact_id)`
Returns all nodes whose `source_artifact_id` matches.

### `get_full_provenance_chain(node_id)`
Walks `DERIVED_FROM` edges and returns all ancestor nodes.

---

## Aggregate

### `count_nodes_by_type()`
Returns `{"CVE": 12, "Malware": 4, ...}`.

### `count_edges_by_type()`
Returns `{"EXPLOITS": 8, "DELIVERS": 3, ...}`.

### `get_graph_statistics()`
Returns `node_counts`, `edge_counts`, `totals`, and `active_node_count`.

---

## Path Finding

### `find_shortest_path(from_node_id, to_node_id, max_depth=10)`
Returns a list of node IDs along the shortest path, or `None`.

### `find_all_paths(from_node_id, to_node_id, max_depth=5)`
Returns a list of all paths (each path is a list of node IDs).

---

## Attack Lifecycle

### `get_attack_lifecycle(cve_id)`
Returns the attack graph rooted at a CVE (up to 5 hops inbound).

### `get_campaign_links(case_id)`
Returns all `LINKED_CAMPAIGN` edges connected to a node.

### `get_timeline(case_id)`
Returns `LogEntry` nodes connected to a case node, ordered by `timestamp`.

---

## Error Handling

All methods raise `GraphQueryError` on failure.  Callers should catch it:

```python
from core.graph.exceptions import GraphQueryError
try:
    nodes = ql.get_nodes_by_type("CVE")
except GraphQueryError as e:
    logger.error("Query failed", error=str(e))
```
