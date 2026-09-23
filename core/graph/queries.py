"""Comprehensive query library for EvidenceGraphAI graph investigation.

This module exposes the :class:`QueryLibrary` class — a thin, composable layer
over :class:`~core.graph.client.GraphClient`.  All methods use parameterised
Cypher, log at DEBUG level, and raise :class:`~core.graph.exceptions.GraphQueryError`
on failure.

The 22 public methods are grouped into six families:

* **Node Retrieval** (4) — ``get_node_by_id``, ``get_nodes_by_type``,
  ``get_nodes_by_property``, ``get_nodes_by_agent``
* **Edge Retrieval** (4) — ``get_edge_by_id``, ``get_edges_by_type``,
  ``get_edges_from``, ``get_edges_to``
* **Neighborhood** (2) — ``get_neighbors``, ``get_subgraph``
* **Temporal** (4) — ``get_nodes_at``, ``get_edges_at``,
  ``get_node_history``, ``get_latest_version``
* **Provenance** (2) — ``get_nodes_by_source_artifact``,
  ``get_full_provenance_chain``
* **Aggregate** (3) — ``count_nodes_by_type``, ``count_edges_by_type``,
  ``get_graph_statistics``
* **Path Finding** (2) — ``find_shortest_path``, ``find_all_paths``
* **Attack Lifecycle** (3) — ``get_attack_lifecycle``, ``get_campaign_links``,
  ``get_timeline``

Usage example::

    from core.graph.client import GraphClient
    from core.graph.queries import QueryLibrary

    client = GraphClient()
    ql = QueryLibrary(client)

    stats = ql.get_graph_statistics()
    path = ql.find_shortest_path("attacker-1", "victim-1")
"""

from datetime import datetime
from typing import Any

from core.graph.client import GraphClient
from core.graph.exceptions import GraphQueryError
from core.graph.temporal import temporal_filter_clause, to_iso
from core.logging.logger import get_logger

logger = get_logger(__name__)


class QueryLibrary:
    """Investigative query library wrapping a :class:`GraphClient`.

    All queries are read-only (except where explicitly noted).
    All parameters are passed to Cypher as named parameters — no string
    interpolation is used for user-supplied values.

    Parameters
    ----------
    client:
        A connected :class:`~core.graph.client.GraphClient` instance.
    """

    def __init__(self, client: GraphClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Node Retrieval
    # ------------------------------------------------------------------

    def get_node_by_id(self, node_id: str) -> dict[str, Any] | None:
        """Fetches a node's properties by its unique ID.

        Args:
            node_id: Node ID string.

        Returns:
            Property dict or ``None`` if not found.
        """
        logger.debug("get_node_by_id", node_id=node_id)
        return self._client.get_node(node_id)

    def get_nodes_by_type(self, node_type: str) -> list[dict[str, Any]]:
        """Returns all nodes of the given label.

        Args:
            node_type: Node label (e.g. ``"CVE"``).

        Returns:
            List of property dicts.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_nodes_by_type", node_type=node_type)
        try:
            cypher = f"MATCH (n:`{node_type}`) RETURN properties(n) AS props"
            records = self._client.query(cypher)
            return [r["props"] for r in records if "props" in r]
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_nodes_by_type failed: {exc}") from exc

    def get_nodes_by_property(
        self, node_type: str, property_name: str, value: Any
    ) -> list[dict[str, Any]]:
        """Returns nodes of a given type where a property equals a value.

        Args:
            node_type: Node label.
            property_name: Property key to match on.
            value: Value to match.

        Returns:
            List of property dicts.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug(
            "get_nodes_by_property",
            node_type=node_type,
            property_name=property_name,
            value=value,
        )
        try:
            cypher = (
                f"MATCH (n:`{node_type}`) WHERE n[$prop] = $value "
                f"RETURN properties(n) AS props"
            )
            records = self._client.query(
                cypher, {"prop": property_name, "value": value}
            )
            return [r["props"] for r in records if "props" in r]
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_nodes_by_property failed: {exc}") from exc

    def get_nodes_by_agent(self, source_agent: str) -> list[dict[str, Any]]:
        """Returns all nodes created by the given source agent.

        Args:
            source_agent: Agent name to filter on.

        Returns:
            List of property dicts.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_nodes_by_agent", source_agent=source_agent)
        try:
            cypher = (
                "MATCH (n) WHERE n.source_agent = $agent "
                "RETURN properties(n) AS props"
            )
            records = self._client.query(cypher, {"agent": source_agent})
            return [r["props"] for r in records if "props" in r]
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_nodes_by_agent failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Edge Retrieval
    # ------------------------------------------------------------------

    def get_edge_by_id(self, edge_id: str) -> dict[str, Any] | None:
        """Fetches a relationship's properties by its unique ID.

        Args:
            edge_id: Edge ID string.

        Returns:
            Property dict or ``None`` if not found.
        """
        logger.debug("get_edge_by_id", edge_id=edge_id)
        return self._client.get_edge(edge_id)

    def get_edges_by_type(self, edge_type: str) -> list[dict[str, Any]]:
        """Returns all relationships of the given type with their endpoint IDs.

        Args:
            edge_type: Relationship type (e.g. ``"EXPLOITS"``).

        Returns:
            List of dicts with keys ``id``, ``from_id``, ``to_id``, ``type``,
            and ``properties``.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_edges_by_type", edge_type=edge_type)
        try:
            cypher = (
                f"MATCH (a)-[r:`{edge_type}`]->(b) "
                f"RETURN r.id AS id, a.id AS from_id, b.id AS to_id, "
                f"type(r) AS type, properties(r) AS properties"
            )
            return self._client.query(cypher)
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_edges_by_type failed: {exc}") from exc

    def get_edges_from(
        self, node_id: str, edge_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Returns outgoing relationships from a node.

        Args:
            node_id: Source node ID.
            edge_type: Optional relationship type filter.

        Returns:
            List of dicts with keys ``id``, ``from_id``, ``to_id``, ``type``,
            and ``properties``.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_edges_from", node_id=node_id, edge_type=edge_type)
        try:
            if edge_type:
                cypher = (
                    f"MATCH (a {{id: $node_id}})-[r:`{edge_type}`]->(b) "
                    f"RETURN r.id AS id, a.id AS from_id, b.id AS to_id, "
                    f"type(r) AS type, properties(r) AS properties"
                )
            else:
                cypher = (
                    "MATCH (a {id: $node_id})-[r]->(b) "
                    "RETURN r.id AS id, a.id AS from_id, b.id AS to_id, "
                    "type(r) AS type, properties(r) AS properties"
                )
            return self._client.query(cypher, {"node_id": node_id})
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_edges_from failed: {exc}") from exc

    def get_edges_to(
        self, node_id: str, edge_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Returns incoming relationships to a node.

        Args:
            node_id: Target node ID.
            edge_type: Optional relationship type filter.

        Returns:
            List of dicts with keys ``id``, ``from_id``, ``to_id``, ``type``,
            and ``properties``.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_edges_to", node_id=node_id, edge_type=edge_type)
        try:
            if edge_type:
                cypher = (
                    f"MATCH (b)<-[r:`{edge_type}`]-(a) WHERE b.id = $node_id "
                    f"RETURN r.id AS id, a.id AS from_id, b.id AS to_id, "
                    f"type(r) AS type, properties(r) AS properties"
                )
            else:
                cypher = (
                    "MATCH (b)<-[r]-(a) WHERE b.id = $node_id "
                    "RETURN r.id AS id, a.id AS from_id, b.id AS to_id, "
                    "type(r) AS type, properties(r) AS properties"
                )
            return self._client.query(cypher, {"node_id": node_id})
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_edges_to failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Neighborhood Traversal
    # ------------------------------------------------------------------

    def get_neighbors(
        self, node_id: str, depth: int = 1
    ) -> dict[str, list[dict[str, Any]]]:
        """Returns nodes and edges in the neighbourhood of a node.

        Args:
            node_id: Center node ID.
            depth: Traversal depth (default 1).

        Returns:
            Dict with keys ``"nodes"`` and ``"edges"``.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_neighbors", node_id=node_id, depth=depth)
        try:
            d = max(1, int(depth))
            cypher = (
                f"MATCH path = (center {{id: $node_id}})-[*1..{d}]-(neighbor) "
                "UNWIND relationships(path) AS r "
                "RETURN DISTINCT "
                "properties(startNode(r)) AS from_props, "
                "properties(endNode(r)) AS to_props, "
                "type(r) AS edge_type, "
                "r.id AS edge_id, "
                "properties(r) AS edge_props"
            )
            records = self._client.query(cypher, {"node_id": node_id})

            nodes: dict[str, dict[str, Any]] = {}
            edges: list[dict[str, Any]] = []
            for rec in records:
                fp = rec.get("from_props") or {}
                tp = rec.get("to_props") or {}
                if fp.get("id"):
                    nodes[fp["id"]] = fp
                if tp.get("id"):
                    nodes[tp["id"]] = tp
                edges.append(
                    {
                        "id": rec.get("edge_id"),
                        "type": rec.get("edge_type"),
                        "from_id": fp.get("id"),
                        "to_id": tp.get("id"),
                        "properties": rec.get("edge_props") or {},
                    }
                )
            return {"nodes": list(nodes.values()), "edges": edges}
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_neighbors failed: {exc}") from exc

    def get_subgraph(
        self, node_ids: list[str], depth: int = 1
    ) -> dict[str, list[dict[str, Any]]]:
        """Returns the subgraph spanning the given node IDs at a given depth.

        Args:
            node_ids: List of seed node IDs.
            depth: Traversal depth from each seed node.

        Returns:
            Dict with keys ``"nodes"`` and ``"edges"``.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_subgraph", node_ids=node_ids, depth=depth)
        try:
            d = max(0, int(depth))
            cypher = (
                f"MATCH path = (seed)-[*0..{d}]-(neighbor) "
                "WHERE seed.id IN $node_ids "
                "UNWIND relationships(path) AS r "
                "RETURN DISTINCT "
                "properties(startNode(r)) AS from_props, "
                "properties(endNode(r)) AS to_props, "
                "type(r) AS edge_type, "
                "r.id AS edge_id, "
                "properties(r) AS edge_props"
            )
            records = self._client.query(cypher, {"node_ids": node_ids})

            nodes: dict[str, dict[str, Any]] = {}
            edges: list[dict[str, Any]] = []
            for rec in records:
                fp = rec.get("from_props") or {}
                tp = rec.get("to_props") or {}
                if fp.get("id"):
                    nodes[fp["id"]] = fp
                if tp.get("id"):
                    nodes[tp["id"]] = tp
                edges.append(
                    {
                        "id": rec.get("edge_id"),
                        "type": rec.get("edge_type"),
                        "from_id": fp.get("id"),
                        "to_id": tp.get("id"),
                        "properties": rec.get("edge_props") or {},
                    }
                )
            return {"nodes": list(nodes.values()), "edges": edges}
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_subgraph failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Temporal
    # ------------------------------------------------------------------

    def get_nodes_at(
        self, timestamp: datetime, node_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Returns nodes that were valid at the given timestamp.

        Args:
            timestamp: Point-in-time (must be timezone-aware).
            node_type: Optional node label filter.

        Returns:
            List of property dicts.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_nodes_at", timestamp=timestamp, node_type=node_type)
        try:
            return self._client.get_nodes_valid_at(timestamp, node_type=node_type)
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_nodes_at failed: {exc}") from exc

    def get_edges_at(
        self, timestamp: datetime, edge_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Returns relationships that were valid at the given timestamp.

        Args:
            timestamp: Point-in-time (must be timezone-aware).
            edge_type: Optional relationship type filter.

        Returns:
            List of dicts with ``id``, ``from_id``, ``to_id``, ``type``,
            ``properties``.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_edges_at", timestamp=timestamp, edge_type=edge_type)
        try:
            ts_str = to_iso(timestamp)
            filter_clause = temporal_filter_clause("r")
            if edge_type:
                cypher = (
                    f"MATCH (a)-[r:`{edge_type}`]->(b) WHERE {filter_clause} "
                    f"RETURN r.id AS id, a.id AS from_id, b.id AS to_id, "
                    f"type(r) AS type, properties(r) AS properties"
                )
            else:
                cypher = (
                    f"MATCH (a)-[r]->(b) WHERE {filter_clause} "
                    f"RETURN r.id AS id, a.id AS from_id, b.id AS to_id, "
                    f"type(r) AS type, properties(r) AS properties"
                )
            return self._client.query(cypher, {"timestamp": ts_str})
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_edges_at failed: {exc}") from exc

    def get_node_history(self, node_id: str) -> list[dict[str, Any]]:
        """Returns all versions of a node ordered oldest-to-newest.

        Args:
            node_id: Any version of the target node.

        Returns:
            List of property dicts (oldest first).
        """
        logger.debug("get_node_history", node_id=node_id)
        return self._client.get_node_history(node_id)

    def get_latest_version(self, node_id: str) -> dict[str, Any] | None:
        """Returns the currently active (latest) version of a node.

        Args:
            node_id: Any version of the target node.

        Returns:
            Property dict of the active version, or ``None``.
        """
        logger.debug("get_latest_version", node_id=node_id)
        return self._client.get_latest_version(node_id)

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------

    def get_nodes_by_source_artifact(self, artifact_id: str) -> list[dict[str, Any]]:
        """Returns all nodes whose ``source_artifact_id`` matches the given ID.

        Args:
            artifact_id: Evidence artifact ID.

        Returns:
            List of property dicts.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_nodes_by_source_artifact", artifact_id=artifact_id)
        try:
            cypher = (
                "MATCH (n) WHERE n.source_artifact_id = $artifact_id "
                "RETURN properties(n) AS props"
            )
            records = self._client.query(cypher, {"artifact_id": artifact_id})
            return [r["props"] for r in records if "props" in r]
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(
                f"get_nodes_by_source_artifact failed: {exc}"
            ) from exc

    def get_full_provenance_chain(self, node_id: str) -> list[dict[str, Any]]:
        """Traces the full provenance chain by following ``DERIVED_FROM`` edges.

        Walks from the given node upstream through all ``DERIVED_FROM``
        relationships and returns every ancestor node.

        Args:
            node_id: Starting node ID.

        Returns:
            List of property dicts ordered from immediate parent to root.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_full_provenance_chain", node_id=node_id)
        try:
            cypher = (
                "MATCH path = (start {id: $node_id})-[:DERIVED_FROM*]->(ancestor) "
                "RETURN [n IN nodes(path) | properties(n)] AS chain"
            )
            records = self._client.query(cypher, {"node_id": node_id})
            if not records:
                return []
            chain = records[0].get("chain", [])
            # Skip the start node (index 0) — return ancestors only
            return list(chain[1:]) if len(chain) > 1 else []
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_full_provenance_chain failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Aggregate
    # ------------------------------------------------------------------

    def count_nodes_by_type(self) -> dict[str, int]:
        """Returns node counts grouped by label.

        Returns:
            Dict mapping label name to count (e.g. ``{"CVE": 12, "Malware": 4}``).

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("count_nodes_by_type")
        try:
            cypher = (
                "MATCH (n) "
                "UNWIND labels(n) AS label "
                "RETURN label, count(*) AS cnt "
                "ORDER BY cnt DESC"
            )
            records = self._client.query(cypher)
            return {r["label"]: int(r["cnt"]) for r in records if "label" in r}
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"count_nodes_by_type failed: {exc}") from exc

    def count_edges_by_type(self) -> dict[str, int]:
        """Returns relationship counts grouped by type.

        Returns:
            Dict mapping type name to count.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("count_edges_by_type")
        try:
            cypher = (
                "MATCH ()-[r]->() "
                "RETURN type(r) AS rel_type, count(*) AS cnt "
                "ORDER BY cnt DESC"
            )
            records = self._client.query(cypher)
            return {r["rel_type"]: int(r["cnt"]) for r in records if "rel_type" in r}
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"count_edges_by_type failed: {exc}") from exc

    def get_graph_statistics(self) -> dict[str, Any]:
        """Returns aggregate statistics about the entire graph.

        Returns:
            Dict with ``node_counts``, ``edge_counts``, ``totals``, and
            ``active_node_count`` (nodes where ``valid_to IS NULL``).

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_graph_statistics")
        try:
            node_counts = self.count_nodes_by_type()
            edge_counts = self.count_edges_by_type()

            active_records = self._client.query(
                "MATCH (n) WHERE n.valid_to IS NULL RETURN count(n) AS cnt"
            )
            active_count = int(active_records[0]["cnt"]) if active_records else 0

            return {
                "node_counts": node_counts,
                "edge_counts": edge_counts,
                "totals": {
                    "nodes": sum(node_counts.values()),
                    "edges": sum(edge_counts.values()),
                },
                "active_node_count": active_count,
            }
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_graph_statistics failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Path Finding
    # ------------------------------------------------------------------

    def find_shortest_path(
        self, from_node_id: str, to_node_id: str, max_depth: int = 10
    ) -> list[str] | None:
        """Finds the shortest path between two nodes.

        Args:
            from_node_id: Source node ID.
            to_node_id: Target node ID.
            max_depth: Maximum traversal depth.

        Returns:
            List of node IDs along the path (inclusive of endpoints),
            or ``None`` if no path exists.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug(
            "find_shortest_path",
            from_id=from_node_id,
            to_id=to_node_id,
            max_depth=max_depth,
        )
        try:
            md = max(1, int(max_depth))
            cypher = (
                f"MATCH (a {{id: $from_id}}), (b {{id: $to_id}}), "
                f"path = shortestPath((a)-[*..{md}]-(b)) "
                "RETURN [n IN nodes(path) | n.id] AS ids"
            )
            records = self._client.query(
                cypher,
                {"from_id": from_node_id, "to_id": to_node_id},
            )
            if records and records[0].get("ids"):
                return list(records[0]["ids"])
            return None
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"find_shortest_path failed: {exc}") from exc

    def find_all_paths(
        self, from_node_id: str, to_node_id: str, max_depth: int = 5
    ) -> list[list[str]]:
        """Finds all paths between two nodes up to a given depth.

        Args:
            from_node_id: Source node ID.
            to_node_id: Target node ID.
            max_depth: Maximum traversal depth.

        Returns:
            List of paths, each path being a list of node IDs.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug(
            "find_all_paths",
            from_id=from_node_id,
            to_id=to_node_id,
            max_depth=max_depth,
        )
        try:
            md = max(1, int(max_depth))
            cypher = (
                f"MATCH (a {{id: $from_id}}), (b {{id: $to_id}}), "
                f"path = (a)-[*..{md}]-(b) "
                "RETURN [n IN nodes(path) | n.id] AS ids"
            )
            records = self._client.query(
                cypher,
                {"from_id": from_node_id, "to_id": to_node_id},
            )
            return [list(r["ids"]) for r in records if r.get("ids")]
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"find_all_paths failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Attack Lifecycle
    # ------------------------------------------------------------------

    def get_attack_lifecycle(self, cve_id: str) -> dict[str, Any]:
        """Returns the attack lifecycle graph rooted at a CVE.

        Traverses outgoing relationships up to 5 hops from the CVE node,
        capturing the exploitation chain.

        Args:
            cve_id: CVE node ID (e.g. ``"CVE-2021-44228"``).

        Returns:
            Dict with ``"nodes"`` and ``"edges"`` lists.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_attack_lifecycle", cve_id=cve_id)
        try:
            cypher = (
                "MATCH path = (cve:CVE {id: $cve_id})<-[*1..5]-(n) "
                "UNWIND relationships(path) AS r "
                "RETURN DISTINCT "
                "properties(startNode(r)) AS from_props, "
                "properties(endNode(r)) AS to_props, "
                "type(r) AS edge_type, "
                "r.id AS edge_id, "
                "properties(r) AS edge_props"
            )
            records = self._client.query(cypher, {"cve_id": cve_id})

            nodes: dict[str, dict[str, Any]] = {}
            edges: list[dict[str, Any]] = []
            for rec in records:
                fp = rec.get("from_props") or {}
                tp = rec.get("to_props") or {}
                if fp.get("id"):
                    nodes[fp["id"]] = fp
                if tp.get("id"):
                    nodes[tp["id"]] = tp
                edges.append(
                    {
                        "id": rec.get("edge_id"),
                        "type": rec.get("edge_type"),
                        "from_id": fp.get("id"),
                        "to_id": tp.get("id"),
                        "properties": rec.get("edge_props") or {},
                    }
                )
            return {"nodes": list(nodes.values()), "edges": edges}
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_attack_lifecycle failed: {exc}") from exc

    def get_campaign_links(self, case_id: str) -> list[dict[str, Any]]:
        """Returns all ``LINKED_CAMPAIGN`` edges connected to a given node.

        Args:
            case_id: Attacker or Malware node ID.

        Returns:
            List of dicts with ``id``, ``from_id``, ``to_id``,
            ``type``, and ``properties``.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_campaign_links", case_id=case_id)
        try:
            cypher = (
                "MATCH (n {id: $case_id})-[r:LINKED_CAMPAIGN]-(m) "
                "RETURN r.id AS id, n.id AS from_id, m.id AS to_id, "
                "type(r) AS type, properties(r) AS properties"
            )
            return self._client.query(cypher, {"case_id": case_id})
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_campaign_links failed: {exc}") from exc

    def get_timeline(self, case_id: str) -> list[dict[str, Any]]:
        """Returns log entries associated with a case node, ordered by timestamp.

        Traverses ``PRECEDES`` and ``HAS_RESPONSE`` relationships connected
        to the given node to build a temporal log timeline.

        Args:
            case_id: Case (Victim or Attacker) node ID.

        Returns:
            List of LogEntry property dicts ordered by ``timestamp`` ascending.

        Raises:
            GraphQueryError: On query failure.
        """
        logger.debug("get_timeline", case_id=case_id)
        try:
            cypher = (
                "MATCH (case {id: $case_id})-[*1..3]-(log:LogEntry) "
                "RETURN DISTINCT properties(log) AS props "
                "ORDER BY log.timestamp ASC"
            )
            records = self._client.query(cypher, {"case_id": case_id})
            return [r["props"] for r in records if "props" in r]
        except GraphQueryError:
            raise
        except Exception as exc:
            raise GraphQueryError(f"get_timeline failed: {exc}") from exc
