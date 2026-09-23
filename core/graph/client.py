"""Neo4j graph client library with connection pooling, transactions, temporal fields, and provenance.

This module implements the primary interface to Neo4j.  All graph write operations
pass through this client, which enforces:

* **Temporal fields** — ``created_at``, ``updated_at``, ``valid_from``, ``valid_to``
  are set automatically on every insert.

* **Provenance fields** — ``source_agent``, ``source_artifact_id``, ``confidence``
  are validated (and optionally enforced against an allowlist) on every insert.

* **Append-only versioning** — nodes are never mutated in place.  The
  :py:meth:`update_node` method soft-closes the existing version and creates a
  new version connected by a ``SUPERSEDES`` relationship.

* **Soft deletion** — :py:meth:`soft_delete` sets ``valid_to`` without physically
  removing data.

All Cypher queries are parameterised — no string concatenation is used for
user-supplied values.
"""

import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from neo4j import Driver, GraphDatabase, Transaction
from neo4j.exceptions import ClientError, ConstraintError, DriverError, Neo4jError

from core.config.settings import Settings, get_settings
from core.graph.exceptions import (
    GraphConnectionError,
    GraphConstraintError,
    GraphQueryError,
    ProvenanceValidationError,
    TemporalValidationError,
)
from core.graph.provenance import parse_known_agents, validate_provenance
from core.graph.temporal import (
    derive_version_id,
    get_root_id,
    temporal_filter_clause,
    to_iso,
    validate_temporal_consistency,
)
from core.graph.temporal import now_utc as _now_utc
from core.logging.logger import get_logger
from core.observability.metrics import (
    GRAPH_ACTIVE_CONNECTIONS,
    GRAPH_QUERY_COUNT,
    GRAPH_QUERY_DURATION_SECONDS,
    GRAPH_QUERY_ERRORS,
)
from core.ontology.validator import OntologyValidator

logger = get_logger(__name__)


def current_utc_iso() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(UTC).isoformat()


class GraphClient:
    """Neo4j Graph Client providing CRUD, Cypher execution, temporal/provenance tagging, and transactions.

    Parameters
    ----------
    settings:
        Application settings.  Defaults to the global singleton.
    driver:
        Pre-built Neo4j driver (useful for testing with a mock).
    validator:
        Ontology validator.  Defaults to the shared ``OntologyValidator``.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        driver: Driver | None = None,
        validator: OntologyValidator | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._driver: Driver | None = driver
        self.validator = validator or OntologyValidator()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Establishes connection driver to Neo4j if not already connected."""
        if self._driver is None:
            try:
                self._driver = GraphDatabase.driver(
                    self.settings.neo4j_uri,
                    auth=(self.settings.neo4j_user, self.settings.neo4j_password),
                    max_connection_pool_size=self.settings.neo4j_max_connection_pool_size,
                    connection_timeout=self.settings.neo4j_connection_timeout,
                )
                logger.info(
                    "Connected to Neo4j database",
                    uri=self.settings.neo4j_uri,
                    database=self.settings.neo4j_database,
                )
            except Exception as e:
                logger.error("Failed to connect to Neo4j", error=str(e))
                raise GraphConnectionError(f"Neo4j connection error: {e}") from e

    def close(self) -> None:
        """Closes the Neo4j driver connection pool."""
        if self._driver is not None:
            self._driver.close()
            self._driver = None
            logger.info("Closed Neo4j database connection pool")

    def health_check(self) -> bool:
        """Checks connectivity to Neo4j database.

        Returns:
            True if healthy, False otherwise.
        """
        try:
            if self._driver is None:
                self.connect()
            assert self._driver is not None
            self._driver.verify_connectivity()
            return True
        except Exception as e:
            logger.warning("Neo4j health check failed", error=str(e))
            return False

    # ------------------------------------------------------------------
    # Query execution
    # ------------------------------------------------------------------

    def query(
        self,
        cypher: str,
        params: dict[str, Any] | None = None,
        tx: Transaction | None = None,
    ) -> list[dict[str, Any]]:
        """Executes a Cypher query with parameters.

        Args:
            cypher: Parameterized Cypher query string.
            params: Parameters dictionary.
            tx: Optional ongoing transaction.

        Returns:
            List of record dictionaries.
        """
        if self._driver is None and tx is None:
            self.connect()

        params = params or {}
        GRAPH_QUERY_COUNT.inc()
        GRAPH_ACTIVE_CONNECTIONS.inc()

        try:
            with GRAPH_QUERY_DURATION_SECONDS.time():
                if tx is not None:
                    result = tx.run(cypher, params)
                    return [record.data() for record in result]
                else:
                    assert self._driver is not None
                    with self._driver.session(
                        database=self.settings.neo4j_database
                    ) as session:
                        result = session.run(cypher, params)
                        return [record.data() for record in result]
        except ConstraintError as e:
            GRAPH_QUERY_ERRORS.inc()
            logger.error("Neo4j constraint error", error=str(e))
            raise GraphConstraintError(f"Constraint error: {e}") from e
        except (ClientError, Neo4jError, DriverError) as e:
            GRAPH_QUERY_ERRORS.inc()
            logger.error("Neo4j query error", error=str(e))
            raise GraphQueryError(f"Query execution error: {e}") from e
        except Exception as e:
            GRAPH_QUERY_ERRORS.inc()
            logger.error("Unexpected error during graph query", error=str(e))
            raise GraphQueryError(f"Unexpected query error: {e}") from e
        finally:
            GRAPH_ACTIVE_CONNECTIONS.dec()

    @contextmanager
    def transaction(self) -> Generator[Transaction, None, None]:
        """Context manager providing explicit transaction control with rollback on error.

        Yields:
            Neo4j Transaction object.
        """
        if self._driver is None:
            self.connect()
        assert self._driver is not None

        session = self._driver.session(database=self.settings.neo4j_database)
        tx = session.begin_transaction()
        try:
            yield tx
            tx.commit()
            logger.debug("Transaction committed successfully")
        except Exception as e:
            tx.rollback()
            logger.warning("Transaction rolled back due to error", error=str(e))
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Internal metadata helpers
    # ------------------------------------------------------------------

    def _apply_metadata(
        self, properties: dict[str, Any], is_update: bool = False
    ) -> dict[str, Any]:
        """Enriches properties with temporal versioning and provenance tracking fields."""
        props = dict(properties)
        now = current_utc_iso()

        # Temporal fields
        props.setdefault("valid_from", now)
        props.setdefault("valid_to", None)
        if not is_update:
            props.setdefault("created_at", now)
        props["updated_at"] = now

        # Provenance fields
        props.setdefault("source_agent", "system")
        props.setdefault("source_artifact_id", None)
        props.setdefault("confidence", 1.0)

        return props

    def _enforce_provenance(self, props: dict[str, Any]) -> None:
        """Validates provenance fields, respecting strict-mode setting.

        Args:
            props: Property dictionary (after ``_apply_metadata``).

        Raises:
            ProvenanceValidationError: If validation fails.
        """
        strict = self.settings.provenance_strict_mode
        known: list[str] | None = None
        if strict:
            known = parse_known_agents(self.settings.known_agents)
        try:
            validate_provenance(props, strict=strict, known_agents=known)
        except ProvenanceValidationError:
            raise

    def _enforce_temporal(self, props: dict[str, Any]) -> None:
        """Validates temporal field consistency.

        Args:
            props: Property dictionary.

        Raises:
            TemporalValidationError: If validation fails.
        """
        try:
            validate_temporal_consistency(props)
        except TemporalValidationError:
            raise

    # ------------------------------------------------------------------
    # Node CRUD
    # ------------------------------------------------------------------

    def create_node(
        self,
        node_type: str,
        properties: dict[str, Any],
        tx: Transaction | None = None,
    ) -> str:
        """Creates a node of a validated type with properties.

        Args:
            node_type: Target node type label (e.g. CVE, Malware).
            properties: Properties dictionary.
            tx: Optional transaction handle.

        Returns:
            The created node ID string.

        Raises:
            GraphValidationError: If schema validation fails.
            ProvenanceValidationError: If provenance fields are invalid.
            TemporalValidationError: If temporal fields are inconsistent.
        """
        self.validator.validate_node(node_type, properties)

        if "id" not in properties:
            properties["id"] = str(uuid.uuid4())

        props = self._apply_metadata(properties)
        self._enforce_provenance(props)
        self._enforce_temporal(props)

        node_id = str(props["id"])

        cypher = f"CREATE (n:`{node_type}`) SET n = $props RETURN n.id AS id"
        records = self.query(cypher, {"props": props}, tx=tx)

        if not records:
            raise GraphQueryError(f"Failed to create node of type '{node_type}'")

        logger.debug("Node created successfully", node_type=node_type, id=node_id)
        return node_id

    def update_node(
        self,
        node_id: str,
        properties: dict[str, Any],
        node_type: str | None = None,
        tx: Transaction | None = None,
    ) -> str:
        """Updates a node using append-only versioning.

        This method NEVER modifies the existing node in place.  Instead:

        1. Fetches the current node and determines its version number.
        2. Soft-closes the existing node (sets ``valid_to = now``).
        3. Creates a new node version with a derived ID (``{original_id}::v{n}``).
        4. Copies all old properties, merges ``properties``, sets ``valid_from = now``.
        5. Creates a ``SUPERSEDES`` edge from the new version to the old version.

        Args:
            node_id: ID of the node to update (root or versioned).
            properties: Property patch to apply to the new version.
            node_type: Optional node type label (fetched from existing node if omitted).
            tx: Optional transaction handle.

        Returns:
            The ID of the new node version.

        Raises:
            GraphQueryError: If the node does not exist or the update fails.
            ProvenanceValidationError: If provenance fields in ``properties`` are invalid.
        """
        # Fetch existing node
        existing = self.get_node(node_id, tx=tx)
        if existing is None:
            raise GraphQueryError(f"Node '{node_id}' not found; cannot update")

        # Determine version number
        existing_version = self._get_version_count(get_root_id(node_id), tx=tx)
        new_version_number = existing_version + 1
        new_id = derive_version_id(get_root_id(node_id), new_version_number)

        now = to_iso(_now_utc())

        # Step 1: Soft-close existing node
        close_cypher = (
            "MATCH (n {id: $node_id}) SET n.valid_to = $now, n.updated_at = $now"
        )
        self.query(close_cypher, {"node_id": node_id, "now": now}, tx=tx)

        # Step 2: Build new node properties
        new_props = dict(existing)
        new_props.update(properties)
        new_props["id"] = new_id
        new_props["valid_from"] = now
        new_props["valid_to"] = None
        new_props["updated_at"] = now
        # created_at is inherited from the existing node (immutable lineage)

        # Enforce provenance + temporal on the new version
        new_props.setdefault("source_agent", "system")
        new_props.setdefault("confidence", 1.0)
        self._enforce_provenance(new_props)
        self._enforce_temporal(new_props)

        # Step 3: Determine label
        if node_type is None:
            type_records = self.query(
                "MATCH (n {id: $node_id}) RETURN labels(n)[0] AS label",
                {"node_id": node_id},
                tx=tx,
            )
            node_type = type_records[0]["label"] if type_records else "Unknown"

        # Step 4: Create new node version
        create_cypher = f"CREATE (n:`{node_type}`) SET n = $props RETURN n.id AS id"
        self.query(create_cypher, {"props": new_props}, tx=tx)

        # Step 5: Create SUPERSEDES edge
        supersedes_props = {
            "id": str(uuid.uuid4()),
            "source_agent": new_props.get("source_agent", "system"),
            "source_artifact_id": new_props.get("source_artifact_id"),
            "confidence": 1.0,
            "valid_from": now,
            "valid_to": None,
            "created_at": now,
            "updated_at": now,
        }
        edge_cypher = (
            "MATCH (new {id: $new_id}), (old {id: $old_id}) "
            "CREATE (new)-[r:SUPERSEDES]->(old) "
            "SET r = $props RETURN r.id AS id"
        )
        self.query(
            edge_cypher,
            {"new_id": new_id, "old_id": node_id, "props": supersedes_props},
            tx=tx,
        )

        logger.debug(
            "Node updated (append-only)",
            root_id=get_root_id(node_id),
            old_id=node_id,
            new_id=new_id,
            version=new_version_number,
        )
        return new_id

    def _get_version_count(self, root_id: str, tx: Transaction | None = None) -> int:
        """Counts how many versions exist for a given root node ID.

        Args:
            root_id: The unversioned root ID.
            tx: Optional transaction handle.

        Returns:
            Count of existing versions (0 if only the original exists).
        """
        cypher = (
            "MATCH (n) WHERE n.id = $root_id OR n.id STARTS WITH $prefix "
            "RETURN count(n) AS cnt"
        )
        records = self.query(
            cypher, {"root_id": root_id, "prefix": f"{root_id}::v"}, tx=tx
        )
        if records:
            cnt = records[0].get("cnt", 1)
            # cnt includes the original; versions = cnt - 1
            return int(cnt) - 1
        return 0

    def get_node(
        self, node_id: str, tx: Transaction | None = None
    ) -> dict[str, Any] | None:
        """Fetches node properties by ID.

        Args:
            node_id: Node ID string.
            tx: Optional transaction handle.

        Returns:
            Properties dictionary or None if not found.
        """
        cypher = "MATCH (n {id: $node_id}) RETURN properties(n) AS props"
        records = self.query(cypher, {"node_id": node_id}, tx=tx)
        if records and "props" in records[0]:
            props = dict(records[0]["props"])
            props.setdefault("valid_to", None)
            return props
        return None

    def get_node_history(
        self, node_id: str, tx: Transaction | None = None
    ) -> list[dict[str, Any]]:
        """Returns all versions of a node ordered from oldest to newest.

        Traverses the ``SUPERSEDES`` chain from the given node (which may be any
        version, including the root).

        Args:
            node_id: Any version of the target node.
            tx: Optional transaction handle.

        Returns:
            List of property dicts ordered oldest-first.
        """
        root = get_root_id(node_id)
        cypher = (
            "MATCH (n) WHERE n.id = $root_id OR n.id STARTS WITH $prefix "
            "RETURN properties(n) AS props, n.valid_from AS vf "
            "ORDER BY vf ASC"
        )
        records = self.query(cypher, {"root_id": root, "prefix": f"{root}::v"}, tx=tx)
        results = []
        for r in records:
            if "props" in r:
                p = dict(r["props"])
                p.setdefault("valid_to", None)
                results.append(p)
        return results

    def get_latest_version(
        self, node_id: str, tx: Transaction | None = None
    ) -> dict[str, Any] | None:
        """Returns the currently active (latest) version of a node.

        The latest version is the one with ``valid_to IS NULL``.

        Args:
            node_id: Any version of the target node.
            tx: Optional transaction handle.

        Returns:
            Properties dict of the active version, or None if not found.
        """
        root = get_root_id(node_id)
        cypher = (
            "MATCH (n) WHERE (n.id = $root_id OR n.id STARTS WITH $prefix) "
            "AND n.valid_to IS NULL "
            "RETURN properties(n) AS props"
        )
        records = self.query(cypher, {"root_id": root, "prefix": f"{root}::v"}, tx=tx)
        if records and "props" in records[0]:
            props = dict(records[0]["props"])
            props.setdefault("valid_to", None)
            return props
        return None

    def get_node_at(
        self, node_id: str, timestamp: datetime, tx: Transaction | None = None
    ) -> dict[str, Any] | None:
        """Fetches the version of a node that was valid at the given timestamp.

        Args:
            node_id: Root or versioned node ID.
            timestamp: Point-in-time query (must be timezone-aware).
            tx: Optional transaction handle.

        Returns:
            Properties dict of the version valid at ``timestamp``, or None.
        """
        ts_str = to_iso(timestamp)
        root = get_root_id(node_id)
        filter_clause = temporal_filter_clause("n")
        cypher = (
            f"MATCH (n) WHERE (n.id = $root_id OR n.id STARTS WITH $prefix) "
            f"AND {filter_clause} "
            f"RETURN properties(n) AS props "
            f"LIMIT 1"
        )
        records = self.query(
            cypher,
            {"root_id": root, "prefix": f"{root}::v", "timestamp": ts_str},
            tx=tx,
        )
        if records and "props" in records[0]:
            props = dict(records[0]["props"])
            props.setdefault("valid_to", None)
            return props
        return None

    def get_nodes_valid_at(
        self,
        timestamp: datetime,
        node_type: str | None = None,
        tx: Transaction | None = None,
    ) -> list[dict[str, Any]]:
        """Returns all nodes (of an optional type) that were valid at the given timestamp.

        Args:
            timestamp: Point-in-time query (must be timezone-aware).
            node_type: Optional node label filter.
            tx: Optional transaction handle.

        Returns:
            List of property dicts.
        """
        ts_str = to_iso(timestamp)
        filter_clause = temporal_filter_clause("n")
        if node_type:
            cypher = (
                f"MATCH (n:`{node_type}`) WHERE {filter_clause} "
                f"RETURN properties(n) AS props"
            )
        else:
            cypher = (
                f"MATCH (n) WHERE {filter_clause} " f"RETURN properties(n) AS props"
            )
        records = self.query(cypher, {"timestamp": ts_str}, tx=tx)
        results = []
        for r in records:
            if "props" in r:
                p = dict(r["props"])
                p.setdefault("valid_to", None)
                results.append(p)
        return results

    def soft_delete(
        self,
        node_id: str,
        at: datetime | None = None,
        tx: Transaction | None = None,
    ) -> None:
        """Soft-deletes a node by setting its ``valid_to`` timestamp.

        Args:
            node_id: ID of the node to soft-delete.
            at: Deletion timestamp.  Defaults to now.
            tx: Optional transaction handle.
        """
        ts = to_iso(at if at is not None else _now_utc())
        cypher = "MATCH (n {id: $node_id}) SET n.valid_to = $ts, n.updated_at = $ts"
        self.query(cypher, {"node_id": node_id, "ts": ts}, tx=tx)
        logger.debug("Node soft-deleted", node_id=node_id, valid_to=ts)

    # ------------------------------------------------------------------
    # Edge CRUD
    # ------------------------------------------------------------------

    def create_edge(
        self,
        from_id: str,
        to_id: str,
        edge_type: str,
        properties: dict[str, Any] | None = None,
        tx: Transaction | None = None,
    ) -> str:
        """Creates a relationship edge between two existing nodes.

        Args:
            from_id: Source node ID.
            to_id: Target node ID.
            edge_type: Relationship type label (e.g. EXPLOITS).
            properties: Edge properties.
            tx: Optional transaction handle.

        Returns:
            The edge ID string.

        Raises:
            ProvenanceValidationError: If provenance fields are invalid.
            TemporalValidationError: If temporal fields are inconsistent.
        """
        props = dict(properties or {})
        self.validator.validate_edge(edge_type, props)

        if "id" not in props or not props["id"]:
            props["id"] = str(uuid.uuid4())

        props = self._apply_metadata(props)
        self._enforce_provenance(props)
        self._enforce_temporal(props)

        edge_id = str(props["id"])

        cypher = (
            f"MATCH (a {{id: $from_id}}), (b {{id: $to_id}}) "
            f"CREATE (a)-[r:`{edge_type}`]->(b) "
            f"SET r = $props "
            f"RETURN r.id AS id"
        )
        records = self.query(
            cypher, {"from_id": from_id, "to_id": to_id, "props": props}, tx=tx
        )

        if not records:
            raise GraphQueryError(
                f"Failed to create relationship '{edge_type}' from '{from_id}' to '{to_id}'"
            )

        logger.debug("Edge created successfully", edge_type=edge_type, id=edge_id)
        return edge_id

    def get_edge(
        self, edge_id: str, tx: Transaction | None = None
    ) -> dict[str, Any] | None:
        """Fetches relationship properties by edge ID.

        Args:
            edge_id: Edge ID string.
            tx: Optional transaction handle.

        Returns:
            Properties dictionary or None if not found.
        """
        cypher = "MATCH ()-[r {id: $edge_id}]->() RETURN properties(r) AS props"
        records = self.query(cypher, {"edge_id": edge_id}, tx=tx)
        if records and "props" in records[0]:
            props = dict(records[0]["props"])
            props.setdefault("valid_to", None)
            return props
        return None

    def get_edge_at(
        self, edge_id: str, timestamp: datetime, tx: Transaction | None = None
    ) -> dict[str, Any] | None:
        """Returns the edge if it was valid at the given timestamp.

        Args:
            edge_id: Edge ID string.
            timestamp: Point-in-time query.
            tx: Optional transaction handle.

        Returns:
            Properties dict or None.
        """
        ts_str = to_iso(timestamp)
        filter_clause = temporal_filter_clause("r")
        cypher = (
            f"MATCH ()-[r {{id: $edge_id}}]->() WHERE {filter_clause} "
            f"RETURN properties(r) AS props"
        )
        records = self.query(cypher, {"edge_id": edge_id, "timestamp": ts_str}, tx=tx)
        if records and "props" in records[0]:
            props = dict(records[0]["props"])
            props.setdefault("valid_to", None)
            return props
        return None

    def soft_delete_edge(
        self,
        edge_id: str,
        at: datetime | None = None,
        tx: Transaction | None = None,
    ) -> None:
        """Soft-deletes a relationship by setting its ``valid_to`` timestamp.

        Args:
            edge_id: ID of the edge to soft-delete.
            at: Deletion timestamp.  Defaults to now.
            tx: Optional transaction handle.
        """
        ts = to_iso(at if at is not None else _now_utc())
        cypher = (
            "MATCH ()-[r {id: $edge_id}]->() SET r.valid_to = $ts, r.updated_at = $ts"
        )
        self.query(cypher, {"edge_id": edge_id, "ts": ts}, tx=tx)
        logger.debug("Edge soft-deleted", edge_id=edge_id, valid_to=ts)
