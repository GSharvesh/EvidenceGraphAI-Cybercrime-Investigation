"""Neo4j graph client library with connection pooling, transactions, temporal fields, and provenance."""

import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, cast

from neo4j import Driver, GraphDatabase, Transaction
from neo4j.exceptions import ClientError, ConstraintError, DriverError, Neo4jError

from core.config.settings import Settings, get_settings
from core.graph.exceptions import (
    GraphConnectionError,
    GraphConstraintError,
    GraphQueryError,
)
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
    """Neo4j Graph Client providing CRUD, Cypher execution, temporal/provenance tagging, and transactions."""

    def __init__(
        self,
        settings: Settings | None = None,
        driver: Driver | None = None,
        validator: OntologyValidator | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._driver: Driver | None = driver
        self.validator = validator or OntologyValidator()

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
            logger.error("Neo4j constraint error", cypher=cypher, error=str(e))
            raise GraphConstraintError(f"Constraint error: {e}") from e
        except (ClientError, Neo4jError, DriverError) as e:
            GRAPH_QUERY_ERRORS.inc()
            logger.error("Neo4j query error", cypher=cypher, error=str(e))
            raise GraphQueryError(f"Query execution error: {e}") from e
        except Exception as e:
            GRAPH_QUERY_ERRORS.inc()
            logger.error(
                "Unexpected error during graph query", cypher=cypher, error=str(e)
            )
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
        """
        self.validator.validate_node(node_type, properties)

        if "id" not in properties:
            properties["id"] = str(uuid.uuid4())

        props = self._apply_metadata(properties)
        node_id = str(props["id"])

        cypher = f"CREATE (n:`{node_type}`) SET n = $props RETURN n.id AS id"
        records = self.query(cypher, {"props": props}, tx=tx)

        if not records:
            raise GraphQueryError(f"Failed to create node of type '{node_type}'")

        logger.debug("Node created successfully", node_type=node_type, id=node_id)
        return node_id

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
        """
        props = dict(properties or {})
        self.validator.validate_edge(edge_type, props)

        if "id" not in props or not props["id"]:
            props["id"] = str(uuid.uuid4())

        props = self._apply_metadata(props)
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
            return cast(dict[str, Any], records[0]["props"])
        return None

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
            return cast(dict[str, Any], records[0]["props"])
        return None
