"""Custom domain exceptions for EvidenceGraphAI graph database interactions."""


class GraphError(Exception):
    """Base exception for all graph database errors."""

    pass


class GraphConnectionError(GraphError):
    """Raised when connecting to Neo4j fails."""

    pass


class GraphQueryError(GraphError):
    """Raised when a Cypher query execution fails."""

    pass


class GraphConstraintError(GraphError):
    """Raised when a database constraint or index rule is violated."""

    pass


class GraphValidationError(GraphError):
    """Raised when node or edge properties fail schema validation."""

    pass


class TemporalValidationError(GraphError):
    """Raised when temporal field values are invalid (e.g., valid_to before valid_from)."""

    pass


class TemporalQueryError(GraphError):
    """Raised when a point-in-time or temporal range query fails."""

    pass


class ProvenanceValidationError(GraphError):
    """Raised when provenance fields are missing, invalid, or fail allowlist check."""

    pass
