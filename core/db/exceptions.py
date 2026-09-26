"""Database domain exceptions for EvidenceGraphAI."""


class DatabaseError(Exception):
    """Base exception for all database errors."""

    pass


class DatabaseConnectionError(DatabaseError):
    """Raised when connecting to PostgreSQL fails."""

    pass


class DatabaseQueryError(DatabaseError):
    """Raised when executing a query fails."""

    pass


class LedgerAppendOnlyViolationError(DatabaseError):
    """Raised when an attempt is made to modify or delete a ledger record."""

    pass
