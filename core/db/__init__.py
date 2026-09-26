"""Database access layer and PostgreSQL client for EvidenceGraphAI."""

from core.db.exceptions import (
    DatabaseConnectionError,
    DatabaseError,
    DatabaseQueryError,
    LedgerAppendOnlyViolationError,
)
from core.db.postgres import PostgresClient

__all__ = [
    "PostgresClient",
    "DatabaseError",
    "DatabaseConnectionError",
    "DatabaseQueryError",
    "LedgerAppendOnlyViolationError",
]
