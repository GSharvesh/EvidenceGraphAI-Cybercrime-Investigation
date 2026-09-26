"""PostgreSQL database client for EvidenceGraphAI."""

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg.rows import dict_row

from core.config.settings import Settings, get_settings
from core.db.exceptions import (
    DatabaseConnectionError,
    DatabaseError,
    DatabaseQueryError,
    LedgerAppendOnlyViolationError,
)
from core.logging.logger import get_logger

logger = get_logger("core.db.postgres")


class PostgresClient:
    """PostgreSQL client providing connection management and parameterized query execution."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @property
    def conninfo(self) -> str:
        """Constructs PostgreSQL connection string."""
        return (
            f"host={self.settings.postgres_host} "
            f"port={self.settings.postgres_port} "
            f"dbname={self.settings.postgres_db} "
            f"user={self.settings.postgres_user} "
            f"password={self.settings.postgres_password}"
        )

    @contextmanager
    def get_connection(
        self,
    ) -> Generator[psycopg.Connection[dict[str, Any]], None, None]:
        """Context manager providing a psycopg connection with dictionary row factory."""
        conn = None
        try:
            conn = psycopg.connect(self.conninfo, row_factory=dict_row)
            yield conn
        except psycopg.OperationalError as exc:
            logger.error("PostgreSQL connection error", error=str(exc))
            raise DatabaseConnectionError(
                f"Failed to connect to PostgreSQL: {exc}"
            ) from exc
        except Exception as exc:
            logger.error("Unexpected database error", error=str(exc))
            raise DatabaseError(f"Database error: {exc}") from exc
        finally:
            if conn and not conn.closed:
                conn.close()

    def health_check(self) -> bool:
        """Returns True if PostgreSQL is reachable and responds to a simple query."""
        try:
            with self.get_connection() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1 AS ok")
                row = cur.fetchone()
                return row is not None and row["ok"] == 1
        except Exception as exc:
            logger.debug("PostgreSQL health check failed", error=str(exc))
            return False

    def execute(
        self,
        query: str,
        params: tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> None:
        """Executes a non-returning query (e.g. INSERT, DDL)."""
        logger.debug("Executing SQL statement", query=query)
        try:
            with self.get_connection() as conn, conn.cursor() as cur:
                cur.execute(query, params)
                conn.commit()
        except psycopg.errors.RaiseException as exc:
            if "Append-only violation" in str(exc):
                raise LedgerAppendOnlyViolationError(str(exc)) from exc
            raise DatabaseQueryError(f"Query execution failed: {exc}") from exc
        except Exception as exc:
            logger.error("SQL execution failed", query=query, error=str(exc))
            raise DatabaseQueryError(f"Query execution failed: {exc}") from exc

    def fetch_one(
        self,
        query: str,
        params: tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Executes a query and returns a single row dict, or None."""
        logger.debug("Fetching one row", query=query)
        try:
            with self.get_connection() as conn, conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchone()
        except psycopg.errors.RaiseException as exc:
            if "Append-only violation" in str(exc):
                raise LedgerAppendOnlyViolationError(str(exc)) from exc
            raise DatabaseQueryError(f"Query execution failed: {exc}") from exc
        except Exception as exc:
            logger.error("SQL fetch_one failed", query=query, error=str(exc))
            raise DatabaseQueryError(f"Query execution failed: {exc}") from exc

    def fetch_all(
        self,
        query: str,
        params: tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Executes a query and returns all matching row dicts."""
        logger.debug("Fetching all rows", query=query)
        try:
            with self.get_connection() as conn, conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall()
        except psycopg.errors.RaiseException as exc:
            if "Append-only violation" in str(exc):
                raise LedgerAppendOnlyViolationError(str(exc)) from exc
            raise DatabaseQueryError(f"Query execution failed: {exc}") from exc
        except Exception as exc:
            logger.error("SQL fetch_all failed", query=query, error=str(exc))
            raise DatabaseQueryError(f"Query execution failed: {exc}") from exc
