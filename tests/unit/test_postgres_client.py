"""Unit tests for PostgresClient with mocked psycopg connection."""

from unittest.mock import MagicMock, patch

import psycopg
import pytest

from core.db.exceptions import (
    DatabaseConnectionError,
    DatabaseError,
    DatabaseQueryError,
    LedgerAppendOnlyViolationError,
)
from core.db.postgres import PostgresClient


def test_conninfo_generation() -> None:
    """Verifies that conninfo property formats parameters correctly."""
    client = PostgresClient()
    conninfo = client.conninfo
    assert "host=" in conninfo
    assert "port=" in conninfo
    assert "dbname=" in conninfo
    assert "user=" in conninfo
    assert "password=" in conninfo


def test_get_connection_success() -> None:
    """Verifies successful connection creation and cleanup."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_conn.closed = False

    with patch("psycopg.connect", return_value=mock_conn) as mock_connect:
        with client.get_connection() as conn:
            assert conn == mock_conn

        mock_connect.assert_called_once()
        mock_conn.close.assert_called_once()


def test_get_connection_operational_error() -> None:
    """Verifies that psycopg.OperationalError is translated to DatabaseConnectionError."""
    client = PostgresClient()

    with (
        patch(
            "psycopg.connect",
            side_effect=psycopg.OperationalError("Connection refused"),
        ),
        pytest.raises(DatabaseConnectionError, match="Failed to connect to PostgreSQL"),
        client.get_connection(),
    ):
        pass


def test_get_connection_unexpected_error() -> None:
    """Verifies that generic exceptions are translated to DatabaseError."""
    client = PostgresClient()

    with (
        patch("psycopg.connect", side_effect=RuntimeError("Unexpected OS crash")),
        pytest.raises(DatabaseError, match="Database connection error"),
        client.get_connection(),
    ):
        pass


def test_health_check_healthy() -> None:
    """Verifies health check returns True when SELECT 1 succeeds."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_cur.fetchone.return_value = {"ok": 1}

    with patch("psycopg.connect", return_value=mock_conn):
        assert client.health_check() is True


def test_health_check_unhealthy() -> None:
    """Verifies health check returns False on database failure."""
    client = PostgresClient()

    with patch(
        "psycopg.connect", side_effect=psycopg.OperationalError("Connection refused")
    ):
        assert client.health_check() is False


def test_execute_query_success() -> None:
    """Verifies execute() runs query and commits."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    with patch("psycopg.connect", return_value=mock_conn):
        client.execute("INSERT INTO test VALUES (%s)", ("val",))
        mock_cur.execute.assert_called_once_with(
            "INSERT INTO test VALUES (%s)", ("val",)
        )
        mock_conn.commit.assert_called_once()


def test_execute_append_only_violation() -> None:
    """Verifies that append-only violation trigger exception is translated to LedgerAppendOnlyViolationError."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_cur.execute.side_effect = psycopg.errors.RaiseException(
        "Append-only violation: UPDATE blocked"
    )

    with (
        patch("psycopg.connect", return_value=mock_conn),
        pytest.raises(LedgerAppendOnlyViolationError),
    ):
        client.execute("UPDATE custody_ledger SET actor = 'bad'")


def test_execute_general_database_error() -> None:
    """Verifies that general SQL errors are translated to DatabaseQueryError."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_cur.execute.side_effect = Exception("Syntax error in SQL")

    with (
        patch("psycopg.connect", return_value=mock_conn),
        pytest.raises(DatabaseQueryError, match="Query execution failed"),
    ):
        client.execute("INVALID SQL")


def test_fetch_one_success() -> None:
    """Verifies fetch_one returns row dictionary."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_cur.fetchone.return_value = {"id": 1, "name": "test"}

    with patch("psycopg.connect", return_value=mock_conn):
        row = client.fetch_one("SELECT * FROM test WHERE id = %s", (1,))
        assert row == {"id": 1, "name": "test"}


def test_fetch_one_append_only_violation() -> None:
    """Verifies fetch_one handles append-only exception if raised."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_cur.execute.side_effect = psycopg.errors.RaiseException(
        "Append-only violation"
    )

    with (
        patch("psycopg.connect", return_value=mock_conn),
        pytest.raises(LedgerAppendOnlyViolationError),
    ):
        client.fetch_one("SELECT * FROM test")


def test_fetch_one_general_error() -> None:
    """Verifies fetch_one wraps generic errors in DatabaseQueryError."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_cur.execute.side_effect = Exception("Table not found")

    with (
        patch("psycopg.connect", return_value=mock_conn),
        pytest.raises(DatabaseQueryError, match="Query execution failed"),
    ):
        client.fetch_one("SELECT * FROM missing")


def test_fetch_all_success() -> None:
    """Verifies fetch_all returns list of row dicts."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_cur.fetchall.return_value = [{"id": 1}, {"id": 2}]

    with patch("psycopg.connect", return_value=mock_conn):
        rows = client.fetch_all("SELECT * FROM test")
        assert len(rows) == 2
        assert rows[0] == {"id": 1}


def test_fetch_all_append_only_violation() -> None:
    """Verifies fetch_all handles append-only violation."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_cur.execute.side_effect = psycopg.errors.RaiseException(
        "Append-only violation"
    )

    with (
        patch("psycopg.connect", return_value=mock_conn),
        pytest.raises(LedgerAppendOnlyViolationError),
    ):
        client.fetch_all("SELECT * FROM test")


def test_fetch_all_general_error() -> None:
    """Verifies fetch_all wraps generic errors in DatabaseQueryError."""
    client = PostgresClient()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_cur.execute.side_effect = Exception("Read error")

    with (
        patch("psycopg.connect", return_value=mock_conn),
        pytest.raises(DatabaseQueryError, match="Query execution failed"),
    ):
        client.fetch_all("SELECT * FROM test")
