"""Unit tests for CustodyLedger operations with mocked PostgreSQL database."""

from unittest.mock import MagicMock

import pytest

from core.custody.chain import GENESIS_HASH
from core.custody.exceptions import CustodyLedgerError
from core.custody.ledger import CustodyLedger
from core.db.exceptions import DatabaseError
from core.db.postgres import PostgresClient


@pytest.fixture
def mock_db() -> MagicMock:
    """Returns a mocked PostgresClient."""
    return MagicMock(spec=PostgresClient)


@pytest.fixture
def ledger(mock_db: MagicMock) -> CustodyLedger:
    """Returns a CustodyLedger instance backed by mocked DB."""
    return CustodyLedger(db_client=mock_db)


def test_append_entry_first_record(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies appending first entry uses GENESIS_HASH."""
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_db.get_connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    # No prior entries in table
    mock_cur.fetchone.side_effect = [
        None,  # SELECT latest for update
        {  # RETURNING inserted row
            "id": 1,
            "evidence_id": "EV-100",
            "action": "INGEST",
            "actor": "investigator",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "sha256": "aabbcc",
            "previous_hash": GENESIS_HASH,
            "entry_hash": "112233",
            "metadata": "{}",
            "signature": None,
        },
    ]

    entry = ledger.append_entry(
        evidence_id="EV-100",
        action="INGEST",
        actor="investigator",
        sha256="aabbcc",
    )

    assert entry.id == 1
    assert entry.evidence_id == "EV-100"
    assert entry.action == "INGEST"
    mock_conn.commit.assert_called_once()


def test_append_entry_with_previous_chain(
    ledger: CustodyLedger, mock_db: MagicMock
) -> None:
    """Verifies that subsequent append links to previous entry_hash."""
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_db.get_connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    mock_cur.fetchone.side_effect = [
        {"entry_hash": "prev_hash_123"},
        {
            "id": 2,
            "evidence_id": "EV-101",
            "action": "ANONYMIZE",
            "actor": "agent",
            "timestamp": "2026-01-01T00:01:00+00:00",
            "sha256": "ddeeff",
            "previous_hash": "prev_hash_123",
            "entry_hash": "entry_hash_456",
            "metadata": {"masked": True},
            "signature": "sig",
        },
    ]

    entry = ledger.append_entry(
        evidence_id="EV-101",
        action="ANONYMIZE",
        actor="agent",
        sha256="ddeeff",
        metadata={"masked": True},
        signature="sig",
    )

    assert entry.id == 2
    assert entry.previous_hash == "prev_hash_123"
    assert entry.metadata == {"masked": True}


def test_append_entry_no_returned_row(
    ledger: CustodyLedger, mock_db: MagicMock
) -> None:
    """Verifies error raised when RETURNING clause fails to return a row."""
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_db.get_connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    mock_cur.fetchone.side_effect = [None, None]

    with pytest.raises(CustodyLedgerError, match="Failed to retrieve inserted"):
        ledger.append_entry(
            evidence_id="EV-100",
            action="INGEST",
            actor="test",
            sha256="abc",
        )


def test_append_entry_database_error(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies DatabaseError during append is wrapped in CustodyLedgerError."""
    mock_db.get_connection.side_effect = DatabaseError("Connection failure")

    with pytest.raises(CustodyLedgerError, match="Failed to append to custody ledger"):
        ledger.append_entry(
            evidence_id="EV-100",
            action="INGEST",
            actor="test",
            sha256="abc",
        )


def test_get_entries_with_filters(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies get_entries formats query and parameters with filters."""
    mock_db.fetch_all.return_value = [
        {
            "id": 1,
            "evidence_id": "EV-100",
            "action": "INGEST",
            "actor": "alice",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "sha256": "abc",
            "previous_hash": GENESIS_HASH,
            "entry_hash": "hash1",
            "metadata": "{}",
            "signature": None,
        }
    ]

    entries = ledger.get_entries(
        evidence_id="EV-100", action="INGEST", actor="alice", limit=10, offset=5
    )

    assert len(entries) == 1
    assert entries[0].evidence_id == "EV-100"
    mock_db.fetch_all.assert_called_once()
    sql, params = mock_db.fetch_all.call_args[0]
    assert "evidence_id = %s" in sql
    assert "action = %s" in sql
    assert "actor = %s" in sql
    assert params == ("EV-100", "INGEST", "alice", 10, 5)


def test_get_entries_database_error(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies get_entries wraps DatabaseError."""
    mock_db.fetch_all.side_effect = DatabaseError("Query failed")

    with pytest.raises(CustodyLedgerError, match="Failed to query ledger entries"):
        ledger.get_entries()


def test_get_entry_by_id_found(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies get_entry_by_id returns entry when row exists."""
    mock_db.fetch_one.return_value = {
        "id": 42,
        "evidence_id": "EV-42",
        "action": "VERIFY",
        "actor": "verifier",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "sha256": "abc",
        "previous_hash": "prev",
        "entry_hash": "hash42",
        "metadata": {"result": "PASS"},
        "signature": None,
    }

    entry = ledger.get_entry_by_id(42)
    assert entry is not None
    assert entry.id == 42
    assert entry.action == "VERIFY"


def test_get_entry_by_id_not_found(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies get_entry_by_id returns None when no row matches."""
    mock_db.fetch_one.return_value = None
    assert ledger.get_entry_by_id(999) is None


def test_get_entry_by_id_database_error(
    ledger: CustodyLedger, mock_db: MagicMock
) -> None:
    """Verifies get_entry_by_id wraps DatabaseError."""
    mock_db.fetch_one.side_effect = DatabaseError("DB error")

    with pytest.raises(CustodyLedgerError, match="Failed to fetch ledger entry"):
        ledger.get_entry_by_id(1)


def test_get_entries_for_evidence(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies get_entries_for_evidence calls get_entries with evidence_id."""
    mock_db.fetch_all.return_value = []
    res = ledger.get_entries_for_evidence("EV-999")
    assert res == []
    sql, params = mock_db.fetch_all.call_args[0]
    assert "evidence_id = %s" in sql
    assert params[0] == "EV-999"


def test_verify_ledger_integrity_success(
    ledger: CustodyLedger, mock_db: MagicMock
) -> None:
    """Verifies verify_ledger_integrity runs verify_chain on all rows."""
    mock_db.fetch_all.return_value = []
    result = ledger.verify_ledger_integrity()
    assert result.is_valid is True
    assert result.total_entries == 0


def test_verify_ledger_integrity_database_error(
    ledger: CustodyLedger, mock_db: MagicMock
) -> None:
    """Verifies verify_ledger_integrity wraps DatabaseError."""
    mock_db.fetch_all.side_effect = DatabaseError("Read failed")

    with pytest.raises(CustodyLedgerError, match="Failed to read ledger for integrity"):
        ledger.verify_ledger_integrity()


def test_get_ledger_stats_success(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies stats calculation from aggregated queries."""
    mock_db.fetch_one.side_effect = [
        {"total": 10},
        {"total_evidence": 5},
        {"timestamp": "2026-09-26T10:00:00+00:00"},
    ]
    mock_db.fetch_all.return_value = [
        {"action": "INGEST", "count": 5},
        {"action": "VERIFY", "count": 5},
    ]

    stats = ledger.get_ledger_stats()
    assert stats["total_entries"] == 10
    assert stats["total_evidence_items"] == 5
    assert stats["action_counts"]["INGEST"] == 5
    assert stats["action_counts"]["VERIFY"] == 5
    assert stats["latest_entry_timestamp"] == "2026-09-26T10:00:00+00:00"


def test_get_ledger_stats_database_error(
    ledger: CustodyLedger, mock_db: MagicMock
) -> None:
    """Verifies stats query wraps DatabaseError."""
    mock_db.fetch_one.side_effect = DatabaseError("Stats failed")

    with pytest.raises(
        CustodyLedgerError, match="Failed to calculate ledger statistics"
    ):
        ledger.get_ledger_stats()


def test_get_latest_entry_found(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies get_latest_entry returns most recent ledger entry."""
    mock_db.fetch_one.return_value = {
        "id": 10,
        "evidence_id": "EV-10",
        "action": "INGEST",
        "actor": "system",
        "timestamp": "2026-09-26T10:00:00+00:00",
        "sha256": "hash10",
        "previous_hash": "prev9",
        "entry_hash": "hash10",
        "metadata": "{}",
        "signature": None,
    }
    entry = ledger.get_latest_entry()
    assert entry is not None
    assert entry.id == 10


def test_get_latest_entry_empty(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies get_latest_entry returns None when ledger is empty."""
    mock_db.fetch_one.return_value = None
    assert ledger.get_latest_entry() is None


def test_get_latest_entry_database_error(
    ledger: CustodyLedger, mock_db: MagicMock
) -> None:
    """Verifies get_latest_entry wraps DatabaseError."""
    mock_db.fetch_one.side_effect = DatabaseError("Read failed")
    with pytest.raises(CustodyLedgerError):
        ledger.get_latest_entry()


def test_row_to_entry_invalid_metadata() -> None:
    """Verifies that invalid json metadata string falls back to empty dictionary."""
    row = {
        "id": 1,
        "evidence_id": "EV-1",
        "action": "INGEST",
        "actor": "alice",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "sha256": "abc",
        "previous_hash": "prev",
        "entry_hash": "hash",
        "metadata": "INVALID_JSON{",
        "signature": None,
    }
    entry = CustodyLedger._row_to_entry(row)
    assert entry.metadata == {}
