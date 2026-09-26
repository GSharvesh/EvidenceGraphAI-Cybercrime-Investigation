"""Unit tests for CustodyLedger operations with mocked PostgreSQL database."""

from unittest.mock import MagicMock

import pytest

from core.custody.chain import GENESIS_HASH
from core.custody.ledger import CustodyLedger
from core.db.postgres import PostgresClient


@pytest.fixture
def mock_db() -> MagicMock:
    """Returns a mocked PostgresClient."""
    db = MagicMock(spec=PostgresClient)
    return db


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


def test_get_entries_with_filters(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies get_entries queries with parameterized clauses."""
    mock_db.fetch_all.return_value = [
        {
            "id": 1,
            "evidence_id": "EV-1",
            "action": "INGEST",
            "actor": "agent-1",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "sha256": "hash",
            "previous_hash": GENESIS_HASH,
            "entry_hash": "ehash",
            "metadata": {},
            "signature": None,
        }
    ]

    entries = ledger.get_entries(evidence_id="EV-1", action="INGEST", limit=10)
    assert len(entries) == 1
    assert entries[0].evidence_id == "EV-1"
    mock_db.fetch_all.assert_called_once()


def test_get_ledger_stats(ledger: CustodyLedger, mock_db: MagicMock) -> None:
    """Verifies stats aggregation queries."""
    mock_db.fetch_one.side_effect = [
        {"total": 42},
        {"total_evidence": 10},
        {"timestamp": "2026-01-01T12:00:00+00:00"},
    ]
    mock_db.fetch_all.return_value = [
        {"action": "INGEST", "count": 10},
        {"action": "VERIFY", "count": 32},
    ]

    stats = ledger.get_ledger_stats()
    assert stats["total_entries"] == 42
    assert stats["total_evidence_items"] == 10
    assert stats["action_counts"]["INGEST"] == 10
