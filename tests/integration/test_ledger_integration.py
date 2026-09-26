"""Integration tests for PostgreSQL chain-of-custody ledger."""

import pytest

from core.custody.ledger import CustodyLedger
from core.db.exceptions import DatabaseQueryError, LedgerAppendOnlyViolationError
from core.db.postgres import PostgresClient
from tests.integration.conftest import postgres_required


@postgres_required
def test_ledger_append_and_verify(test_postgres: PostgresClient) -> None:
    """Verifies that appending sequential entries to PostgreSQL preserves hash chain integrity."""
    ledger = CustodyLedger(db_client=test_postgres)

    e1 = ledger.append_entry(
        evidence_id="TestPhase2_EV_1",
        action="INGEST",
        actor="integration-tester",
        sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        metadata={"filename": "test1.pcap"},
    )
    assert e1.id is not None

    e2 = ledger.append_entry(
        evidence_id="TestPhase2_EV_1",
        action="VERIFY",
        actor="integration-verifier",
        sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        metadata={"status": "PASS"},
    )
    assert e2.id is not None
    assert e2.previous_hash == e1.entry_hash

    verification = ledger.verify_ledger_integrity()
    assert verification.is_valid is True


@postgres_required
def test_ledger_update_blocked_by_trigger(test_postgres: PostgresClient) -> None:
    """Verifies that database triggers prevent UPDATE queries on custody_ledger."""
    ledger = CustodyLedger(db_client=test_postgres)
    entry = ledger.append_entry(
        evidence_id="TestPhase2_EV_IMMUTABLE",
        action="INGEST",
        actor="investigator",
        sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    )

    with pytest.raises(
        (LedgerAppendOnlyViolationError, DatabaseQueryError)
    ) as exc_info:
        test_postgres.execute(
            "UPDATE custody_ledger SET actor = 'tamperer' WHERE id = %s",
            (entry.id,),
        )
    assert "Append-only violation" in str(exc_info.value)


@postgres_required
def test_ledger_delete_blocked_by_trigger(test_postgres: PostgresClient) -> None:
    """Verifies that database triggers prevent DELETE queries on custody_ledger."""
    ledger = CustodyLedger(db_client=test_postgres)
    entry = ledger.append_entry(
        evidence_id="TestPhase2_EV_NO_DELETE",
        action="INGEST",
        actor="investigator",
        sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
    )

    with pytest.raises(
        (LedgerAppendOnlyViolationError, DatabaseQueryError)
    ) as exc_info:
        test_postgres.execute(
            "DELETE FROM custody_ledger WHERE id = %s",
            (entry.id,),
        )
    assert "Append-only violation" in str(exc_info.value)
