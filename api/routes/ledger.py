"""Chain of Custody Ledger API endpoints for querying and integrity verification."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from api.dependencies import get_custody_ledger
from core.custody.chain import ChainVerificationResult, LedgerEntry
from core.custody.ledger import CustodyLedger

router = APIRouter(tags=["Custody Ledger"])


class LedgerQueryResponse(BaseModel):
    """Paginated list of custody ledger entries."""

    entries: list[LedgerEntry]
    total_count: int
    limit: int
    offset: int


@router.get(
    "/ledger",
    response_model=LedgerQueryResponse,
    summary="Query chain of custody ledger records with filtering and pagination",
)
def get_ledger_records(
    evidence_id: str | None = Query(None, description="Filter by evidence ID"),
    action: str | None = Query(
        None, description="Filter by action (INGEST, VERIFY, etc.)"
    ),
    actor: str | None = Query(None, description="Filter by actor identity"),
    limit: int = Query(100, ge=1, le=1000, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    ledger: CustodyLedger = Depends(get_custody_ledger),
) -> LedgerQueryResponse:
    """Returns immutable chain-of-custody ledger records."""
    entries = ledger.get_entries(
        evidence_id=evidence_id,
        action=action,
        actor=actor,
        limit=limit,
        offset=offset,
    )
    stats = ledger.get_ledger_stats()
    return LedgerQueryResponse(
        entries=entries,
        total_count=stats.get("total_entries", len(entries)),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/ledger/verify",
    response_model=ChainVerificationResult,
    summary="Verify mathematical integrity and cryptographic continuity of the hash chain",
)
def verify_ledger(
    ledger: CustodyLedger = Depends(get_custody_ledger),
) -> ChainVerificationResult:
    """Performs full hash chain verification across all ledger entries, checking
    canonical hash computation and sequential link continuity."""
    return ledger.verify_ledger_integrity()
