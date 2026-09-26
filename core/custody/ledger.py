"""Append-only forensic custody ledger manager for EvidenceGraphAI."""

import json
from datetime import UTC, datetime
from typing import Any

from core.custody.chain import (
    GENESIS_HASH,
    ChainVerificationResult,
    LedgerEntry,
    compute_entry_hash,
    verify_chain,
)
from core.custody.exceptions import CustodyLedgerError
from core.db.exceptions import DatabaseError
from core.db.postgres import PostgresClient
from core.logging.logger import get_logger

logger = get_logger("core.custody.ledger")


class CustodyLedger:
    """Manages recording and verification of immutable chain-of-custody actions in PostgreSQL."""

    def __init__(self, db_client: PostgresClient | None = None) -> None:
        self.db = db_client or PostgresClient()

    def get_latest_entry(self) -> LedgerEntry | None:
        """Fetches the latest entry recorded in the global ledger to obtain the chain head."""
        sql = "SELECT * FROM custody_ledger ORDER BY id DESC LIMIT 1"
        try:
            row = self.db.fetch_one(sql)
            if not row:
                return None
            return self._row_to_entry(row)
        except DatabaseError as exc:
            raise CustodyLedgerError(
                f"Failed to fetch latest ledger entry: {exc}"
            ) from exc

    def append_entry(
        self,
        evidence_id: str,
        action: str,
        actor: str,
        sha256: str,
        metadata: dict[str, Any] | None = None,
        signature: str | None = None,
        timestamp: datetime | str | None = None,
    ) -> LedgerEntry:
        """Appends a new immutable action record to the custody ledger with cryptographic hash chaining.

        Args:
            evidence_id: Target evidence ID string.
            action: Ledger action (INGEST, DERIVE, ACCESS, EXPORT, VERIFY, ANONYMIZE, ERROR).
            actor: Identity of actor performing the action.
            sha256: SHA256 digest of the artifact.
            metadata: Optional arbitrary context metadata.
            signature: Optional digital signature.
            timestamp: Optional custom timestamp (defaults to current UTC time).

        Returns:
            Newly created LedgerEntry.

        Raises:
            CustodyLedgerError: On database or integrity calculation error.
        """
        if timestamp is None:
            ts_str = datetime.now(UTC).isoformat()
        elif isinstance(timestamp, datetime):
            ts_str = timestamp.isoformat()
        else:
            ts_str = str(timestamp)

        meta = metadata or {}

        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    # Lock table briefly in share row exclusive mode or fetch latest entry inside transaction
                    cur.execute(
                        "SELECT id, entry_hash FROM custody_ledger ORDER BY id DESC LIMIT 1 FOR UPDATE"
                    )
                    latest_row = cur.fetchone()
                    previous_hash = (
                        latest_row["entry_hash"] if latest_row else GENESIS_HASH
                    )

                    entry_hash = compute_entry_hash(
                        evidence_id=evidence_id,
                        action=action,
                        actor=actor,
                        timestamp=ts_str,
                        sha256=sha256,
                        previous_hash=previous_hash,
                        metadata=meta,
                    )

                    insert_sql = """
                    INSERT INTO custody_ledger (
                        evidence_id, action, actor, timestamp, sha256,
                        previous_hash, entry_hash, metadata, signature
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    ) RETURNING id, evidence_id, action, actor, timestamp, sha256, previous_hash, entry_hash, metadata, signature
                    """
                    cur.execute(
                        insert_sql,
                        (
                            evidence_id,
                            action,
                            actor,
                            ts_str,
                            sha256,
                            previous_hash,
                            entry_hash,
                            json.dumps(meta),
                            signature,
                        ),
                    )
                    inserted_row = cur.fetchone()
                conn.commit()

            if not inserted_row:
                raise CustodyLedgerError("Failed to retrieve inserted ledger record")

            logger.info(
                "Appended ledger entry",
                id=inserted_row["id"],
                evidence_id=evidence_id,
                action=action,
                actor=actor,
                entry_hash=entry_hash[:16] + "...",
            )
            return self._row_to_entry(inserted_row)

        except DatabaseError as exc:
            logger.error("Failed to append ledger entry", error=str(exc))
            raise CustodyLedgerError(
                f"Failed to append to custody ledger: {exc}"
            ) from exc
        except Exception as exc:
            logger.error("Unexpected error appending to custody ledger", error=str(exc))
            raise CustodyLedgerError(f"Custody ledger append error: {exc}") from exc

    def get_entries(
        self,
        evidence_id: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[LedgerEntry]:
        """Queries ledger entries with optional filtering and pagination."""
        clauses = []
        params: list[Any] = []

        if evidence_id:
            clauses.append("evidence_id = %s")
            params.append(evidence_id)
        if action:
            clauses.append("action = %s")
            params.append(action)
        if actor:
            clauses.append("actor = %s")
            params.append(actor)

        where_str = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
        SELECT * FROM custody_ledger
        {where_str}
        ORDER BY id ASC
        LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])

        try:
            rows = self.db.fetch_all(sql, tuple(params))
            return [self._row_to_entry(r) for r in rows]
        except DatabaseError as exc:
            raise CustodyLedgerError(f"Failed to query ledger entries: {exc}") from exc

    def get_entry_by_id(self, entry_id: int) -> LedgerEntry | None:
        """Fetches a specific ledger entry by its primary key ID."""
        sql = "SELECT * FROM custody_ledger WHERE id = %s"
        try:
            row = self.db.fetch_one(sql, (entry_id,))
            return self._row_to_entry(row) if row else None
        except DatabaseError as exc:
            raise CustodyLedgerError(
                f"Failed to fetch ledger entry {entry_id}: {exc}"
            ) from exc

    def get_entries_for_evidence(self, evidence_id: str) -> list[LedgerEntry]:
        """Returns the complete chain of custody entries for a specific evidence ID."""
        return self.get_entries(evidence_id=evidence_id, limit=10000, offset=0)

    def verify_ledger_integrity(self) -> ChainVerificationResult:
        """Retrieves the complete global ledger and validates hash chain continuity and integrity."""
        sql = "SELECT * FROM custody_ledger ORDER BY id ASC"
        try:
            rows = self.db.fetch_all(sql)
            return verify_chain(rows)
        except DatabaseError as exc:
            raise CustodyLedgerError(
                f"Failed to read ledger for integrity verification: {exc}"
            ) from exc

    def get_ledger_stats(self) -> dict[str, Any]:
        """Calculates summary statistics across the custody ledger."""
        try:
            total_count_row = self.db.fetch_one(
                "SELECT COUNT(*) AS total FROM custody_ledger"
            )
            total_entries = int(total_count_row["total"]) if total_count_row else 0

            unique_evidence_row = self.db.fetch_one(
                "SELECT COUNT(DISTINCT evidence_id) AS total_evidence FROM custody_ledger"
            )
            total_evidence = (
                int(unique_evidence_row["total_evidence"]) if unique_evidence_row else 0
            )

            action_rows = self.db.fetch_all(
                "SELECT action, COUNT(*) AS count FROM custody_ledger GROUP BY action"
            )
            action_counts = {r["action"]: int(r["count"]) for r in action_rows}

            latest_row = self.db.fetch_one(
                "SELECT timestamp FROM custody_ledger ORDER BY id DESC LIMIT 1"
            )
            latest_ts = str(latest_row["timestamp"]) if latest_row else None

            return {
                "total_entries": total_entries,
                "total_evidence_items": total_evidence,
                "action_counts": action_counts,
                "latest_entry_timestamp": latest_ts,
            }
        except DatabaseError as exc:
            raise CustodyLedgerError(
                f"Failed to calculate ledger statistics: {exc}"
            ) from exc

    @staticmethod
    def _row_to_entry(row: dict[str, Any]) -> LedgerEntry:
        """Converts a database row dictionary to a LedgerEntry model."""
        meta = row.get("metadata")
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        elif not isinstance(meta, dict):
            meta = {}

        ts = row["timestamp"]
        ts_str = ts.isoformat() if isinstance(ts, datetime) else str(ts)

        return LedgerEntry(
            id=row.get("id"),
            evidence_id=row["evidence_id"],
            action=row["action"],
            actor=row["actor"],
            timestamp=ts_str,
            sha256=row["sha256"],
            previous_hash=row["previous_hash"],
            entry_hash=row["entry_hash"],
            metadata=meta,
            signature=row.get("signature"),
        )
