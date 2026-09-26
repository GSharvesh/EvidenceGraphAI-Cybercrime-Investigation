-- EvidenceGraphAI Migration 001: Forensic Chain of Custody Ledger
-- Creates append-only custody_ledger table, indexes, and immutability triggers.

CREATE TABLE IF NOT EXISTS custody_ledger (
    id BIGSERIAL PRIMARY KEY,
    evidence_id VARCHAR(128) NOT NULL,
    action VARCHAR(32) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sha256 VARCHAR(64) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    entry_hash VARCHAR(64) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    signature TEXT
);

CREATE INDEX IF NOT EXISTS idx_custody_ledger_evidence_id ON custody_ledger(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_ledger_timestamp ON custody_ledger(timestamp);
CREATE INDEX IF NOT EXISTS idx_custody_ledger_action ON custody_ledger(action);
CREATE INDEX IF NOT EXISTS idx_custody_ledger_entry_hash ON custody_ledger(entry_hash);

-- Enforce append-only semantics via database-level trigger
CREATE OR REPLACE FUNCTION prevent_custody_ledger_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Append-only violation: UPDATE and DELETE operations are strictly prohibited on table custody_ledger.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_custody_ledger_mutation ON custody_ledger;

CREATE TRIGGER trg_prevent_custody_ledger_mutation
BEFORE UPDATE OR DELETE ON custody_ledger
FOR EACH ROW
EXECUTE FUNCTION prevent_custody_ledger_mutation();
