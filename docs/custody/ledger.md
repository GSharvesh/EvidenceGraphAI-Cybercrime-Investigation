# Forensic Chain of Custody Ledger

## 1. Overview

The **Chain of Custody Ledger** is an append-only relational ledger maintained in PostgreSQL (`custody_ledger` table). Every action performed on forensic evidence (such as ingestion, derivation, verification, anonymization, and manifest export) is permanently recorded with cryptographic linking.

---

## 2. Table Schema

```sql
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
```

---

## 3. Supported Action Types

| Action | Description | Triggers |
| :--- | :--- | :--- |
| `INGEST` | Initial ingestion of raw or pre-filtered artifact | Ingestion pipeline completion |
| `ANONYMIZE` | DPDP Act 2023 PII scrubbing / masking operation | Pre-ingestion or on-demand filter |
| `VERIFY` | Cryptographic SHA256 integrity recomputation | Verification service invocation |
| `EXPORT` | Evidence Manifest generation / export | Manifest generator execution |
| `DERIVE` | Sub-artifact extraction (e.g. payload from PCAP) | Forensic extraction routines |
| `ACCESS` | Evidence viewing or investigative query | Audit logging |
| `ERROR` | Compensatory logging of partial pipeline failures | Ingestion rollback / anomaly handling |

---

## 4. Append-Only Invariant Enforcement

Immutability is enforced at the database layer via a PostgreSQL trigger:

```sql
CREATE OR REPLACE FUNCTION prevent_custody_ledger_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Append-only violation: UPDATE and DELETE operations are strictly prohibited on table custody_ledger.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_custody_ledger_mutation
BEFORE UPDATE OR DELETE ON custody_ledger
FOR EACH ROW
EXECUTE FUNCTION prevent_custody_ledger_mutation();
```

Any attempt to update or delete rows results in an immediate `LedgerAppendOnlyViolationError`.
