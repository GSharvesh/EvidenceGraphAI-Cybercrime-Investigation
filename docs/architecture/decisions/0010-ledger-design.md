# ADR 0010: Relational Append-Only Chain of Custody Ledger Design

## Status
Accepted

## Context
Forensic investigation requires strict legal admissibility under the Indian Evidence Act Section 65B and global judicial standards. Every action performed on evidence (ingestion, derivation, verification, anonymization, and export) must be permanently logged in a tamper-evident manner. We needed to choose the underlying storage engine and concurrency architecture for the chain-of-custody ledger.

## Decision
We chose **PostgreSQL** (`custody_ledger` table) accessed via `psycopg` 3 with database-level trigger enforcement (`trg_prevent_custody_ledger_mutation`) that rejects all `UPDATE` and `DELETE` SQL commands.

## Alternatives Considered
1. **Append to Neo4j Graph:** Storing custody as graph nodes/edges adds graph overhead and lacks relational row-level transactional locks (`SELECT FOR UPDATE`).
2. **Blockchain / Hyperledger:** Excessive operational complexity and latency for Phase 2; cryptographic hash chaining inside PostgreSQL provides equivalent mathematical tamper evidence with sub-millisecond query performance.
3. **Flat Append-Only File:** Difficult to query with pagination and filters concurrently.

## Consequences
- **Positive:** Sub-millisecond ACID transactions, strict trigger-enforced immutability, simple relational querying, zero extra external infrastructure beyond PostgreSQL.
- **Negative:** Requires PostgreSQL connection pool management during high-concurrency ingestion.
