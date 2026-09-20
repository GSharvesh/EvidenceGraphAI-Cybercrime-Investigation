# ADR 0001: Use Neo4j as Central Knowledge Graph Engine

## Status
Accepted

## Context
EvidenceGraphAI requires a scalable graph database to represent complex cybercrime topologies, temporally ordered attack lifecycles, and multi-hop relationships across heterogeneous forensic entities (IPs, Domains, Hashes, Log Entries, Certificates).

## Decision
We select **Neo4j 5.x** as the primary knowledge graph database.

## Consequences
- Native Cypher query support for graph pattern matching and path traversal.
- ACID transaction guarantees for multi-node attack path construction.
- Strict uniqueness constraints and indexing per node type.
