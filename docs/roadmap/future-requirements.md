# EvidenceGraphAI Future Phase Requirements

This document records architectural specifications for features belonging to future phases (Phase 1 through Phase 8), ensuring zero scope creep in Phase 0 while preserving forward compatibility.

---

## Agent Framework Specifications (Phases 1-8)

Every agent will inherit from a base `AgentInterface` and publish domain graph events.

### Planned Agents
- **Ingestion Agent**: Normalizes PCAP, EVTX, memory dumps into `EvidenceArtifact` nodes.
- **Vulnerability Agent**: Fetches NVD data and attaches CVSS scores to `CVE` nodes.
- **Threat Reconstruction Agent**: Builds `PRECEDES` temporal links between `LogEntry` nodes.
- **Sandbox Replay Agent**: Parses CAPEv2 JSON reports into `Malware` and `APKSample` behavioral graph nodes.
- **Similarity Agent**: Computes 5-vector similarity score across cases.
- **Chain of Custody Agent**: Writes immutable audit log hashes into PostgreSQL ledger.
- **Copilot Agent**: Executes GraphRAG natural language queries against Neo4j.

---

## Legal Compliance Architecture (Phase 6)
- **Section 65B Certificate Generator**: Auto-generates electronic evidence compliance documentation under Section 65B of the Indian Evidence Act.
- **DPDP Act 2023 Compliance**: Data anonymization and PII masking filters.

---

## GraphRAG & UI Architecture (Phase 8)
- Neo4j vector indexing and Cypher retrieval chain.
- React / Cytoscape.js interactive graph visualizer dashboard.
