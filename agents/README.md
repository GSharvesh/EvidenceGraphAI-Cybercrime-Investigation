# EvidenceGraphAI Agents Architecture

This directory contains modular agent components for EvidenceGraphAI. 

## Phase 0 Scope Notice
In Phase 0 (Foundation & Setup), no agent business logic is implemented. All agent subdirectories contain placeholder `__init__.py` files as required by **AC-27**. Agent implementation will occur sequentially in Phase 1 through Phase 8.

## Planned Agents Architecture

| Agent Subdirectory | Description | Target Phase |
|--------------------|-------------|--------------|
| `ingestion/` | Forensic artifact ingestion & normalization | Phase 1 |
| `vulnerability/` | CVE & NVD intelligence enrichment | Phase 1 |
| `threat_reconstruction/` | Attack lifecycle graph builder | Phase 2 |
| `sandbox_replay/` | CAPEv2 & MobSF execution analyzer | Phase 3 |
| `malware_intel/` | Malware family & YARA extractor | Phase 3 |
| `crypto_evidence/` | TLS & certificate evidence analyzer | Phase 4 |
| `log_correlation/` | Multi-source log correlator | Phase 4 |
| `similarity/` | Multi-dimensional graph similarity engine | Phase 5 |
| `chain_of_custody/` | Section 65B & DPDP compliance ledger | Phase 6 |
| `detection_engineering/` | Sigma & YARA rule generator | Phase 7 |
| `threat_intel/` | External OSINT & threat feed aggregator | Phase 7 |
| `copilot/` | GraphRAG investigation assistant | Phase 8 |
