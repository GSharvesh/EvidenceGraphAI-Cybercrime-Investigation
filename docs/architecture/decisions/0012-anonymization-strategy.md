# ADR 0012: DPDP Act 2023 Forensic Anonymization Strategy

## Status
Accepted

## Context
Under the Digital Personal Data Protection (DPDP) Act 2023, personal data of victims and uninvolved third parties captured in network PCAPs and server logs must be protected. We evaluated whether to use Microsoft Presidio (which requires multi-hundred MB spaCy NLP models) or a high-performance, deterministic regex and checksum-validated engine.

## Decision
We implemented a high-precision, zero-network-dependency regex + algorithmic checksum detector ([`PIIDetector`](file:///d:/EvidenceGraphAI/core/privacy/pii_detector.py)) tailored for Indian statutory identifiers (Aadhaar with Verhoeff verification, Income Tax PAN format, Indian phone numbers, emails, credit cards with Luhn check, and private IP ranges) combined with three transformation strategies (`MASK`, `PSEUDONYMIZE`, `REDACT`).

## Alternatives Considered
- **Microsoft Presidio:** Heavyweight (>500MB runtime overhead, external language model downloads that fail in offline/airgapped forensic labs, slow streaming performance on multi-megabyte log files).
- **Generic LLM Scrubbing:** Non-deterministic and introduces data leakage risks.

## Consequences
- **Positive:** Microsecond-latency execution, zero external network dependencies in airgapped environments, 100% deterministic pseudonymization, Verhoeff/Luhn checksum verification.
- **Negative:** Deep semantic entity extraction (e.g. uncommon human names without context) requires future Phase 7 GraphRAG NLP enhancements.
