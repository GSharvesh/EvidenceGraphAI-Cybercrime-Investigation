# Digital Personal Data Protection (DPDP) Act 2023 Compliance

## 1. Statutory Context

The **Digital Personal Data Protection Act, 2023 (DPDP Act)** regulates the processing of digital personal data in India. In forensic investigations, personal data of victims, bystanders, and uninvolved citizens may reside within captured network packets or server logs. EvidenceGraphAI implements privacy-by-design filters to detect and scrub or pseudonymize personal data before persistent storage or cross-agency sharing.

---

## 2. Core Privacy Principles Implemented

1. **Purpose Limitation & Data Minimization:** Only evidence necessary for threat attribution and crime investigation is retained in raw form; unrelated personal identifiers are masked.
2. **Deterministic Pseudonymization:** Allows threat correlation across multiple forensic incidents without exposing raw PII.
3. **Auditability & Traceability:** Every anonymization event is immutably recorded in the custody ledger (`ANONYMIZE` action) documenting exact category counts and methods without leaking cleartext PII.
4. **Preservation of Investigative Value:** Threat actor indicators (e.g. malicious C2 domain names, public attacker IPs, exploit payloads) are preserved while personal victim data is masked.
