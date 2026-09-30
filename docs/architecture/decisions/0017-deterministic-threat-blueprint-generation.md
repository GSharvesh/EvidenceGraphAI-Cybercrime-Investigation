# 17. Deterministic Threat Blueprint Generation

Date: 2026-09-28
Status: Accepted

## Context

Automated threat reconstruction requires translating abstract vulnerability data (CVSS vectors, CWE types, affected components) into concrete multi-stage attack lifecycle hypotheses mapped to MITRE ATT&CK techniques.

We evaluated two potential approaches for blueprint generation:
1. **LLM-Only Non-Deterministic Reconstruction:** Prompting an LLM to generate attack graphs directly.
2. **Deterministic Vector-Decoded Rule Engine:** Parsing structured CVSS v3.1 vector strings, CWE classifications, and vulnerability profiles into a formal kill-chain graph with decaying stage probabilities.

## Decision

We chose a **Deterministic Vector-Decoded Rule Engine** with strict ATT&CK ontology alignment:

1. **CVSS Metric Vector Decoding:**
   - `AV:N` (Network) maps to Initial Access (e.g., T1190 - Exploit Public-Facing Application).
   - `AV:L` (Local) / `AV:A` (Adjacent) map to Lateral Movement or Privilege Escalation.
   - `PR:N` (No Privileges Required) + `UI:N` (No User Interaction) yields highest initial stage confidence (0.95).
   - `C:H` / `I:H` / `A:H` determine Impact techniques (T1499, T1565, T1485).

2. **Phase Decay Function:**
   - Multi-stage chains apply exponential phase decay ($P(t) = P_0 \times \alpha^{stage}$ where $\alpha = 0.85$) to reflect decreasing certainty in downstream post-exploitation predictions.

3. **Graph Materialization:**
   - Creates `CVENode`, `ATTACKTechniqueNode`, and `EXPECTED_TO_LEAD_TO` edges with `status="hypothesized"`.

## Consequences

- **Positive:** 100% reproducible and verifiable blueprints across test suites and forensic audits.
- **Positive:** Zero latency and zero API cost for blueprint generation.
- **Positive:** Integrates seamlessly into the temporal graph model (`status` evolves from `hypothesized` to `confirmed`/`refuted`).
