# 19. Rule-Based MITRE ATT&CK Mapping Engine

Date: 2026-09-28
Status: Accepted

## Context

Forensic artifacts (raw log messages, command-line traces, script contents, network payloads) must be categorized into standard MITRE ATT&CK enterprise tactics and techniques (e.g., T1059.004 Unix Shell, T1046 Network Service Discovery, T1190 Exploit Public-Facing Application).

We considered:
1. **Large Language Model / Embedding Similarity Matching**
2. **Deterministic Compiled Regex & Keyword Pattern Engine**

## Decision

We chose a **Deterministic Compiled Regex & Keyword Pattern Engine** (`core/agents/attack_mapper`):

1. **Pre-Compiled Pattern Registry:**
   - Over 50 high-precision regex signatures mapped to ATT&CK Technique IDs (e.g. JNDI lookup payloads `\$\{jndi:(?:ldap|rmi|dns)` -> T1190, `base64 -d` -> T1027, `powershell -enc` -> T1059.001).

2. **Confidence Scoring:**
   - Explicit signatures assign high confidence (0.85–0.99) based on specificity.
   - Secondary keyword/heuristic matches assign proportional base confidence.

3. **Graph Materialization:**
   - Creates `MAPS_TO` edges from source artifact nodes (`LogEntry`, `CVE`, `Malware`) to `ATT&CKTechnique` nodes with `mapping_confidence` properties and provenance tracking.

## Consequences

- **Positive:** Microsecond-latency execution across millions of log lines.
- **Positive:** Explainable, transparent rule definitions with zero hallucination.
- **Positive:** Easily extensible by adding signatures to `core/agents/attack_mapper/rules.py`.
