# Threat Reconstruction Agent

## Overview

The `ThreatReconstructionAgent` synthesizes multi-stage attack lifecycle hypotheses (threat blueprints) from analyzed vulnerability properties.

## Architecture

1. **Kill Chain Profiling:** Analyzes attack vector (`AV:N`, `AV:L`), privileges required (`PR:N`, `PR:L`), and impact metrics to synthesize an ordered sequence of ATT&CK techniques spanning:
   - Initial Access (e.g. T1190)
   - Execution (e.g. T1059.004)
   - Privilege Escalation / Discovery (e.g. T1068, T1046, T1082)
   - Impact / Exfiltration (e.g. T1499, T1041)

2. **Phase Decay Probabilities:** Computes transitional edge probabilities using exponential decay:
   $$P(stage) = P_0 \times (0.85)^{stage}$$

3. **Graph Materialization:** Persists techniques and connects consecutive stages using `EXPECTED_TO_LEAD_TO` relationships with `status="hypothesized"`.

## Usage Example

```python
from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent

agent = ThreatReconstructionAgent()
blueprint = agent.blueprint(cve_id="CVE-2021-44228", actor="threat_reconstruction")

print(f"Blueprint ID: {blueprint.blueprint_id}")
print(f"Techniques: {[t.technique_id for t in blueprint.techniques]}")
```

## API Endpoints

- `POST /vulnerability/blueprint` — Generate threat blueprint for an analyzed CVE.
- `GET /vulnerability/blueprint/{blueprint_id}` — Retrieve blueprint metadata.
