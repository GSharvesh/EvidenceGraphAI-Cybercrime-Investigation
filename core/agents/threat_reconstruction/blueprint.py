"""Blueprint generation engine for the Threat Reconstruction Agent.

Produces a deterministic, rule-based attack blueprint from a CVE analysis.
The blueprint maps a vulnerability profile to an ordered sequence of ATT&CK
techniques (initial access → execution → persistence → …) using heuristics.

Design (ADR 0020 — rules-first approach):
- No ML model.  Pure deterministic rule engine.
- Rules are defined as ordered tuples: (phase_index, technique_data, condition_fn).
- The blueprint confidence decreases as the kill chain progresses (later stages
  are more uncertain than the initial exploitation step).
"""

from __future__ import annotations

import uuid
from typing import Any

from core.agents.threat_reconstruction.models import (
    Blueprint,
    BlueprintEdge,
    BlueprintTechnique,
)

# ---------------------------------------------------------------------------
# Kill chain phase ordering (ATT&CK Enterprise)
# ---------------------------------------------------------------------------
_PHASES = [
    "initial-access",  # 0
    "execution",  # 1
    "persistence",  # 2
    "privilege-escalation",  # 3
    "defense-evasion",  # 4
    "credential-access",  # 5
    "discovery",  # 6
    "lateral-movement",  # 7
    "collection",  # 8
    "command-and-control",  # 9
    "exfiltration",  # 10
    "impact",  # 11
]

# ---------------------------------------------------------------------------
# Blueprint rules
# Each entry: dict with technique info + condition function.
# condition(profile) → bool
# profile keys: attack_vector, cvss_score, cwe_id, remote_exploitable,
#               requires_auth, requires_user_interaction, attack_vector
# ---------------------------------------------------------------------------

_BLUEPRINT_RULES: list[dict[str, Any]] = [
    # ── Initial Access ─────────────────────────────────────────────────────
    {
        "phase": 0,
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "condition": lambda p: p.get("attack_vector") == "NETWORK"
        and not p.get("requires_auth"),
        "base_confidence": 0.95,
        "rationale": "Unauthenticated network-reachable vulnerability → direct public-facing exploitation.",
    },
    {
        "phase": 0,
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "initial-access",
        "condition": lambda p: p.get("requires_user_interaction") is True,
        "base_confidence": 0.75,
        "rationale": "User interaction required — phishing is the delivery vector.",
    },
    {
        "phase": 0,
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "initial-access",
        "condition": lambda p: p.get("requires_auth") is True
        and p.get("attack_vector") == "NETWORK",
        "base_confidence": 0.65,
        "rationale": "Network exploitation requiring credentials → valid account likely compromised first.",
    },
    {
        "phase": 0,
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "execution",
        "condition": lambda p: p.get("requires_user_interaction") is True
        and p.get("attack_vector") == "LOCAL",
        "base_confidence": 0.80,
        "rationale": "Local user-interaction exploitation → client-side code execution.",
    },
    # ── Execution ─────────────────────────────────────────────────────────
    {
        "phase": 1,
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "condition": lambda p: (p.get("cvss_score") or 0) >= 7.0
        and p.get("attack_vector") == "NETWORK",
        "base_confidence": 0.85,
        "rationale": "High-severity RCE on network service → shell/script interpreter access.",
    },
    {
        "phase": 1,
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "privilege-escalation",
        "condition": lambda p: p.get("attack_vector") == "LOCAL"
        and (p.get("cvss_score") or 0) >= 6.0,
        "base_confidence": 0.75,
        "rationale": "Local privilege escalation vulnerability.",
    },
    # ── Persistence ────────────────────────────────────────────────────────
    {
        "phase": 2,
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "persistence",
        "condition": lambda p: (p.get("cvss_score") or 0) >= 7.5
        and p.get("attack_vector") == "NETWORK",
        "base_confidence": 0.60,
        "rationale": "After RCE, attacker likely establishes persistence via scheduled jobs.",
    },
    {
        "phase": 2,
        "technique_id": "T1547",
        "technique_name": "Boot/Logon Autostart Execution",
        "tactic": "persistence",
        "condition": lambda p: p.get("attack_vector") == "LOCAL"
        and (p.get("cvss_score") or 0) >= 6.0,
        "base_confidence": 0.55,
        "rationale": "Local exploitation → autostart persistence to survive reboots.",
    },
    # ── Defense Evasion ────────────────────────────────────────────────────
    {
        "phase": 4,
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "defense-evasion",
        "condition": lambda p: (p.get("cvss_score") or 0) >= 7.0,
        "base_confidence": 0.45,
        "rationale": "Sophisticated exploits include payload obfuscation for evasion.",
    },
    # ── Discovery ─────────────────────────────────────────────────────────
    {
        "phase": 6,
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "condition": lambda p: p.get("attack_vector") == "NETWORK",
        "base_confidence": 0.50,
        "rationale": "After network-based exploitation, attacker enumerates system info.",
    },
    # ── Command and Control ────────────────────────────────────────────────
    {
        "phase": 9,
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "condition": lambda p: p.get("attack_vector") == "NETWORK"
        and (p.get("cvss_score") or 0) >= 7.0,
        "base_confidence": 0.65,
        "rationale": "Network RCE enables establishing C2 channel over application-layer protocol.",
    },
    # ── Exfiltration ────────────────────────────────────────────────────────
    {
        "phase": 10,
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "exfiltration",
        "condition": lambda p: p.get("attack_vector") == "NETWORK"
        and (p.get("cvss_score") or 0) >= 8.0,
        "base_confidence": 0.50,
        "rationale": "Critical network vulnerability enables data exfiltration over the C2 channel.",
    },
    # ── Impact ─────────────────────────────────────────────────────────────
    {
        "phase": 11,
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "impact",
        "condition": lambda p: (p.get("availability_impact") == "HIGH")
        and (p.get("confidentiality_impact") == "NONE"),
        "base_confidence": 0.80,
        "rationale": "Pure availability impact → DoS is the primary objective.",
    },
]


# ---------------------------------------------------------------------------
# Confidence decay across phases
# ---------------------------------------------------------------------------


def _phase_decay(phase: int, base: float) -> float:
    """Applies a decay factor to confidence based on kill-chain phase distance.

    Initial access is highly certain; later steps become increasingly speculative.
    """
    decay = max(0.0, 1.0 - (phase * 0.08))  # ~8% decay per phase
    return round(max(0.05, base * decay), 3)


# ---------------------------------------------------------------------------
# generate_blueprint
# ---------------------------------------------------------------------------


def generate_blueprint(
    cve_id: str,
    cve_profile: dict[str, Any],
) -> Blueprint:
    """Generates a hypothetical attack blueprint from a CVE profile.

    Args:
        cve_id: CVE identifier.
        cve_profile: Dict with keys extracted from ``CVEAnalysis``:
            - ``attack_vector`` (str): NETWORK | LOCAL | ADJACENT | PHYSICAL
            - ``cvss_score`` (float | None)
            - ``cwe_id`` (str | None)
            - ``requires_auth`` (bool)
            - ``requires_user_interaction`` (bool)
            - ``availability_impact`` (str): NONE | LOW | HIGH
            - ``confidentiality_impact`` (str): NONE | LOW | HIGH
            - ``integrity_impact`` (str): NONE | LOW | HIGH

    Returns:
        ``Blueprint`` with ordered techniques and edges.  All techniques
        start with ``status="hypothesized"``.
    """
    blueprint_id = f"BP-{cve_id}-{uuid.uuid4().hex[:8].upper()}"

    # Collect matching techniques
    selected: list[BlueprintTechnique] = []
    seen_ids: set[str] = set()

    for rule in _BLUEPRINT_RULES:
        try:
            if rule["condition"](cve_profile) and rule["technique_id"] not in seen_ids:
                phase = rule["phase"]
                confidence = _phase_decay(phase, rule["base_confidence"])
                selected.append(
                    BlueprintTechnique(
                        technique_id=rule["technique_id"],
                        technique_name=rule["technique_name"],
                        tactic=rule["tactic"],
                        tactic_phase=phase,
                        confidence=confidence,
                        status="hypothesized",
                        rationale=rule["rationale"],
                    )
                )
                seen_ids.add(rule["technique_id"])
        except Exception:
            continue  # Rule evaluation failures are non-fatal

    # Sort by tactic phase so the blueprint reads in kill-chain order
    selected.sort(key=lambda t: (t.tactic_phase, -t.confidence))

    # Build directed edges between consecutive techniques
    edges: list[BlueprintEdge] = []
    for i in range(len(selected) - 1):
        src = selected[i]
        dst = selected[i + 1]
        # Edge probability is the geometric mean of the two endpoint confidences
        prob = round((src.confidence * dst.confidence) ** 0.5, 3)
        edges.append(
            BlueprintEdge(
                from_technique_id=src.technique_id,
                to_technique_id=dst.technique_id,
                probability=prob,
                status="hypothesized",
            )
        )

    # Overall confidence = average across all technique steps
    total_conf = (
        round(sum(t.confidence for t in selected) / len(selected), 3)
        if selected
        else 0.0
    )

    return Blueprint(
        blueprint_id=blueprint_id,
        cve_id=cve_id,
        techniques=selected,
        edges=edges,
        total_confidence=total_conf,
    )
