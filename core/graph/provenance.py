"""Provenance enforcement helpers for EvidenceGraphAI.

This module provides pure utility functions for validating and constructing
provenance fields on graph entities.  It has no Neo4j dependency.

Provenance Model
----------------
Every node and every relationship carries three provenance fields:

* ``source_agent``       — Name of the agent that created this entity.
                           Must match ``^[a-z][a-z0-9_]{2,63}$``.
* ``source_artifact_id`` — Evidence artifact ID that produced this entity.
                           Optional (None for derived/inferred facts).
* ``confidence``         — Float in ``[0.0, 1.0]`` indicating confidence in
                           this fact.

Validation Modes
----------------
**Flexible (default):** ``source_agent`` must match the naming regex only.
Any valid agent name is accepted without consulting an allowlist.

**Strict (opt-in):** ``source_agent`` must additionally be present in the
``KNOWN_AGENTS`` list configured via the ``KNOWN_AGENTS`` and
``PROVENANCE_STRICT_MODE`` settings.  Enable with ``PROVENANCE_STRICT_MODE=true``.

Strict mode is intended for high-assurance deployments where only pre-approved
agents may write to the graph.  Phase 2 agents self-register by adding their
name to the ``KNOWN_AGENTS`` environment variable — no code changes required.
"""

import re
from typing import Any

from core.graph.exceptions import ProvenanceValidationError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Regex that all source_agent values must satisfy.
AGENT_NAME_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

#: Default allowlist used when strict mode is enabled.
#: Extend via the ``KNOWN_AGENTS`` environment variable (comma-separated).
DEFAULT_KNOWN_AGENTS: list[str] = ["system", "manual"]

#: Sentinel for the minimum allowed confidence value.
CONFIDENCE_MIN: float = 0.0

#: Sentinel for the maximum allowed confidence value.
CONFIDENCE_MAX: float = 1.0


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_provenance(
    fields: dict[str, Any],
    *,
    strict: bool = False,
    known_agents: list[str] | None = None,
) -> None:
    """Validates provenance fields on a property dictionary.

    Rules (always applied):
    - ``source_agent`` must be present and non-empty.
    - ``source_agent`` must match ``^[a-z][a-z0-9_]{2,63}$``.
    - ``confidence`` must be present and in ``[0.0, 1.0]``.

    Additional rules when ``strict=True``:
    - ``source_agent`` must be in ``known_agents`` (or ``DEFAULT_KNOWN_AGENTS``).

    ``source_artifact_id`` is optional and not validated beyond type.

    Args:
        fields: Property dictionary to validate.
        strict: If True, enforce the agent allowlist.
        known_agents: Allowlist of valid agent names (used when ``strict=True``).

    Raises:
        ProvenanceValidationError: If any rule is violated.
    """
    # --- source_agent ---
    agent = fields.get("source_agent")
    if agent is None or agent == "":
        raise ProvenanceValidationError(
            "'source_agent' is required and must be a non-empty string"
        )

    if not isinstance(agent, str):
        raise ProvenanceValidationError(
            f"'source_agent' must be a string, got {type(agent).__name__}"
        )

    if not AGENT_NAME_PATTERN.match(agent):
        raise ProvenanceValidationError(
            f"'source_agent' value '{agent}' does not match required pattern "
            f"{AGENT_NAME_PATTERN.pattern!r}. "
            f"Must start with a lowercase letter and contain only lowercase letters, "
            f"digits, and underscores (3–64 characters total)."
        )

    if strict:
        allowlist = known_agents if known_agents is not None else DEFAULT_KNOWN_AGENTS
        if agent not in allowlist:
            raise ProvenanceValidationError(
                f"'source_agent' value '{agent}' is not in the known-agents allowlist "
                f"{allowlist!r}. "
                f"Add the agent name to the KNOWN_AGENTS environment variable or "
                f"disable PROVENANCE_STRICT_MODE."
            )

    # --- confidence ---
    confidence = fields.get("confidence")
    if confidence is None:
        raise ProvenanceValidationError(
            "'confidence' is required and must be a float in [0.0, 1.0]"
        )

    if not isinstance(confidence, int | float):
        raise ProvenanceValidationError(
            f"'confidence' must be a numeric value, got {type(confidence).__name__}"
        )

    confidence_float = float(confidence)
    if not (CONFIDENCE_MIN <= confidence_float <= CONFIDENCE_MAX):
        raise ProvenanceValidationError(
            f"'confidence' must be in [{CONFIDENCE_MIN}, {CONFIDENCE_MAX}], "
            f"got {confidence_float}"
        )


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def default_provenance(
    source_agent: str = "system",
    source_artifact_id: str | None = None,
    confidence: float = 1.0,
) -> dict[str, Any]:
    """Constructs a provenance field dictionary with the given values.

    Args:
        source_agent: Name of the creating agent (default: ``"system"``).
        source_artifact_id: Originating evidence artifact ID (optional).
        confidence: Confidence score in ``[0.0, 1.0]`` (default: ``1.0``).

    Returns:
        Dictionary with ``source_agent``, ``source_artifact_id``,
        and ``confidence`` keys.
    """
    return {
        "source_agent": source_agent,
        "source_artifact_id": source_artifact_id,
        "confidence": confidence,
    }


def parse_known_agents(raw: str) -> list[str]:
    """Parses a comma-separated agent name string into a list.

    Strips whitespace, removes empty entries.

    Args:
        raw: Comma-separated string (e.g. ``"system,manual,vuln_agent"``).

    Returns:
        Cleaned list of agent name strings.
    """
    return [a.strip() for a in raw.split(",") if a.strip()]
