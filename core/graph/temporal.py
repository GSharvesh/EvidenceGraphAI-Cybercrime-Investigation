"""Temporal versioning helpers for EvidenceGraphAI.

This module provides pure utility functions for managing temporal fields on graph
entities.  It has no Neo4j dependency — it operates on plain Python dicts and
datetime objects.

Temporal Model
--------------
Every node and every relationship carries four temporal fields:

* ``created_at``  — ISO-8601 UTC timestamp of first insertion.  **Immutable.**
* ``updated_at``  — ISO-8601 UTC timestamp of the most recent write.  Auto-set.
* ``valid_from``  — Domain validity start.  Defaults to ``created_at``.
* ``valid_to``    — Domain validity end.  ``None`` means "still valid".

Soft Deletion
-------------
Setting ``valid_to`` to the current timestamp marks an entity as no longer valid
without physically deleting it.  Queries that want "current" data filter on
``valid_from <= now AND (valid_to IS NULL OR valid_to > now)``.

Append-Only Versioning
----------------------
Nodes are never mutated in place.  An "update" operation:
1. Sets the existing node's ``valid_to`` to *now* (soft-close).
2. Creates a new node version with a derived ID (``{original_id}::v{n}``).
3. Copies all properties, applies the patch, sets ``valid_from=now``.
4. Creates a ``SUPERSEDES`` edge from the new version to the old version.
"""

import re
from datetime import UTC, datetime
from typing import Any

from core.graph.exceptions import TemporalValidationError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ISO_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"  # date and time
    r"(\.\d+)?"  # optional fractional seconds
    r"([+-]\d{2}:\d{2}|Z)?$"  # optional timezone
)


# ---------------------------------------------------------------------------
# Timestamp utilities
# ---------------------------------------------------------------------------


def now_utc() -> datetime:
    """Returns the current UTC datetime with timezone info."""
    return datetime.now(UTC)


def to_iso(dt: datetime) -> str:
    """Converts a datetime to an ISO-8601 string.

    Args:
        dt: A timezone-aware datetime object.

    Returns:
        ISO-8601 formatted string (e.g. ``"2024-01-15T12:30:00+00:00"``).
    """
    return dt.isoformat()


def from_iso(s: str) -> datetime:
    """Parses an ISO-8601 string to a UTC-aware datetime.

    Args:
        s: ISO-8601 timestamp string.

    Returns:
        Timezone-aware datetime in UTC.

    Raises:
        TemporalValidationError: If the string cannot be parsed.
    """
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            # Assume UTC when no timezone is specified
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except (ValueError, TypeError) as exc:
        raise TemporalValidationError(
            f"Cannot parse ISO-8601 timestamp '{s}': {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Default field factories
# ---------------------------------------------------------------------------


def default_temporal_fields() -> dict[str, Any]:
    """Returns a dict of temporal fields with current UTC defaults.

    The returned dict has:
    - ``created_at``: now (ISO-8601 string)
    - ``updated_at``: now (same value)
    - ``valid_from``: now
    - ``valid_to``: ``None``

    Returns:
        Dictionary of temporal field defaults.
    """
    now = to_iso(now_utc())
    return {
        "created_at": now,
        "updated_at": now,
        "valid_from": now,
        "valid_to": None,
    }


# ---------------------------------------------------------------------------
# Validity predicates
# ---------------------------------------------------------------------------


def is_valid_at(props: dict[str, Any], timestamp: datetime) -> bool:
    """Returns True if an entity is valid at the given timestamp.

    An entity is valid at ``timestamp`` when:
    - ``valid_from <= timestamp``
    - ``valid_to IS NULL OR valid_to > timestamp``

    Args:
        props: Node or edge property dictionary containing temporal fields.
        timestamp: The point-in-time to evaluate (must be timezone-aware).

    Returns:
        True if the entity is valid at ``timestamp``.
    """
    valid_from_str = props.get("valid_from")
    valid_to_str = props.get("valid_to")

    if valid_from_str is None:
        return False

    valid_from = from_iso(str(valid_from_str))
    if timestamp < valid_from:
        return False

    if valid_to_str is not None:
        valid_to = from_iso(str(valid_to_str))
        if timestamp >= valid_to:
            return False

    return True


# ---------------------------------------------------------------------------
# Cypher clause builders
# ---------------------------------------------------------------------------


def temporal_filter_clause(alias: str) -> str:
    """Returns a Cypher WHERE fragment filtering entities valid at ``$timestamp``.

    Example usage::

        clause = temporal_filter_clause("n")
        cypher = f"MATCH (n:CVE) WHERE {clause} RETURN n"

    The generated clause expects a ``$timestamp`` parameter of type string
    (ISO-8601) in the Cypher query parameters.

    Args:
        alias: Cypher node or relationship alias (e.g. ``"n"``, ``"r"``).

    Returns:
        Cypher WHERE fragment string.
    """
    return (
        f"{alias}.valid_from <= $timestamp "
        f"AND ({alias}.valid_to IS NULL OR {alias}.valid_to > $timestamp)"
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_temporal_consistency(props: dict[str, Any]) -> None:
    """Validates that temporal fields are internally consistent.

    Rules checked:
    - ``valid_from`` must be a parseable ISO-8601 string (if present).
    - ``valid_to`` must be a parseable ISO-8601 string (if present).
    - ``valid_from <= valid_to`` when both are present.
    - ``created_at`` must be a parseable ISO-8601 string (if present).

    Args:
        props: Property dictionary to validate.

    Raises:
        TemporalValidationError: If any consistency rule is violated.
    """
    valid_from_str = props.get("valid_from")
    valid_to_str = props.get("valid_to")
    created_at_str = props.get("created_at")

    valid_from: datetime | None = None
    valid_to: datetime | None = None

    if valid_from_str is not None:
        valid_from = from_iso(str(valid_from_str))

    if valid_to_str is not None:
        valid_to = from_iso(str(valid_to_str))

    if created_at_str is not None:
        from_iso(str(created_at_str))  # raises if unparseable

    if valid_from is not None and valid_to is not None and valid_to <= valid_from:
        raise TemporalValidationError(
            f"valid_to ({valid_to_str!r}) must be after valid_from ({valid_from_str!r})"
        )


def derive_version_id(original_id: str, version: int) -> str:
    """Constructs a versioned node ID from the original ID and version number.

    Args:
        original_id: The root node ID.
        version: Monotonically increasing version number (1-based).

    Returns:
        Derived ID string, e.g. ``"CVE-2021-44228::v2"``.
    """
    return f"{original_id}::v{version}"


def get_root_id(node_id: str) -> str:
    """Extracts the root ID from a possibly versioned node ID.

    For ``"CVE-2021-44228::v3"`` returns ``"CVE-2021-44228"``.
    For ``"CVE-2021-44228"`` returns ``"CVE-2021-44228"`` unchanged.

    Args:
        node_id: Possibly versioned node ID string.

    Returns:
        Root (unversioned) ID string.
    """
    if "::" in node_id:
        return node_id.split("::")[0]
    return node_id
