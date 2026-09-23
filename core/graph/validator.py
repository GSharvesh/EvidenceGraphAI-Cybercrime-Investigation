"""Graph validator for EvidenceGraphAI.

Checks the entire graph against the ontology and reports violations.

Rules
-----
1. **Orphan nodes** — nodes with no incoming *or* outgoing edges.
2. **Invalid edge types** — edges whose source/target node types are not
   allowed by the ontology for that relationship.
3. **Missing required properties** — nodes/edges missing properties marked
   ``required: true`` in ``schema.yaml``.
4. **Invalid property types** — properties whose values do not match the
   declared schema type.
5. **Dangling references** — edges pointing to non-existent nodes.
6. **Confidence range** — ``confidence`` outside ``[0.0, 1.0]``.
7. **Temporal consistency** — ``valid_to`` is not ``None`` and is not after
   ``valid_from``.

The validator is **read-only** — it never writes to the graph.  It returns a
structured :class:`ValidationReport`.

CLI Usage
---------
.. code-block:: bash

    python -m core.graph.validator [--severity {error,warning,info}]
                                   [--rule RULE_NAME]
                                   [--json]
                                   [--fail-on {error,warning}]

Exit codes:
- ``0`` — no violations at or above ``--fail-on`` level.
- ``1`` — violations found at or above ``--fail-on`` level.
- ``2`` — runtime error.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any

from core.graph.client import GraphClient
from core.graph.temporal import from_iso
from core.logging.logger import get_logger
from core.ontology.loader import OntologyLoader

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}


@dataclass
class Violation:
    """A single validation violation."""

    severity: str  # "error" | "warning" | "info"
    rule: str
    entity_id: str
    entity_type: str  # "node" or "edge"
    message: str

    def severity_level(self) -> int:
        """Numeric severity level for comparison."""
        return _SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict[str, str]:
        """Serialises the violation to a plain dict."""
        return {
            "severity": self.severity,
            "rule": self.rule,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "message": self.message,
        }


@dataclass
class ValidationReport:
    """Aggregate result of a graph validation run."""

    violations: list[Violation] = field(default_factory=list)

    def add(self, violation: Violation) -> None:
        """Appends a violation to the report."""
        self.violations.append(violation)

    def has_violations_at(self, severity: str) -> bool:
        """Returns True if any violation is at or above the given severity."""
        threshold = _SEVERITY_ORDER.get(severity, 0)
        return any(v.severity_level() >= threshold for v in self.violations)

    def summary(self) -> dict[str, int]:
        """Returns a count dict by severity level."""
        counts: dict[str, int] = {"error": 0, "warning": 0, "info": 0}
        for v in self.violations:
            if v.severity in counts:
                counts[v.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Serialises the full report."""
        return {
            "violations": [v.to_dict() for v in self.violations],
            "total": len(self.violations),
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Validator class
# ---------------------------------------------------------------------------

_SCHEMA_TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "float": (int, float),
    "integer": int,
    "boolean": bool,
    "list": list,
}


class GraphValidator:
    """Validates the entire graph against the ontology schema.

    Parameters
    ----------
    client:
        Connected :class:`~core.graph.client.GraphClient`.
    loader:
        :class:`~core.ontology.loader.OntologyLoader` to use.
        Defaults to the shared instance.
    """

    def __init__(
        self,
        client: GraphClient,
        loader: OntologyLoader | None = None,
    ) -> None:
        self._client = client
        self._loader = loader or OntologyLoader()
        self._schema = self._loader.load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self,
        rules: list[str] | None = None,
    ) -> ValidationReport:
        """Runs all (or a subset of) validation rules and returns a report.

        Args:
            rules: Optional list of rule names to run.  If ``None``, all
                   rules are run.

        Returns:
            A :class:`ValidationReport` with collected violations.
        """
        report = ValidationReport()
        all_rules = {
            "orphan_nodes": self._check_orphan_nodes,
            "invalid_edge_types": self._check_invalid_edge_types,
            "missing_required_properties": self._check_missing_required_properties,
            "invalid_property_types": self._check_invalid_property_types,
            "dangling_references": self._check_dangling_references,
            "confidence_range": self._check_confidence_range,
            "temporal_consistency": self._check_temporal_consistency,
        }
        to_run = rules if rules else list(all_rules.keys())
        for rule_name in to_run:
            fn = all_rules.get(rule_name)
            if fn is None:
                logger.warning("Unknown validation rule skipped", rule=rule_name)
                continue
            try:
                fn(report)
            except Exception as exc:
                logger.error(
                    "Validation rule raised an exception",
                    rule=rule_name,
                    error=str(exc),
                )
        return report

    # ------------------------------------------------------------------
    # Rule implementations
    # ------------------------------------------------------------------

    def _check_orphan_nodes(self, report: ValidationReport) -> None:
        """Rule 1: Detect nodes with no edges (isolated nodes)."""
        cypher = (
            "MATCH (n) WHERE NOT (n)--() "
            "RETURN properties(n) AS props, labels(n)[0] AS label"
        )
        records = self._client.query(cypher)
        for rec in records:
            props = rec.get("props") or {}
            node_id = str(props.get("id", "<unknown>"))
            report.add(
                Violation(
                    severity="warning",
                    rule="orphan_nodes",
                    entity_id=node_id,
                    entity_type="node",
                    message=(
                        f"Node '{node_id}' (label: {rec.get('label')}) "
                        f"has no incoming or outgoing edges."
                    ),
                )
            )

    def _check_invalid_edge_types(self, report: ValidationReport) -> None:
        """Rule 2: Detect edges whose endpoint types violate the ontology."""
        rel_schema: dict[str, Any] = self._schema.get("relationships", {})
        cypher = (
            "MATCH (a)-[r]->(b) "
            "RETURN type(r) AS rel_type, "
            "labels(a)[0] AS from_label, "
            "labels(b)[0] AS to_label, "
            "r.id AS edge_id"
        )
        records = self._client.query(cypher)
        for rec in records:
            rel_type = rec.get("rel_type", "")
            from_label = rec.get("from_label", "")
            to_label = rec.get("to_label", "")
            edge_id = str(rec.get("edge_id", "<unknown>"))

            if rel_type not in rel_schema:
                report.add(
                    Violation(
                        severity="error",
                        rule="invalid_edge_types",
                        entity_id=edge_id,
                        entity_type="edge",
                        message=(
                            f"Relationship type '{rel_type}' is not defined in the ontology."
                        ),
                    )
                )
                continue

            rel_def = rel_schema[rel_type]
            allowed_sources: list[str] = rel_def.get("source_types", [])
            allowed_targets: list[str] = rel_def.get("target_types", [])

            if allowed_sources and from_label not in allowed_sources:
                report.add(
                    Violation(
                        severity="error",
                        rule="invalid_edge_types",
                        entity_id=edge_id,
                        entity_type="edge",
                        message=(
                            f"Edge '{rel_type}' ({edge_id}) has source label '{from_label}' "
                            f"which is not in allowed sources {allowed_sources}."
                        ),
                    )
                )

            if allowed_targets and to_label not in allowed_targets:
                report.add(
                    Violation(
                        severity="error",
                        rule="invalid_edge_types",
                        entity_id=edge_id,
                        entity_type="edge",
                        message=(
                            f"Edge '{rel_type}' ({edge_id}) has target label '{to_label}' "
                            f"which is not in allowed targets {allowed_targets}."
                        ),
                    )
                )

    def _check_missing_required_properties(self, report: ValidationReport) -> None:
        """Rule 3: Detect missing required properties on nodes and edges."""
        node_schema: dict[str, Any] = self._schema.get("nodes", {})
        rel_schema: dict[str, Any] = self._schema.get("relationships", {})

        # --- Nodes ---
        cypher = "MATCH (n) RETURN properties(n) AS props, labels(n)[0] AS label"
        for rec in self._client.query(cypher):
            props = rec.get("props") or {}
            label = rec.get("label", "")
            node_id = str(props.get("id", "<unknown>"))
            if label not in node_schema:
                continue
            required = [
                k
                for k, v in node_schema[label].get("properties", {}).items()
                if v.get("required", False)
            ]
            for prop in required:
                if prop not in props or props[prop] is None:
                    report.add(
                        Violation(
                            severity="error",
                            rule="missing_required_properties",
                            entity_id=node_id,
                            entity_type="node",
                            message=(
                                f"Node '{node_id}' (label: {label}) is missing "
                                f"required property '{prop}'."
                            ),
                        )
                    )

        # --- Edges ---
        cypher = (
            "MATCH ()-[r]->() "
            "RETURN properties(r) AS props, type(r) AS rel_type, r.id AS edge_id"
        )
        for rec in self._client.query(cypher):
            props = rec.get("props") or {}
            rel_type = rec.get("rel_type", "")
            edge_id = str(rec.get("edge_id", "<unknown>"))
            if rel_type not in rel_schema:
                continue
            required = [
                k
                for k, v in rel_schema[rel_type].get("properties", {}).items()
                if v.get("required", False)
            ]
            for prop in required:
                if prop not in props or props[prop] is None:
                    report.add(
                        Violation(
                            severity="error",
                            rule="missing_required_properties",
                            entity_id=edge_id,
                            entity_type="edge",
                            message=(
                                f"Edge '{edge_id}' (type: {rel_type}) is missing "
                                f"required property '{prop}'."
                            ),
                        )
                    )

    def _check_invalid_property_types(self, report: ValidationReport) -> None:
        """Rule 4: Detect properties whose values do not match the declared type."""
        node_schema: dict[str, Any] = self._schema.get("nodes", {})
        rel_schema: dict[str, Any] = self._schema.get("relationships", {})

        def _check(
            props: dict[str, Any],
            schema_props: dict[str, Any],
            entity_id: str,
            entity_type: str,
        ) -> None:
            for prop_name, prop_def in schema_props.items():
                declared_type = prop_def.get("type", "string")
                expected = _SCHEMA_TYPE_MAP.get(declared_type)
                if (
                    expected is None
                    or prop_name not in props
                    or props[prop_name] is None
                ):
                    continue
                if not isinstance(props[prop_name], expected):
                    report.add(
                        Violation(
                            severity="warning",
                            rule="invalid_property_types",
                            entity_id=entity_id,
                            entity_type=entity_type,
                            message=(
                                f"Property '{prop_name}' on {entity_type} '{entity_id}' "
                                f"should be {declared_type}, "
                                f"got {type(props[prop_name]).__name__}."
                            ),
                        )
                    )

        for rec in self._client.query(
            "MATCH (n) RETURN properties(n) AS props, labels(n)[0] AS label"
        ):
            props = rec.get("props") or {}
            label = rec.get("label", "")
            node_id = str(props.get("id", "<unknown>"))
            if label in node_schema:
                _check(props, node_schema[label].get("properties", {}), node_id, "node")

        for rec in self._client.query(
            "MATCH ()-[r]->() RETURN properties(r) AS props, type(r) AS rt, r.id AS eid"
        ):
            props = rec.get("props") or {}
            rel_type = rec.get("rt", "")
            edge_id = str(rec.get("eid", "<unknown>"))
            if rel_type in rel_schema:
                _check(
                    props, rel_schema[rel_type].get("properties", {}), edge_id, "edge"
                )

    def _check_dangling_references(self, report: ValidationReport) -> None:
        """Rule 5: Detect edges referencing non-existent nodes."""
        cypher = (
            "MATCH (a)-[r]->(b) "
            "WHERE a IS NULL OR b IS NULL "
            "RETURN r.id AS edge_id, type(r) AS rel_type"
        )
        records = self._client.query(cypher)
        for rec in records:
            edge_id = str(rec.get("edge_id", "<unknown>"))
            report.add(
                Violation(
                    severity="error",
                    rule="dangling_references",
                    entity_id=edge_id,
                    entity_type="edge",
                    message=(
                        f"Edge '{edge_id}' (type: {rec.get('rel_type')}) references "
                        f"a non-existent node."
                    ),
                )
            )

    def _check_confidence_range(self, report: ValidationReport) -> None:
        """Rule 6: Detect nodes/edges with confidence outside [0.0, 1.0]."""
        node_cypher = (
            "MATCH (n) WHERE n.confidence IS NOT NULL "
            "AND (n.confidence < 0.0 OR n.confidence > 1.0) "
            "RETURN properties(n) AS props, labels(n)[0] AS label"
        )
        for rec in self._client.query(node_cypher):
            props = rec.get("props") or {}
            node_id = str(props.get("id", "<unknown>"))
            report.add(
                Violation(
                    severity="error",
                    rule="confidence_range",
                    entity_id=node_id,
                    entity_type="node",
                    message=(
                        f"Node '{node_id}' has confidence={props.get('confidence')} "
                        f"which is outside [0.0, 1.0]."
                    ),
                )
            )

        edge_cypher = (
            "MATCH ()-[r]->() WHERE r.confidence IS NOT NULL "
            "AND (r.confidence < 0.0 OR r.confidence > 1.0) "
            "RETURN r.id AS edge_id, type(r) AS rel_type, r.confidence AS conf"
        )
        for rec in self._client.query(edge_cypher):
            edge_id = str(rec.get("edge_id", "<unknown>"))
            report.add(
                Violation(
                    severity="error",
                    rule="confidence_range",
                    entity_id=edge_id,
                    entity_type="edge",
                    message=(
                        f"Edge '{edge_id}' (type: {rec.get('rel_type')}) has "
                        f"confidence={rec.get('conf')} which is outside [0.0, 1.0]."
                    ),
                )
            )

    def _check_temporal_consistency(self, report: ValidationReport) -> None:
        """Rule 7: Detect entities where valid_to is not None and <= valid_from."""
        node_cypher = (
            "MATCH (n) WHERE n.valid_to IS NOT NULL "
            "RETURN properties(n) AS props, labels(n)[0] AS label"
        )
        for rec in self._client.query(node_cypher):
            props = rec.get("props") or {}
            node_id = str(props.get("id", "<unknown>"))
            vf_str = props.get("valid_from")
            vt_str = props.get("valid_to")
            if vf_str and vt_str:
                try:
                    vf = from_iso(str(vf_str))
                    vt = from_iso(str(vt_str))
                    if vt <= vf:
                        report.add(
                            Violation(
                                severity="error",
                                rule="temporal_consistency",
                                entity_id=node_id,
                                entity_type="node",
                                message=(
                                    f"Node '{node_id}': valid_to ({vt_str!r}) "
                                    f"is not after valid_from ({vf_str!r})."
                                ),
                            )
                        )
                except Exception:
                    report.add(
                        Violation(
                            severity="error",
                            rule="temporal_consistency",
                            entity_id=node_id,
                            entity_type="node",
                            message=(
                                f"Node '{node_id}': could not parse temporal fields "
                                f"valid_from={vf_str!r}, valid_to={vt_str!r}."
                            ),
                        )
                    )

        edge_cypher = (
            "MATCH ()-[r]->() WHERE r.valid_to IS NOT NULL "
            "RETURN properties(r) AS props, r.id AS edge_id, type(r) AS rel_type"
        )
        for rec in self._client.query(edge_cypher):
            props = rec.get("props") or {}
            edge_id = str(rec.get("edge_id", "<unknown>"))
            vf_str = props.get("valid_from")
            vt_str = props.get("valid_to")
            if vf_str and vt_str:
                try:
                    vf = from_iso(str(vf_str))
                    vt = from_iso(str(vt_str))
                    if vt <= vf:
                        report.add(
                            Violation(
                                severity="error",
                                rule="temporal_consistency",
                                entity_id=edge_id,
                                entity_type="edge",
                                message=(
                                    f"Edge '{edge_id}' (type: {rec.get('rel_type')}): "
                                    f"valid_to ({vt_str!r}) is not after valid_from ({vf_str!r})."
                                ),
                            )
                        )
                except Exception:
                    report.add(
                        Violation(
                            severity="error",
                            rule="temporal_consistency",
                            entity_id=edge_id,
                            entity_type="edge",
                            message=(
                                f"Edge '{edge_id}': could not parse temporal fields."
                            ),
                        )
                    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m core.graph.validator",
        description="Validate the EvidenceGraphAI graph against the ontology.",
    )
    parser.add_argument(
        "--severity",
        choices=["error", "warning", "info"],
        default="warning",
        help="Minimum severity level to display (default: warning)",
    )
    parser.add_argument(
        "--rule",
        default=None,
        help="Run only the named rule (omit to run all)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of a table",
    )
    parser.add_argument(
        "--fail-on",
        choices=["error", "warning"],
        default="error",
        dest="fail_on",
        help="Exit with code 1 if violations at this level or above exist (default: error)",
    )
    return parser


def _print_table(violations: list[Violation], min_severity: str) -> None:
    threshold = _SEVERITY_ORDER.get(min_severity, 0)
    filtered = [v for v in violations if v.severity_level() >= threshold]
    if not filtered:
        print("No violations found.")
        return
    col_widths = [10, 30, 36, 6, 80]
    headers = ["SEVERITY", "RULE", "ENTITY_ID", "TYPE", "MESSAGE"]
    sep = "  ".join("-" * w for w in col_widths)
    header_row = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(header_row)
    print(sep)
    for v in filtered:
        row = "  ".join(
            s.ljust(col_widths[i])
            for i, s in enumerate(
                [v.severity, v.rule, v.entity_id, v.entity_type, v.message]
            )
        )
        print(row)
    print(f"\nTotal: {len(filtered)} violation(s) shown.")


def main() -> int:
    """CLI entry point.

    Returns:
        Exit code: 0 = clean, 1 = violations, 2 = runtime error.
    """
    parser = _build_parser()
    args = parser.parse_args()

    try:
        client = GraphClient()
        validator = GraphValidator(client)
        rules = [args.rule] if args.rule else None
        report = validator.validate(rules=rules)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_table(report.violations, args.severity)
        summary = report.summary()
        print(
            f"Summary: {summary['error']} error(s), {summary['warning']} warning(s), {summary['info']} info(s)"
        )

    if report.has_violations_at(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
