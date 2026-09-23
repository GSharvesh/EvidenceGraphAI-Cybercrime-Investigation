"""Graph query and validation API routes for EvidenceGraphAI.

Endpoints
---------
GET /graph/export
    Returns the full graph (or a filtered subset) as JSON.
    Restricted to localhost by default.

GET /graph/stats
    Returns aggregate graph statistics.

GET /graph/validate
    Runs the graph validator and returns the report.

Security
--------
All three endpoints are restricted to localhost by default
(``DEV_VIEWER_ALLOW_REMOTE=false``).  They are logged with client IP on every
request.  They must **never** be exposed publicly without authentication —
see ``docs/roadmap/future-requirements.md``.
"""

import ipaddress
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse

from api.dependencies import get_app_settings, get_graph_client
from core.config.settings import Settings
from core.graph.client import GraphClient
from core.graph.exceptions import GraphQueryError
from core.graph.queries import QueryLibrary
from core.graph.validator import GraphValidator
from core.logging.logger import get_logger

router = APIRouter(prefix="/graph", tags=["Graph"])
logger = get_logger(__name__)

_LOCALHOST_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def _is_localhost(ip_str: str) -> bool:
    """Returns True if the given IP string is a loopback address."""
    if ip_str in ("testclient", "localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _LOCALHOST_NETWORKS)
    except ValueError:
        return False


def _get_client_ip(request: Request) -> str:
    """Extracts the real client IP from the request."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    client = request.client
    if client:
        return client.host
    return "unknown"


def _guard_dev_endpoint(request: Request, settings: Settings) -> None:
    """Checks that the request is permitted by the dev-viewer security policy.

    Raises:
        HTTPException 503 if the viewer is disabled.
        HTTPException 403 if remote access is not allowed and the client is remote.
    """
    if not settings.dev_viewer_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Developer graph endpoints are disabled (DEV_VIEWER_ENABLED=false).",
        )

    client_ip = _get_client_ip(request)
    logger.info("Dev endpoint access", path=request.url.path, client_ip=client_ip)

    if not settings.dev_viewer_allow_remote and not _is_localhost(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Access to this endpoint is restricted to localhost. "
                "Set DEV_VIEWER_ALLOW_REMOTE=true to allow remote access."
            ),
        )


@router.get(
    "/export",
    summary="Export the full graph as JSON (developer endpoint)",
    response_class=JSONResponse,
)
def export_graph(
    request: Request,
    limit: int = Query(
        default=1000, ge=1, le=10000, description="Maximum nodes to return"
    ),
    node_type: str | None = Query(default=None, description="Filter nodes by label"),
    settings: Settings = Depends(get_app_settings),
    graph_client: GraphClient = Depends(get_graph_client),
) -> dict[str, Any]:
    """Exports graph nodes and edges as JSON for the developer viewer.

    .. warning::
        This endpoint returns the full graph without authentication.
        It must not be exposed publicly.  See ``docs/roadmap/future-requirements.md``.

    Args:
        limit: Maximum number of nodes to return (default 1000).
        node_type: Optional node label filter.
    """
    _guard_dev_endpoint(request, settings)

    try:
        if node_type:
            node_cypher = (
                f"MATCH (n:`{node_type}`) RETURN properties(n) AS props, "
                f"labels(n) AS labels LIMIT $limit"
            )
        else:
            node_cypher = (
                "MATCH (n) RETURN properties(n) AS props, "
                "labels(n) AS labels LIMIT $limit"
            )
        node_records = graph_client.query(node_cypher, {"limit": limit})

        nodes = []
        node_ids = set()
        for rec in node_records:
            props = rec.get("props") or {}
            labels_list = rec.get("labels") or []
            node_data = dict(props)
            node_data["_labels"] = labels_list
            nodes.append(node_data)
            if props.get("id"):
                node_ids.add(props["id"])

        # Fetch edges between exported nodes
        edge_cypher = (
            "MATCH (a)-[r]->(b) "
            "WHERE a.id IN $node_ids AND b.id IN $node_ids "
            "RETURN r.id AS id, a.id AS from_id, b.id AS to_id, "
            "type(r) AS type, properties(r) AS properties"
        )
        edge_records = graph_client.query(edge_cypher, {"node_ids": list(node_ids)})
        edges = [dict(rec) for rec in edge_records]

        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }
    except GraphQueryError as exc:
        logger.error("Graph export failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Graph export failed.",
        ) from exc


@router.get(
    "/stats",
    summary="Aggregate graph statistics",
)
def graph_stats(
    graph_client: GraphClient = Depends(get_graph_client),
) -> dict[str, Any]:
    """Returns node counts, edge counts, and aggregate totals.

    This endpoint is publicly accessible (no localhost restriction).
    """
    try:
        ql = QueryLibrary(graph_client)
        return ql.get_graph_statistics()
    except GraphQueryError as exc:
        logger.error("Graph stats failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve graph statistics.",
        ) from exc


@router.get(
    "/validate",
    summary="Run graph validator and return violations (developer endpoint)",
)
def validate_graph(
    request: Request,
    severity: str = Query(
        default="warning", description="Minimum severity: error, warning, info"
    ),
    rule: str | None = Query(default=None, description="Run only a specific rule"),
    settings: Settings = Depends(get_app_settings),
    graph_client: GraphClient = Depends(get_graph_client),
) -> dict[str, Any]:
    """Runs the graph validator and returns the violation report.

    .. warning::
        This endpoint is restricted to localhost by default.
        See ``docs/roadmap/future-requirements.md``.
    """
    _guard_dev_endpoint(request, settings)

    valid_severities = {"error", "warning", "info"}
    if severity not in valid_severities:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"severity must be one of {sorted(valid_severities)}",
        )

    try:
        validator = GraphValidator(graph_client)
        rules = [rule] if rule else None
        report = validator.validate(rules=rules)

        threshold = {"info": 0, "warning": 1, "error": 2}.get(severity, 0)
        filtered_violations = [
            v.to_dict() for v in report.violations if v.severity_level() >= threshold
        ]
        return {
            "violations": filtered_violations,
            "total": len(filtered_violations),
            "summary": report.summary(),
        }
    except GraphQueryError as exc:
        logger.error("Graph validation failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Graph validation failed.",
        ) from exc
