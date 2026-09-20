"""Prometheus metrics route."""

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter(tags=["Metrics"])


@router.get(
    "/metrics",
    summary="Expose Prometheus metrics",
)
def get_metrics() -> Response:
    """Returns Prometheus formatted metrics."""
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
