"""Health check route performing deep checks across infrastructure services."""

import socket
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel

from api.dependencies import get_app_settings, get_graph_client
from core.config.settings import Settings
from core.graph.client import GraphClient

router = APIRouter(tags=["Health"])


class ServicesHealth(BaseModel):
    neo4j: str
    postgres: str
    redis: str
    minio: str


class HealthResponse(BaseModel):
    status: str
    services: ServicesHealth


def _check_tcp_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Helper to check if TCP socket connection succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Deep health check across Neo4j, PostgreSQL, Redis, and MinIO",
)
def check_health(
    response: Response,
    settings: Settings = Depends(get_app_settings),
    graph_client: GraphClient = Depends(get_graph_client),
) -> HealthResponse:
    """Performs deep health checks on Neo4j, PostgreSQL, Redis, and MinIO.

    Returns HTTP 200 if all services respond, HTTP 503 if any fail.
    """
    # Neo4j check
    neo4j_healthy = graph_client.health_check()

    # Postgres TCP check
    postgres_healthy = _check_tcp_port(settings.postgres_host, settings.postgres_port)

    # Redis TCP check
    parsed_redis = urlparse(settings.redis_url)
    redis_host = parsed_redis.hostname or "localhost"
    redis_port = parsed_redis.port or 6379
    redis_healthy = _check_tcp_port(redis_host, redis_port)

    # MinIO TCP check
    minio_parts = settings.minio_endpoint.split(":")
    minio_host = minio_parts[0]
    minio_port = int(minio_parts[1]) if len(minio_parts) > 1 else 9000
    minio_healthy = _check_tcp_port(minio_host, minio_port)

    services_status = ServicesHealth(
        neo4j="healthy" if neo4j_healthy else "unhealthy",
        postgres="healthy" if postgres_healthy else "unhealthy",
        redis="healthy" if redis_healthy else "unhealthy",
        minio="healthy" if minio_healthy else "unhealthy",
    )

    all_healthy = neo4j_healthy and postgres_healthy and redis_healthy and minio_healthy

    if not all_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status="healthy" if all_healthy else "unhealthy",
        services=services_status,
    )
