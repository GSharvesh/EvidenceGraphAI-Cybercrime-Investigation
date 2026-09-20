"""FastAPI dependency injection providers."""

from collections.abc import Generator

from fastapi import Depends
from structlog.stdlib import BoundLogger

from core.config.settings import Settings, get_settings
from core.graph.client import GraphClient
from core.logging.logger import get_logger

_graph_client_instance: GraphClient | None = None


def get_app_settings() -> Settings:
    """Dependency provider for application settings."""
    return get_settings()


def get_app_logger() -> BoundLogger:
    """Dependency provider for structlog logger."""
    return get_logger("api")


def get_graph_client(
    settings: Settings = Depends(get_app_settings),
) -> Generator[GraphClient, None, None]:
    """Dependency provider for Neo4j GraphClient instance."""
    global _graph_client_instance
    if _graph_client_instance is None:
        _graph_client_instance = GraphClient(settings=settings)
    yield _graph_client_instance
