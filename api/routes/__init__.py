"""API router endpoints for EvidenceGraphAI."""

from api.routes.health import router as health_router
from api.routes.metrics import router as metrics_router

__all__ = ["health_router", "metrics_router"]
