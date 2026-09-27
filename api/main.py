"""Main FastAPI application for EvidenceGraphAI."""

import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path

import structlog
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.routes.dev_viewer import router as dev_viewer_router
from api.routes.graph import router as graph_router
from api.routes.health import router as health_router
from api.routes.ingest import router as ingest_router
from api.routes.ledger import router as ledger_router
from api.routes.manifests import router as manifests_router
from api.routes.metrics import router as metrics_router
from api.routes.sse import router as sse_router
from core.config.settings import get_settings
from core.logging.logger import configure_logging, get_logger
from core.observability.metrics import HTTP_REQUEST_COUNT, HTTP_REQUEST_DURATION_SECONDS

settings = get_settings()
configure_logging(
    log_level=settings.log_level, is_json=(settings.app_env == "production")
)
logger = get_logger("api.main")

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="EvidenceGraphAI REST API Engine",
    debug=settings.app_debug,
)

# CORS middleware
origins = [
    origin.strip() for origin in settings.api_cors_origins.split(",") if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def correlation_id_and_logging_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Middleware adding correlation ID tracking and request logging."""
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

    start_time = time.perf_counter()
    try:
        response = await call_next(request)
        duration = time.perf_counter() - start_time

        HTTP_REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status_code=str(response.status_code),
        ).inc()

        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=request.method, endpoint=request.url.path
        ).observe(duration)

        response.headers["X-Correlation-ID"] = correlation_id
        return response
    except Exception as e:
        duration = time.perf_counter() - start_time
        HTTP_REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status_code="500",
        ).inc()
        logger.error(
            "Unhandled exception in API request",
            path=request.url.path,
            method=request.method,
            error=str(e),
            duration=duration,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
            headers={"X-Correlation-ID": correlation_id},
        )


app.include_router(health_router)
app.include_router(metrics_router)
app.include_router(graph_router)
app.include_router(dev_viewer_router)
app.include_router(ingest_router)
app.include_router(ledger_router)
app.include_router(manifests_router)
app.include_router(sse_router)

# Mount static assets directory
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")


@app.get(
    "/dev/ingestion-portal",
    response_class=HTMLResponse,
    summary="Forensic Ingestion & Chain of Custody Portal (developer tool)",
    include_in_schema=True,
)
def serve_ingestion_portal() -> HTMLResponse:
    """Serves the developer Forensic Ingest Console single-page interface."""
    portal_path = Path(__file__).parent / "static" / "ingestion_portal.html"
    if not portal_path.exists():
        return HTMLResponse(
            content="<h3>Ingestion portal file not found</h3>",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return HTMLResponse(content=portal_path.read_text(encoding="utf-8"))


@app.get("/", summary="Root application metadata")
def read_root() -> dict[str, str]:
    """Returns application metadata."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
    }
