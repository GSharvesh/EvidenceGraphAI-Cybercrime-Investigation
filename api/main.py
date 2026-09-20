"""Main FastAPI application for EvidenceGraphAI."""

import time
import uuid
from collections.abc import Callable

import structlog
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes.health import router as health_router
from api.routes.metrics import router as metrics_router
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
    request: Request, call_next: Callable
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


@app.get("/", summary="Root application metadata")
def read_root() -> dict[str, str]:
    """Returns application metadata."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
    }
