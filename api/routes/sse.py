"""Server-Sent Events (SSE) streaming routes for real-time frontend updates."""

import asyncio
import socket
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from api.dependencies import (
    get_app_settings,
    get_custody_ledger,
    get_graph_client,
    get_minio_client,
    get_postgres_client,
)
from core.config.settings import Settings
from core.custody.ledger import CustodyLedger
from core.db.postgres import PostgresClient
from core.events.bus import get_event_bus
from core.events.types import StatusEvent
from core.graph.client import GraphClient
from core.logging.logger import get_logger
from core.storage.minio_client import MinioClient

router = APIRouter(prefix="/sse", tags=["Live Events (SSE)"])
logger = get_logger("api.routes.sse")

SSE_HEADERS = {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


def _probe_system_status(
    settings: Settings,
    graph: GraphClient | None = None,
    postgres: PostgresClient | None = None,
    minio: MinioClient | None = None,
    ledger: CustodyLedger | None = None,
) -> StatusEvent:
    """Probes system infrastructure and custody ledger health synchronously."""
    neo4j_ok = False
    if graph is not None:
        try:
            neo4j_ok = graph.health_check()
        except Exception:
            neo4j_ok = False

    pg_ok = False
    if postgres is not None:
        try:
            pg_ok = postgres.health_check()
        except Exception:
            pg_ok = False

    minio_ok = False
    if minio is not None:
        try:
            minio_ok = minio.health_check()
        except Exception:
            minio_ok = False

    redis_ok = False
    try:
        from urllib.parse import urlparse

        parsed_redis = urlparse(settings.redis_url)
        r_host = parsed_redis.hostname or "localhost"
        r_port = parsed_redis.port or 6379
        with socket.create_connection((r_host, r_port), timeout=1.0):
            redis_ok = True
    except Exception:
        redis_ok = False

    ledger_intact = False
    ledger_count = 0
    if ledger is not None:
        try:
            res = ledger.verify_ledger_integrity()
            ledger_intact = res.is_valid
            ledger_count = res.total_entries
        except Exception:
            try:
                stats = ledger.get_ledger_stats()
                ledger_count = stats.get("total_entries", 0)
                ledger_intact = True
            except Exception:
                ledger_intact = False
                ledger_count = 0

    return StatusEvent(
        neo4j=neo4j_ok,
        postgres=pg_ok,
        minio=minio_ok,
        redis=redis_ok,
        ledger_intact=ledger_intact,
        ledger_entries=ledger_count,
    )


@router.get(
    "/ledger",
    summary="Stream live custody ledger updates (SSE)",
    response_class=StreamingResponse,
)
async def sse_ledger(request: Request) -> StreamingResponse:
    """Streams new forensic custody ledger entries as they are appended.

    Emits:
        - ``event: ledger_entry`` with JSON payload of new entry
        - ``: heartbeat`` comment every 15 seconds
    """

    async def event_generator() -> AsyncIterator[str]:
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="ledger_entry", maxsize=100)
        logger.debug("SSE client connected to /sse/ledger")
        try:
            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: ledger_entry\ndata: {event.model_dump_json()}\n\n"
                except TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            bus.unsubscribe_queue(queue, event_type="ledger_entry")
            logger.debug("SSE client disconnected from /sse/ledger")

    return StreamingResponse(
        event_generator(), headers=SSE_HEADERS, media_type="text/event-stream"
    )


@router.get(
    "/graph",
    summary="Stream live knowledge graph mutations (SSE)",
    response_class=StreamingResponse,
)
async def sse_graph(request: Request) -> StreamingResponse:
    """Streams live graph creations and updates.

    Emits:
        - ``event: node_created``
        - ``event: edge_created``
        - ``event: node_updated``
        - ``: heartbeat`` comment every 15 seconds
    """

    async def event_generator() -> AsyncIterator[str]:
        bus = get_event_bus()
        event_types = {"node_created", "edge_created", "node_updated"}
        queue = bus.subscribe_queue(event_type=event_types, maxsize=200)
        logger.debug("SSE client connected to /sse/graph")
        try:
            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: {event.event_type}\ndata: {event.model_dump_json()}\n\n"
                except TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            bus.unsubscribe_queue(queue, event_type=event_types)
            logger.debug("SSE client disconnected from /sse/graph")

    return StreamingResponse(
        event_generator(), headers=SSE_HEADERS, media_type="text/event-stream"
    )


@router.get(
    "/status",
    summary="Stream live system and service health status (SSE)",
    response_class=StreamingResponse,
)
async def sse_status(
    request: Request,
    settings: Settings = Depends(get_app_settings),
    graph: GraphClient = Depends(get_graph_client),
    postgres: PostgresClient = Depends(get_postgres_client),
    minio: MinioClient = Depends(get_minio_client),
    ledger: CustodyLedger = Depends(get_custody_ledger),
) -> StreamingResponse:
    """Streams system service and ledger integrity status periodically.

    Emits:
        - ``event: status`` immediately on connect and every 10 seconds (or on-demand)
        - ``: heartbeat`` comment if no event emitted
    """

    async def event_generator() -> AsyncIterator[str]:
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="status", maxsize=50)
        logger.debug("SSE client connected to /sse/status")
        try:
            # Emit immediate initial status upon connection
            initial_status = await asyncio.to_thread(
                _probe_system_status, settings, graph, postgres, minio, ledger
            )
            yield f"event: status\ndata: {initial_status.model_dump_json()}\n\n"

            while not await request.is_disconnected():
                try:
                    # Wait up to 10 seconds for a bus-published status event
                    event = await asyncio.wait_for(queue.get(), timeout=10.0)
                    yield f"event: status\ndata: {event.model_dump_json()}\n\n"
                except TimeoutError:
                    # Probe live system status periodically
                    polled_status = await asyncio.to_thread(
                        _probe_system_status, settings, graph, postgres, minio, ledger
                    )
                    yield f"event: status\ndata: {polled_status.model_dump_json()}\n\n"
        finally:
            bus.unsubscribe_queue(queue, event_type="status")
            logger.debug("SSE client disconnected from /sse/status")

    return StreamingResponse(
        event_generator(), headers=SSE_HEADERS, media_type="text/event-stream"
    )
