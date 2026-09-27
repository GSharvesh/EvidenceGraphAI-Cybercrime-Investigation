# 15. Server-Sent Events (SSE) for Real-Time Frontend Updates

Date: 2026-09-27
Status: Accepted

## Context

Phase 1 established the Developer Graph Viewer (`/dev/viewer`), and Phase 2 established the Forensic Ingest Console (`/dev/ingestion-portal`). In their initial implementations, both frontends were static Single Page Applications that loaded data once on initialization and required manual page reloads to observe subsequent graph modifications, artifact ingestions, or custody ledger entries.

To support live developer workflows and real-time observability across concurrent ingestion pipelines, we required a real-time event streaming protocol to broadcast updates from the backend to connected browser sessions.

We considered three primary approaches:
1. **Short / Long Polling (`setInterval` / HTTP Long-Polling)**
2. **WebSockets (`ws://`, full-duplex persistent TCP connection)**
3. **Server-Sent Events (`text/event-stream` / HTML5 `EventSource` over HTTP)**

## Decision

We chose **Server-Sent Events (SSE)** via FastAPI StreamingResponse and native browser `EventSource` API for all real-time developer frontend telemetry in Phase 2.1.

### Rationale

1. **Unidirectional Server-to-Client Stream:** The browser only consumes event notifications (new ledger entries, graph node/edge creations, system health heartbeats). All client-to-server operations (ingestion, graph mutations, manual verifications) remain standard RESTful HTTP POST/GET requests. WebSockets would introduce bidirectional protocol overhead with no functional necessity.
2. **Native HTTP & Firewall Compatibility:** SSE operates over standard HTTP/1.1 and HTTP/2 connections (`text/event-stream`). It works transparently through standard corporate proxies, API gateways, load balancers, and TLS termination with zero custom configuration.
3. **Built-in Auto-Reconnection & Heartbeats:** Browser `EventSource` provides native reconnection handling. Combined with our client-side exponential backoff (`live.js`) and periodic `: ping` SSE keepalive frames, the streaming connection is robust against transient network drops.
4. **Lightweight FastAPI Async Generators:** FastAPI natively supports SSE using `StreamingResponse` wrapping async generator functions connected to an in-memory `AsyncEventBus` and Redis Pub/Sub backend.
5. **No Additional Dependencies:** SSE requires no heavy frontend libraries (e.g. Socket.io) and uses native browser APIs (`window.EventSource`).

## Architecture & Endpoints

- `GET /sse/ledger`: Broadcasts `LedgerEntryCreated` events to update the Forensic Ingestion Console timeline in real time.
- `GET /sse/graph`: Broadcasts `GraphNodeCreated`, `GraphEdgeCreated`, and `GraphNodeUpdated` events to dynamically render new elements in the Developer Graph Viewer.
- `GET /sse/status`: Broadcasts 5-second system health and infrastructure connectivity metrics.

## Consequences

- **Positive:** Immediate, zero-reload UI updates when artifacts are ingested or graph mutations occur.
- **Positive:** Low memory and CPU overhead compared to WebSocket state machines.
- **Negative:** Limited to text-based UTF-8 payloads (JSON encoded), which is optimal for our event schema.
- **Negative:** Maximum concurrent HTTP/1.1 connections per browser domain (6 limit). Addressed by multiplexing related event topics and keeping connections scoped to active viewer tabs.
