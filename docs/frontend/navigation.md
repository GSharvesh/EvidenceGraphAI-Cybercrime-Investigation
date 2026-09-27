# EvidenceGraphAI Developer Navigation & Real-Time System

Phase 2.1 introduced a unified top navigation bar, deep-linking capabilities, and Server-Sent Events (SSE) live updates across all developer interfaces.

## 1. Unified Navigation Bar (`nav.js`)

All developer web pages include the standard navigation bar (`/static/assets/nav.js`), which renders:
- **Brand Identity:** EvidenceGraphAI branding with home link.
- **Active Navigation Links:**
  - **Forensic Ingest Console:** `/dev/ingestion-portal` (Phase 2)
  - **Graph Viewer:** `/dev/viewer` (Phase 1)
  - **Swagger API:** `/docs` (Interactive OpenAPI documentation)
- **Upcoming Feature Placeholders (Disabled):**
  - **Similarity Explorer** (Phase 4 placeholder)
  - **Copilot** (Phase 5 placeholder)
- **Live SSE Connection Indicator:**
  - `🟢 Live` (Connected to event stream)
  - `🟡 Reconnecting` (Attempting exponential backoff reconnection)
  - `🔴 Disconnected` (Stream offline)

## 2. Cross-Page Deep Linking (`utils.js`)

Seamless bidirectional navigation between forensic artifacts and the cybercrime attack graph:

### A. Graph Viewer to Ingestion Portal
When inspecting an `EvidenceArtifact` node in `/dev/viewer`, the property inspector displays a link:
`View chain of custody →`
This navigates to `/dev/ingestion-portal?evidence=<artifact_id>`, which:
1. Automatically scrolls to the corresponding timeline entry in the cryptographic ledger.
2. Highlights and pulses the card.
3. Automatically opens the metadata inspector modal.

### B. Ingestion Portal to Graph Viewer
When inspecting any custody ledger entry or Section 65B manifest in `/dev/ingestion-portal`, the modal includes:
`[View in Graph Viewer ↗]`
This navigates to `/dev/viewer?focus=<evidence_id>`, which:
1. Waits for the network graph topology to render.
2. Automatically focuses, centers, and smoothly zooms into the node (scale 1.5x).
3. Opens the node details property panel.

## 3. Real-Time Streaming Architecture (`live.js`, `status.js`, `animations.js`)

- **Event Bus:** Asynchronous Python event bus in `core/events/bus.py` publishing to in-memory queues and Redis.
- **Endpoints:**
  - `/sse/ledger` — Real-time append of new forensic custody ledger entries without reloading.
  - `/sse/graph` — Real-time node and relationship updates in the vis.js attack graph.
  - `/sse/status` — Periodic heartbeat monitoring system status and service health.
- **Micro-Animations:** Micro-animations and counter transitions respecting `prefers-reduced-motion`.
