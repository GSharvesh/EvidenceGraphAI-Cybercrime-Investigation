# ADR 0013: Forensic Ingest Console Architecture & Visualization Choice

## Status
Accepted

## Context
Phase 2 required a novel developer frontend for forensic ingestion and chain of custody visualization without introducing complex Node.js build toolchains or heavy SPA frameworks.

## Decision
We implemented a self-contained single-page HTML application (`api/static/ingestion_portal.html`) served directly by FastAPI at `/dev/ingestion-portal`.
1. **Visualization Library:** Cytoscape.js loaded via CDN for interactive graph topology rendering.
2. **Design Language:** Modern dark-mode cybersecurity aesthetic with glassmorphism, glowing status indicators, monospace cryptographic digests, and an interactive vertical timeline.
3. **Real-time Client Hashing:** Web Crypto API streaming hash computation directly in the browser during file drop.

## Alternatives Considered
- **React / Next.js SPA:** Requires Node.js build pipelines, npm dependencies, and extra CI complexity not needed for Phase 2 developer tools.
- **D3.js:** More verbose for simple node-link graph rendering than Cytoscape.js.

## Consequences
- **Positive:** Zero frontend build steps, instant developer feedback, responsive, rich cybersecurity aesthetic, standalone portability.
- **Negative:** Full multi-page production frontend with OAuth authentication is deferred to future milestones.
