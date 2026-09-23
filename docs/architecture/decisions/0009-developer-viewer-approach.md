# ADR 0009 — Developer Graph Viewer Approach

**Status:** Accepted
**Date:** 2024-12-01
**Deciders:** EvidenceGraphAI Core Team
**Technical Story:** Phase 1 — Evidence Graph Core

---

## Context and Problem Statement

During development, engineers need to visually inspect the live graph without
writing Cypher queries.  A graph viewer dramatically reduces the feedback loop
when debugging data ingestion, testing agent output, and verifying ontology
compliance.

The question is: how should the viewer be delivered, and how should it be
secured?

---

## Considered Options

### Option A — External tool (Neo4j Browser / Bloom)
Use the built-in Neo4j Browser at `http://localhost:7474` or Neo4j Bloom.

**Pros:** No development effort. Full feature set.
**Cons:** Neo4j Browser exposes full Cypher access (destructive queries possible). Bloom requires a license. Not integrated into the EvidenceGraphAI stack. Engineers need separate credentials.
**Decision: Rejected as the primary tool.** Neo4j Browser may still be used for ad-hoc Cypher during development.

### Option B — Standalone React/Next.js app
Build a dedicated frontend application.

**Pros:** Rich UX possibilities.
**Cons:** Major scope creep for Phase 1. Requires a separate build pipeline, npm dependencies, deployment. Overkill for a developer debugging tool.
**Decision: Rejected.**

### Option C — Served by the FastAPI app (single HTML file) ✅
Ship a single self-contained HTML file using `vis.js` from a CDN.  Serve it
from the existing FastAPI app at `/dev/viewer`.  Restrict to localhost by
default.

**Pros:**
- Zero additional infrastructure — the existing API server serves the file.
- Single file with no build step.
- `vis.js` is battle-tested for graph visualisation.
- Localhost restriction prevents accidental public exposure.
- Can be disabled entirely in production via `DEV_VIEWER_ENABLED=false`.

**Cons:**
- CDN dependency (vis.js) — **mitigated:** pin the exact version in the URL
  (`vis-network@9.1.9`). Offline use requires vendoring the file.
- No authentication — **mitigated:** localhost-only by default + security
  banner + env flag to disable entirely.
- Limited features vs. a full React app — **accepted:** this is a developer
  debug tool, not a production UI.

**Decision: Accepted.**

---

## Decision Outcome

**Chosen option: Option C — Single-file vis.js viewer served by FastAPI.**

### Security Controls

| Control | Implementation |
|---------|---------------|
| Disabled by default in production | `DEV_VIEWER_ENABLED=true` (dev) / `false` (prod) |
| Localhost-only by default | IP check in `_guard_dev_endpoint()` |
| Remote access opt-in | `DEV_VIEWER_ALLOW_REMOTE=false` (default) |
| Security banner | Prominently displayed in the HTML UI |
| Access logging | Every request logged with client IP |

### Future Requirements

Authentication, RBAC, and a production-grade UI are deferred to Phase 3.
See `docs/roadmap/future-requirements.md`.

---

## References

- `api/routes/dev_viewer.py`
- `api/routes/graph.py` — `_guard_dev_endpoint()`
- `api/static/dev_viewer.html`
- `docs/graph/developer-viewer.md`
- `docs/roadmap/future-requirements.md`
