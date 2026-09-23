# Future Requirements

This document captures features deliberately deferred from Phase 1 to maintain scope
focus.  These items must be addressed before production deployment.

---

## Security & Authentication

### DEV_VIEWER_001 — Authentication for Graph Viewer
**Priority:** MUST before production
**Blocked by:** Phase 3 (Auth layer)

The `/dev/viewer`, `/graph/export`, and `/graph/validate` endpoints currently
have **no authentication**.  They are restricted to localhost by default, but
this is a defense-in-depth measure only.

Required:
- OAuth 2.0 / OIDC integration for API authentication.
- Role-based access control: `investigator`, `analyst`, `admin`.
- Viewer access scoped to `analyst` and `admin` roles.
- Audit log of all viewer access events.

### DEV_VIEWER_002 — TLS for Viewer Endpoints
**Priority:** MUST before production

All endpoints must be served over HTTPS in production.  Configure via a
reverse proxy (nginx/Caddy) in front of uvicorn.

---

## Graph Query Security

### QUERY_001 — Cypher Injection Prevention Audit
**Priority:** MUST before production

All Cypher in Phase 1 uses parameterised queries.  A formal audit must confirm
there is no string interpolation of user input anywhere in the query path.

---

## Scalability

### SCALE_001 — Temporal Index Optimisation
**Priority:** SHOULD before high-volume production

At >1M nodes, point-in-time queries may require composite indexes:
```cypher
CREATE INDEX node_type_temporal_idx FOR (n:CVE) ON (n.valid_from, n.valid_to);
```
Profile and benchmark before adding.

### SCALE_002 — Version Pruning Policy
**Priority:** SHOULD

Old node versions (valid_to set > N months ago) may be archived to a separate
Neo4j database or cold storage.  Define a retention policy in Phase 4.

---

## Developer Viewer

### VIEWER_001 — Offline vis.js Bundle
**Priority:** SHOULD for air-gapped deployments

Currently, vis.js is loaded from a CDN (`unpkg.com`).  For air-gapped
environments, vendor the JS file into `api/static/`.

### VIEWER_002 — Production-Grade Graph UI
**Priority:** SHOULD Phase 3

Replace the single-file viewer with a React-based application with:
- Filtering by temporal window (point-in-time slider).
- SUPERSEDES chain visualisation.
- Provenance waterfall view.
- Full-text search across all properties.

---

## CI/CD

### CI_001 — Integration Test Neo4j Service Health Gate
**Priority:** MUST for CI reliability

The CI `validate-graph` job must wait for Neo4j to report `(healthy)` before
running integration tests.  Add a Docker service health check gate.

---

## References

- `docs/architecture/decisions/0009-developer-viewer-approach.md`
- `api/routes/graph.py` — current security implementation
