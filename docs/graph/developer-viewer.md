# Developer Graph Viewer

The developer graph viewer is a browser-based tool for inspecting the live
evidence graph during development.  It is served by the FastAPI application
at `/dev/viewer`.

> **Security warning**: This tool has no authentication. It is restricted to
> `localhost` by default. Never expose it publicly.

---

## Access

With the API server running:

```
http://localhost:8000/dev/viewer
```

---

## Features

- **Node/edge visualisation** — interactive graph rendered with vis.js.
- **Node type filters** — toggle visibility by label with colour legend.
- **Edge type filters** — toggle visibility by relationship type.
- **Search** — filter visible nodes by ID or any property value.
- **Property inspector** — click any node or edge to see all its properties.
- **Refresh** — reload graph data from the API without reloading the page.
- **Statistics bar** — total nodes, total edges, visible nodes/edges count.
- **Security banner** — persistent reminder that this is a developer tool.

---

## Security Controls

| Control | Default | Setting |
|---------|---------|---------|
| Viewer enabled | `true` | `DEV_VIEWER_ENABLED` |
| Localhost only | `true` | `DEV_VIEWER_ALLOW_REMOTE=false` |
| Access logging | Always | Hardcoded |

To **disable** in production:
```env
DEV_VIEWER_ENABLED=false
```

To allow remote access (trusted network only, never public):
```env
DEV_VIEWER_ALLOW_REMOTE=true
```

---

## Related API Endpoints

All three endpoints are localhost-restricted by default.

| Endpoint | Description |
|----------|-------------|
| `GET /dev/viewer` | Serves the viewer HTML |
| `GET /graph/export?limit=N&node_type=X` | Graph data for the viewer |
| `GET /graph/stats` | Aggregate statistics (public) |
| `GET /graph/validate` | Run graph validator |

---

## References

- `api/routes/dev_viewer.py`
- `api/routes/graph.py`
- `api/static/dev_viewer.html`
- `docs/architecture/decisions/0009-developer-viewer-approach.md`
- `docs/roadmap/future-requirements.md` — authentication roadmap
