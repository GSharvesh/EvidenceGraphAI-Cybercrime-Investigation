# EvidenceGraphAI Developer Setup Guide

This guide provides step-by-step developer onboarding instructions for EvidenceGraphAI Phase 0.

---

## Prerequisites

1. **Python**: Python `>=3.11` (specifically tested on Python `3.11.8`).
2. **Docker**: Docker Engine `>=24.0` and Docker Compose `v2.x` / `v5.x`.
3. **Git**: Installed and configured.

---

## Step-by-Step Setup

### 1. Clone & Initialize Repository
```bash
git clone <repo-url>
cd EvidenceGraphAI
```

### 2. Create and Activate Virtual Environment
On Windows:
```bash
py -3.11 -m venv .venv
.\.venv\Scripts\activate
```

On Linux / macOS:
```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

Verify interpreter:
```bash
python --version
# Should output: Python 3.11.8
```

### 3. Install Package and Dependencies
```bash
pip install -e .[dev]
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 5. Start Infrastructure Services
```bash
make docker-up
```

Verify container status:
```bash
docker compose -f infra/docker/docker-compose.yml ps
# Ensure neo4j, postgres, redis, and minio containers display "healthy"
```

### 6. Seed Neo4j Ontology Constraints
```bash
python infra/scripts/seed_ontology.py
```

### 7. Run Validation Suite
```bash
make validate
```
Or execute directly:
```bash
bash scripts/validate_phase0.sh
```

---

## Troubleshooting Common Issues

### Port Conflicts
If ports `7474`, `7687`, `5432`, `6379`, `9000`, or `9001` are already in use on your host system:
1. Stop competing host services or containers.
2. Copy `infra/docker/docker-compose.override.yml.example` to `infra/docker/docker-compose.override.yml` and adjust host port mappings.

### Database Connection Failures
Verify container status and logs:
```bash
docker compose -f infra/docker/docker-compose.yml logs neo4j
```
