# EvidenceGraphAI Developer Setup Guide

This guide provides complete step-by-step developer onboarding for EvidenceGraphAI Phase 0.
Follow every step in order. Expected time: ~10 minutes.

---

## Prerequisites

| Tool | Required Version | Install |
|------|-----------------|---------|
| Python | `>=3.11` (tested on `3.11.8`) | [python.org](https://www.python.org/downloads/) or `py -3.11` on Windows |
| Docker Desktop | `>=24.0` with Compose v2 | [docker.com](https://docs.docker.com/get-docker/) |
| Git | Any recent version | [git-scm.com](https://git-scm.com/) |
| GNU Make (optional) | Any | Windows: `winget install GnuWin32.Make` or use script equivalents |

---

## Step-by-Step Setup

### 1. Clone & Initialize Repository

```bash
git clone <repo-url>
cd EvidenceGraphAI
```

---

### 2. Create and Activate Virtual Environment

**Windows (PowerShell):**
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> If you get an execution policy error on Windows:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

**Linux / macOS:**
```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

Verify the active interpreter:
```bash
python --version
# Expected: Python 3.11.8
```

---

### 3. Install Package and Dependencies

```bash
pip install -e .[dev]
```

This installs both runtime and development dependencies (ruff, black, mypy, pytest, pre-commit, etc.).

---

### 4. Install Pre-commit Hooks

```bash
pre-commit install
```

This registers `.pre-commit-config.yaml` hooks to run on every `git commit`.

---

### 5. Configure Environment Variables

```bash
# Linux/macOS
cp .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

Open `.env` and review. For local development, the defaults are:

| Variable | Default | Notes |
|----------|---------|-------|
| `NEO4J_URI` | `bolt://localhost:7687` | Local Docker |
| `NEO4J_USER` | `neo4j` | Default neo4j user |
| `NEO4J_PASSWORD` | `devpassword123` | Change in production |
| `POSTGRES_DSN` | `postgresql://...` | Local Docker |
| `REDIS_URL` | `redis://localhost:6379` | Local Docker |
| `MINIO_ENDPOINT` | `localhost:9000` | Local Docker |

> **Security**: `.env` is gitignored. Never commit it.

---

### 6. Start Infrastructure Services

```bash
# Linux/macOS / WSL
docker compose -f infra/docker/docker-compose.yml up -d

# Windows PowerShell equivalent (Makefile target)
# make docker-up
```

Wait ~60 seconds for all services to become healthy:

```bash
docker compose -f infra/docker/docker-compose.yml ps
```

All four services should show `(healthy)`:
```
NAME                       STATUS
evidencegraphai-neo4j      Up (healthy)
evidencegraphai-postgres   Up (healthy)
evidencegraphai-redis      Up (healthy)
evidencegraphai-minio      Up (healthy)
```

---

### 7. Seed Neo4j Ontology Constraints and Indexes

```bash
python infra/scripts/seed_ontology.py
```

This creates uniqueness constraints and indexes for all 11 node types using `IF NOT EXISTS` clauses (idempotent — safe to re-run).

Verify constraints were created:
```bash
docker compose -f infra/docker/docker-compose.yml exec neo4j \
  cypher-shell -u neo4j -p devpassword123 "SHOW CONSTRAINTS;"
```

---

### 8. Run Validation Suite

**Unit tests with coverage:**
```bash
pytest tests/unit -v --cov=core --cov-report=term-missing
# Expected: 37 passed, ≥80% coverage
```

**Integration tests (requires Docker services running):**
```bash
pytest tests/integration -v
```

**Full validation script:**
```bash
# Linux/macOS
bash scripts/validate_phase0.sh

# Windows PowerShell
.\scripts\verify_phase0.ps1
```

---

### 9. Start the API Server

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Verify endpoints:
```bash
curl http://localhost:8000/
curl http://localhost:8000/health
curl http://localhost:8000/metrics
```

---

## Available Make Targets

| Target | Command | Description |
|--------|---------|-------------|
| `make install` | `pip install -e .[dev]` | Install dependencies |
| `make lint` | `ruff check . && black --check .` | Run linters |
| `make format` | `black .` | Auto-format code |
| `make typecheck` | `mypy core api` | Static type analysis |
| `make test` | `pytest tests/` | Run all tests |
| `make test-unit` | `pytest tests/unit` | Unit tests only |
| `make test-integration` | `pytest tests/integration` | Integration tests |
| `make docker-up` | `docker compose up -d` | Start services |
| `make docker-down` | `docker compose down` | Stop services |
| `make validate` | `bash scripts/validate_phase0.sh` | Full validation |
| `make clean` | Remove build artifacts | Cleanup |

> **Windows note**: `make` requires [GnuWin32](http://gnuwin32.sourceforge.net/packages/make.htm) or WSL. Use the underlying commands directly otherwise.

---

## Troubleshooting

### Port Conflicts

If ports `7474`, `7687`, `5432`, `6379`, `9000`, or `9001` are already in use:

1. Stop competing services: `docker ps` to find conflicts.
2. Copy the override template:
   ```bash
   cp infra/docker/docker-compose.override.yml.example infra/docker/docker-compose.override.yml
   ```
3. Edit port mappings as needed.

### Docker Service Not Starting

Check service logs:
```bash
docker compose -f infra/docker/docker-compose.yml logs neo4j
docker compose -f infra/docker/docker-compose.yml logs postgres
```

### Windows AppLocker / DLL Restriction (mypy)

On some Windows systems, `mypy` may fail with `ImportError: DLL load failed while importing stats: An Application Control policy has blocked this file.`

This is an OS-level AppLocker restriction, not a code error. Type checking runs correctly in the Linux CI environment. To verify locally, use WSL or a Linux machine.

### Windows PowerShell Activation Error

If `.\.venv\Scripts\Activate.ps1` is blocked:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Database Connection Failures

```bash
# Check service health
docker compose -f infra/docker/docker-compose.yml ps

# View specific service logs
docker compose -f infra/docker/docker-compose.yml logs neo4j
docker compose -f infra/docker/docker-compose.yml logs postgres
```

### Neo4j Browser UI

Access at: `http://localhost:7474`
- Username: `neo4j`
- Password: value of `NEO4J_PASSWORD` in `.env`
