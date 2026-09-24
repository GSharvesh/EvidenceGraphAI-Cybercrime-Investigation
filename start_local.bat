@echo off
title EvidenceGraphAI - Full Local Development Environment
cd /d "%~dp0"

echo ===============================================================================
echo            EvidenceGraphAI - Full Local Development Environment
echo ===============================================================================
echo(

REM -----------------------------------------------------------------------------
REM Step 1: Environment Configuration (.env)
REM -----------------------------------------------------------------------------
echo [1/7] Checking environment configuration...
if not exist ".env" (
    if exist ".env.example" (
        echo [INFO] .env not found. Creating .env from .env.example...
        copy .env.example .env >nul
        echo [OK] .env created successfully.
    ) else (
        echo [WARNING] Neither .env nor .env.example found.
    )
) else (
    echo [OK] .env configuration file found.
)
echo(

REM -----------------------------------------------------------------------------
REM Step 2: Verify Docker Daemon and Start Infrastructure Services
REM -----------------------------------------------------------------------------
echo [2/7] Checking Docker daemon and starting services...
docker info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker is not running or not found in PATH.
    echo Please start Docker Desktop and run this script again.
    echo(
    pause
    exit /b 1
)

echo Starting Docker Compose services [Neo4j, Postgres, Redis, MinIO]...
docker compose -f infra/docker/docker-compose.yml up -d
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to start Docker containers.
    pause
    exit /b 1
)

echo(
echo Active Docker Containers:
docker compose -f infra/docker/docker-compose.yml ps
echo [OK] Docker infrastructure services are up and running.
echo(

REM -----------------------------------------------------------------------------
REM Step 3: Verify Python Virtual Environment and Dependencies
REM -----------------------------------------------------------------------------
echo [3/7] Verifying Python virtual environment [.venv]...
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at .venv\Scripts\python.exe
    echo Please create and install the virtual environment:
    echo   python -m venv .venv
    echo   .\.venv\Scripts\pip install -e .[dev]
    echo(
    pause
    exit /b 1
)

echo [OK] Python runtime:
.\.venv\Scripts\python.exe --version

echo Ensuring project package is installed in editable mode...
.\.venv\Scripts\pip.exe install -q -e . --no-deps >nul 2>&1
echo [OK] Package installed in editable mode.
echo(

REM -----------------------------------------------------------------------------
REM Step 4: Seed Neo4j Ontology Constraints and Indexes
REM -----------------------------------------------------------------------------
echo [4/7] Initializing Neo4j ontology constraints and indexes...
.\.venv\Scripts\python.exe infra/scripts/seed_ontology.py
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Ontology constraint initialization encountered an issue; proceeding...
) else (
    echo [OK] Neo4j constraints and indexes verified online.
)
echo(

REM -----------------------------------------------------------------------------
REM Step 5: Seed Sample Graph Data [Phase 1 Log4Shell Scenario]
REM -----------------------------------------------------------------------------
echo [5/7] Seeding sample multi-stage attack graph data into Neo4j...
.\.venv\Scripts\python.exe scripts/seed_sample_graph.py
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Sample graph seeding encountered an issue; proceeding...
) else (
    echo [OK] Sample graph seeded successfully [17 nodes, 18 relationships].
)
echo(

REM -----------------------------------------------------------------------------
REM Step 6: Print Complete Service Directory and Endpoints
REM -----------------------------------------------------------------------------
echo ===============================================================================
echo                        AVAILABLE SERVICES AND DOCUMENTS
echo ===============================================================================
echo(
echo   [Visual Frontend and Viewers]
echo   * Phase 1 Developer Graph Viewer : http://localhost:8000/dev/viewer
echo   * Interactive Swagger UI Docs    : http://localhost:8000/docs
echo   * ReDoc API Documentation        : http://localhost:8000/redoc
echo   * OpenAPI JSON Schema            : http://localhost:8000/openapi.json
echo(
echo   [Graph and Analysis Endpoints]
echo   * Root Metadata                  : http://localhost:8000/
echo   * Graph Summary Stats            : http://localhost:8000/graph/stats
echo   * Graph JSON-LD / D3 Export      : http://localhost:8000/graph/export
echo   * 7-Rule Graph Validation Report : http://localhost:8000/graph/validate
echo(
echo   [Infrastructure Consoles]
echo   * Neo4j Browser Console          : http://localhost:7474 - user: neo4j / pass: evidencegraphai_dev
echo   * MinIO Object Storage Console   : http://localhost:9001 - user: minioadmin / pass: minioadmin
echo(
echo   [Health and Observability]
echo   * Health Check Endpoint          : http://localhost:8000/health
echo   * Prometheus Metrics             : http://localhost:8000/metrics
echo(
echo ===============================================================================
echo(

REM -----------------------------------------------------------------------------
REM Step 7: Open Frontend and Docs in Browser, then Start FastAPI Server
REM -----------------------------------------------------------------------------
echo [6/7] Launching Developer Graph Viewer and Swagger UI in browser...
start http://localhost:8000/dev/viewer
start http://localhost:8000/docs

echo [7/7] Starting Uvicorn development server on http://0.0.0.0:8000 [reload enabled]...
echo Press Ctrl+C in this terminal to stop the server.
echo(

.\.venv\Scripts\python.exe -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

echo(
echo FastAPI server has stopped.
pause
