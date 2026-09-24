@echo off
setlocal enabledelayedexpansion

title EvidenceGraphAI - Local Development Environment
cd /d "%~dp0"

echo ===============================================================================
echo                EvidenceGraphAI - Local Environment Launcher
echo ===============================================================================
echo.

:: 1. Verify Docker is available
echo [1/5] Checking Docker daemon status...
docker info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker is not running or not found in PATH.
    echo Please start Docker Desktop and run this script again.
    echo.
    pause
    exit /b 1
)
echo [OK] Docker daemon is running.
echo.

:: 2. Start / verify background infrastructure services
echo [2/5] Starting background containers (Neo4j, Postgres, Redis, MinIO)...
docker compose -f infra/docker/docker-compose.yml up -d
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to start Docker containers.
    pause
    exit /b 1
)
echo [OK] Docker services are up.
echo.

:: 3. Check Python Virtual Environment
echo [3/5] Verifying Python virtual environment (.venv)...
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at .venv\Scripts\python.exe
    echo Please create and install dependencies first:
    echo   python -m venv .venv
    echo   .\.venv\Scripts\pip install -e .[dev]
    echo.
    pause
    exit /b 1
)
echo [OK] Python environment verified.
echo.

:: 4. Seed ontology indexes and constraints
echo [4/5] Initializing Neo4j ontology constraints and indexes...
.\.venv\Scripts\python.exe infra/scripts/seed_ontology.py
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Ontology seeding had issues; continuing startup...
) else (
    echo [OK] Ontology schema and indexes verified online.
)
echo.

:: 5. Print Available Documentation and Endpoints
echo ===============================================================================
echo                        AVAILABLE SERVICES AND DOCUMENTS
echo ===============================================================================
echo.
echo   [API Documentation]
echo   * Interactive Swagger UI : http://127.0.0.1:8000/docs
echo   * ReDoc Documentation    : http://127.0.0.1:8000/redoc
echo   * OpenAPI JSON Schema    : http://127.0.0.1:8000/openapi.json
echo.
echo   [Applications and Tools]
echo   * Developer Graph Viewer : http://127.0.0.1:8000/dev/viewer
echo   * Neo4j Browser Console  : http://localhost:7474 (neo4j / evidencegraphai_dev)
echo   * MinIO Storage Console  : http://localhost:9001 (minioadmin / minioadmin)
echo.
echo   [Health and Telemetry]
echo   * Health Check Endpoint  : http://127.0.0.1:8000/health
echo   * Prometheus Metrics     : http://127.0.0.1:8000/metrics
echo.
echo ===============================================================================
echo.
echo [5/5] Launching browser to API documentation and starting FastAPI server...
echo.

:: Open documentation in default browser after a short delay in background
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:8000/docs"

:: Start Uvicorn development server
.\.venv\Scripts\uvicorn.exe api.main:app --host 127.0.0.1 --port 8000 --reload

echo.
echo FastAPI server has stopped.
pause
