#!/usr/bin/env python3
"""
EvidenceGraphAI — Local Development Environment Orchestrator

Starts infrastructure services (PostgreSQL, Neo4j, Redis, MinIO),
runs migrations and schema constraints, optionally seeds sample data,
launches FastAPI/Uvicorn, verifies /health, and opens the developer portal.

Usage:
    python scripts/start_local.py [OPTIONS]

Options:
    --help          Show this help message and exit
    --seed          Seed sample attack graph and forensic artifacts
    --no-browser    Do not automatically open browser windows
    --no-docker     Skip Docker Compose startup (assume infra is already running)
    --no-reload     Start Uvicorn without auto-reload
    --host HOST     Host address to bind the API server (default: 127.0.0.1)
    --port PORT     Port to bind the API server (default: 8000)
"""

import argparse
import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "infra" / "docker" / "docker-compose.yml"
ENV_FILE = REPO_ROOT / ".env"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
PID_FILE = REPO_ROOT / ".evidencegraphai_api.pid"

# ANSI Colors (simple, standard)
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


def log_step(step: str, title: str) -> None:
    print(f"\n{BOLD}[{step}] {title}{RESET}")


def log_ok(msg: str) -> None:
    print(f"  {GREEN}[OK]{RESET} {msg}")


def log_info(msg: str) -> None:
    print(f"  {CYAN}[INFO]{RESET} {msg}")


def log_wait(msg: str) -> None:
    print(f"  {YELLOW}[WAIT]{RESET} {msg}")


def log_error(msg: str) -> None:
    print(f"  {RED}[ERROR]{RESET} {msg}")


def print_banner() -> None:
    print(
        f"""{CYAN}{BOLD}===================================================
 EvidenceGraphAI — Local Development Environment
==================================================={RESET}"""
    )


@dataclass
class ServiceCheck:
    name: str
    host: str
    port: int
    container_name: str


SERVICES = [
    ServiceCheck("PostgreSQL", "127.0.0.1", 5432, "evidencegraphai-postgres"),
    ServiceCheck("Neo4j", "127.0.0.1", 7687, "evidencegraphai-neo4j"),
    ServiceCheck("Redis", "127.0.0.1", 6379, "evidencegraphai-redis"),
    ServiceCheck("MinIO", "127.0.0.1", 9000, "evidencegraphai-minio"),
]


def check_tcp_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_docker_logs(container_name: str, tail: int = 20) -> str:
    try:
        res = subprocess.run(
            ["docker", "logs", "--tail", str(tail), container_name],
            capture_output=True,
            text=True,
            check=False,
        )
        return res.stdout + "\n" + res.stderr
    except Exception as e:
        return f"Failed to retrieve docker logs: {e}"


def check_environment() -> None:
    log_step("1/7", "Environment Check")

    # 1. Check Python version
    log_ok(f"Python {sys.version.split()[0]} available.")

    # 2. Check / Create .env
    if not ENV_FILE.exists():
        if ENV_EXAMPLE.exists():
            import shutil

            shutil.copy(ENV_EXAMPLE, ENV_FILE)
            log_info("Created .env from .env.example (preserving defaults).")
        else:
            log_info("Neither .env nor .env.example found; continuing with defaults.")
    else:
        log_ok(".env configuration file found.")

    # 3. Check virtual environment
    venv_python = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    if sys.platform != "win32":
        venv_python = REPO_ROOT / ".venv" / "bin" / "python"

    if not venv_python.exists():
        log_info("Creating Python virtual environment in .venv...")
        res = subprocess.run([sys.executable, "-m", "venv", str(REPO_ROOT / ".venv")])
        if res.returncode != 0:
            log_error("Failed to create virtual environment.")
            sys.exit(1)
        log_ok("Virtual environment created.")

        log_info("Installing package dependencies (pip install -e .)...")
        pip_bin = str(venv_python.parent / "pip")
        install_res = subprocess.run(
            [pip_bin, "install", "-e", "."], cwd=str(REPO_ROOT)
        )
        if install_res.returncode != 0:
            log_error("Failed to install package dependencies.")
            sys.exit(1)
        log_ok("Package installed in editable mode.")
    else:
        log_ok("Virtual environment verified.")


def check_and_start_docker(no_docker: bool) -> None:
    log_step("2/7", "Infrastructure")
    if no_docker:
        log_info("--no-docker specified: Skipping Docker Compose management.")
        return

    # Verify docker is installed and daemon is running
    try:
        ver_res = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        if ver_res.returncode != 0:
            log_error("Command 'docker --version' failed.")
            log_error("Docker is not installed or not in system PATH.")
            sys.exit(1)

        info_res = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            check=False,
        )
        if info_res.returncode != 0:
            log_error("Command 'docker info' failed.")
            log_error(
                "Docker daemon is not running. Please start Docker Desktop and retry."
            )
            sys.exit(1)
    except FileNotFoundError:
        log_error("Command 'docker' not found in PATH.")
        log_error(
            "Please install and start Docker Desktop: https://www.docker.com/products/docker-desktop/"
        )
        sys.exit(1)

    log_info(f"Starting Docker Compose services ({COMPOSE_FILE.name})...")
    up_res = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"],
        capture_output=True,
        text=True,
        check=False,
    )
    if up_res.returncode != 0:
        log_error(
            f"Failed to start Docker Compose services.\nOutput:\n{up_res.stderr or up_res.stdout}"
        )
        sys.exit(1)
    log_ok("Docker Compose services up and running.")


def wait_for_infrastructure(timeout: int = 120) -> None:
    log_step("3/7", "Health Checks")
    start_time = time.time()

    for svc in SERVICES:
        log_wait(f"Waiting for {svc.name} ({svc.host}:{svc.port})...")
        while time.time() - start_time < timeout:
            if check_tcp_port(svc.host, svc.port, timeout=1.0):
                log_ok(f"{svc.name} is ready.")
                break
            time.sleep(1.0)
        else:
            log_error(f"{svc.name} failed to become ready within {timeout}s.")
            log_error(f"Connection check to {svc.host}:{svc.port} failed.")
            logs = get_docker_logs(svc.container_name, tail=20)
            print(
                f"\n--- Last 20 lines of Docker logs for {svc.container_name} ---\n{logs}\n---"
            )
            sys.exit(1)


def run_database_migrations_and_schema() -> None:
    log_step("4/7", "Migrations & Schema")
    python_bin = sys.executable

    # 1. PostgreSQL migrations
    log_info("Running PostgreSQL migrations (scripts/migrate_postgres.py)...")
    migrate_script = REPO_ROOT / "scripts" / "migrate_postgres.py"
    if migrate_script.exists():
        res = subprocess.run(
            [python_bin, str(migrate_script)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if res.returncode != 0:
            log_error(
                f"PostgreSQL migration failed.\nCommand: {python_bin} {migrate_script}\nOutput:\n{res.stderr or res.stdout}"
            )
            sys.exit(1)
        log_ok("PostgreSQL migrations applied successfully.")
    else:
        log_error(f"Migration script not found: {migrate_script}")
        sys.exit(1)

    # 2. Neo4j ontology constraints & indexes
    log_info(
        "Initializing Neo4j ontology constraints (infra/scripts/seed_ontology.py)..."
    )
    seed_ontology_script = REPO_ROOT / "infra" / "scripts" / "seed_ontology.py"
    if seed_ontology_script.exists():
        res = subprocess.run(
            [python_bin, str(seed_ontology_script)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if res.returncode != 0:
            log_error(
                f"Neo4j ontology constraints initialization failed.\nCommand: {python_bin} {seed_ontology_script}\nOutput:\n{res.stderr or res.stdout}"
            )
            sys.exit(1)
        log_ok("Neo4j ontology constraints and indexes verified.")
    else:
        log_info("Neo4j ontology script not found; skipping.")

    # 3. MinIO artifact storage bucket setup
    log_info("Ensuring MinIO artifact storage bucket...")
    try:
        # Import and run BucketManager directly or via python inline
        setup_minio_cmd = (
            "from core.storage.bucket_manager import BucketManager; "
            "BucketManager().setup_artifact_storage()"
        )
        res = subprocess.run(
            [python_bin, "-c", setup_minio_cmd],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if res.returncode != 0:
            log_error(
                f"MinIO bucket initialization failed.\nOutput:\n{res.stderr or res.stdout}"
            )
            sys.exit(1)
        log_ok("MinIO artifact storage bucket ready.")
    except Exception as e:
        log_error(f"MinIO bucket setup error: {e}")
        sys.exit(1)


def seed_sample_data(seed: bool) -> None:
    log_step("5/7", "Seed")
    if not seed:
        log_info(
            "Skipping sample data seeding (run with --seed to seed sample graph & artifacts)."
        )
        return

    python_bin = sys.executable
    log_info("Seeding sample data (--seed supplied)...")

    # 1. Seed sample graph
    seed_graph_script = REPO_ROOT / "scripts" / "seed_sample_graph.py"
    if seed_graph_script.exists():
        log_info("Seeding sample multi-stage attack graph...")
        res = subprocess.run(
            [python_bin, str(seed_graph_script)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if res.returncode != 0:
            log_error(
                f"Sample graph seeding failed.\nCommand: {python_bin} {seed_graph_script}\nOutput:\n{res.stderr or res.stdout}"
            )
            sys.exit(1)
        log_ok("Sample attack graph seeded.")

    # 2. Seed sample artifacts
    seed_artifacts_script = REPO_ROOT / "scripts" / "seed_sample_artifacts.py"
    if seed_artifacts_script.exists():
        log_info("Seeding sample forensic artifacts...")
        res = subprocess.run(
            [python_bin, str(seed_artifacts_script)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if res.returncode != 0:
            log_error(
                f"Sample artifacts seeding failed.\nCommand: {python_bin} {seed_artifacts_script}\nOutput:\n{res.stderr or res.stdout}"
            )
            sys.exit(1)
        log_ok("Sample forensic artifacts seeded.")

    log_ok("Sample data seeded.")


def start_fastapi(host: str, port: int, no_reload: bool) -> subprocess.Popen:
    log_step("6/7", "API")

    # Check if port is already in use
    health_url = f"http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}/health"
    if check_tcp_port("127.0.0.1", port, timeout=0.5):
        try:
            req = urllib.request.urlopen(health_url, timeout=2.0)
            if req.status == 200:
                log_info(
                    f"Port {port} is already running a healthy EvidenceGraphAI API instance."
                )
                log_info("Reusing running API instance.")
                # Return dummy object or monitor
        except Exception:
            log_error(
                f"Port {port} is occupied by an unresponsive or conflicting process."
            )
            log_error(
                f"Please run '.\\stop_local.bat' or free port {port} before starting."
            )
            sys.exit(1)

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "api.main:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if not no_reload:
        cmd.append("--reload")

    log_info(
        f"Starting Uvicorn server ({host}:{port}, reload={'disabled' if no_reload else 'enabled'})..."
    )
    proc = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
        stdout=None,
        stderr=None,
    )

    # Write PID file
    try:
        PID_FILE.write_text(str(proc.pid), encoding="utf-8")
    except Exception as e:
        log_info(f"Note: Could not write PID file: {e}")

    return proc


def wait_for_api_health(
    host: str, port: int, proc: subprocess.Popen | None, timeout: int = 60
) -> None:
    health_url = f"http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}/health"
    log_wait(f"Waiting for API to become healthy ({health_url})...")
    start_time = time.time()

    while time.time() - start_time < timeout:
        if proc and proc.poll() is not None:
            log_error(
                f"FastAPI process exited prematurely with code {proc.returncode}."
            )
            if PID_FILE.exists():
                PID_FILE.unlink(missing_ok=True)
            sys.exit(1)

        try:
            req = urllib.request.urlopen(health_url, timeout=1.5)
            if req.status == 200:
                log_ok("API healthy.")
                return
        except Exception:
            pass
        time.sleep(0.5)

    log_error(f"API health check timed out after {timeout}s.")
    log_error(f"URL: {health_url}")
    if proc:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    if PID_FILE.exists():
        PID_FILE.unlink(missing_ok=True)
    sys.exit(1)


def launch_browser_and_print_urls(host: str, port: int, no_browser: bool) -> None:
    log_step("7/7", "Browser & Directory")
    base_url = f"http://localhost:{port}"
    portal_url = f"{base_url}/dev/ingestion-portal"
    viewer_url = f"{base_url}/dev/viewer"
    docs_url = f"{base_url}/docs"
    redoc_url = f"{base_url}/redoc"

    print(
        f"""
{CYAN}{BOLD}===============================================================================
                        AVAILABLE SERVICES & ENDPOINTS
==============================================================================={RESET}

  {BOLD}[Interactive Developer Frontends]{RESET}
  * Forensic Ingest Console : {MAGENTA}{portal_url}{RESET} (Primary)
  * Graph Viewer            : {MAGENTA}{viewer_url}{RESET}
  * API Docs (Swagger UI)   : {MAGENTA}{docs_url}{RESET}
  * ReDoc Documentation     : {MAGENTA}{redoc_url}{RESET}

  {BOLD}[Real-Time SSE Event Streams (Phase 2.1)]{RESET}
  * Ledger Stream           : {CYAN}{base_url}/sse/ledger{RESET}
  * Graph Stream            : {CYAN}{base_url}/sse/graph{RESET}
  * Health Stream           : {CYAN}{base_url}/sse/status{RESET}

  {BOLD}[Forensic Ingestion & Custody Endpoints]{RESET}
  * Multipart Ingestion API : POST {base_url}/ingest
  * Custody Ledger Trail    : GET  {base_url}/ledger
  * Ledger Verifier         : GET  {base_url}/ledger/verify
  * Section 65B Manifest    : POST {base_url}/manifests/generate

  {BOLD}[Infrastructure Consoles]{RESET}
  * Neo4j Browser           : http://localhost:7474 (neo4j / evidencegraphai_dev)
  * MinIO Storage Console   : http://localhost:9001 (minioadmin / minioadmin)

{CYAN}==============================================================================={RESET}
"""
    )

    if not no_browser:
        log_info("Opening browser tabs...")

        tabs = [
            ("Forensic Ingest Console", portal_url),
            ("Graph Viewer", viewer_url),
            ("Swagger API", docs_url),
        ]

        for name, url in tabs:
            try:
                webbrowser.open(url)
                log_ok(f"{name}\n      {url}")
                time.sleep(0.5)
            except Exception as e:
                log_info(f"Note: Could not open {name} in browser: {e}")

        print(f"\n  {GREEN}{BOLD}EvidenceGraphAI is running.{RESET}")
    else:
        log_info("--no-browser specified: Skipping browser auto-launch.")
        print(f"\n  {GREEN}{BOLD}EvidenceGraphAI is running.{RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EvidenceGraphAI Local Development Orchestrator"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address to bind the API server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the API server (default: 8000)",
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        default=False,
        help="Seed sample attack graph and forensic artifacts into database",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        default=False,
        help="Do not automatically open browser windows",
    )
    parser.add_argument(
        "--no-docker",
        action="store_true",
        default=False,
        help="Skip Docker Compose startup and management (use already-running infrastructure)",
    )
    parser.add_argument(
        "--no-reload",
        action="store_true",
        default=False,
        help="Start Uvicorn without auto-reload",
    )
    args = parser.parse_args()

    os.chdir(str(REPO_ROOT))
    print_banner()

    check_environment()
    check_and_start_docker(no_docker=args.no_docker)
    wait_for_infrastructure(timeout=120)
    run_database_migrations_and_schema()
    seed_sample_data(seed=args.seed)

    api_proc = start_fastapi(host=args.host, port=args.port, no_reload=args.no_reload)
    wait_for_api_health(host=args.host, port=args.port, proc=api_proc, timeout=60)

    launch_browser_and_print_urls(
        host=args.host, port=args.port, no_browser=args.no_browser
    )

    log_info("FastAPI process running. Press Ctrl+C to stop.\n")

    # Handle Ctrl+C cleanly
    def handle_signal(sig, frame):
        print(f"\n{YELLOW}[INFO] Stopping FastAPI server...{RESET}")
        if api_proc:
            try:
                api_proc.terminate()
                api_proc.wait(timeout=5)
            except Exception:
                with contextlib.suppress(Exception):
                    api_proc.kill()
        if PID_FILE.exists():
            PID_FILE.unlink(missing_ok=True)
        print(
            f"{GREEN}[OK] FastAPI server stopped. (Docker infrastructure left running){RESET}"
        )
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        # Keep process alive and monitor child
        while True:
            if api_proc.poll() is not None:
                log_info("FastAPI process terminated.")
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        handle_signal(signal.SIGINT, None)
    finally:
        if PID_FILE.exists():
            PID_FILE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
