#!/usr/bin/env python3
"""
EvidenceGraphAI — Local Development Teardown Script

Stops running local FastAPI/Uvicorn processes and optionally halts
Docker Compose infrastructure services.

Usage:
    python scripts/stop_local.py [OPTIONS]

Options:
    --help      Show this help message and exit
    --docker    Stop Docker Compose infrastructure services
    --infra     Alias for --docker
    --all       Stop FastAPI and all Docker infrastructure services
"""

import argparse
import os
import signal
import subprocess
import sys
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "infra" / "docker" / "docker-compose.yml"
PID_FILE = REPO_ROOT / ".evidencegraphai_api.pid"

# ANSI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def log(msg: str, color: str = "") -> None:
    print(f"{color}{msg}{RESET}")


def stop_fastapi_process() -> None:
    log("Stopping EvidenceGraphAI API / Uvicorn processes...", BOLD)
    stopped = False

    # 1. Check PID file
    if PID_FILE.exists():
        try:
            pid_str = PID_FILE.read_text(encoding="utf-8").strip()
            if pid_str.isdigit():
                pid = int(pid_str)
                log(
                    f"  [INFO] Found recorded PID {pid} from .evidencegraphai_api.pid",
                    CYAN,
                )
                try:
                    if sys.platform == "win32":
                        # Windows taskkill
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(pid)],
                            capture_output=True,
                            check=False,
                        )
                    else:
                        os.kill(pid, signal.SIGTERM)
                    stopped = True
                    log(f"  [OK] Terminated FastAPI process (PID {pid}).", GREEN)
                except Exception as e:
                    log(f"  [INFO] Process {pid} was not running: {e}", YELLOW)
        except Exception as e:
            log(f"  [WARNING] Could not read PID file: {e}", YELLOW)
        finally:
            PID_FILE.unlink(missing_ok=True)

    # 2. Targeted cleanup of uvicorn running on port 8000 (if still listening)
    if sys.platform == "win32":
        cmd = (
            "Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | "
            "ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue; "
            'Write-Host "Stopped process on port 8000 (PID $($_.OwningProcess))" }'
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.stdout.strip():
                log(f"  [OK] {res.stdout.strip()}", GREEN)
                stopped = True
        except Exception as e:
            log(f"  [WARNING] Port check error: {e}", YELLOW)
    else:
        try:
            subprocess.run(
                ["pkill", "-f", "uvicorn api.main:app"],
                capture_output=True,
                check=False,
            )
            stopped = True
        except Exception:
            pass

    if not stopped and not PID_FILE.exists():
        log("  [OK] No active FastAPI processes found.", GREEN)


def stop_docker_infrastructure() -> None:
    log("\nStopping Docker Compose infrastructure services...", BOLD)
    try:
        res = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "down"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            log(
                "  [OK] Docker infrastructure services stopped (volumes preserved).",
                GREEN,
            )
        else:
            log(
                f"  [ERROR] Docker Compose stop failed:\n{res.stderr or res.stdout}",
                RED,
            )
    except Exception as e:
        log(f"  [ERROR] Could not stop Docker: {e}", RED)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EvidenceGraphAI Local Development Teardown"
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        default=False,
        help="Stop Docker Compose infrastructure services (Postgres, Neo4j, Redis, MinIO)",
    )
    parser.add_argument(
        "--infra",
        action="store_true",
        default=False,
        help="Alias for --docker",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        default=False,
        help="Stop FastAPI and all Docker infrastructure services",
    )
    args = parser.parse_args()

    stop_fastapi_process()

    stop_infra = args.docker or args.infra or args.all
    if stop_infra:
        stop_docker_infrastructure()
    else:
        log("\nNote: Docker infrastructure services remain running.", CYAN)
        log("To stop Docker containers as well, run: .\\stop_local.bat --docker", CYAN)


if __name__ == "__main__":
    main()
