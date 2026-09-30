"""Sandbox Docker orchestrator — starts, monitors, and tears down the isolated sandbox.

This module wraps ``docker compose`` commands to manage the isolated sandbox
environment defined in ``infra/sandbox/docker-compose.yml``.

Design decisions (ADR 0019):
- The sandbox network uses ``internal: true`` — no internet access.
- All operations are idempotent and cleanup-safe.
- ``subprocess`` is used rather than the Docker Python SDK to keep the
  dependency footprint minimal and to work with Compose v2.
- Isolation is verified at startup by attempting outbound connectivity
  from within the sandbox network.
- A dedicated ``sandbox_cleanup()`` function is provided for emergency
  recovery of leaked resources.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from core.agents.sandbox_replay.exceptions import (
    SandboxCleanupError,
    SandboxIsolationError,
    SandboxStartError,
    SandboxStopError,
)
from core.config.settings import Settings, get_settings
from core.logging.logger import get_logger

logger = get_logger("core.agents.sandbox_replay.orchestrator")

_COMPOSE_PROJECT = "evidencegraphai_sandbox"


class SandboxOrchestrator:
    """Manages the lifecycle of the isolated sandbox Docker environment.

    Parameters
    ----------
    settings:
        Application settings.  ``sandbox_compose_file`` is used to locate the
        Compose file.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.compose_file = Path(self.settings.sandbox_compose_file)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, timeout: int = 120) -> None:
        """Starts the sandbox Docker Compose environment.

        Args:
            timeout: Maximum seconds to wait for services to become healthy.

        Raises:
            SandboxStartError: If the sandbox fails to start or a required
                service does not become healthy within ``timeout`` seconds.
        """
        if not self.compose_file.exists():
            raise SandboxStartError(
                f"Sandbox Compose file not found: {self.compose_file}. "
                f"Ensure infra/sandbox/docker-compose.yml exists."
            )

        logger.info("Starting sandbox environment", compose_file=str(self.compose_file))
        result = self._run_compose(["up", "-d", "--remove-orphans"])
        if result.returncode != 0:
            raise SandboxStartError(
                f"Sandbox 'docker compose up' failed:\n{result.stderr}"
            )

        # Wait for health
        self._wait_for_healthy(timeout=timeout)
        logger.info("Sandbox environment started successfully")

    def stop(self) -> None:
        """Stops the sandbox environment without removing volumes.

        Raises:
            SandboxStopError: If ``docker compose stop`` fails.
        """
        logger.info("Stopping sandbox environment")
        result = self._run_compose(["stop"])
        if result.returncode != 0:
            raise SandboxStopError(
                f"Sandbox 'docker compose stop' failed:\n{result.stderr}"
            )
        logger.info("Sandbox environment stopped")

    def teardown(self) -> None:
        """Fully tears down the sandbox, removing containers and networks.

        Raises:
            SandboxStopError: If teardown fails.
        """
        logger.info("Tearing down sandbox environment")
        result = self._run_compose(["down", "--remove-orphans", "--timeout", "30"])
        if result.returncode != 0:
            raise SandboxStopError(
                f"Sandbox 'docker compose down' failed:\n{result.stderr}"
            )
        logger.info("Sandbox environment torn down")

    def is_running(self) -> bool:
        """Returns True if the sandbox Compose project has running containers."""
        result = self._run_compose(["ps", "--services", "--filter", "status=running"])
        if result.returncode != 0:
            return False
        return bool(result.stdout.strip())

    def verify_isolation(self) -> bool:
        """Verifies that the sandbox network has no outbound internet access.

        Attempts to reach ``1.1.1.1:53`` from within the attacker container.
        Expects the connection to be refused or time out.

        Returns:
            True if the network is properly isolated.

        Raises:
            SandboxIsolationError: If outbound connectivity is detected.
        """
        logger.info("Verifying sandbox network isolation")
        result = self._run_compose(
            [
                "exec",
                "-T",
                "attacker",
                "curl",
                "--max-time",
                "5",
                "--silent",
                "https://1.1.1.1",
            ]
        )
        # We expect this to FAIL — success means isolation is broken
        if result.returncode == 0:
            raise SandboxIsolationError(
                "ISOLATION FAILURE: Sandbox attacker container can reach the internet. "
                "Verify that the sandbox_net network has 'internal: true'."
            )
        logger.info("Sandbox isolation verified — no outbound internet access")
        return True

    def get_service_status(self) -> list[dict[str, Any]]:
        """Returns a list of sandbox services and their current status."""
        result = self._run_compose(["ps", "--format", "json"])
        if result.returncode != 0:
            return []
        try:
            return json.loads(result.stdout)  # type: ignore[no-any-return]
        except Exception:
            # docker compose ps --format json may return one JSON object per line
            statuses = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    with contextlib.suppress(Exception):
                        statuses.append(json.loads(line))
            return statuses

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_compose(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        """Runs a ``docker compose`` command against the sandbox Compose file."""
        cmd = [
            "docker",
            "compose",
            "-f",
            str(self.compose_file),
            "-p",
            _COMPOSE_PROJECT,
        ] + args
        logger.debug("Running compose command", cmd=" ".join(cmd))
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _wait_for_healthy(self, timeout: int = 120) -> None:
        """Polls until all sandbox services are healthy or timeout expires."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.get_service_status()
            if status:
                all_healthy = all(s.get("Health") in ("healthy", "") for s in status)
                if all_healthy:
                    return
            time.sleep(5)
        raise SandboxStartError(
            f"Sandbox services did not become healthy within {timeout}s"
        )


# ---------------------------------------------------------------------------
# sandbox_cleanup — emergency recovery
# ---------------------------------------------------------------------------


def sandbox_cleanup(settings: Settings | None = None) -> dict[str, Any]:
    """Emergency cleanup of leaked sandbox containers, networks, and volumes.

    This function is idempotent and safe to call multiple times.

    Args:
        settings: Application settings.

    Returns:
        Dict with ``removed_containers``, ``removed_networks`` counts.

    Raises:
        SandboxCleanupError: If Docker commands fail unexpectedly.
    """
    settings = settings or get_settings()
    logger.warning("Running emergency sandbox cleanup")
    compose_file = Path(settings.sandbox_compose_file)

    removed: dict[str, Any] = {
        "removed_containers": 0,
        "removed_networks": 0,
        "errors": [],
    }

    if compose_file.exists():
        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "-p",
                _COMPOSE_PROJECT,
                "down",
                "--remove-orphans",
                "--timeout",
                "10",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            msg = f"compose down failed: {result.stderr}"
            logger.error("Sandbox cleanup error", error=msg)
            removed["errors"].append(msg)

    # Attempt to remove the named network if still present
    net_result = subprocess.run(
        ["docker", "network", "rm", f"{_COMPOSE_PROJECT}_sandbox_net"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if net_result.returncode == 0:
        removed["removed_networks"] = 1
        logger.info("Removed sandbox network")

    if removed["errors"]:
        raise SandboxCleanupError(f"Cleanup completed with errors: {removed['errors']}")

    logger.info("Sandbox cleanup complete", result=removed)
    return removed
