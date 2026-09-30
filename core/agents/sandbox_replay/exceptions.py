"""Custom exceptions for the Sandbox Replay Agent."""


class SandboxError(Exception):
    """Base exception for all Sandbox Replay Agent errors."""


class SandboxStartError(SandboxError):
    """Raised when the sandbox Docker network fails to start."""


class SandboxStopError(SandboxError):
    """Raised when the sandbox fails to shut down cleanly."""


class SandboxIsolationError(SandboxError):
    """Raised when sandbox internet isolation verification fails."""


class SandboxTimeoutError(SandboxError):
    """Raised when a sandbox replay exceeds the configured timeout."""


class SandboxCleanupError(SandboxError):
    """Raised when cleanup of leaked sandbox resources fails."""


class ReplayScriptError(SandboxError):
    """Raised when an attack replay script fails or produces no telemetry."""


class TelemetryIngestError(SandboxError):
    """Raised when sandbox telemetry cannot be ingested via Phase 2's ingestor."""


class ReplaySessionNotFoundError(SandboxError):
    """Raised when a requested replay session ID does not exist."""
