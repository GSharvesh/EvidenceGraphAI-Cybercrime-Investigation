# Sandbox Resource Cleanup & Safety

## Idempotent Teardown Mechanism

Sandbox execution involves temporary Docker containers, volumes, network bridges, and local artifact files. The `SandboxCleanup` utility (`core/agents/sandbox_replay/orchestrator.py:sandbox_cleanup`) ensures that no lingering processes or files remain across replays.

## Teardown Guarantees

1. **Graceful Container Termination:** Stops all running sandbox containers (`docker compose down -v`).
2. **Volume Cleanup:** Removes transient capture directories and unlinks unpersisted PCAP / log files.
3. **Emergency Cleanup on Failure:** Invoked within `finally` blocks across all `SandboxReplayAgent.replay()` invocations, ensuring safety even when scripts timeout or exceptions occur.
4. **Standalone CLI Invocation:** Developers can trigger emergency cleanup via:
   ```bash
   python -c "from core.agents.sandbox_replay.orchestrator import sandbox_cleanup; sandbox_cleanup()"
   ```
