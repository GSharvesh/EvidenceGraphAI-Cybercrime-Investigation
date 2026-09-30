# Sandbox Architecture

## Topology

The Phase 3 sandbox environment runs in a dedicated Docker network isolated from the external internet (`internal: true`).

```
+-------------------------------------------------------------------+
|                        Docker Network                             |
|                        (internal: true)                           |
|                                                                   |
|   +-------------------+                     +-----------------+   |
|   |                   |   attack traffic    |                 |   |
|   |     attacker      | ------------------> |     victim      |   |
|   |                   |                     |                 |   |
|   +-------------------+                     +-----------------+   |
|             \                                     /               |
|              \                                   /                |
|               \                                 /                 |
|                v                               v                  |
|             +------------------------------------+                |
|             |          collector                 |                |
|             |          (tcpdump sidecar)         |                |
|             +------------------------------------+                |
|                               |                                   |
+-------------------------------|-----------------------------------+
                                v
                      Mounted Volume (/captures)
                                |
                                v
                     MinIO / Custody Ledger
```

## Security Controls

1. **No WAN Egress:** `internal: true` prevents malware or exploit payloads from phoning home or reaching real-world infrastructure.
2. **Resource Limits:** Docker memory and CPU limits prevent denial-of-service on the host system.
3. **Automated Teardown:** `SandboxCleanup` ensures all containers, volumes, and temporary files are removed after session completion.
