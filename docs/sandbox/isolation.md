# Sandbox Network Isolation & Air-Gap Verification

## Isolation Architecture

The sandbox uses Docker's built-in `internal: true` network driver setting on bridge network `evidencegraphai-sandbox-isolated`.

```
                  +-----------------------------------+
                  |         Docker Daemon Host        |
                  |                                   |
                  |   +---------------------------+   |
                  |   |  Internal Bridge Network  |   |
                  |   |     (internal: true)      |   |
                  |   |                           |   |
[ WAN / Internet ] --x-- [ Attacker | Victim | Collector ]
  (BLOCKED)       |   +---------------------------+   |
                  +-----------------------------------+
```

## Verification Procedure

The script `infra/sandbox/scripts/verify_isolation.sh` executes three active probing tests from within the container:

1. **DNS Lookup Probe:** Queries `google.com` via system resolver. Expected: Timeout / Resolution failure.
2. **Raw TCP Egress Probe:** Attempts connection to `1.1.1.1:53`. Expected: No route / Connection refused.
3. **HTTP Egress Probe:** Attempts `curl http://example.com`. Expected: Connection failure.

If any probe succeeds, the script exits with status `1` and aborts the replay session immediately.
