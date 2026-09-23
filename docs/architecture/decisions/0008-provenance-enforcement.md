# ADR 0008 — Provenance Enforcement Strategy

**Status:** Accepted
**Date:** 2024-12-01
**Deciders:** EvidenceGraphAI Core Team
**Technical Story:** Phase 1 — Evidence Graph Core

---

## Context and Problem Statement

In a graph-based forensic platform, every fact must carry provenance: who or
what created it, from which evidence artefact, and with what confidence.  This
is non-negotiable for legal defensibility.

The question is: how strictly should the platform enforce the validity of the
`source_agent` field?

- **Too strict:** Future Phase 2 agents cannot register themselves without a
  code change. Developer onboarding is blocked.
- **Too loose:** Arbitrary strings are inserted, provenance becomes meaningless.

---

## Decision Drivers

* Legal defensibility — provenance must be machine-readable and consistent.
* Developer velocity — Phase 2 agents must self-register without PRs.
* Production security — untrusted code must not inject arbitrary agent names.
* Test ergonomics — unit and integration tests must not have to register agents.

---

## Considered Options

### Option A — Strict allowlist by default (agent names hardcoded)
Every valid agent name must be hardcoded in the source.

**Pros:** Maximum control.
**Cons:** Every new Phase 2 agent requires a code change and deployment. Blocks developer velocity. Tests need code changes.
**Decision: Rejected.**

### Option B — No validation (any string accepted)
`source_agent` is written as-is with no validation.

**Pros:** Maximum flexibility.
**Cons:** Provenance becomes meaningless. Forensic audit trail is unreliable.
**Decision: Rejected.**

### Option C — Regex validation by default, optional strict mode ✅
In **flexible mode** (default): `source_agent` must match
`^[a-z][a-z0-9_]{2,63}$` — a machine-readable, lowercase identifier format.

In **strict mode** (opt-in via `PROVENANCE_STRICT_MODE=true`): `source_agent`
must additionally be present in the `KNOWN_AGENTS` comma-separated environment
variable.

**Pros:**
- Machine-readable agent names enforced by default (no garbage strings).
- Phase 2 agents self-register by adding their name to `KNOWN_AGENTS` in the
  environment — no code changes required.
- Strict mode is available for high-assurance production deployments.
- Tests use `"system"` or `"manual"` — always valid without registration.

**Cons:**
- Two modes adds some complexity.
  **Mitigation:** Documented clearly. Default is always safe (flexible mode).

**Decision: Accepted.**

---

## Decision Outcome

**Chosen option: Option C — Regex validation by default, optional strict mode.**

### Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `PROVENANCE_STRICT_MODE` | `false` | If `true`, enforce allowlist |
| `KNOWN_AGENTS` | `system,manual` | Comma-separated agent allowlist |

### Agent Name Regex

```
^[a-z][a-z0-9_]{2,63}$
```

Rules:
- Must start with a lowercase letter.
- May contain lowercase letters, digits, and underscores.
- Length: 3–64 characters.

### Provenance Fields

| Field | Required | Description |
|-------|----------|-------------|
| `source_agent` | Yes | Agent that created this entity |
| `source_artifact_id` | No | Origin evidence artefact ID |
| `confidence` | Yes | Float in `[0.0, 1.0]` |

---

## References

- `core/graph/provenance.py`
- `core/config/settings.py` — `provenance_strict_mode`, `known_agents`
- `docs/graph/provenance.md`
