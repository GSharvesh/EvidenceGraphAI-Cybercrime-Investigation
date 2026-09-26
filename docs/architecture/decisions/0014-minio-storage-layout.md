# ADR 0014: MinIO S3 Object Storage Layout & Immutability Architecture

## Status
Accepted

## Context
Raw forensic artifacts and generated Evidence Manifests must be stored securely with collision-resistant, predictable object keys and immutable access policies.

## Decision
We structured object paths under the bucket `evidencegraphai-artifacts` as:
1. `evidence/{evidence_id}/{sha256}` for raw/anonymized forensic artifacts.
2. `manifests/{manifest_id}.json` for Section 65B certified manifests.
3. Enabled bucket versioning via `BucketManager`.
4. Disallowed object deletion via the Phase 2 API.

## Consequences
- **Positive:** Unambiguous deterministic object resolution, collision resistance, full audit trail, versioned history.
- **Negative:** Requires storage cleanup policies in non-production development environments.
