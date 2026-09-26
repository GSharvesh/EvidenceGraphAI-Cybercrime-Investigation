# MinIO Object Storage Layout & Immutability Architecture

## 1. Storage Layout

Forensic evidence artifacts and Section 65B certified manifests are persisted in an S3-compatible MinIO object vault under the designated bucket `evidencegraphai-artifacts`.

### Key Hierarchy
```
evidencegraphai-artifacts/
├── evidence/
│   └── {evidence_id}/
│       └── {sha256}                (Raw or scrubbed forensic artifact binary)
└── manifests/
    └── {manifest_id}.json          (Section 65B Evidence Manifest document)
```

### Deterministic Naming Rationale
1. **Collision Resistance:** Each evidence item is prefixed with its globally unique Evidence ID (`EV-<uuid>`) and keyed by the exact SHA256 digest of its bytes.
2. **Immutability:** Re-ingesting an identical file under the same Evidence ID resolves to the identical cryptographic path. Altering content results in a different SHA256, instantly exposing any tampering attempt.
3. **Auditability:** Storage URIs follow the canonical format `minio://evidencegraphai-artifacts/evidence/{evidence_id}/{sha256}`.

---

## 2. Object Metadata

Every uploaded artifact object carries system and user metadata:

| Metadata Key | Description | Example |
| :--- | :--- | :--- |
| `evidence-id` | Canonical Evidence Identifier | `EV-3eb51b76-4a93-4c5e-bd71-f34f9a02a2c7` |
| `sha256` | Cryptographic SHA256 hash digest | `b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a8c` |
| `original-filename` | User-supplied / sanitized filename | `traffic_capture.pcap` |
| `artifact-type` | Classified forensic artifact type | `PCAP` |

---

## 3. Immutability & Versioning Controls

1. **Bucket Versioning:** Bucket versioning is enabled via [`BucketManager`](file:///d:/EvidenceGraphAI/core/storage/bucket_manager.py) to preserve all historical object states.
2. **API Deletion Prohibition:** The REST API strictly exposes no object deletion endpoints in Phase 2.
3. **Tamper Detection:** The on-demand verification service [`ArtifactVerifier`](file:///d:/EvidenceGraphAI/core/custody/verifier.py) streams bytes directly from MinIO, recomputes the SHA256 digest, and flags discrepancies against the PostgreSQL custody ledger.
