# Ingestion & Evidence REST API Reference

The Phase 2 REST API provides endpoints for artifact upload, cryptographic verification, metadata retrieval, custody ledger querying, and Section 65B manifest generation.

---

## 1. Ingestion Endpoints

### `POST /ingest`
Uploads and ingests a raw forensic artifact.

- **Content-Type:** `multipart/form-data`
- **Form Parameters:**
  - `file` (File, required): Raw forensic artifact.
  - `actor` (string, optional, default: `"system"`): Investigator or agent identity.
  - `anonymize` (bool, optional, default: `null`): Explicitly enable/disable DPDP anonymization.
  - `anonymize_method` (string, optional, default: `"MASK"`): Anonymization strategy (`MASK`, `PSEUDONYMIZE`, `REDACT`).
  - `evidence_type_hint` (string, optional): Contextual hint for file classification.
- **Response (201 Created):**
  ```json
  {
    "evidence_id": "EV-3eb51b76-4a93-4c5e-bd71-f34f9a02a2c7",
    "sha256": "b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a8c",
    "original_sha256": null,
    "artifact_type": "PCAP",
    "original_filename": "network_capture.pcap",
    "file_size_bytes": 1048576,
    "storage_path": "minio://evidencegraphai-artifacts/evidence/EV-3eb51b76.../b94f6f...",
    "node_id": "EV-3eb51b76-4a93-4c5e-bd71-f34f9a02a2c7",
    "ledger_entry_id": 142,
    "anonymized": false,
    "anonymization_stats": null,
    "created_at": "2026-09-26T10:00:00.000Z"
  }
  ```

---

## 2. Evidence & Verification Endpoints

### `GET /evidence/{evidence_id}`
Returns metadata, storage location, and complete custody timeline for a specific artifact.

### `GET /evidence/{evidence_id}/verify`
Recomputes SHA256 from MinIO object and checks against ledger records.
- **Response (200 OK):**
  ```json
  {
    "evidence_id": "EV-3eb51b76...",
    "status": "MATCH",
    "stored_sha256": "b94f6f125c79e3a5...",
    "recomputed_sha256": "b94f6f125c79e3a5...",
    "match": true,
    "verified_at": "2026-09-26T10:05:00.000Z",
    "ledger_entry_id": 143,
    "message": "Cryptographic hash successfully verified: artifact is pristine and unaltered"
  }
  ```

### `GET /evidence/{evidence_id}/manifest`
Generates a Section 65B certified Evidence Manifest for a single artifact.

### `GET /ingest/stats`
Returns system-wide ingestion metrics, total evidence items, ledger action breakdown, and storage bucket info.

---

## 3. Custody Ledger Endpoints

### `GET /ledger`
Queries ledger records with pagination and filtering.
- **Query Parameters:** `evidence_id`, `action`, `actor`, `limit` (default: 100), `offset` (default: 0).

### `GET /ledger/verify`
Runs complete mathematical hash chain verification across all ledger blocks.
- **Response (200 OK):**
  ```json
  {
    "is_valid": true,
    "total_entries": 143,
    "broken_at_id": null,
    "message": "Chain integrity successfully verified; all hashes and links match",
    "error_details": null
  }
  ```

---

## 4. Evidence Manifest Endpoints

### `POST /manifests`
Generates, signs, and archives a Section 65B Evidence Manifest for a list of evidence IDs.
- **Payload:** `{"evidence_ids": ["EV-1", "EV-2"], "generator_identity": "Forensic Officer", "actor": "agent-1"}`

### `GET /manifests/{manifest_id}`
Fetches an archived manifest JSON from storage.

### `POST /manifests/verify`
Verifies the digital HMAC-SHA256 signature of an Evidence Manifest document.

---

## 5. Developer Frontend

### `GET /dev/ingestion-portal`
Serves the single-page interactive Forensic Ingest Console.
