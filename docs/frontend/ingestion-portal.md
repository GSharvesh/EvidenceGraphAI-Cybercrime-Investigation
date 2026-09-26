# Forensic Ingest Console User Guide

## 1. Overview

The **Forensic Ingest Console** (`GET /dev/ingestion-portal`) is a single-page interactive developer tool that treats the forensic chain of custody as a first-class visual object.

---

## 2. Key Features

1. **Drag-and-Drop Ingestion Zone:** Instant client-side file inspection, magic byte detection, and size categorization before upload.
2. **Live SHA256 Visualizer:** Real-time Web Crypto API streaming hash display during artifact selection and ingest.
3. **Chain of Custody Timeline:** Vertical interactive timeline rendering color-coded actions (`INGEST`, `VERIFY`, `ANONYMIZE`, `EXPORT`), actor tags, UTC timestamps, and cryptographic hash links (`previous_hash` &rarr; `entry_hash`).
4. **Ledger Integrity Status Badge:** Live badge connected to `/ledger/verify`. Green indicates an unbroken chain; red alerts to tampering and pinpoints the exact entry ID where continuity broke.
5. **Section 65B Manifest Generator:** One-click legal manifest producer with inline JSON inspection and digital signature verification.
6. **Cytoscape.js Mini Graph View:** Live topology rendering of the newly registered `EvidenceArtifact` node connected to the custody vault and database entities.
7. **Security Banner:** Prominent warning indicating that authentication is deferred to future production milestones.
