# EvidenceGraphAI Ontology Reference Guide

This document defines the machine-readable graph schema specified in `core/ontology/schema.yaml`.

---

## Node Types (11 Total)

| Node Label | Description | Key Properties | Unique Constraint |
|------------|-------------|----------------|-------------------|
| **CVE** | Vulnerability record | `id` (req), `cvss_score`, `severity`, `description` | `n.id IS UNIQUE` |
| **Victim** | Victim asset/org | `id` (req), `name` (req), `sector`, `ip_address` | `n.id IS UNIQUE` |
| **Attacker** | Threat actor profile | `id` (req), `name` (req), `aliases`, `country_of_origin` | `n.id IS UNIQUE` |
| **Malware** | Malware binary entity | `id` (req), `sha256` (req), `family`, `malware_type` | `n.id IS UNIQUE`, Index: `sha256` |
| **APKSample** | Android APK package | `id` (req), `sha256` (req), `package_name` (req), `min_sdk` | `n.id IS UNIQUE`, Index: `sha256` |
| **Domain** | DNS record | `id` (req), `name` (req), `registrar`, `created_date` | `n.id IS UNIQUE`, Index: `name` |
| **IPAddress** | IP address record | `id` (req), `addr` (req), `asn`, `country` | `n.id IS UNIQUE`, Index: `addr` |
| **Certificate** | Cryptographic X.509 cert | `id` (req), `fingerprint` (req), `issuer`, `subject` | `n.id IS UNIQUE` |
| **ATT&CKTechnique** | MITRE ATT&CK technique | `id` (req), `name` (req), `tactic` | `n.id IS UNIQUE` |
| **LogEntry** | Forensic log event | `id` (req), `timestamp` (req), `source` (req), `event_id` | `n.id IS UNIQUE`, Index: `timestamp` |
| **EvidenceArtifact** | Raw artifact container | `id` (req), `artifact_type` (req), `storage_path`, `hash_sha256` | `n.id IS UNIQUE` |

*Note: Every node automatically includes temporal versioning fields (`valid_from`, `valid_to`, `created_at`, `updated_at`) and provenance tracking fields (`source_agent`, `source_artifact_id`, `confidence`).*

---

## Relationship Types (14 Total)

| Edge Label | Description | Allowed Sources | Allowed Targets | Key Properties |
|------------|-------------|-----------------|-----------------|----------------|
| **EXPLOITS** | Exploit relationship | `Attacker`, `Malware` | `CVE` | `vector` |
| **DELIVERS** | Payload delivery | `Attacker`, `Domain`, `IPAddress` | `Malware`, `APKSample` | `delivery_method` |
| **COMMUNICATES_WITH** | Network C2 communication | `Malware`, `Victim`, `APKSample` | `Domain`, `IPAddress` | `port`, `protocol` |
| **USES_CERTIFICATE** | TLS Certificate association | `Domain`, `Malware`, `APKSample` | `Certificate` | `validation_status` |
| **MAPS_TO** | ATT&CK Technique mapping | `LogEntry`, `Malware`, `APKSample` | `ATT&CKTechnique` | `mapping_confidence` |
| **LINKED_CAMPAIGN** | Threat campaign link | `Attacker`, `Malware` | `Attacker`, `Malware` | `campaign_name` |
| **DOWNGRADES_TO** | Protocol downgrade | `Certificate`, `Domain` | `Certificate`, `Domain` | `reason` |
| **DERIVED_FROM** | Forensic artifact lineage | `LogEntry`, `EvidenceArtifact` | `EvidenceArtifact` | `extraction_method` |
| **PRECEDES** | Log event temporal sequence | `LogEntry` | `LogEntry` | `time_delta_ms` |
| **EXPECTED_TO_LEAD_TO** | Probabilistic ATT&CK step | `ATT&CKTechnique` | `ATT&CKTechnique` | `probability` |
| **DETECTED_BY** | Detection rule match | `Malware`, `LogEntry`, `APKSample` | `EvidenceArtifact` | `rule_name` |
| **EXPORTED_AS** | Graph export format | `EvidenceArtifact` | `EvidenceArtifact` | `format` |
| **HAS_RESPONSE** | Response action link | `Victim`, `LogEntry` | `EvidenceArtifact` | `status` |
| **RESOLVES_TO** | DNS IP Resolution | `Domain` | `IPAddress` | `resolved_at` |

---

## Database Constraints & Index Statements

```cypher
// Uniqueness Constraints
CREATE CONSTRAINT cve_id_unique IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT victim_id_unique IF NOT EXISTS FOR (n:Victim) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT attacker_id_unique IF NOT EXISTS FOR (n:Attacker) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT malware_id_unique IF NOT EXISTS FOR (n:Malware) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT apksample_id_unique IF NOT EXISTS FOR (n:APKSample) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT domain_id_unique IF NOT EXISTS FOR (n:Domain) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT ipaddress_id_unique IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT certificate_id_unique IF NOT EXISTS FOR (n:Certificate) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT attacktechnique_id_unique IF NOT EXISTS FOR (n:`ATT&CKTechnique`) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT logentry_id_unique IF NOT EXISTS FOR (n:LogEntry) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT evidenceartifact_id_unique IF NOT EXISTS FOR (n:EvidenceArtifact) REQUIRE n.id IS UNIQUE;

// Performance Indexes
CREATE INDEX malware_sha256_idx IF NOT EXISTS FOR (n:Malware) ON (n.sha256);
CREATE INDEX apksample_sha256_idx IF NOT EXISTS FOR (n:APKSample) ON (n.sha256);
CREATE INDEX domain_name_idx IF NOT EXISTS FOR (n:Domain) ON (n.name);
CREATE INDEX ipaddress_addr_idx IF NOT EXISTS FOR (n:IPAddress) ON (n.addr);
CREATE INDEX logentry_timestamp_idx IF NOT EXISTS FOR (n:LogEntry) ON (n.timestamp);
```
