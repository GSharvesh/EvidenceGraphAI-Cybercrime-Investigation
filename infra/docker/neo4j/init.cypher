// EvidenceGraphAI Reference Cypher Initialization Schema
// Note: Programmatic execution is performed via infra/scripts/seed_ontology.py

// --- Uniqueness Constraints (11 Node Types) ---
CREATE CONSTRAINT cve_id_unique IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT victim_id_unique IF NOT EXISTS FOR (n:Victim) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT attacker_id_unique IF NOT EXISTS FOR (n:Attacker) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT malware_id_unique IF NOT EXISTS FOR (n:Malware) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT apksample_id_unique IF NOT EXISTS FOR (n:APKSample) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT domain_id_unique IF NOT EXISTS FOR (n:Domain) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT ipaddress_id_unique IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT certificate_id_unique IF NOT EXISTS FOR (n:Certificate) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT attacktechnique_id_unique IF NOT EXISTS FOR (n:ATT&CKTechnique) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT logentry_id_unique IF NOT EXISTS FOR (n:LogEntry) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT evidenceartifact_id_unique IF NOT EXISTS FOR (n:EvidenceArtifact) REQUIRE n.id IS UNIQUE;

// --- Performance Indexes ---
CREATE INDEX malware_sha256_idx IF NOT EXISTS FOR (n:Malware) ON (n.sha256);
CREATE INDEX apksample_sha256_idx IF NOT EXISTS FOR (n:APKSample) ON (n.sha256);
CREATE INDEX domain_name_idx IF NOT EXISTS FOR (n:Domain) ON (n.name);
CREATE INDEX ipaddress_addr_idx IF NOT EXISTS FOR (n:IPAddress) ON (n.addr);
CREATE INDEX logentry_timestamp_idx IF NOT EXISTS FOR (n:LogEntry) ON (n.timestamp);
