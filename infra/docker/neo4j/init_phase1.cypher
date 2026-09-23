// EvidenceGraphAI Phase 1 — Additional Performance Indexes
// Run AFTER init.cypher (which creates the Phase 0 constraints and indexes).
// All statements use IF NOT EXISTS so they are safe to re-run.

// Temporal query indexes
CREATE INDEX logentry_valid_from_idx IF NOT EXISTS FOR (n:LogEntry) ON (n.valid_from);
CREATE INDEX artifact_valid_from_idx IF NOT EXISTS FOR (n:EvidenceArtifact) ON (n.valid_from);
CREATE INDEX logentry_created_at_idx IF NOT EXISTS FOR (n:LogEntry) ON (n.created_at);

// Provenance query indexes
CREATE INDEX logentry_source_agent_idx IF NOT EXISTS FOR (n:LogEntry) ON (n.source_agent);
CREATE INDEX artifact_source_agent_idx IF NOT EXISTS FOR (n:EvidenceArtifact) ON (n.source_agent);
CREATE INDEX artifact_source_artifact_idx IF NOT EXISTS FOR (n:EvidenceArtifact) ON (n.source_artifact_id);

// Lookup indexes
CREATE LOOKUP INDEX node_label_lookup IF NOT EXISTS FOR (n) ON EACH labels(n);
CREATE LOOKUP INDEX rel_type_lookup IF NOT EXISTS FOR ()-[r]-() ON EACH type(r);
