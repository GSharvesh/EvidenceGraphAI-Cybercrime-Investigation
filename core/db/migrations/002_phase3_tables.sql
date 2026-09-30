-- EvidenceGraphAI Migration 002: Phase 3 - CVE Cache and Sandbox Sessions
-- Creates tables for NVD response caching, sandbox replay sessions, and ATT&CK mappings.

-- ------------------------------------------------------------------
-- Table: cve_cache
-- Purpose: PostgreSQL-backed cache for NVD API 2.0 responses.
--          Avoids hammering NVD with repeated requests for the same CVE.
--          Cache TTL is enforced at the application layer (nvd_client.py).
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id      VARCHAR(32) PRIMARY KEY,
    payload     JSONB       NOT NULL,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_url  TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_cache_fetched_at ON cve_cache(fetched_at);

-- ------------------------------------------------------------------
-- Table: replay_sessions
-- Purpose: Records sandbox replay session metadata.
--          Keyed by session_id (UUID). Telemetry artifact IDs stored
--          as JSONB array. Status: pending, running, completed, failed.
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS replay_sessions (
    session_id      VARCHAR(64)  PRIMARY KEY,
    blueprint_id    VARCHAR(64)  NOT NULL,
    cve_id          VARCHAR(32)  NOT NULL,
    status          VARCHAR(16)  NOT NULL DEFAULT 'pending',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    attack_script   TEXT,
    telemetry_paths JSONB        NOT NULL DEFAULT '[]'::jsonb,
    artifact_ids    JSONB        NOT NULL DEFAULT '[]'::jsonb,
    confirmed_techniques JSONB   NOT NULL DEFAULT '[]'::jsonb,
    refuted_techniques   JSONB   NOT NULL DEFAULT '[]'::jsonb,
    replay_report   JSONB,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_replay_sessions_cve_id      ON replay_sessions(cve_id);
CREATE INDEX IF NOT EXISTS idx_replay_sessions_blueprint_id ON replay_sessions(blueprint_id);
CREATE INDEX IF NOT EXISTS idx_replay_sessions_status       ON replay_sessions(status);
CREATE INDEX IF NOT EXISTS idx_replay_sessions_created_at   ON replay_sessions(created_at);

-- ------------------------------------------------------------------
-- Table: attack_mappings
-- Purpose: Stores ATT&CK technique mappings produced by the mapper.
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_mappings (
    id              BIGSERIAL    PRIMARY KEY,
    evidence_id     VARCHAR(128) NOT NULL,
    technique_id    VARCHAR(32)  NOT NULL,
    technique_name  VARCHAR(256),
    tactic          VARCHAR(128),
    confidence      FLOAT        NOT NULL DEFAULT 0.0,
    rule_name       VARCHAR(256),
    rule_pattern    TEXT,
    mapped_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    session_id      VARCHAR(64),
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_attack_mappings_evidence_id   ON attack_mappings(evidence_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_technique_id  ON attack_mappings(technique_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_session_id    ON attack_mappings(session_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_mapped_at     ON attack_mappings(mapped_at);
