"""Typed configuration settings for EvidenceGraphAI using pydantic-settings."""

from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and optional .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Application Configuration
    app_name: str = Field(default="EvidenceGraphAI", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    app_env: str = Field(
        default="development", description="Environment: development/staging/production"
    )
    app_debug: bool = Field(default=False, description="Debug mode toggle")
    log_level: str = Field(default="INFO", description="Logging level")

    # Neo4j Graph Database Configuration
    neo4j_uri: str = Field(
        default="bolt://localhost:7687", description="Neo4j connection URI"
    )
    neo4j_user: str = Field(default="neo4j", description="Neo4j username")
    neo4j_password: str = Field(default="devpassword123", description="Neo4j password")
    neo4j_database: str = Field(default="neo4j", description="Neo4j database name")
    neo4j_max_connection_pool_size: int = Field(
        default=50, description="Max connection pool size"
    )
    neo4j_connection_timeout: int = Field(
        default=30, description="Connection timeout in seconds"
    )

    # PostgreSQL Configuration
    postgres_host: str = Field(default="localhost", description="PostgreSQL host")
    postgres_port: int = Field(default=5432, description="PostgreSQL port")
    postgres_db: str = Field(default="evidencegraphai", description="Database name")
    postgres_user: str = Field(
        default="evidencegraphai", description="PostgreSQL username"
    )
    postgres_password: str = Field(
        default="devpassword123", description="PostgreSQL password"
    )

    # Redis Configuration
    redis_url: str = Field(
        default="redis://localhost:6379/0", description="Redis connection URL"
    )

    # MinIO / S3 Configuration
    minio_endpoint: str = Field(default="localhost:9000", description="MinIO endpoint")
    minio_access_key: str = Field(default="minioadmin", description="MinIO access key")
    minio_secret_key: str = Field(default="minioadmin", description="MinIO secret key")
    minio_bucket: str = Field(
        default="evidencegraphai-artifacts", description="Artifact storage bucket"
    )
    minio_secure: bool = Field(
        default=False, description="Use TLS for MinIO connection"
    )

    # API Configuration
    api_host: str = Field(default="0.0.0.0", description="API listener bind IP")
    api_port: int = Field(default=8000, description="API listener port")
    api_workers: int = Field(default=1, description="API worker count")
    api_cors_origins: str = Field(
        default="http://localhost:3000", description="Comma-separated CORS origins"
    )

    # Provenance Configuration (Phase 1)
    provenance_strict_mode: bool = Field(
        default=False,
        description="If true, source_agent must be in KNOWN_AGENTS list",
    )
    known_agents: str = Field(
        default="system,manual,vulnerability_intelligence,threat_reconstruction,sandbox_replay,attack_mapper",
        description="Comma-separated allowlist of known agent names (used in strict mode)",
    )

    # Developer Viewer Configuration (Phase 1)
    dev_viewer_enabled: bool = Field(
        default=True,
        description="Enable the developer graph viewer and /graph/export endpoints",
    )
    dev_viewer_allow_remote: bool = Field(
        default=False,
        description="If false, restrict viewer/export/validate endpoints to localhost only",
    )

    # Test Database Configuration (Phase 1)
    neo4j_test_database: str = Field(
        default="neo4j",
        description="Separate Neo4j database for integration tests",
    )

    # Observability Configuration
    metrics_enabled: bool = Field(default=True, description="Enable Prometheus metrics")
    metrics_port: int = Field(default=8000, description="Metrics export port")

    # Ingestion Configuration (Phase 2)
    ingestion_max_file_size_mb: int = Field(
        default=2048, description="Maximum allowed file size for upload in MB"
    )
    ingestion_allowed_types: str = Field(
        default="pcap,json,pe,elf,apk,text,pdf,cert_pem,cert_der",
        description="Comma-separated list of allowed file types for ingestion",
    )
    ingestion_anonymize_pcap: bool = Field(
        default=True, description="Enable DPDP anonymization filter on PCAPs"
    )
    ingestion_anonymize_logs: bool = Field(
        default=True, description="Enable DPDP anonymization filter on Logs"
    )

    # Evidence Manifest Configuration (Phase 2)
    manifest_signing_key: str = Field(
        default="dev-insecure-manifest-signing-key-32b",
        description="HMAC key for signing Section 65B / Section 63 Evidence Manifests",
    )
    manifest_signing_algorithm: str = Field(
        default="HMAC-SHA256",
        description="Default signing algorithm: HMAC-SHA256 or Ed25519",
    )
    manifest_signing_private_key: str | None = Field(
        default=None,
        description="Hex-encoded 32-byte Ed25519 private signing key (optional/prod)",
    )
    manifest_signing_public_key: str | None = Field(
        default=None,
        description="Hex-encoded 32-byte Ed25519 public verification key (optional/prod)",
    )
    manifest_generator_identity: str = Field(
        default="EvidenceGraphAI",
        description="Identity of the Evidence Manifest generator",
    )
    manifest_default_legal_framework: str = Field(
        default="Section 65B Indian Evidence Act / BNSS 2023",
        description="Default statutory framework name for evidence manifests",
    )
    manifest_default_legal_declaration: str | None = Field(
        default=None,
        description="Custom default statutory legal certificate declaration text (None = built-in template)",
    )

    @model_validator(mode="after")
    def validate_production_credentials(self) -> "Settings":
        """Ensures insecure development defaults cannot be silently used in production."""
        if self.app_env.lower() in ("production", "prod"):
            insecure_defaults = [
                (
                    self.manifest_signing_key == "dev-insecure-manifest-signing-key-32b"
                    or len(self.manifest_signing_key) < 32,
                    "MANIFEST_SIGNING_KEY must be a secure key of at least 32 characters in production",
                ),
                (
                    self.neo4j_password in ("devpassword123", ""),
                    "NEO4J_PASSWORD must not use development default credentials in production",
                ),
                (
                    self.postgres_password in ("devpassword123", ""),
                    "POSTGRES_PASSWORD must not use development default credentials in production",
                ),
                (
                    self.minio_access_key == "minioadmin"
                    or self.minio_secret_key == "minioadmin",
                    "MINIO credentials must not use default admin credentials in production",
                ),
                (
                    self.manifest_signing_algorithm.upper() == "ED25519"
                    and (
                        not self.manifest_signing_private_key
                        or len(self.manifest_signing_private_key) != 64
                    ),
                    "MANIFEST_SIGNING_PRIVATE_KEY must be a valid 64-character hex Ed25519 key when Ed25519 algorithm is selected in production",
                ),
            ]
            for is_insecure, message in insecure_defaults:
                if is_insecure:
                    raise ValueError(f"Insecure production configuration: {message}")
        return self

    # --- Phase 3 Settings ---

    # NVD API Configuration
    nvd_api_key: str = Field(
        default="",
        description="NVD API 2.0 key (optional; anonymous rate-limit: 5 req/30s, with key: 50 req/30s)",
    )
    nvd_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NVD CVE API 2.0 base URL",
    )
    nvd_cache_ttl_days: int = Field(
        default=7,
        description="CVE cache TTL in days; stale entries are re-fetched from NVD",
    )
    nvd_request_timeout: int = Field(
        default=30,
        description="NVD API request timeout in seconds",
    )
    nvd_max_retries: int = Field(
        default=3,
        description="Maximum retry attempts for failed NVD API calls",
    )

    # Sandbox Configuration
    sandbox_compose_file: str = Field(
        default="infra/sandbox/docker-compose.yml",
        description="Path to the sandbox Docker Compose file",
    )
    sandbox_replay_timeout: int = Field(
        default=300,
        description="Maximum sandbox replay duration in seconds",
    )
    sandbox_telemetry_dir: str = Field(
        default="/tmp/evidencegraphai/sandbox",
        description="Host path for sandbox telemetry output (mounted volume)",
    )


@lru_cache
def get_settings() -> Settings:
    """Returns a cached instance of application settings."""
    return Settings()
