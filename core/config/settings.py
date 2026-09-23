"""Typed configuration settings for EvidenceGraphAI using pydantic-settings."""

from functools import lru_cache

from pydantic import Field
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
        default="system,manual",
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


@lru_cache
def get_settings() -> Settings:
    """Returns a cached instance of application settings."""
    return Settings()
