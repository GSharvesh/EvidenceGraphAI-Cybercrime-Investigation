"""Unit tests for core configuration settings."""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from core.config.settings import Settings


def test_default_settings() -> None:
    """Verifies default values in Settings class."""
    settings = Settings()
    assert settings.app_name == "EvidenceGraphAI"
    assert settings.app_version == "0.1.0"
    assert settings.app_env in ["development", "testing"]
    assert settings.neo4j_uri == "bolt://localhost:7687"
    assert settings.postgres_port == 5432
    assert settings.metrics_enabled is True
    assert settings.manifest_signing_algorithm == "HMAC-SHA256"
    assert settings.manifest_signing_private_key is None
    assert settings.manifest_signing_public_key is None


def test_env_settings_override() -> None:
    """Verifies overriding settings via environment variables."""
    env_vars = {
        "APP_NAME": "CustomEvidenceGraph",
        "LOG_LEVEL": "DEBUG",
        "NEO4J_PORT": "7688",
        "POSTGRES_PORT": "5433",
        "MANIFEST_SIGNING_ALGORITHM": "Ed25519",
    }
    with patch.dict(os.environ, env_vars):
        settings = Settings()
        assert settings.app_name == "CustomEvidenceGraph"
        assert settings.log_level == "DEBUG"
        assert settings.postgres_port == 5433
        assert settings.manifest_signing_algorithm == "Ed25519"


def test_invalid_setting_type() -> None:
    """Verifies validation error on invalid integer type for port."""
    with patch.dict(os.environ, {"POSTGRES_PORT": "not-an-int"}):
        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "postgres_port" in str(exc_info.value)


def test_production_rejects_insecure_defaults() -> None:
    """Verifies that APP_ENV=production raises ValidationError if default dev credentials are used."""
    with patch.dict(os.environ, {"APP_ENV": "production"}):
        with pytest.raises(ValidationError) as exc_info:
            Settings()
        err_msg = str(exc_info.value)
        assert "Insecure production configuration" in err_msg


def test_production_accepts_secure_secrets() -> None:
    """Verifies that APP_ENV=production succeeds when all credentials are set securely."""
    secure_env = {
        "APP_ENV": "production",
        "MANIFEST_SIGNING_KEY": "a-very-secure-random-prod-key-with-64-bytes-entropy-minimum!",
        "NEO4J_PASSWORD": "StrongNeo4jPassword#2026",
        "POSTGRES_PASSWORD": "StrongPostgresPassword#2026",
        "MINIO_ACCESS_KEY": "prod_minio_operator",
        "MINIO_SECRET_KEY": "ProdMinIOStrongSecretKey#2026",
    }
    with patch.dict(os.environ, secure_env):
        settings = Settings()
        assert settings.app_env == "production"
        assert settings.manifest_signing_key == secure_env["MANIFEST_SIGNING_KEY"]


def test_production_rejects_missing_ed25519_key() -> None:
    """Verifies that APP_ENV=production with Ed25519 algorithm rejects missing or invalid private key."""
    base_secure_env = {
        "APP_ENV": "production",
        "MANIFEST_SIGNING_KEY": "a-very-secure-random-prod-key-with-64-bytes-entropy-minimum!",
        "NEO4J_PASSWORD": "StrongNeo4jPassword#2026",
        "POSTGRES_PASSWORD": "StrongPostgresPassword#2026",
        "MINIO_ACCESS_KEY": "prod_minio_operator",
        "MINIO_SECRET_KEY": "ProdMinIOStrongSecretKey#2026",
        "MANIFEST_SIGNING_ALGORITHM": "Ed25519",
    }
    with patch.dict(os.environ, base_secure_env):
        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "MANIFEST_SIGNING_PRIVATE_KEY" in str(exc_info.value)

    # Also test invalid length
    with patch.dict(
        os.environ,
        {**base_secure_env, "MANIFEST_SIGNING_PRIVATE_KEY": "short-key"},
    ):
        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "MANIFEST_SIGNING_PRIVATE_KEY" in str(exc_info.value)


def test_production_accepts_valid_ed25519_config() -> None:
    """Verifies that APP_ENV=production with Ed25519 succeeds with a 64-character hex key."""
    secure_ed25519_env = {
        "APP_ENV": "production",
        "MANIFEST_SIGNING_KEY": "a-very-secure-random-prod-key-with-64-bytes-entropy-minimum!",
        "NEO4J_PASSWORD": "StrongNeo4jPassword#2026",
        "POSTGRES_PASSWORD": "StrongPostgresPassword#2026",
        "MINIO_ACCESS_KEY": "prod_minio_operator",
        "MINIO_SECRET_KEY": "ProdMinIOStrongSecretKey#2026",
        "MANIFEST_SIGNING_ALGORITHM": "Ed25519",
        "MANIFEST_SIGNING_PRIVATE_KEY": "a" * 64,
        "MANIFEST_SIGNING_PUBLIC_KEY": "b" * 64,
    }
    with patch.dict(os.environ, secure_ed25519_env):
        settings = Settings()
        assert settings.manifest_signing_algorithm == "Ed25519"
        assert settings.manifest_signing_private_key == "a" * 64
        assert settings.manifest_signing_public_key == "b" * 64


def test_legal_framework_settings_configurable() -> None:
    """Verifies configurable default legal framework settings."""
    custom_fw = {
        "MANIFEST_DEFAULT_LEGAL_FRAMEWORK": "Section 63 Bharatiya Sakshya Adhiniyam, 2023 / BNSS 2023",
        "MANIFEST_DEFAULT_LEGAL_DECLARATION": "Custom declaration from env",
    }
    with patch.dict(os.environ, custom_fw):
        settings = Settings()
        assert (
            settings.manifest_default_legal_framework
            == custom_fw["MANIFEST_DEFAULT_LEGAL_FRAMEWORK"]
        )
        assert (
            settings.manifest_default_legal_declaration
            == custom_fw["MANIFEST_DEFAULT_LEGAL_DECLARATION"]
        )
