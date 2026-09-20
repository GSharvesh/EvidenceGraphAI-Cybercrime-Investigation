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


def test_env_settings_override() -> None:
    """Verifies overriding settings via environment variables."""
    env_vars = {
        "APP_NAME": "CustomEvidenceGraph",
        "LOG_LEVEL": "DEBUG",
        "NEO4J_PORT": "7688",
        "POSTGRES_PORT": "5433",
    }
    with patch.dict(os.environ, env_vars):
        settings = Settings()
        assert settings.app_name == "CustomEvidenceGraph"
        assert settings.log_level == "DEBUG"
        assert settings.postgres_port == 5433


def test_invalid_setting_type() -> None:
    """Verifies validation error on invalid integer type for port."""
    with patch.dict(os.environ, {"POSTGRES_PORT": "not-an-int"}):
        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "postgres_port" in str(exc_info.value)
