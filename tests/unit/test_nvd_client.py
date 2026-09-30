"""Unit tests for the NVD API client (NVDClient) — FR-1."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from core.agents.vulnerability.exceptions import (
    NVDCVENotFoundError,
    NVDOfflineError,
    NVDRateLimitError,
)
from core.agents.vulnerability.nvd_client import NVDClient, _is_cache_fresh
from core.config.settings import Settings


@pytest.fixture
def mock_settings() -> Settings:
    return Settings(
        app_env="testing",
        nvd_api_key="",
        nvd_base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        nvd_cache_ttl_days=7,
        nvd_request_timeout=10,
        nvd_max_retries=2,
    )


@pytest.fixture
def mock_db() -> MagicMock:
    db = MagicMock()
    db.fetch_one.return_value = None  # No cache by default
    return db


@pytest.fixture
def nvd_client(mock_settings, mock_db) -> NVDClient:
    return NVDClient(settings=mock_settings, db_client=mock_db)


def _nvd_response(cve_id: str = "CVE-2021-44228") -> dict:
    """Returns a minimal NVD API 2.0 vulnerability response dict."""
    return {
        "cve": {
            "id": cve_id,
            "published": "2021-12-10T00:00:00.000Z",
            "lastModified": "2024-01-01T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "Log4Shell RCE vulnerability"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "CHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "availabilityImpact": "HIGH",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 6.0,
                    }
                ]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-917"}]}],
            "configurations": [],
            "references": [
                {"url": "https://github.com/apache/logging-log4j2/commit/abc123def456"}
            ],
        }
    }


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


class TestIsCacheFresh:
    def test_fresh_entry(self):
        fetched = datetime.now(UTC) - timedelta(days=3)
        assert _is_cache_fresh(fetched, ttl_days=7) is True

    def test_stale_entry(self):
        fetched = datetime.now(UTC) - timedelta(days=10)
        assert _is_cache_fresh(fetched, ttl_days=7) is False

    def test_exactly_at_ttl(self):
        fetched = datetime.now(UTC) - timedelta(days=7, seconds=1)
        assert _is_cache_fresh(fetched, ttl_days=7) is False

    def test_naive_datetime(self):
        fetched = datetime.now() - timedelta(days=2)  # no tzinfo
        assert _is_cache_fresh(fetched, ttl_days=7) is True


# ---------------------------------------------------------------------------
# Fetch from cache
# ---------------------------------------------------------------------------


class TestFetchFromCache:
    def test_returns_none_when_no_cache(self, nvd_client, mock_db):
        mock_db.fetch_one.return_value = None
        result = nvd_client._load_from_cache("CVE-2021-44228")
        assert result is None

    def test_returns_cached_payload(self, nvd_client, mock_db):
        payload = _nvd_response()
        mock_db.fetch_one.return_value = {
            "payload": json.dumps(payload),
            "fetched_at": datetime.now(UTC).isoformat(),
        }
        result = nvd_client._load_from_cache("CVE-2021-44228")
        assert result is not None
        cached_payload, fetched_at = result
        assert cached_payload["cve"]["id"] == "CVE-2021-44228"

    def test_handles_db_error_gracefully(self, nvd_client, mock_db):
        mock_db.fetch_one.side_effect = Exception("DB down")
        result = nvd_client._load_from_cache("CVE-2021-44228")
        assert result is None


# ---------------------------------------------------------------------------
# HTTP fetch
# ---------------------------------------------------------------------------


class TestFetchFromNVD:
    def test_successful_fetch(self, nvd_client):
        response_data = {"totalResults": 1, "vulnerabilities": [_nvd_response()]}

        with patch("httpx.Client") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = response_data
            mock_client_cls.return_value.__enter__.return_value.get.return_value = (
                mock_resp
            )

            result = nvd_client._fetch_from_nvd("CVE-2021-44228")
            assert result["cve"]["id"] == "CVE-2021-44228"

    def test_raises_not_found_on_404(self, nvd_client):
        with patch("httpx.Client") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_client_cls.return_value.__enter__.return_value.get.return_value = (
                mock_resp
            )

            with pytest.raises(NVDCVENotFoundError):
                nvd_client._fetch_from_nvd("CVE-9999-99999")

    def test_raises_not_found_on_empty_results(self, nvd_client):
        with patch("httpx.Client") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"totalResults": 0, "vulnerabilities": []}
            mock_client_cls.return_value.__enter__.return_value.get.return_value = (
                mock_resp
            )

            with pytest.raises(NVDCVENotFoundError):
                nvd_client._fetch_from_nvd("CVE-9999-00001")

    def test_raises_rate_limit_after_retries(self, nvd_client):
        with patch("httpx.Client") as mock_client_cls, patch("time.sleep"):
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_client_cls.return_value.__enter__.return_value.get.return_value = (
                mock_resp
            )

            with pytest.raises(NVDRateLimitError):
                nvd_client._fetch_from_nvd("CVE-2021-44228")


# ---------------------------------------------------------------------------
# fetch_cve — integration of cache + HTTP
# ---------------------------------------------------------------------------


class TestFetchCVE:
    def test_returns_cached_fresh_data(self, nvd_client, mock_db):
        payload = _nvd_response()
        mock_db.fetch_one.return_value = {
            "payload": json.dumps(payload),
            "fetched_at": datetime.now(UTC).isoformat(),
        }
        result = nvd_client.fetch_cve("CVE-2021-44228")
        assert result["cve"]["id"] == "CVE-2021-44228"

    def test_fetches_from_nvd_on_miss(self, nvd_client, mock_db):
        mock_db.fetch_one.return_value = None  # No cache
        response_data = {"totalResults": 1, "vulnerabilities": [_nvd_response()]}

        with patch("httpx.Client") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = response_data
            mock_client_cls.return_value.__enter__.return_value.get.return_value = (
                mock_resp
            )

            result = nvd_client.fetch_cve("CVE-2021-44228")
            assert result["cve"]["id"] == "CVE-2021-44228"
            mock_db.execute.assert_called_once()  # Cache saved

    def test_returns_stale_cache_when_nvd_offline(self, nvd_client, mock_db):
        stale_payload = _nvd_response()
        mock_db.fetch_one.return_value = {
            "payload": json.dumps(stale_payload),
            "fetched_at": (datetime.now(UTC) - timedelta(days=30)).isoformat(),
        }
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.get.side_effect = (
                ConnectionError("NVD down")
            )

            result = nvd_client.fetch_cve("CVE-2021-44228")
            assert result["cve"]["id"] == "CVE-2021-44228"

    def test_raises_offline_error_when_no_cache(self, nvd_client, mock_db):
        mock_db.fetch_one.return_value = None
        with patch("httpx.Client") as mock_client_cls, patch("time.sleep"):
            mock_client_cls.return_value.__enter__.return_value.get.side_effect = (
                ConnectionError("NVD down")
            )

            with pytest.raises(NVDOfflineError):
                nvd_client.fetch_cve("CVE-2021-44228")

    def test_normalizes_cve_id_uppercase(self, nvd_client, mock_db):
        mock_db.fetch_one.return_value = None
        response_data = {"totalResults": 1, "vulnerabilities": [_nvd_response()]}
        with patch("httpx.Client") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = response_data
            mock_client_cls.return_value.__enter__.return_value.get.return_value = (
                mock_resp
            )
            # Should work with lowercase input
            result = nvd_client.fetch_cve("cve-2021-44228")
            assert result is not None

    def test_handles_500_502_503_504_server_errors(self, nvd_client, mock_db):
        mock_db.fetch_one.return_value = None
        with patch("httpx.Client") as mock_client_cls, patch("time.sleep"):
            mock_resp = MagicMock()
            mock_resp.status_code = 503
            mock_resp.text = "Service Unavailable"
            mock_client_cls.return_value.__enter__.return_value.get.return_value = (
                mock_resp
            )

            with pytest.raises(NVDOfflineError):
                nvd_client.fetch_cve("CVE-2021-44228")

    def test_sends_api_key_header_when_configured(self, mock_db):
        settings_with_key = Settings(nvd_api_key="test-secret-api-key")
        client = NVDClient(settings=settings_with_key, db_client=mock_db)
        mock_db.fetch_one.return_value = None

        with patch("httpx.Client") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "totalResults": 1,
                "vulnerabilities": [_nvd_response()],
            }
            mock_client_cls.return_value.__enter__.return_value.get.return_value = (
                mock_resp
            )

            client.fetch_cve("CVE-2021-44228")
            # Verify apiKey header was included in httpx.Client initialization
            call_kwargs = mock_client_cls.call_args.kwargs
            headers = call_kwargs.get("headers", {})
            assert headers.get("apiKey") == "test-secret-api-key"

    def test_get_cached_cves_lists_records(self, nvd_client, mock_db):
        mock_db.fetch_all.return_value = [
            {"cve_id": "CVE-2021-44228", "fetched_at": "2024-01-01T00:00:00Z"},
            {"cve_id": "CVE-2022-22965", "fetched_at": "2024-01-02T00:00:00Z"},
        ]
        records = nvd_client.get_cached_cves(limit=10, offset=0)
        assert len(records) == 2
        assert records[0]["cve_id"] == "CVE-2021-44228"

    def test_get_cached_cves_db_error_returns_empty(self, nvd_client, mock_db):
        mock_db.fetch_all.side_effect = Exception("DB error")
        records = nvd_client.get_cached_cves()
        assert records == []

    def test_fetch_nvd_httpx_timeout_and_connect_error(self, nvd_client, mock_db):
        import httpx

        mock_db.fetch_one.return_value = None
        with patch("httpx.Client") as mock_client_cls, patch("time.sleep"):
            mock_client_cls.return_value.__enter__.return_value.get.side_effect = (
                httpx.TimeoutException("Timeout")
            )
            with pytest.raises(NVDOfflineError):
                nvd_client.fetch_cve("CVE-2021-44228")

        with patch("httpx.Client") as mock_client_cls, patch("time.sleep"):
            mock_client_cls.return_value.__enter__.return_value.get.side_effect = (
                httpx.ConnectError("Connection failed")
            )
            with pytest.raises(NVDOfflineError):
                nvd_client.fetch_cve("CVE-2021-44228")
