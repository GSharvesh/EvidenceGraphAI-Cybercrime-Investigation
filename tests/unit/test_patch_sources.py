"""Unit tests for the multi-source patch resolver (patch_sources.py)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from core.agents.vulnerability.models import SourceType
from core.agents.vulnerability.patch_sources import (
    SourceResult,
    _parse_osv_response,
    build_patch_info_from_sources,
    resolve_all_sources,
    resolve_commit_urls,
    resolve_nvd_patch_tagged,
    resolve_pr_mr_urls,
    resolve_release_tag_urls,
)

# ---------------------------------------------------------------------------
# Fixtures / constants
# ---------------------------------------------------------------------------

GITHUB_COMMIT_URL = "https://github.com/apache/log4j2/commit/abc123def456789a"
GITLAB_COMMIT_URL = "https://gitlab.com/group/project/-/commit/aabbccdd1234567"
GITHUB_PR_URL = "https://github.com/apache/log4j2/pull/42"
GITLAB_MR_URL = "https://gitlab.com/group/project/-/merge_requests/7"
GITHUB_RELEASE_URL = "https://github.com/apache/log4j2/releases/tag/v2.17.1"
GITHUB_TAG_URL = "https://github.com/apache/log4j2/tree/rel/2.17.1"

SAMPLE_DIFF = """\
--- a/src/Main.java
+++ b/src/Main.java
@@ -10,3 +10,3 @@
-    public void process(String input) {
+    public void process(String input) {
+        // FIXED: sanitized
     }
"""

OSV_PAYLOAD_WITH_GIT_COMMIT = {
    "id": "CVE-2021-44228",
    "aliases": ["GHSA-jfh8-c2jp-hdp8"],
    "affected": [
        {
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/apache/logging-log4j2",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "be881e503e14b267fb8a8f94b6d15eff811a7b07"},
                    ],
                }
            ]
        }
    ],
    "references": [
        {"url": "https://github.com/advisories/GHSA-jfh8-c2jp-hdp8"},
    ],
}

OSV_PAYLOAD_FIXED_VERSION_ONLY = {
    "id": "CVE-2021-44228",
    "aliases": ["GHSA-jfh8-c2jp-hdp8"],
    "affected": [
        {
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.17.1"},
                    ],
                }
            ]
        }
    ],
    "references": [
        {"url": "https://github.com/advisories/GHSA-jfh8-c2jp-hdp8"},
    ],
}

OSV_PAYLOAD_NO_FIX = {
    "id": "CVE-2021-44228",
    "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
    "references": [],
}


# ---------------------------------------------------------------------------
# TestResolveCommitUrls
# ---------------------------------------------------------------------------


class TestResolveCommitUrls:
    def test_finds_github_commit(self):
        with patch("httpx.Client") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = SAMPLE_DIFF
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            results = resolve_commit_urls([GITHUB_COMMIT_URL])
        assert len(results) == 1
        assert results[0].source_type == SourceType.GITHUB_COMMIT
        assert results[0].confidence == 0.95
        assert results[0].commit_sha == "abc123def456789a"
        assert results[0].diff_text == SAMPLE_DIFF

    def test_finds_gitlab_commit(self):
        with patch("httpx.Client") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = SAMPLE_DIFF
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            results = resolve_commit_urls([GITLAB_COMMIT_URL])
        assert len(results) == 1
        assert results[0].source_type == SourceType.GITLAB_COMMIT

    def test_no_commit_urls_returns_empty(self):
        results = resolve_commit_urls(
            ["https://nvd.nist.gov/vuln", "https://vendor.com/"]
        )
        assert results == []

    def test_diff_fetch_failure_still_returns_result(self):
        """Even if the diff fetch fails, the source result is still returned."""
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = Exception(
                "net error"
            )
            results = resolve_commit_urls([GITHUB_COMMIT_URL])
        assert len(results) == 1
        assert results[0].diff_text is None
        assert results[0].commit_sha is not None

    def test_404_diff_still_returns_result(self):
        with patch("httpx.Client") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            results = resolve_commit_urls([GITHUB_COMMIT_URL])
        assert len(results) == 1
        assert results[0].diff_text is None

    def test_deduplicates_same_url(self):
        with patch("httpx.Client") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            results = resolve_commit_urls([GITHUB_COMMIT_URL, GITHUB_COMMIT_URL])
        assert len(results) == 1

    def test_empty_references_returns_empty(self):
        assert resolve_commit_urls([]) == []


# ---------------------------------------------------------------------------
# TestResolvePrMrUrls
# ---------------------------------------------------------------------------


class TestResolvePrMrUrls:
    def test_finds_github_pr(self):
        results = resolve_pr_mr_urls([GITHUB_PR_URL])
        assert len(results) == 1
        assert results[0].source_type == SourceType.GITHUB_PR
        assert results[0].confidence == 0.85
        assert results[0].diff_text is None

    def test_finds_gitlab_mr(self):
        results = resolve_pr_mr_urls([GITLAB_MR_URL])
        assert len(results) == 1
        assert results[0].source_type == SourceType.GITLAB_MR

    def test_no_pr_urls_returns_empty(self):
        results = resolve_pr_mr_urls(["https://nvd.nist.gov/", GITHUB_COMMIT_URL])
        assert results == []

    def test_deduplicates_same_url(self):
        results = resolve_pr_mr_urls([GITHUB_PR_URL, GITHUB_PR_URL])
        assert len(results) == 1


# ---------------------------------------------------------------------------
# TestResolveReleaseTagUrls
# ---------------------------------------------------------------------------


class TestResolveReleaseTagUrls:
    def test_finds_github_release(self):
        results = resolve_release_tag_urls([GITHUB_RELEASE_URL])
        assert len(results) == 1
        assert results[0].source_type == SourceType.GITHUB_RELEASE
        assert results[0].confidence == 0.75
        assert "2.17.1" in results[0].fixed_versions

    def test_finds_github_tag(self):
        results = resolve_release_tag_urls([GITHUB_TAG_URL])
        assert len(results) == 1
        assert results[0].source_type == SourceType.GITHUB_TAG
        assert "2.17.1" in results[0].fixed_versions

    def test_branch_name_in_tag_url_does_not_populate_fixed_versions(self):
        """Branch names like 'main' must not be recorded as fixed versions."""
        url = "https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228"
        results = resolve_release_tag_urls([url])
        assert len(results) == 1
        assert results[0].fixed_versions == []
        assert "main" not in results[0].fixed_versions

    def test_non_github_release_not_matched(self):
        results = resolve_release_tag_urls(
            ["https://bitbucket.org/x/y/downloads/v1.0.zip"]
        )
        assert results == []

    def test_empty_returns_empty(self):
        assert resolve_release_tag_urls([]) == []


# ---------------------------------------------------------------------------
# TestResolveNvdPatchTagged
# ---------------------------------------------------------------------------


class TestResolveNvdPatchTagged:
    def test_finds_patch_tagged(self):
        refs = [{"url": "https://vendor.com/fix", "tags": ["Patch"]}]
        results = resolve_nvd_patch_tagged(refs)
        assert len(results) == 1
        assert results[0].source_type == SourceType.NVD_PATCH_TAG
        assert results[0].confidence == 0.70

    def test_finds_vendor_advisory_tagged(self):
        refs = [{"url": "https://vendor.com/advisory", "tags": ["Vendor Advisory"]}]
        results = resolve_nvd_patch_tagged(refs)
        assert len(results) == 1
        assert results[0].source_type == SourceType.VENDOR_ADVISORY
        assert results[0].confidence == 0.65

    def test_untagged_refs_ignored(self):
        refs = [{"url": "https://nvd.nist.gov/vuln", "tags": ["Third Party Advisory"]}]
        results = resolve_nvd_patch_tagged(refs)
        assert results == []

    def test_empty_returns_empty(self):
        assert resolve_nvd_patch_tagged([]) == []

    def test_deduplicates_same_url(self):
        refs = [
            {"url": "https://vendor.com/fix", "tags": ["Patch"]},
            {"url": "https://vendor.com/fix", "tags": ["Patch"]},
        ]
        results = resolve_nvd_patch_tagged(refs)
        assert len(results) == 1

    def test_missing_tags_key_handled(self):
        refs = [{"url": "https://vendor.com/fix"}]
        results = resolve_nvd_patch_tagged(refs)
        assert results == []


# ---------------------------------------------------------------------------
# TestParseOsvResponse
# ---------------------------------------------------------------------------


class TestParseOsvResponse:
    def test_extracts_git_commit_and_repo(self):
        results = _parse_osv_response("CVE-2021-44228", OSV_PAYLOAD_WITH_GIT_COMMIT)
        commit_results = [r for r in results if r.commit_sha is not None]
        assert len(commit_results) >= 1
        assert (
            commit_results[0].commit_sha == "be881e503e14b267fb8a8f94b6d15eff811a7b07"
        )
        assert commit_results[0].confidence == 0.90
        # Git commit range must NOT pollute fixed_versions
        assert commit_results[0].fixed_versions == []

    def test_fixed_version_only_produces_ghsa_result(self):
        results = _parse_osv_response("CVE-2021-44228", OSV_PAYLOAD_FIXED_VERSION_ONLY)
        assert len(results) >= 1
        advisory_results = [r for r in results if r.fixed_versions]
        assert advisory_results
        assert "2.17.1" in advisory_results[0].fixed_versions
        assert advisory_results[0].source_type in (
            SourceType.GHSA,
            SourceType.OSV_DATABASE,
        )
        assert advisory_results[0].confidence == 0.80

    def test_no_fix_returns_empty(self):
        results = _parse_osv_response("CVE-2021-44228", OSV_PAYLOAD_NO_FIX)
        assert results == []

    def test_ghsa_alias_sets_ghsa_source_type(self):
        results = _parse_osv_response("CVE-2021-44228", OSV_PAYLOAD_FIXED_VERSION_ONLY)
        ghsa_results = [r for r in results if r.source_type == SourceType.GHSA]
        assert ghsa_results


# ---------------------------------------------------------------------------
# TestBuildPatchInfoFromSources
# ---------------------------------------------------------------------------


class TestBuildPatchInfoFromSources:
    def test_no_sources_returns_unavailable(self):
        pi = build_patch_info_from_sources("CVE-2021-99999", [])
        assert pi.available is False
        assert pi.fix_exists is False
        assert "No remediation" in pi.fetch_error

    def test_source_with_diff_sets_available(self):
        sources = [
            SourceResult(
                SourceType.GITHUB_COMMIT,
                "https://github.com/x/y/commit/abc.diff",
                0.95,
                commit_sha="abcdef1",
                diff_text=SAMPLE_DIFF,
            )
        ]
        pi = build_patch_info_from_sources("CVE-2021-44228", sources)
        assert pi.available is True
        assert pi.fix_exists is True
        assert pi.diff_text == SAMPLE_DIFF
        assert pi.source_type == SourceType.GITHUB_COMMIT
        assert pi.confidence == 0.95

    def test_source_without_diff_sets_fix_exists_only(self):
        sources = [
            SourceResult(
                SourceType.GHSA,
                "https://github.com/advisories/GHSA-xxxx",
                0.80,
                fixed_versions=["2.17.1"],
            )
        ]
        pi = build_patch_info_from_sources("CVE-2021-44228", sources)
        assert pi.available is False
        assert pi.fix_exists is True
        assert "2.17.1" in pi.fixed_versions
        assert pi.source_type == SourceType.GHSA
        assert "Fix confirmed" in pi.fetch_error

    def test_aggregates_fixed_versions_from_all_sources(self):
        sources = [
            SourceResult(
                SourceType.GITHUB_RELEASE,
                "https://github.com/x/y/releases/tag/v2.17.1",
                0.75,
                fixed_versions=["2.17.1"],
            ),
            SourceResult(
                SourceType.GHSA,
                "https://github.com/advisories/GHSA-xxxx",
                0.80,
                fixed_versions=["2.17.0"],
            ),
        ]
        pi = build_patch_info_from_sources("CVE-2021-44228", sources)
        assert "2.17.1" in pi.fixed_versions
        assert "2.17.0" in pi.fixed_versions

    def test_highest_confidence_source_selected(self):
        sources = [
            SourceResult(SourceType.VENDOR_ADVISORY, "https://vendor.com/a", 0.65),
            SourceResult(
                SourceType.GITHUB_COMMIT,
                "https://github.com/x/y/commit/abc.diff",
                0.95,
                diff_text=SAMPLE_DIFF,
            ),
        ]
        sources.sort(key=lambda s: s.confidence, reverse=True)
        pi = build_patch_info_from_sources("CVE-2021-44228", sources)
        assert pi.source_type == SourceType.GITHUB_COMMIT


# ---------------------------------------------------------------------------
# TestResolveAllSources (integration-style, fully mocked network)
# ---------------------------------------------------------------------------


class TestResolveAllSources:
    def test_returns_empty_when_no_refs_and_osv_404(self):
        with patch("core.agents.vulnerability.patch_sources.httpx.Client") as mc:
            mc.return_value.__enter__.return_value.get.return_value = MagicMock(
                status_code=404
            )
            results = resolve_all_sources("CVE-2099-99999", [])
        assert results == []

    def test_commit_url_takes_highest_confidence(self):
        refs = [GITHUB_COMMIT_URL, GITHUB_RELEASE_URL]
        with patch("core.agents.vulnerability.patch_sources.httpx.Client") as mc:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = SAMPLE_DIFF

            def side_effect(url, **kwargs):
                return mock_resp

            mc.return_value.__enter__.return_value.get.side_effect = side_effect
            results = resolve_all_sources("CVE-2021-44228", refs)
        assert results
        assert results[0].confidence >= results[-1].confidence

    def test_all_source_types_can_be_returned(self):
        refs = [GITHUB_COMMIT_URL, GITHUB_PR_URL, GITHUB_RELEASE_URL]
        refs_with_tags = [
            {"url": "https://vendor.com/advisory", "tags": ["Vendor Advisory"]},
            {"url": "https://vendor.com/patch", "tags": ["Patch"]},
        ]
        with patch("core.agents.vulnerability.patch_sources.httpx.Client") as mc:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mc.return_value.__enter__.return_value.get.return_value = mock_resp
            results = resolve_all_sources(
                "CVE-2021-44228", refs, references_with_tags=refs_with_tags
            )
        source_types = {r.source_type for r in results}
        assert SourceType.GITHUB_PR in source_types
        assert SourceType.GITHUB_RELEASE in source_types
        assert SourceType.NVD_PATCH_TAG in source_types

    def test_deduplication_by_url(self):
        refs = [GITHUB_COMMIT_URL, GITHUB_COMMIT_URL]
        with patch("core.agents.vulnerability.patch_sources.httpx.Client") as mc:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mc.return_value.__enter__.return_value.get.return_value = mock_resp
            results = resolve_all_sources("CVE-2021-44228", refs)
        urls = [r.url for r in results]
        assert len(urls) == len(set(urls)), "Duplicate URLs found"

    def test_network_errors_are_non_fatal(self):
        refs = [GITHUB_COMMIT_URL]
        with patch("core.agents.vulnerability.patch_sources.httpx.Client") as mc:
            mc.return_value.__enter__.return_value.get.side_effect = Exception(
                "net error"
            )
            results = resolve_all_sources("CVE-2021-44228", refs)
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# TestVersionCleaning - Semantic Hardening
# ---------------------------------------------------------------------------


class TestVersionCleaning:
    """Verifies that fixed_versions only contains valid package/product versions."""

    def test_valid_versions_cleaned(self):
        from core.agents.vulnerability.patch_sources import (
            clean_version_string,
            is_valid_version,
        )

        assert clean_version_string("2.15.0") == "2.15.0"
        assert clean_version_string("v2.17.1") == "2.17.1"
        assert clean_version_string("rel/5.3.18") == "5.3.18"
        assert clean_version_string("5.2.20.RELEASE") == "5.2.20.RELEASE"
        assert clean_version_string("1.0.0-beta.2") == "1.0.0-beta.2"
        assert is_valid_version("2.15.0") is True

    def test_git_commit_shas_rejected_as_versions(self):
        from core.agents.vulnerability.patch_sources import clean_version_string

        # 40-character and 7-character hex SHAs must return None
        assert clean_version_string("38513a7d57343881f7bf58f37e67d6a87e0a47c5") is None
        assert clean_version_string("ad361d2e517e765f69db464d9407ac2dd80bc93e") is None
        assert clean_version_string("cfa701b8726f06528e9d408b1b94f333f70da45f") is None
        assert clean_version_string("abcdef1") is None

    def test_branch_names_rejected_as_versions(self):
        from core.agents.vulnerability.patch_sources import clean_version_string

        for branch in ("main", "master", "HEAD", "trunk", "dev", "staging", "latest"):
            assert clean_version_string(branch) is None

    def test_urls_and_cve_ids_rejected(self):
        from core.agents.vulnerability.patch_sources import clean_version_string

        assert clean_version_string("https://github.com/apache/log4j") is None
        assert clean_version_string("CVE-2021-44228") is None
        assert clean_version_string("CVE-2022-22965") is None

    def test_file_names_rejected(self):
        from core.agents.vulnerability.patch_sources import clean_version_string

        assert clean_version_string("log4j-core-2.15.0.jar") is None
        assert clean_version_string("release-v1.0.zip") is None
        assert clean_version_string("patch.diff") is None


# ---------------------------------------------------------------------------
# TestCVERegressionSuites - CVE-2021-44228 and CVE-2022-22965
# ---------------------------------------------------------------------------


class TestCVERegressionSuites:
    """Explicit regression tests for CVE-2021-44228 and CVE-2022-22965 data quality."""

    def test_cve_2021_44228_regression(self):
        from core.agents.vulnerability.patch_analyzer import PatchAnalyzer

        analyzer = PatchAnalyzer()
        raw_refs = [
            {
                "url": "https://logging.apache.org/log4j/2.x/security.html",
                "tags": ["Vendor Advisory", "Release Notes"],
            },
            {
                "url": "https://www.oracle.com/security-alerts/cpuapr2022.html",
                "tags": ["Patch", "Third Party Advisory"],
            },
            {
                "url": "https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228",
                "tags": ["Exploit", "Third Party Advisory"],
            },
        ]
        plain_refs = [r["url"] for r in raw_refs]

        with patch("core.agents.vulnerability.patch_sources.resolve_osv") as mock_osv:
            mock_osv.return_value = [
                SourceResult(
                    source_type=SourceType.GITHUB_COMMIT,
                    url="https://github.com/apache/logging-log4j2/commit/38513a7d57343881f7bf58f37e67d6a87e0a47c5",
                    confidence=0.90,
                    commit_sha="38513a7d57343881f7bf58f37e67d6a87e0a47c5",
                    diff_text=SAMPLE_DIFF,
                    fixed_versions=[],  # Git range produces empty fixed_versions
                    notes="OSV-sourced commit",
                )
            ]
            patch_info = analyzer.fetch_patch_multisource(
                "CVE-2021-44228", plain_refs, references_with_tags=raw_refs
            )
            remediation = analyzer.build_remediation_info(
                "CVE-2021-44228", patch_info, plain_refs, references_with_tags=raw_refs
            )

        # 1. fix_exists is True and diff is available
        assert patch_info.fix_exists is True
        assert patch_info.available is True

        # 2. commit SHA is stored separately
        assert patch_info.commit_sha == "38513a7d57343881f7bf58f37e67d6a87e0a47c5"
        assert (
            "38513a7d57343881f7bf58f37e67d6a87e0a47c5"
            in remediation.remediation_commits
        )

        # 3. fixed_versions contains NO commit SHAs, NO 'main' branch
        for v in remediation.fixed_versions:
            assert len(v) != 40
            assert v != "main"
            assert v != "master"

        # 4. Patch URLs contains the commit URL
        assert any(
            "38513a7d57343881f7bf58f37e67d6a87e0a47c5" in u
            for u in remediation.patch_urls
        )

        # 5. Advisory URLs remain available
        assert (
            "https://logging.apache.org/log4j/2.x/security.html"
            in remediation.advisory_urls
        )

        # 6. Provenance is preserved
        assert patch_info.source_type == SourceType.GITHUB_COMMIT
        assert patch_info.confidence == 0.90

    def test_cve_2022_22965_regression(self):
        from core.agents.vulnerability.patch_analyzer import PatchAnalyzer

        analyzer = PatchAnalyzer()
        raw_refs = [
            {
                "url": "https://tanzu.vmware.com/security/cve-2022-22965",
                "tags": ["Vendor Advisory", "Mitigation"],
            },
            {
                "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-254054.pdf",
                "tags": ["Patch", "Third Party Advisory"],
            },
        ]
        plain_refs = [r["url"] for r in raw_refs]

        with patch("core.agents.vulnerability.patch_sources.resolve_osv") as mock_osv:
            mock_osv.return_value = [
                SourceResult(
                    source_type=SourceType.GITHUB_COMMIT,
                    url="https://github.com/spring-projects/spring-framework/commit/cfa701b8726f06528e9d408b1b94f333f70da45f",
                    confidence=0.90,
                    commit_sha="cfa701b8726f06528e9d408b1b94f333f70da45f",
                    diff_text="diff --git a/gradle.properties b/gradle.properties\n",
                    fixed_versions=[],
                    notes="OSV-sourced commit",
                )
            ]
            patch_info = analyzer.fetch_patch_multisource(
                "CVE-2022-22965", plain_refs, references_with_tags=raw_refs
            )
            remediation = analyzer.build_remediation_info(
                "CVE-2022-22965", patch_info, plain_refs, references_with_tags=raw_refs
            )

        assert patch_info.fix_exists is True
        assert patch_info.available is True
        assert patch_info.commit_sha == "cfa701b8726f06528e9d408b1b94f333f70da45f"
        assert (
            "cfa701b8726f06528e9d408b1b94f333f70da45f"
            in remediation.remediation_commits
        )
        assert (
            "cfa701b8726f06528e9d408b1b94f333f70da45f" not in remediation.fixed_versions
        )
        assert (
            "https://tanzu.vmware.com/security/cve-2022-22965"
            in remediation.advisory_urls
        )
