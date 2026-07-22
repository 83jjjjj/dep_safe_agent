

from unittest.mock import patch, MagicMock
from depsafe.tool.cve_checker import check_cve
from depsafe.tool.cve_checker import check_github_advisory


class TestCheckCve:
    def test_detects_known_vulnerability(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-xxxx",
                    "aliases": ["CVE-2023-32681"],
                    "summary": "Test vulnerability",
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]
                                }
                            ]
                        }
                    ],
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"}]
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()
        with patch("httpx.post", return_value=mock_response):
            results = check_cve("flask", "2.3.1")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2023-32681"
        assert results[0].fixed_ver == "2.31.0"
        assert results[0].pkg_name == "flask"
        assert results[0].severity == "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"

    @patch("src.depsafe.tool.cve_checker.httpx.post")
    def test_check_cve_severity_fallback(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-yyyy",
                    "aliases": ["CVE-2024-99999"],
                    "summary": "Test fallback severity",
                    "affected": [],
                    "database_specific": {
                        "severity": "MODERATE"
                    }
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        results = check_cve("some-package", "1.0.0")
        assert len(results) == 1
        assert results[0].severity == "MODERATE"

    def test_safe_version_returns_empty(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulns": []}
        mock_response.raise_for_status = MagicMock()
        with patch("httpx.post", return_value=mock_response):
            results = check_cve("flask", "999.0.0")
        assert results == []

    def test_api_error_returns_empty(self):
        with patch("httpx.post", side_effect=Exception("timeout")):
            results = check_cve("flask", "2.3.1")
        assert results == []

class TestGitHubAdvisory:
    def test_no_token_returns_empty(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        results = check_github_advisory("flask", "2.3.1")
        assert results == []

    def test_detects_vulnerable_version(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [{
                        "vulnerableVersionRange": ">= 2.3.0, < 2.3.3",
                        "firstPatchedVersion": {"identifier": "2.3.3"},
                        "advisory": {
                            "ghsaId": "GHSA-xxxx-xxxx-xxxx",
                            "summary": "Flask session leak",
                            "severity": "HIGH",
                            "identifiers": [
                                {"type": "CVE", "value": "CVE-2023-30861"}
                            ]
                        }
                    }]
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.post", return_value=mock_resp):
            results = check_github_advisory("flask", "2.3.1")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2023-30861"
        assert results[0].fixed_ver == "2.3.3"
        assert results[0].severity == "HIGH"

    def test_version_not_in_range_is_skipped(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [{
                        "vulnerableVersionRange": "< 2.0",  # 只影响 2.0 以下
                        "firstPatchedVersion": {"identifier": "2.0.0"},
                        "advisory": {
                            "ghsaId": "GHSA-yyyy",
                            "summary": "Old issue",
                            "severity": "LOW",
                            "identifiers": []
                        }
                    }]
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.post", return_value=mock_resp):
            results = check_github_advisory("flask", "3.0.0")  # 3.0.0 不在 <2.0 范围内
        assert results == []

    def test_api_error_returns_empty(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
        with patch("httpx.post", side_effect=Exception("timeout")):
            results = check_github_advisory("flask", "2.3.1")
        assert results == []
