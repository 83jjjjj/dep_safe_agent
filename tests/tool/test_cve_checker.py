

from unittest.mock import patch, MagicMock
from depsafe.tool.cve_checker import check_cve


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
