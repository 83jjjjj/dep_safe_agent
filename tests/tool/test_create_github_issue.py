from depsafe.tool.create_github_issue import _build_issue_body, create_github_issue


class TestBuildIssueBody:
    def test_contains_all_required_sections(self):
        """issue body 包含 CVE、包名、优先级、可达性、修复建议"""
        body = _build_issue_body("CVE-2024-1234", "flask", "P0", "reachable", "升级到 2.3.3")
        assert "CVE-2024-1234" in body
        assert "flask" in body
        assert "P0" in body
        assert "reachable" in body
        assert "升级到 2.3.3" in body
        assert "security" in body
        assert "needs-manual-fix" in body

    def test_missing_token_returns_error(self, monkeypatch):
        """无 GITHUB_TOKEN → success=False"""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        result = create_github_issue("test", "CVE-2024-1234", "flask", "P0", "reachable")
        assert result["success"] is False
        assert "GITHUB_TOKEN" in result["error"]
