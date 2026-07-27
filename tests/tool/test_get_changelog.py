
import pytest
from depsafe.tool.get_changelog import (
    RawFileFetcher, ChangelogOrchestrator, Changelog,
)


class TestParseMarkdownChangelog:
    def test_extracts_versions_in_range(self):
        """from < ver <= to 范围内的版本被提取"""
        fetcher = RawFileFetcher()
        md = """
## [2.0.0] - Latest
Major rewrite.

### v1.5.0
Added feature X.

## 1.0.0
Initial release.
"""
        logs = fetcher._parse_markdown_changelog(md, "1.0.0", "2.0.0")
        assert len(logs) == 2
        assert logs[0]["ver_name"] == "2.0.0"
        assert logs[1]["ver_name"] == "1.5.0"
        assert "feature X" in logs[1]["changelog"]

    def test_excludes_out_of_range(self):
        """from_ver 及以前 / to_ver 之后的版本不收录"""
        fetcher = RawFileFetcher()
        md = """
## [3.0.0]  ← 超过 to_ver
## [2.0.0]  ← 在范围内
## [1.0.0]  ← <= from_ver，不收
"""
        logs = fetcher._parse_markdown_changelog(md, "1.0.0", "2.0.0")
        assert len(logs) == 1
        assert logs[0]["ver_name"] == "2.0.0"

    def test_invalid_version_skipped(self):
        """无效版本号不崩溃，跳过"""
        fetcher = RawFileFetcher()
        md = """
## [not.a.version]
garbage
## [2.0.0]
valid release
"""
        logs = fetcher._parse_markdown_changelog(md, "1.0.0", "3.0.0")
        assert len(logs) == 1
        assert logs[0]["ver_name"] == "2.0.0"

    def test_no_matching_versions_returns_empty(self):
        """范围内无版本 → 空"""
        fetcher = RawFileFetcher()
        logs = fetcher._parse_markdown_changelog("no versions here", "1.0.0", "2.0.0")
        assert logs == []


class TestGitHubReleasesPath:
    @pytest.mark.asyncio
    async def test_returns_changelog_when_releases_found(self, monkeypatch):
        """PyPI 有 repo → GitHub Releases 有数据 → 返回 Changelog"""
        async def mock_pypi(pkg):
            return "https://github.com/psf/requests"
        monkeypatch.setattr("depsafe.tool.get_changelog._get_pypi_source_url", mock_pypi)
        async def mock_releases(owner, repo):
            yield {"tag_name": "v2.31.0", "body": "CVE-2023-32681 fix"}
            yield {"tag_name": "v2.30.0", "body": "Feature release"}
            yield {"tag_name": "v2.25.0", "body": "Base version"}
        monkeypatch.setattr("depsafe.tool.get_changelog._iter_github_releases", mock_releases)
        orch = ChangelogOrchestrator(model=None)
        result = await orch.get_changelog("requests", "2.25.0", "2.31.0")
        assert len(result.changelogs) == 2
        assert result.source.startswith("github_repo:")
        assert result.changelogs[0]["ver_name"] == "2.31.0"

    @pytest.mark.asyncio
    async def test_no_pypi_repo_falls_through(self, monkeypatch):
        """PyPI 无 repo → 跳过 Tier 1 和 2 → 进入 LLM 兜底"""
        async def mock_pypi(pkg):
            return None
        monkeypatch.setattr("depsafe.tool.get_changelog._get_pypi_source_url", mock_pypi)
        async def mock_llm_search(self, pkg, from_ver, to_ver):
            return Changelog(pkg_name=pkg, changelogs=[],
                            from_ver=from_ver, to_ver=to_ver,
                            source="llm_agentic_search")
        monkeypatch.setattr(
            "depsafe.tool.get_changelog.LLMSearchFallback.search", mock_llm_search
        )
        orch = ChangelogOrchestrator(model=None)
        result = await orch.get_changelog("some-pkg", "1.0.0", "2.0.0")
        assert result.source == "llm_agentic_search"

    @pytest.mark.asyncio
    async def test_invalid_version_returns_empty(self, monkeypatch):
        """版本号格式不对 → 返回空 Changelog，走 LLM 兜底"""
        async def mock_llm_search(self, pkg, from_ver, to_ver):
            return Changelog(pkg_name=pkg, changelogs=[],
                            from_ver=from_ver, to_ver=to_ver,
                            source="llm_agentic_search")
        monkeypatch.setattr(
            "depsafe.tool.get_changelog.LLMSearchFallback.search", mock_llm_search
        )
        orch = ChangelogOrchestrator(model=None)
        result = await orch.get_changelog("flask", "not-a-version", "2.0.0")
        assert result.changelogs == []


class TestRawFileFetcher:
    @pytest.mark.asyncio
    async def test_finds_and_parses_changelog_md(self, monkeypatch):
        """HEAD 返回 200 → GET 返回内容 → _parse_markdown_changelog 解析"""
        async def mock_head(owner, repo, filename):
            return filename == "CHANGELOG.md"
        monkeypatch.setattr("depsafe.tool.get_changelog._check_raw_file_exists", mock_head)
        async def mock_get(self, url, **kwargs):
            class Resp:
                text = "## [1.5.0]\nBug fixes.\n## [1.0.0]\nOld."
                def raise_for_status(self): pass
            return Resp()
        monkeypatch.setattr("httpx.AsyncClient.get", mock_get)
        fetcher = RawFileFetcher()
        result = await fetcher.fetch("owner", "repo", "1.0.0", "1.5.0")
        assert result is not None
        assert result.source == "github_raw_file:CHANGELOG.md"
        assert len(result.changelogs) == 1

    @pytest.mark.asyncio
    async def test_no_candidates_returns_none(self, monkeypatch):
        """所有候选文件都不存在 → None"""
        async def mock_head(owner, repo, filename):
            return False
        monkeypatch.setattr("depsafe.tool.get_changelog._check_raw_file_exists", mock_head)
        fetcher = RawFileFetcher()
        result = await fetcher.fetch("owner", "repo", "1.0.0", "2.0.0")
        assert result is None


class TestLiveGetChangelog:
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_real_requests_package(self):
        """真实跑 requests 包的 changelog 获取"""
        orch = ChangelogOrchestrator(model=None)
        result = await orch.get_changelog("requests", "2.25.0", "2.31.0")
        assert len(result.changelogs) > 0 or result.source == "llm_agentic_search"
