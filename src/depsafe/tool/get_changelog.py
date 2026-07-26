
import os
import re
import httpx
from typing import Optional
from pydantic import BaseModel, Field
from packaging.version import parse as parse_version, InvalidVersion

from depsafe.model import LitellmModel

class Changelog(BaseModel):
    pkg_name: str = Field(..., description="依赖包的名称")
    changelogs: list[dict[str, str]] = Field(..., description="from_ver和to_ver之间每个版本的changelog内容")
    from_ver: str = Field(..., description="项目当前的依赖包版本")
    to_ver: str = Field(..., description="依赖包的第一个修复版本")
    source: str = Field(..., description="changelog来源")

class ChangelogOrchestrator:
    """编排器：统一管理降级逻辑"""
    def __init__(self, llm_model: LitellmModel):
        self.raw_fetcher = RawFileFetcher()
        self.llm_fallback = LLMSearchFallback(llm_model)

    async def get_changelog(self, pkg: str, from_ver: str, to_ver: str) -> Changelog:
        """
        获取指定包在两个版本之间的变更日志

        Args:
            pkg: 
            from_ver: 
            to_ver:
        
        Returns:

        """
        # 通过pypi拿到repo链接
        pypi_url = f"https://pypi.org/pypi/{pkg}/json"
        repo_url = None
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(pypi_url)
                response.raise_for_status()
                data = response.json()
                project_urls = data.get("info", {}).get("project_urls", {})
                repo_url = project_urls.get("Source")
            except Exception as e:
                print(f"访问PyPI失败：{e}")
                return Changelog(pkg_name=pkg, changelogs=[], from_ver=from_ver, to_ver=to_ver, source="")
        if not repo_url:
            print(f"未找到 {pkg} 的 GitHub 仓库链接")
            return Changelog(pkg_name=pkg, changelogs=[], from_ver=from_ver, to_ver=to_ver, source="")
        # 访问github拿到release
        parts = repo_url.rstrip('/').split('/')
        owner, repo = parts[-2], parts[-1]
        headers = {"Accept": "application/vnd.github.v3+json"}
        token = os.getenv("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            print("未找到 GITHUB_TOKEN，跳过 GitHub Repo-release 查询")
        github_api_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
        try:
            min_ver = parse_version(from_ver)
            max_ver = parse_version(to_ver)
        except InvalidVersion as e:
            print(f"版本号格式无效：{e}")
            return Changelog(pkg_name=pkg, changelogs=[], from_ver=from_ver, to_ver=to_ver, source="")
        # 分页获取releases
        changelogs = []
        page = 1
        async with httpx.AsyncClient(headers=headers) as client:
            while True:
                try:
                    response = await client.get(github_api_url, params={"page": page, "per_page": 100})
                    response.raise_for_status()
                    releases = response.json()
                except Exception as e:
                    print(f"获取 GitHub Releases 失败: {e}")
                    break
                if not releases:
                    break
                older_than_min = False
                for rel in releases:
                    ver_name = rel.get("tag_name", "").lstrip("v")
                    try:
                        cur_ver = parse_version(ver_name)
                    except InvalidVersion:
                        continue
                    if cur_ver > max_ver:
                        continue
                    if cur_ver <= min_ver:
                        older_than_min = True
                        break
                    changelog = rel.get("body") or "无变更日志"
                    changelogs.append({"ver_name": ver_name, "changelog": changelog})
                if older_than_min:
                    break
                page += 1
        if changelogs:
            return Changelog(
                pkg_name=pkg, 
                changelogs=changelogs,
                from_ver=from_ver,
                to_ver=to_ver,
                source=f"github_repo:{repo_url}")
        print(f"[降级] GitHub Releases 未找到，尝试探测 Raw 文件...")
        raw_file_changelog = await self.raw_fetcher.fetch(owner, repo, from_ver, to_ver)
        if raw_file_changelog:
            return raw_file_changelog
        print(f"[降级] Raw 文件未找到，启动 LLM 自主搜索...")
        return await self.llm_fallback.search(pkg, from_ver, to_ver)

class RawFileFetcher:
    """降级：非标准文件探测，适用于个人项目或老项目"""
    # 候选文件名优先级队列
    CANDIDATES = ["CHANGELOG.md", "CHANGES.md", "HISTORY.md"]

    async def fetch(self, owner: str, repo: str, from_ver: str, to_ver: str) -> Optional[Changelog]:
        """并发探测候选文件，只请求头部更快速，收到200再下载内容"""
        base_raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main"
        async with httpx.AsyncClient() as client:
            for filename in self.CANDIDATES:
                url = f"{base_raw_url}/{filename}"
                try:
                    head_resp = await client.head(url, follow_redirects=True)
                    if head_resp.status_code == 200:
                        get_resp = await client.get(url, follow_redirects=True)
                        content = get_resp.text
                        parsed_logs = self._parse_markdown_changelog(content, from_ver, to_ver)
                        if parsed_logs:
                            return Changelog(
                                pkg_name=repo,
                                changelogs=parsed_logs,
                                from_ver=from_ver,
                                to_ver=to_ver,
                                source=f"github_raw_file:{filename}"
                            )
                except Exception:
                    continue
        return None

    def _parse_markdown_changelog(self, text: str, from_ver: str, to_ver: str) -> list[dict[str, str]]:
        """
        专门解析 Markdown 格式的 Changelog。
        返回一个包含多个版本日志的列表。
        """
        try:
            min_ver = parse_version(from_ver)
            max_ver = parse_version(to_ver)
        except InvalidVersion:
            return []
        # 匹配 ## [1.2.3] 或 ### v1.2.3 等格式
        # 这个正则捕获标题行和直到下一个标题之前的所有内容
        heading_pattern = re.compile(r"^(#{2,4})\s*\[?v?([0-9]+\.[0-9]+\.[0-9]+[^\n]*)\]?(.*?)$(.*?)(?=(?:^#{2,4}\s*\[?v?[0-9])|\Z)", re.MULTILINE | re.DOTALL | re.IGNORECASE)
        parsed_logs = []
        for match in heading_pattern.finditer(text):
            version_str = match.group(2).strip()
            try:
                cur_ver = parse_version(version_str)
                if min_ver < cur_ver <= max_ver:
                    # match.group(3) 是标题行的其余部分，match.group(4) 是正文
                    body = (match.group(3) + match.group(4)).strip()
                    parsed_logs.append({"ver_name": version_str, "changelog": body})
            except InvalidVersion:
                continue       
        parsed_logs.sort(key=lambda x: parse_version(x["ver_name"]), reverse=True)
        return parsed_logs

class LLMSearchFallback:
    """降级：LLM 自主搜索"""
    def __init__(self, llm_model: LitellmModel):
        self.llm_model = llm_model

    async def search(self, pkg: str, from_ver: str, to_ver: str) -> Changelog:
        prompt = f"""
你是一个专业的软件供应链安全分析师。请查找 Python 包 `{pkg}` 从版本 `{from_ver}` 到 `{to_ver}` 的变更日志。

搜索策略：
1. 优先搜索 GitHub 仓库的 Releases 页面。
2. 其次搜索官方文档或技术博客。

输出要求：
1. 你必须严格按照 `Changelog` 数据模型的结构返回 JSON 数据。
2. `pkg_name` 字段为包名。
3. `from_ver` 和 `to_ver` 字段填入对应的版本号。
4. `source` 字段填入 "llm_agentic_search"。
5. `changelogs` 字段是一个列表，请尽可能找出这个区间内所有版本的变更日志。如果找不到具体版本，可以只放一个包含摘要信息的字典。
6. 如果完全找不到任何信息，`changelogs` 列表可以为空。
"""
        messages = [{"role": "user", "content": prompt}]
        llm_response = await self.model.query(messages, response_format=Changelog)
        parsed_changelog = llm_response.get("parsed")
        if isinstance(parsed_changelog, Changelog):
            return parsed_changelog
        return Changelog(
            pkg_name=pkg,
            changelogs=[{"ver_name": "search_failed", "changelog": "LLM结构化输出changelog失败"}],
            from_ver=from_ver,
            to_ver=to_ver,
            source="llm_agentic_search"
        )
