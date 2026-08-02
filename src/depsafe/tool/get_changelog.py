import os
import re
from collections.abc import AsyncGenerator

import httpx
from packaging.version import InvalidVersion
from packaging.version import parse as parse_version
from pydantic import BaseModel, Field
from tavily import TavilyClient

from depsafe.environment import LocalEnvironment
from depsafe.model import BASH_TOOL_SCHEMA, LitellmModel


class Changelog(BaseModel):
    pkg_name: str = Field(..., description="依赖包的名称")
    changelogs: list[dict[str, str]] = Field(
        ..., description="from_ver和to_ver之间每个版本的changelog内容"
    )
    from_ver: str = Field(..., description="项目当前的依赖包版本")
    to_ver: str = Field(..., description="依赖包的第一个修复版本")
    source: str = Field(..., description="changelog来源")


async def _get_pypi_source_url(pkg: str) -> str | None:
    """调 PyPI JSON API，返回 Source repo URL"""
    pypi_url = f"https://pypi.org/pypi/{pkg}/json"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(pypi_url)
            response.raise_for_status()
            data = response.json()
            project_urls = data.get("info", {}).get("project_urls", {})
            return project_urls.get("Source")
        except Exception as e:
            print(f"访问PyPI失败：{e}")
            return None


async def _iter_github_releases(owner: str, repo: str) -> AsyncGenerator[dict, None]:
    """调 GitHub Releases API，逐个返回 release"""
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        print("未找到 GITHUB_TOKEN，将使用未认证请求（限流严格）")
    github_api_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
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
            for rel in releases:
                yield rel
            page += 1


class ChangelogOrchestrator:
    """编排器：统一管理降级逻辑"""

    def __init__(self, model: LitellmModel):
        self.env = LocalEnvironment()
        self.env.local_tools["web_search"] = web_search
        self.env.local_tools["get_changelog"] = self.get_changelog
        self.raw_fetcher = RawFileFetcher()
        self.llm_fallback = LLMSearchFallback(model, self.env)

    async def get_changelog(self, pkg: str, from_ver: str, to_ver: str) -> Changelog:
        """
        获取指定包在两个版本之间的变更日志

        Args:
            pkg: 依赖包名称
            from_ver: 要查询变更日志的起始版本
            to_ver: 要查询变更日志的目标版本

        Returns:
            依赖包的变更日志
        """
        # 通过pypi拿到repo链接
        repo_url = await _get_pypi_source_url(pkg)
        owner, repo = None, None
        if not repo_url:
            print(f"未找到 {pkg} 的 GitHub 仓库链接")
        # 访问github拿到release
        if repo_url:
            parts = repo_url.rstrip("/").split("/")
            owner, repo = parts[-2], parts[-1]
        try:
            min_ver = parse_version(from_ver)
            max_ver = parse_version(to_ver)
            version_valid = True
        except InvalidVersion as e:
            print(f"版本号格式无效：{e}")
            version_valid = False
        if owner and repo and version_valid:
            changelogs = []
            async for rel in _iter_github_releases(owner, repo):
                ver_name = rel.get("tag_name", "").lstrip("v")
                try:
                    cur_ver = parse_version(ver_name)
                except InvalidVersion:
                    continue
                if cur_ver > max_ver:
                    continue
                if cur_ver <= min_ver:
                    break
                changelog = rel.get("body") or "无变更日志"
                changelogs.append({"ver_name": ver_name, "changelog": changelog})
            if changelogs:
                return Changelog(
                    pkg_name=pkg,
                    changelogs=changelogs,
                    from_ver=from_ver,
                    to_ver=to_ver,
                    source=f"github_repo:{repo_url}",
                )
        if owner and repo:
            print("[降级] GitHub Releases 未找到，尝试探测 Raw 文件...")
            raw_file_changelog = await self.raw_fetcher.fetch(owner, repo, from_ver, to_ver)
            if raw_file_changelog:
                return raw_file_changelog
        print("[降级] Raw 文件未找到，启动 LLM 自主搜索...")
        return await self.llm_fallback.search(pkg, from_ver, to_ver)


async def _check_raw_file_exists(owner: str, repo: str, filename: str) -> bool:
    """HEAD 请求检查 raw 文件是否存在"""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{filename}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.head(url, follow_redirects=True)
            return response.status_code == 200
        except Exception:
            return False


class RawFileFetcher:
    """降级：非标准文件探测，适用于个人项目或老项目"""

    # 候选文件名优先级队列
    CANDIDATES = ["CHANGELOG.md", "CHANGES.md", "HISTORY.md"]

    async def fetch(self, owner: str, repo: str, from_ver: str, to_ver: str) -> Changelog | None:
        """并发探测候选文件，只请求头部更快速，收到200再下载内容"""
        base_raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main"
        async with httpx.AsyncClient() as client:
            for filename in self.CANDIDATES:
                url = f"{base_raw_url}/{filename}"
                try:
                    if await _check_raw_file_exists(owner, repo, filename):
                        get_resp = await client.get(url, follow_redirects=True)
                        content = get_resp.text
                        parsed_logs = self._parse_markdown_changelog(content, from_ver, to_ver)
                        if parsed_logs:
                            return Changelog(
                                pkg_name=repo,
                                changelogs=parsed_logs,
                                from_ver=from_ver,
                                to_ver=to_ver,
                                source=f"github_raw_file:{filename}",
                            )
                except Exception:
                    continue
        return None

    def _parse_markdown_changelog(
        self, text: str, from_ver: str, to_ver: str
    ) -> list[dict[str, str]]:
        """
        专门解析 Markdown 格式的 Changelog。
        返回一个包含多个版本日志的列表。
        """
        try:
            min_ver = parse_version(from_ver)
            max_ver = parse_version(to_ver)
        except InvalidVersion:
            return []
        parsed_logs = []
        current_log = []
        current_version = None
        # 匹配 ## [1.2.3] 或 ### v1.2.3 等格式的标题行
        heading_pattern = re.compile(r"^(#{2,4})\s*\[?v?([^\]\s]+)\]?", re.IGNORECASE)
        for line in text.splitlines():
            match = heading_pattern.match(line)
            if match:
                # 1. 如果之前正在记录一个版本的日志，先把它保存下来
                if current_version is not None and current_log:
                    parsed_logs.append(
                        {"ver_name": current_version, "changelog": "\n".join(current_log).strip()}
                    )
                # 2. 开始处理新版本
                version_str = match.group(2).strip()
                try:
                    parse_version(version_str)
                    current_version = version_str
                    current_log = [line]
                except InvalidVersion:
                    current_version = None
                    current_log = None
            else:
                if current_log is not None:
                    current_log.append(line)
        if current_version is not None and current_log:
            parsed_logs.append(
                {"ver_name": current_version, "changelog": "\n".join(current_log).strip()}
            )
        parsed_logs.sort(key=lambda x: parse_version(x["ver_name"]), reverse=True)
        final_logs = []
        for log in parsed_logs:
            try:
                ver = parse_version(log["ver_name"])
                if min_ver < ver <= max_ver:
                    final_logs.append(log)
            except InvalidVersion:
                continue
        return final_logs


def web_search(query: str) -> str:
    """
    在互联网上搜索最新信息。
    输入搜索关键词，返回相关的网页标题和内容摘要。
    """
    try:
        tavily_client = TavilyClient(api_key=os.getenv('TAVILY_API_KEY'))
        response = tavily_client.search(query, max_results=3, include_raw_content=False)
        if not response.get("results"):
            return "未找到相关搜索结果。"
        formatted_results = []
        for r in response["results"]:
            formatted_results.append(f"### {r['title']}\n来源: {r['url']}\n{r['content']}")
        return "\n\n---\n\n".join(formatted_results)
    except Exception as e:
        return f"搜索执行失败: {e}"


WEB_SEARCH_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": "在互联网上搜索最新信息，用于查找包的更新日志、安全公告等。",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "搜索关键词，例如 'requests python package changelog 2.31.0'",
                }
            },
            "required": ["query"],
        },
    },
}


class LLMSearchFallback:
    """降级策略：LLM 自主搜索（轻量版，带工具调用循环）"""

    def __init__(self, model: LitellmModel, env: LocalEnvironment):
        self.model = model
        self.env = env

    async def search(self, pkg: str, from_ver: str, to_ver: str) -> "Changelog":
        TavilyClient(api_key=os.getenv("TAVILY_API_KEY"))
        task_prompt = f"""
你是一个专业的软件供应链安全分析师。请查找 Python 包 `{pkg}` 从版本 `{from_ver}` 到 `{to_ver}` 的变更日志。

你可以使用以下工具：
1. `web_search`: 在互联网上搜索信息。
2. `bash`: 执行 shell 命令。

工作流程：
1. 使用 `web_search` 搜索相关信息（建议搜索 "{pkg} github releases {to_ver}" 等）。
2. 收集到足够信息后，**必须**调用 `bash` 工具执行以下命令来结束任务：
   `echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT`
   并在该命令的下一行输出你总结的最终报告内容。

注意：不要直接输出文本，必须通过调用工具来交互。
"""
        messages = [
            {
                "role": "system",
                "content": "你是一个会使用搜索工具的助手。请通过调用工具获取信息，然后给出最终总结。",
            },
            {"role": "user", "content": task_prompt},
        ]
        max_steps = 3
        fail_reason = None
        for step in range(max_steps):
            response = await self.model.query(
                messages=messages, tools=[WEB_SEARCH_TOOL_SCHEMA, BASH_TOOL_SCHEMA]
            )
            actions = response.get("extra", {}).get("actions", [])
            if not actions:
                fail_reason = "LLM未调用任何工具。"
                break
            messages.append(response)
            try:
                results = [self.env.execute(action) for action in actions]
                messages += self.model.format_toolcall_observation_results(response, results)
            except Submitted as e:
                final_summary = e.value["content"]
                return await self._structure_output(final_summary, pkg, from_ver, to_ver)
            except Exception:
                pass
        fail_reason = fail_reason if fail_reason else "LLM搜索任务达最大调用次数"
        return Changelog(
            pkg_name=pkg,
            changelogs=[{"ver_name": "search_failed", "changelog": fail_reason}],
            from_ver=from_ver,
            to_ver=to_ver,
            source="llm_agentic_search",
        )

    async def _structure_output(
        self, summary_text: str, pkg: str, from_ver: str, to_ver: str
    ) -> Changelog:
        """使用结构化输出，将 LLM 的文本总结转换为 Changelog 对象"""
        struct_prompt = f"""
请将以下变更日志总结，严格按照 Changelog 数据模型的结构转换为 JSON 格式。

总结内容：
{summary_text}

要求：
1. pkg_name: {pkg}
2. from_ver: {from_ver}
3. to_ver: {to_ver}
4. source: "llm_agentic_search"
5. changelogs: 如果总结中提到了具体的版本，请拆分成多个字典；如果没有，就放一个包含整体总结的字典。
"""
        response = await self.model.query(
            messages=[{"role": "user", "content": struct_prompt}],
            response_format=Changelog,
        )
        parsed_changelog = response.get("parsed")
        if isinstance(parsed_changelog, Changelog):
            return parsed_changelog
        return Changelog(
            pkg_name=pkg,
            changelogs=[{"ver_name": "llm_summary", "changelog": summary_text}],
            from_ver=from_ver,
            to_ver=to_ver,
            source="llm_agentic_search",
        )
