import os
import re
from collections.abc import AsyncGenerator

import httpx
from packaging.version import InvalidVersion
from packaging.version import parse as parse_version
from pydantic import BaseModel, Field
from tavily import TavilyClient

from depsafe.budget import CostBudget, StepCounter
from depsafe.environment.local import LocalEnvironment
from depsafe.model import BASH_TOOL_SCHEMA, LitellmModel
from depsafe.tool.utils.subagent import SubAgent


class Changelog(BaseModel):
    pkg_name: str = Field(..., description="依赖包的名称")
    changelogs: list[dict[str, str]] = Field(default_factory=list, description="from_ver和to_ver之间每个版本的changelog内容")
    from_ver: str = Field(..., description="项目当前的依赖包版本")
    to_ver: str = Field(..., description="依赖包的第一个修复版本")
    source: str = Field(..., description="changelog来源")
    warnings: list[str] = Field(default_factory=list, description="降级过程中的警告信息，记录了哪些步骤失败以及原因")


async def _get_pypi_source_url(pkg: str) -> tuple[str | None, str | None]:
    """调 PyPI JSON API，返回 (Source repo URL, error_msg)"""
    pypi_url = f"https://pypi.org/pypi/{pkg}/json"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(pypi_url)
            response.raise_for_status()
            data = response.json()
            project_urls = data.get("info", {}).get("project_urls", {})
            return project_urls.get("Source"), None
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"


async def _iter_github_releases(owner: str, repo: str, warnings: list[str]) -> AsyncGenerator[dict, None]:
    """调 GitHub Releases API，逐个返回 release。错误写入 warnings。"""
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        warnings.append("未找到 GITHUB_TOKEN，将使用未认证请求（限流严格）")
    github_api_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    page = 1
    async with httpx.AsyncClient(headers=headers) as client:
        while True:
            try:
                response = await client.get(github_api_url, params={"page": page, "per_page": 100})
                response.raise_for_status()
                releases = response.json()
            except Exception as e:
                warnings.append(f"GitHub Releases 请求失败 (page={page}): {type(e).__name__}: {e}")
                break
            if not releases:
                break
            for rel in releases:
                yield rel
            page += 1


class ChangelogOrchestrator:
    """编排器：统一管理降级逻辑"""

    def __init__(self, model: LitellmModel, env: LocalEnvironment, step_counter: StepCounter):
        self.step_counter = step_counter
        self.env = env
        self.env.local_tools["web_search"] = web_search
        self.env.local_tools["get_changelog"] = self.get_changelog
        self.raw_fetcher = RawFileFetcher()
        self.llm_fallback = LLMSearchFallback(model, self.env, step_counter)

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
        warnings: list[str] = []
        # 通过pypi拿到repo链接
        repo_url, pypi_err = await _get_pypi_source_url(pkg)
        if not repo_url:
            warnings.append(f"PyPI 未找到 {pkg} 的 GitHub 仓库链接: {pypi_err or '无 Source URL'}")
        owner, repo = None, None
        if not repo_url:
            print(f"未找到 {pkg} 的 GitHub 仓库链接")
        # 访问github拿到release
        if repo_url:
            parts = repo_url.rstrip("/").split("/")
            if len(parts) >= 2:
                owner, repo = parts[-2], parts[-1]
            else:
                warnings.append(f"PyPI Source URL 格式无法解析: {repo_url}")
        try:
            min_ver = parse_version(from_ver)
            max_ver = parse_version(to_ver)
            version_valid = True
        except InvalidVersion as e:
            warnings.append(f"版本号格式无效: {e}")
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
                    warnings=warnings,
                )
        if owner and repo:
            warnings.append("[降级] GitHub Releases 未找到，尝试探测 Raw 文件...")
            raw_result, raw_warnings = await self.raw_fetcher.fetch(owner, repo, from_ver, to_ver)
            warnings.extend(raw_warnings)
            if raw_result:
                raw_result.warnings = warnings
                return raw_result
        warnings.append("[降级] Raw 文件未找到，启动 LLM 自主搜索...")
        llm_result = await self.llm_fallback.search(pkg, from_ver, to_ver)
        llm_result.warnings = warnings + llm_result.warnings
        return await llm_result


class RawFileFetcher:
    """降级：非标准文件探测，适用于个人项目或老项目"""

    # 候选文件名优先级队列
    CANDIDATES = ["CHANGELOG.md", "CHANGES.md", "HISTORY.md"]

    async def fetch(self, owner: str, repo: str, from_ver: str, to_ver: str) -> tuple["Changelog | None", list[str]]:
        """并发探测候选文件，收到 200 再下载内容。返回 (Changelog | None, warnings)。"""
        warnings: list[str] = []
        base_raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main"
        async with httpx.AsyncClient() as client:
            for filename in self.CANDIDATES:
                url = f"{base_raw_url}/{filename}"
                # 直接在此处进行 HEAD 检查，避免重复创建 client
                try:
                    head_resp = await client.head(url, follow_redirects=True, timeout=10.0)
                    if head_resp.status_code != 200:
                        continue
                except Exception as e:
                    warnings.append(f"检查 {filename} 是否存在时出错: {type(e).__name__}: {e}")
                    continue
                # 存在则下载内容
                try:
                    get_resp = await client.get(url, follow_redirects=True, timeout=15.0)
                    get_resp.raise_for_status()
                    content = get_resp.text
                    parsed_logs = self._parse_markdown_changelog(content, from_ver, to_ver)
                    if parsed_logs:
                        return (
                            Changelog(
                                pkg_name=repo,
                                changelogs=parsed_logs,
                                from_ver=from_ver,
                                to_ver=to_ver,
                                source=f"github_raw_file:{filename}",
                            ),
                            warnings,
                        )
                    warnings.append(f"{filename} 存在但未解析出匹配版本的 changelog")
                except Exception as e:
                    warnings.append(f"下载 {filename} 失败: {type(e).__name__}: {e}")
                    continue
        return None, warnings

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
                    parsed_logs.append({"ver_name": current_version, "changelog": "\n".join(current_log).strip()})
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
            parsed_logs.append({"ver_name": current_version, "changelog": "\n".join(current_log).strip()})
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
        tavily_client = TavilyClient(api_key=os.getenv("TAVILY_API_KEY"))
        response = tavily_client.search(query, max_results=3, include_raw_content=False)
        if not response.get("results"):
            return "未找到相关搜索结果。"
        formatted_results = []
        for r in response["results"]:
            formatted_results.append(f"### {r['title']}\n来源: {r['url']}\n{r['content']}")
        return "\n\n---\n\n".join(formatted_results)
    except Exception as e:
        return f"搜索执行失败: {type(e).__name__}: {e}"


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


SUBMIT_RESULT_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "submit_result",
        "description": (
            "提交最终结果并结束当前任务。"
            "当你已经收集到足够信息、可以给出最终结论时，必须调用此工具。"
            "调用此工具后，任务将立即终止。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "result": {
                    "type": "object",
                    "description": "任务的最终结果，结构化对象。",
                    "properties": {
                        "pkg_name": {
                            "type": "string",
                            "description": "依赖包的名称",
                        },
                        "changelogs": {
                            "type": "array",
                            "description": "from_ver和to_ver之间每个版本的changelog内容",
                            "items": {
                                "type": "object",
                                "additionalProperties": {"type": "string"},
                            },
                        },
                        "from_ver": {
                            "type": "string",
                            "description": "项目当前的依赖包版本",
                        },
                        "to_ver": {
                            "type": "string",
                            "description": "依赖包的第一个修复版本",
                        },
                        "source": {
                            "type": "string",
                            "description": "changelog来源",
                        },
                    },
                    "required": [
                        "pkg_name",
                        "changelogs",
                        "from_ver",
                        "to_ver",
                        "source",
                    ],
                }
            },
            "required": ["result"],
        },
    },
}


class LLMSearchFallback:
    def __init__(self, model: LitellmModel, env: LocalEnvironment, step_counter: StepCounter, cost_budget: CostBudget):
        self.model = model
        self.env = env
        self.step_counter = step_counter
        self.cost_budget = cost_budget

    async def search(self, pkg: str, from_ver: str, to_ver: str) -> Changelog:
        tools = [WEB_SEARCH_TOOL_SCHEMA, BASH_TOOL_SCHEMA, SUBMIT_RESULT_TOOL_SCHEMA]
        system_prompt = """\
你是一个专业的软件供应链安全分析师。
请通过调用工具获取信息，然后给出最终总结。
不要直接输出文本，必须通过调用工具来交互。
"""
        user_prompt = f"""\
请查找 Python 包 `{pkg}` 从版本 `{from_ver}` 到 `{to_ver}` 的变更日志。

你可以使用以下工具：
1. `web_search`: 在互联网上搜索信息。
2. `bash`: 执行 shell 命令。
3. `submit_result`: 当你收集到足够信息后，调用此工具提交最终总结。

工作流程：
1. 使用 `web_search` 搜索相关信息（建议搜索 `{pkg} github releases {to_ver}` 等）。
2. 分析搜索结果。
3. 一旦你有了最终的总结，**必须**调用 `submit_result` 工具，将结构化的 changelog 信息放入 `result` 参数中。

`result` 参数必须包含以下字段：
- `pkg_name`: 依赖包名称
- `changelogs`: 每个版本的 changelog 内容列表
- `from_ver`: 当前版本
- `to_ver`: 第一个修复版本
- `source`: changelog 来源

注意：不要直接输出文本，必须通过调用工具来交互。
"""
        sub_agent = SubAgent(
            model=self.model,
            env=self.env,
            step_counter=self.step_counter,
            cost_budget=self.cost_budget,
            max_steps=5,
        )
        result = await sub_agent.run(system_prompt, user_prompt, tools)
        warnings: list[str] = []
        if result.get("exit_status") == "Submitted":
            return result["submission"]
        warnings.append(f"LLM SubAgent 未能提交结果 (exit_status={result.get('exit_status')}), raw={result}")
        return Changelog(
            pkg_name=pkg,
            changelogs=[],
            from_ver=from_ver,
            to_ver=to_ver,
            source="llm_web_search",
            warnings=warnings,
        )
