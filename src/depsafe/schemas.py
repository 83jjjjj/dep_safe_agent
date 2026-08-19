from pydantic import BaseModel, Field


class BashInput(BaseModel):
    command: str = Field(..., description="The bash command to execute")


_bash_params = BashInput.model_json_schema()
_bash_params.pop("title", None)
BASH_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": "Execute a bash command",
        "parameters": _bash_params,
    },
}


class ScanVulnsInput(BaseModel):
    dep_file_path: str = Field(
        ..., description="依赖文件相对于项目根目录的路径，例如 'requirements.txt'、'pyproject.toml' 或 'Pipfile'。"
    )


_vuln_params = ScanVulnsInput.model_json_schema()
_vuln_params.pop("title", None)
SCAN_VULNS_SCHEMA = {
    "type": "function",
    "function": {
        "name": "scan_vulns",
        "description": "扫描项目的依赖文件，查找已知漏洞（CVE）。返回本轮需要修复的漏洞列表，数量受系统预算控制。若返回空列表则表示无更多漏洞。",
        "parameters": _vuln_params,
    },
}


class AnalyzeReachabilityInput(BaseModel):
    file_path: str = Field(..., description="待分析的代码文件路径，例如 'src/main.py'")
    target_functions: list[str] = Field(
        ...,
        description="需要追踪的目标函数完整路径列表，例如 ['requests.get', 'os.system']",
    )


_reach_params = AnalyzeReachabilityInput.model_json_schema()
_reach_params.pop("title", None)
ANALYZE_REACHABILITY_SCHEMA = {
    "type": "function",
    "function": {
        "name": "analyze_reachability",
        "description": (
            "分析指定文件中漏洞触发条件的可达性。"
            "先通过 AST 追踪 target_functions 的调用链；"
            "若未发现高置信度证据且提供了 target_description，"
            "自动启动语义代码搜索以覆盖属性赋值、配置变更等非函数调用类触发条件。"
            "返回调用证据列表（含行号、代码片段、置信度、证据类型）及分析错误信息。"
        ),
        "parameters": _reach_params,
    },
}


class DynamicCallResolution(BaseModel):
    """单条动态调用的解析结果"""

    original_line: int = Field(..., description="原始代码行号")
    resolved_path: str = Field(..., description="解析后的完整函数路径")
    confidence: str = Field(..., description="置信度: high / medium / low")


class DynamicCallsResult(BaseModel):
    """SubAgent 探索动态调用可达性的提交结果"""

    resolved_calls: list[DynamicCallResolution] = Field(default_factory=list, description="动态调用解析结果列表")


_dynamic_calls_params = DynamicCallsResult.model_json_schema()
_dynamic_calls_params.pop("title", None)

DYNAMIC_CALLS_SUBMIT_RESULT_SCHEMA = {
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
                "result": _dynamic_calls_params,
            },
            "required": ["result"],
        },
    },
}


class SemanticSearchResult(BaseModel):
    """SubAgent 语义探索可达性的提交结果"""

    reachable: bool = Field(..., description="漏洞触发条件是否可达")
    evidence_code: str = Field(default="", description="匹配的代码行，不可达时为空字符串")
    evidence_line: int = Field(default=0, description="行号，不可达时为 0")
    reasoning: str = Field(default="", description="一句话判断理由")


_semantic_search_params = SemanticSearchResult.model_json_schema()
_semantic_search_params.pop("title", None)

SEMANTIC_SEARCH_SUBMIT_RESULT_SCHEMA = {
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
                "result": _semantic_search_params,
            },
            "required": ["result"],
        },
    },
}


class WebSearchInput(BaseModel):
    query: str = Field(..., description="搜索关键词，例如 'requests python package changelog 2.31.0'")


_web_params = WebSearchInput.model_json_schema()
_web_params.pop("title", None)
WEB_SEARCH_SCHEMA = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": "在互联网上搜索最新信息，输入搜索关键词，返回相关的网页标题和内容摘要。",
        "parameters": _web_params,
    },
}


class GetChangelogInput(BaseModel):
    pkg: str = Field(..., description="依赖包名称，例如 'requests' 或 'litellm'")
    from_ver: str = Field(..., description="项目当前使用的依赖版本，例如 '2.25.1'")
    to_ver: str = Field(..., description="目标修复版本，例如 '2.31.0'")


_changelog_params = GetChangelogInput.model_json_schema()
_changelog_params.pop("title", None)
GET_CHANGELOG_SCHEMA = {
    "type": "function",
    "function": {
        "name": "get_changelog",
        "description": (
            "获取指定 Python 包在两个版本之间的变更日志。"
            "自动按 GitHub Releases → Raw Changelog 文件 → LLM 联网搜索 三级降级获取。"
            "返回结构化的 Changelog 对象，包含每个版本的变更记录、来源及降级警告。"
        ),
        "parameters": _changelog_params,
    },
}


class PriorityInput(BaseModel):
    cvss_vector: str | None = Field(
        None, description="CVSS v3.1 向量字符串，如 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'"
    )
    advisory_severity: str | None = Field(None, description="GitHub Advisory 返回的危害等级，如 'MODERATE'、'HIGH'")
    reachability_confidence: str = Field(
        ..., description="可达性分析置信度：'high'（静态确定调用）、'low'（动态调用）、'none'（未发现调用）"
    )
    has_breaking_change: bool = Field(..., description="修复版本的 changelog 中是否包含影响当前项目的破坏性变更")


_priority_params = PriorityInput.model_json_schema()
_priority_params.pop("title", None)
ASSESS_PRIORITY_SCHEMA = {
    "type": "function",
    "function": {
        "name": "assess_priority",
        "description": (
            "综合评估漏洞修复优先级。根据 CVSS 向量/公告严重性、可达性置信度、破坏性变更三个维度，"
            "判定 P0-P4 优先级并给出标准化危害等级和判定理由。"
        ),
        "parameters": _priority_params,
    },
}


class ApplyFixAndVerifyInput(BaseModel):
    pkg_name: str = Field(..., description="待修复的包名，如 'requests'")
    cve_id: str = Field(..., description="CVE 编号，如 'CVE-2024-1234'")
    target_version: str = Field(..., description="目标修复版本，如 '2.3.1'")
    module_name: str = Field(
        ..., description="包的导入模块名。当包名与 import 名不一致时必填，如包名 'Pillow' 对应模块名 'PIL'"
    )


_fix_params = ApplyFixAndVerifyInput.model_json_schema()
_fix_params.pop("title", None)
APPLY_FIX_AND_VERIFY_SCHEMA = {
    "type": "function",
    "function": {
        "name": "apply_fix_and_verify",
        "description": (
            "尝试将指定包升级到目标版本并进行完整验证（依赖文件更新 → 锁文件生成 → 隔离环境安装/import/pip check → 项目测试 → Git 推送）。"
            "返回结构化的修复结果，包含成功状态、错误日志及建议的下一步操作。"
        ),
        "parameters": _fix_params,
    },
}


class CreateGithubPrInput(BaseModel):
    title: str = Field(..., description="PR 标题")
    head_branch: str = Field(..., description="修复所在的源分支，如 'fix/security-update-requests-CVE-2024-1234'")
    base_branch: str = Field(..., description="目标合并分支，如 'main' 或 'develop'")
    cve_id: str = Field(..., description="CVE 编号")
    pkg_name: str = Field(..., description="受影响的包名")
    old_version: str = Field(..., description="升级前的版本号")
    new_version: str = Field(..., description="升级后的版本号")
    priority: str = Field(..., description="漏洞优先级：P0 / P1 / P2")
    reason: str = Field(..., description="优先级判定理由")
    reachability: str = Field(..., description="漏洞可达性置信度")
    test_skipped: bool = Field(..., description="是否跳过了自动化测试")
    breaking_changes: list[str] | None = Field(None, description="破坏性变更列表。仅当 priority 为 P1 时传入，P0/P2 可省略")


_pr_params = CreateGithubPrInput.model_json_schema()
_pr_params.pop("title", None)
CREATE_GITHUB_PR_SCHEMA = {
    "type": "function",
    "function": {
        "name": "create_github_pr",
        "description": (
            "在修复验证成功后创建安全修复 Pull Request。"
            "P0 自动开启 Auto-merge，P1 创建 Draft PR 并标记 needs-review，P2 创建普通 PR。"
        ),
        "parameters": _pr_params,
    },
}


class CreateGithubIssueInput(BaseModel):
    title: str = Field(..., description="Issue 标题")
    cve_id: str = Field(..., description="CVE 编号")
    pkg_name: str = Field(..., description="受影响的包名")
    priority: str = Field(..., description="漏洞优先级，如 P0 / P1 / P2")
    reachability: str = Field(..., description="漏洞可达性置信度，如 high / low / none")
    fix_suggestion: str | None = Field(None, description="修复建议（可选）")
    labels: list[str] | None = Field(
        None,
        description="额外标签列表。'security' 和 'needs-manual-fix' 会自动添加，无需手动传入",
    )


_issue_params = CreateGithubIssueInput.model_json_schema()
_issue_params.pop("title", None)
CREATE_GITHUB_ISSUE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "create_github_issue",
        "description": "在当前仓库创建安全修复 Issue。当自动修复均失败、需要人工介入时调用。",
        "parameters": _issue_params,
    },
}


class AttemptRecord(BaseModel):
    """单次尝试记录（从 FixAttemptResult 中提取）"""

    success: bool = Field(..., description="本次修复尝试是否成功")
    attempted_version: str = Field(..., description="本次尝试升级的目标版本号，如 '2.31.0'")
    raw_error: str | None = Field(None, description="错误日志，包含完整的报错堆栈信息")
    branch_name: str | None = Field(None, description="本次尝试创建的 Git 修复分支名称")
    test_skipped: bool = Field(False, description="是否因为项目中没有测试套件而跳过了测试执行")


class CreateSecurityReportInput(BaseModel):
    """create_security_report 工具的输入参数"""

    pkg_name: str = Field(..., description="待修复的包名")
    cve_id: str = Field(..., description="CVE 编号，如 CVE-2023-xxxxx")
    priority: str = Field(..., description="漏洞优先级：P0/P1/P2/P3/P4")
    reachability: str = Field(..., description="漏洞可达性：reachable/unreachable/unknown")
    fix_suggestion: str | None = Field(None, description="自动修复全部失败时由 LLM 生成的修复建议")
    attempt: AttemptRecord = Field(..., description="修复尝试的结果")


_report_params = CreateSecurityReportInput.model_json_schema()
_report_params.pop("title", None)
CREATE_SECURITY_REPORT_SCHEMA = {
    "type": "function",
    "function": {
        "name": "create_security_report",
        "description": "将漏洞修复尝试的结果追加到 SECURITY_FIX_REPORT.md。当所有版本自动修复均失败时调用。",
        "parameters": _report_params,
    },
}
