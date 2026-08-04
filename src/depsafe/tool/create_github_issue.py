import os

import requests
from pydantic import BaseModel, Field
from utils.github import get_repo_info

CREATE_GITHUB_ISSUE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "create_github_issue",
        "description": "在当前仓库创建安全修复 Issue。当所有版本自动修复均失败时调用。",
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Issue 标题"},
                "cve_id": {"type": "string", "description": "CVE 编号"},
                "pkg_name": {"type": "string", "description": "受影响的包名"},
                "priority": {"type": "string", "description": "漏洞优先级"},
                "reachability": {"type": "string", "description": "漏洞可达性"},
                "fix_suggestion": {"type": "string", "description": "修复建议"},
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "额外标签（security 和 needs-manual-fix 会自动添加）",
                },
            },
            "required": ["title", "cve_id", "pkg_name", "priority", "reachability"],
        },
    },
}


class IssueCreateResult(BaseModel):
    """Issue 创建结果"""

    success: bool = Field(..., description="Issue 是否创建成功")
    issue_url: str | None = Field(None, description="创建成功时返回的 Issue 网页链接（HTML URL）")
    issue_number: int | None = Field(None, description="创建成功时返回的 Issue 编号")
    error: str | None = Field(None, description="创建失败时的错误信息，如 Token 缺失或 API 请求报错")


def _build_issue_body(
    cve_id: str,
    pkg_name: str,
    priority: str,
    reachability: str,
    fix_suggestion: str | None,
) -> str:
    """拼装 Issue body"""
    lines = [
        "## Security Vulnerability Detected",
        "",
        f"- **CVE**: {cve_id}",
        f"- **Package**: `{pkg_name}`",
        f"- **Priority**: {priority}",
        f"- **Reachability**: {reachability}",
        "",
        "---",
        "",
        "### Description",
        "",
        f"The automated security fix agent attempted to resolve **{cve_id}** "
        f"by upgrading `{pkg_name}`, but all available versions failed.",
        "",
        "### Fix Suggestion",
        "",
        fix_suggestion or "_No suggestion provided. Manual investigation required._",
        "",
        "---",
        "",
        "> Detailed diagnostic logs are available in `./SECURITY_FIX_REPORT.md`",
        "",
        "### Labels",
        "- `security`",
        "- `needs-manual-fix`",
    ]
    return "\n".join(lines)


def create_github_issue(
    title: str,
    cve_id: str,
    pkg_name: str,
    priority: str,
    reachability: str,
    fix_suggestion: str | None = None,
    labels: list[str] | None = None,
) -> dict:
    """
    在当前仓库创建安全修复 Issue。

    Args:
        title: Issue 标题
        cve_id: CVE 编号
        pkg_name: 受影响的包名
        priority: 漏洞优先级
        reachability: 漏洞可达性
        fix_suggestion: 修复建议（可选）
        labels: 额外标签（security 和 needs-manual-fix 会自动添加）

    Returns:
        包含 Issue URL 和状态的字典
    """
    # 1. 获取 GitHub Token
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return {
            "success": False,
            "error": "GITHUB_TOKEN environment variable is not set",
        }
    # 2. 解析仓库信息
    try:
        owner, repo = get_repo_info()
    except RuntimeError as e:
        return {
            "success": False,
            "error": str(e),
        }
    # 3. 拼装 Issue body
    body = _build_issue_body(
        cve_id=cve_id,
        pkg_name=pkg_name,
        priority=priority,
        reachability=reachability,
        fix_suggestion=fix_suggestion,
    )
    # 4. 合并标签（去重）
    all_labels = list(set(["security", "needs-manual-fix"] + (labels or [])))
    # 5. 调用 GitHub REST API 创建 Issue
    api_url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "title": title,
        "body": body,
        "labels": all_labels,
    }
    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        return {
            "success": True,
            "issue_url": data["html_url"],
            "issue_number": data["number"],
        }
    except requests.RequestException as e:
        error_msg = str(e)
        if hasattr(e, "response") and e.response is not None:
            error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
        return {
            "success": False,
            "error": error_msg,
        }
