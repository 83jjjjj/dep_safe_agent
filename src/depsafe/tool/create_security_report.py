from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

from depsafe.schemas import AttemptRecord


class CreateSecurityReportResult(BaseModel):
    """安全修复报告创建结果"""

    success: bool = Field(..., description="报告是否成功写入")
    report_path: str | None = Field(None, description="报告文件的绝对路径，失败时为 None")
    cve_id: str | None = Field(None, description="本次追加的 CVE 编号")
    message: str | None = Field(None, description="成功时的摘要信息")
    error: str | None = Field(None, description="失败时的错误详情，成功时为 None")


def _build_report_section(
    pkg_name: str,
    cve_id: str,
    priority: str,
    reachability: str,
    fix_suggestion: str | None,
    attempt: AttemptRecord,
    timestamp: str,
) -> str:
    """构建单个 CVE 的报告章节"""
    result_emoji = "✅" if attempt.success else "❌"
    result_text = "自动修复成功" if attempt.success else "自动修复失败"
    lines = [
        "",
        "---",
        "",
        f"## {cve_id} ({timestamp})",
        "",
        f"- **包名**: `{pkg_name}`",
        f"- **优先级**: {priority}",
        f"- **可达性**: {reachability}",
        f"- **目标版本**: `{attempt.attempted_version}`",
        f"- **修复结果**: {result_emoji} {result_text}",
    ]
    if not attempt.success and fix_suggestion:
        lines.append(f"- **修复建议**: {fix_suggestion}")
    if not attempt.success and attempt.raw_error:
        lines.extend(
            [
                "",
                "### 错误诊断日志",
                "",
                "<details>",
                "<summary>展开查看完整堆栈</summary>",
                "",
                "```",
                attempt.raw_error.strip(),
                "```",
                "",
                "</details>",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def create_security_report(
    pkg_name: str,
    cve_id: str,
    priority: str,
    reachability: str,
    attempt: AttemptRecord,
    fix_suggestion: str | None = None,
) -> dict:
    """
    将漏洞修复尝试的结果追加到项目根目录的 SECURITY_FIX_REPORT.md。

    Args:
        pkg_name: 待修复的包名
        cve_id: CVE 编号
        priority: 漏洞优先级
        reachability: 漏洞可达性
        attempts: 所有修复尝试的结果列表（FixAttemptResult 形式）
        fix_suggestion: 修复建议

    Returns:
        包含报告路径和状态的字典
    """
    report_path = Path("SECURITY_FIX_REPORT.md")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    section = _build_report_section(
        pkg_name=pkg_name,
        cve_id=cve_id,
        priority=priority,
        reachability=reachability,
        fix_suggestion=fix_suggestion,
        attempt=attempt,
        timestamp=timestamp,
    )
    if not report_path.exists():
        header = (
            "# Security Fix Report\n\n"
            f"> Auto-generated at {timestamp}\n\n"
            "This report contains all security vulnerability fix attempts.\n"
        )
    try:
        if not report_path.exists():
            report_path.write_text(header, encoding="utf-8")
        with open(report_path, "a", encoding="utf-8") as f:
            f.write(section)
    except OSError as e:
        return {"success": False, "error": f"Failed to write report: {type(e).__name__}: {e}"}
    return {
        "success": True,
        "report_path": str(report_path.resolve()),
        "cve_id": cve_id,
        "message": f"Report section for {cve_id} appended to {report_path}",
    }
