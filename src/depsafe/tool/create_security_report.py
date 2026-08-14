from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field


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
    attempts: list[AttemptRecord] = Field(..., description="所有修复尝试的结果列表，按尝试顺序排列")


# 自动生成 schema，与 AttemptRecord 的 Field 描述完全同步
CREATE_SECURITY_REPORT_SCHEMA = {
    "type": "function",
    "function": {
        "name": "create_security_report",
        "description": "将漏洞修复尝试的结果追加到 SECURITY_FIX_REPORT.md。当所有版本自动修复均失败时调用。",
        "parameters": CreateSecurityReportInput.model_json_schema(),
    },
}


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
    attempts: list[AttemptRecord],
    timestamp: str,
) -> str:
    """构建单个 CVE 的报告章节"""
    any_success = any(a.success for a in attempts)
    result_emoji = "✅" if any_success else "❌"
    result_text = "自动修复成功" if any_success else "自动修复失败"
    lines = [
        "",
        "---",
        "",
        f"## {cve_id} ({timestamp})",
        "",
        f"- **包名**: {pkg_name}",
        f"- **优先级**: {priority}",
        f"- **可达性**: {reachability}",
        f"- **修复结果**: {result_emoji} {result_text}",
    ]
    if fix_suggestion:
        lines.append(f"- **修复建议**: {fix_suggestion}")
    lines.extend(
        [
            "",
            "### 尝试记录",
            "",
            "| 版本 | 结果 | 失败原因 |",
            "|------|------|----------|",
        ]
    )
    for attempt in attempts:
        status = "✅" if attempt.success else "❌"
        lines.append(f"| {attempt.attempted_version} | {status} |")
    failed_attempts = [a for a in attempts if not a.success and a.raw_error]
    if failed_attempts:
        lines.extend(
            [
                "",
                "### 原始错误日志",
                "",
                "<details>",
                "<summary>展开查看</summary>",
                "",
            ]
        )
        for attempt in failed_attempts:
            lines.append(f"#### 版本 {attempt.attempted_version}")
            lines.append("")
            lines.append("```")
            lines.append(attempt.raw_error)
            lines.append("```")
            lines.append("")
        lines.append("</details>")
    lines.append("")
    return "\n".join(lines)


def create_security_report(
    pkg_name: str,
    cve_id: str,
    priority: str,
    reachability: str,
    attempts: list[AttemptRecord],
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
        attempts=attempts,
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
