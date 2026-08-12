import logging
from typing import Any

from pydantic import BaseModel

from depsafe.exceptions import Submitted
from depsafe.tool.assess_priority import assess_priority
from depsafe.tool.create_github_issue import create_github_issue
from depsafe.tool.create_github_pr import create_github_pr
from depsafe.tool.create_security_report import create_security_report
from depsafe.tool.get_changelog import get_changelog
from depsafe.tool.reachability_analyzer import analyze_reachability
from depsafe.tool.utils.cve_checker import Vulnerability, check_cve, check_github_advisory
from depsafe.tool.vuln_scanner import VulnBudget

logger = logging.getLogger(__name__)


class LocalEnvironment:
    TOOL_REGISTRY = {
        "check_cve": check_cve,
        "analyze_reachability": analyze_reachability,
        "get_changelog": get_changelog,
        "assess_priority": assess_priority,
        "create_github_issue": create_github_issue,
        "create_github_pr": create_github_pr,
        "create_security_report": create_security_report,
    }

    def __init__(self, vuln_budget: VulnBudget):
        self.vuln_budget = vuln_budget

    def execute(self, action: dict) -> dict:
        tool_name = action.get("name", "")
        args = action.get("arguments", {})
        func = self.TOOL_REGISTRY.get(tool_name)
        if not func:
            return {
                "output": f"Unknown local tool: {tool_name}",
                "returncode": -1,
                "exception_info": f"Tool '{tool_name}' not found in registry",
                "extra": {"exception_type": "KeyError", "exception": ""},
            }
        if tool_name == "submit_result":  # subagent中结束标识
            submission = action["arguments"]["result"]
            raise Submitted(
                {
                    "role": "exit",
                    "content": submission,
                    "extra": {"exit_status": "Submitted", "submission": submission},
                }
            )
        try:
            result = func(**args)
            return self._normalize_result(tool_name, result)
        except Exception as e:
            logger.warning(f"Local tool {tool_name} raised {type(e).__name__}: {e}")
            return {
                "output": f"Tool execution error: {e}",
                "returncode": -1,
                "exception_info": f"An error occurred while executing the {tool_name}: {e}",
                "extra": {"exception_type": type(e).__name__, "exception": str(e)},
            }

    def _normalize_output(self, tool_name: str, result: Any) -> dict:
        """
        统一适配层：将不同风格的返回值转为标准格式。
        同时处理控制流逻辑（scan_vulns 空列表 → Submitted）。
        """
        # Case 1: Pydantic BaseModel with success/error 字段
        if isinstance(result, BaseModel) and hasattr(result, "success"):
            if result.success:
                normalized = {"output": result.model_dump(), "returncode": 0}
            else:
                normalized = {
                    "output": getattr(result, "error", "Unknown error"),
                    "returncode": 1,
                    "exception_info": getattr(result, "error", "Tool returned success=False"),
                    "extra": {"exception_type": "ToolBusinessError"},
                }
            # apply_fix_and_verify 的特殊 budget 标记逻辑
            if tool_name == "apply_fix_and_verify" and result.success:
                output = result.model_dump()
                if isinstance(output, dict) and output.get("pkg_name"):
                    self.vuln_budget.mark_covered([Vulnerability(pkg_name=output["pkg_name"], cve_id=output["cve_id"])])
            return normalized

        # Case 2: scan_vulns 返回空列表 → 触发 Submitted
        if tool_name == "scan_vulns" and not result:
            raise Submitted(
                {
                    "role": "exit",
                    "content": "No more vulnerabilities are found.",
                    "extra": {"exit_status": "Submitted", "submission": "No more vulnerabilities are found."},
                }
            )

        # Case 3: 普通返回值（dict, list, str 等）
        return {"output": result, "returncode": 0}
