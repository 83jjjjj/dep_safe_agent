import inspect
import subprocess

from depsafe.exceptions import Submitted
from depsafe.tool.assess_priority import assess_priority
from depsafe.tool.create_github_issue import create_github_issue
from depsafe.tool.create_github_pr import create_github_pr
from depsafe.tool.create_security_report import create_security_report
from depsafe.tool.get_changelog import get_changelog
from depsafe.tool.reachability_analyzer import analyze_reachability
from depsafe.tool.utils.cve_checker import Vulnerability, check_cve, check_github_advisory
from depsafe.tool.vuln_scanner import VulnBudget


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
            return {"status": "error", "error": f"未知本地工具: {tool_name}"}
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
            return {"output": result}
        except Exception as e:
            return {"output": f"工具执行出错: {e}"}
