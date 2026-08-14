import logging

from pydantic_core import to_jsonable_python

from depsafe.exceptions import Submitted
from depsafe.tool.assess_priority import assess_priority
from depsafe.tool.create_github_issue import create_github_issue
from depsafe.tool.create_github_pr import create_github_pr
from depsafe.tool.create_security_report import create_security_report
from depsafe.tool.utils.cve_checker import check_cve
from depsafe.tool.vuln_scanner import VulnBudget

logger = logging.getLogger(__name__)


class LocalEnvironment:
    TOOL_REGISTRY = {
        "check_cve": check_cve,
        "assess_priority": assess_priority,
        "create_github_issue": create_github_issue,
        "create_github_pr": create_github_pr,
        "create_security_report": create_security_report,
        # 动态注册
        # "analyze_reachability": analyze_reachability,
        # "get_changelog": get_changelog,
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
        except Exception as e:
            logger.warning(f"Local tool {tool_name} raised {type(e).__name__}: {e}")
            return {
                "output": f"Tool execution error: {e}",
                "returncode": -1,
                "exception_info": f"An error occurred while executing the {tool_name}: {e}",
                "extra": {"exception_type": type(e).__name__, "exception": str(e)},
            }
        try:
            # 将任意类型包括原生类型 BaseModel 类型及嵌套类型，转为 jsonsafe dict
            serialized = to_jsonable_python(result)
        except (TypeError, ValueError, OverflowError) as e:
            return {
                "output": None,
                "returncode": -1,
                "exception_info": (f"Failed to serialize output of '{tool_name}': {type(e).__name__}: {e}"),
                "extra": {
                    "exception_type": "SerializationError",
                    "exception": str(e),
                },
            }
        return {
            "output": serialized,
            "returncode": 0,
            "exception_info": "",
        }
