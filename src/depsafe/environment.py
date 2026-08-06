import asyncio
import inspect
import subprocess

from depsafe.exceptions import Submitted
from depsafe.tool.assess_priority import assess_priority
from depsafe.tool.cve_checker import check_cve, check_github_advisory
from depsafe.tool.dep_parser import parse_deps


class LocalEnvironment:
    def __init__(self):
        self.local_tools = {
            "parse_deps": parse_deps,
            "check_cve": check_cve,
            "check_github_advisory": check_github_advisory,
            "assess_priority": assess_priority,
        }

    async def execute(self, action: dict) -> dict:
        tool_name = action["name"]
        if tool_name in self.local_tools:
            if tool_name == "submit_result":  # subagent中结束标识
                submission = action["arguments"]["result"]
                raise Submitted(
                    {
                        "role": "exit",
                        "content": submission,
                        "extra": {"exit_status": "Submitted", "submission": submission},
                    }
                )
            func = self.local_tools[tool_name]
            try:
                if inspect.iscoroutinefunction(func):
                    result = asyncio.get_event_loop().run_until_complete(func(**action["arguments"]))
                else:
                    result = func(**action["arguments"])
                return {"output": result}
            except Exception as e:
                return {"output": f"工具执行出错: {e}"}
        if tool_name == "bash":
            command = action["arguments"]["command"]
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                text=True,
                encoding="utf-8",
            )
            stdout, _ = process.communicate()
            completed_process = subprocess.CompletedProcess(command, process.returncode, stdout=stdout)
            output = {
                "output": completed_process.stdout,
                "returncode": completed_process.returncode,
            }
            lines = output["output"].lstrip().splitlines(keepends=True)
            if lines and lines[0].strip() == "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" and output["returncode"] == 0:
                submission = "".join(lines[1:])
                raise Submitted(
                    {
                        "role": "exit",
                        "content": submission,
                        "extra": {"exit_status": "Submitted", "submission": submission},
                    }
                )
            return output
        else:
            return {"output": "Error, unknown tool call."}
