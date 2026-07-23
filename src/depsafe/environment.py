
import subprocess
from depsafe.exceptions import Submitted
from depsafe.tool.dep_parser import parse_deps
from depsafe.tool.cve_checker import check_cve, check_github_advisory

class LocalEnvironment:
    def execute(self, action: dict) -> dict:
        tool_name = action["name"]
        if tool_name == "bash":
            command = action["arguments"]["command"]
            process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                shell=True,
                text=True,
                encoding="utf-8")
            stdout, _ = process.communicate()
            completed_process = subprocess.CompletedProcess(command, process.returncode, stdout=stdout)
            output = {
                "output": completed_process.stdout,
                "returncode": completed_process.returncode
            }
            lines = output["output"].lstrip().splitlines(keepends=True)
            if lines and lines[0].strip() == "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" and output["returncode"] == 0:
                submission = "".join(lines[1:])
                raise Submitted(
                    {
                        "role": "exit",
                        "content": submission,
                    }
                )
            return output
        elif tool_name == "parse_deps":
            return {
                "output": parse_deps(**action["arguments"])
            }
        elif tool_name == "check_cve":
            return {
                "output": check_cve(**action["arguments"])
            }
        elif tool_name == "check_github_advisory":
            return {
                "output": check_github_advisory(**action["arguments"])
            }
        else:
            return {
                "output": "Error, unknown tool call."
            }
