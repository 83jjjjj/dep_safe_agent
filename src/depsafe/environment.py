
import subprocess
from depsafe.exceptions import Submitted

class LocalEnvironment:
    def execute(self, action: dict) -> dict:
        command = action["command"]
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