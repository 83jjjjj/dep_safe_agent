
import subprocess

class LocalEnvironment:
    def execute(self, action: dict) -> dict:
        command = action["command"]
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            shell=True,
            text=True)
        stdout, _ = process.communicate()
        completed_process = subprocess.CompletedProcess(command, process.returncode, stdout=stdout)
        output = {
            "output": completed_process.stdout,
            "returncode": completed_process.returncode
        }
        return output