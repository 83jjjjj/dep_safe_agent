import hashlib
import json
import logging
import subprocess
from pathlib import Path

from dep_safe_agent.src.depsafe.exceptions import Submitted
from dep_safe_agent.src.depsafe.tool.utils.cve_checker import Vulnerability

logger = logging.getLogger(__name__)


class DockerEnvironment:
    ALLOWED_TOOLS = {"bash", "parse_deps", "apply_fix_and_verify"}

    def __init__(self, config: dict, project_root: str):
        self.docker_cfg = config.get("docker", {})
        self.project_root = Path(project_root).resolve()
        self.image = self.docker_cfg.get("image", "python:3.12-slim")
        self.cwd = self.docker_cfg.get("cwd", "/workspace")
        self.timeout = self.docker_cfg.get("timeout", 300)
        self.docker_bin = self.docker_cfg.get("executable", "docker")
        self.run_args = self.docker_cfg.get("run_args", [])
        # 容器名：固定前缀 + 项目路径哈希，确保同项目幂等，重启时自动清理
        project_hash = hashlib.md5(str(self.project_root).encode()).hexdigest()[:8]
        self.container_name = f"vuln_agent_{project_hash}"
        self._init_container()

    def _init_container(self):
        logger.info(f"清理残余容器: {self.container_name}")
        subprocess.run([self.docker_bin, "rm", "-f", self.container_name], capture_output=True, text=True)
        cmd = [
            self.docker_bin,
            "run",
            "-d",
            "--name",
            self.container_name,
            "-v",
            f"{self.project_root}:{self.cwd}",
            "-w",
            self.cwd,
            *self.run_args,
            self.image,
            "sleep",
            "infinity",
        ]
        logger.info(f"启动容器: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"容器启动失败: {result.stderr}")

    def execute(self, action: dict) -> dict:
        tool_name = action["name"]
        if tool_name not in self.ALLOWED_TOOLS:
            return {"status": "error", "error": f"工具 {tool_name} 不允许在 Docker 中执行"}
        args = action.get("arguments", {})
        container_cmd = self._build_container_cmd(tool_name, args)
        exec_cmd = [self.docker_bin, "exec", "-w", self.cwd, self.container_name, *container_cmd]
        try:
            result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=self.timeout)
            # 判断returncode和scan/apply函数的时机相对位置待定
            if tool_name == "scan_vulns" and not result:  # 主循环结束标识
                submission = "No more vulnerabilities are found."
                raise Submitted(
                    {
                        "role": "exit",
                        "content": submission,
                        "extra": {"exit_status": "Submitted", "submission": submission},
                    }
                )
            if tool_name == "apply_fix_and_verify":  # 用于标记修复成功的漏洞
                output = result.get("output", {})
                if isinstance(output, dict) and output.get("success"):
                    self.vuln_budget.mark_covered(
                        [
                            Vulnerability(
                                pkg_name=output["pkg_name"],
                                cve_id=output["cve_id"],
                            )
                        ]
                    )
            if result.returncode == 0:
                parsed_output = self._parse_output(result.stdout)
                return {
                    "output": parsed_output,
                    "returncode": 0,
                    "extra": {"stdout": result.stdout, "stderr": result.stderr},
                }
            else:
                return {
                    "output": result.stdout + "\n" + result.stderr,
                    "returncode": result.returncode,
                    "exception_info": f"Command failed with code {result.returncode}",
                    "extra": {"exception_type": "SubprocessError", "exception": result.stderr},
                }
        except Submitted:
            raise
        # 待合并？
        except subprocess.TimeoutExpired:
            return {
                "output": f"Execution timed out ({self.timeout}s)",
                "returncode": -1,
                "exception_info": "TimeoutExpired",
                "extra": {"exception_type": "TimeoutExpired", "exception": "Docker exec timeout"},
            }
        except Exception as e:
            return {
                "output": f"An error occurred while executing the command: {e}",
                "returncode": -1,
                "exception_info": f"An error occurred: {e}",
                "extra": {"exception_type": type(e).__name__, "exception": str(e)},
            }
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

    def _build_container_cmd(self, tool_name: str, args: dict) -> list[str]:
        """根据工具名构造容器内执行命令。你可以按自己的 CLI 设计修改这里。"""
        if tool_name == "bash":
            return ["bash", "-c", args.get("command", "")]
        # 对于 parse_deps / apply_fix_and_verify，假设你有对应的 python 脚本
        # 或者你可以直接把工具代码 copy 进镜像，这里用 python -m 调用
        arg_str = " ".join(f"--{k} {v}" for k, v in args.items())
        return ["python", "-m", f"agent.tools.{tool_name}", arg_str]

    def _parse_output(self, stdout: str):
        """尝试解析 stdout 末尾的 JSON，失败则返回原始字符串"""
        lines = stdout.strip().splitlines()
        if lines:
            try:
                return json.loads(lines[-1])
            except json.JSONDecodeError:
                pass
        return stdout

    def cleanup(self):
        logger.info(f"销毁容器: {self.container_name}")
        subprocess.run([self.docker_bin, "rm", "-f", self.container_name], capture_output=True, text=True)

    def __del__(self):
        try:
            self.cleanup()
        except Exception:
            pass
