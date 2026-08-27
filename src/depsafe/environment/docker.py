import hashlib
import json
import logging
import os
import subprocess
from pathlib import Path

from pydantic import ValidationError

from depsafe.budget import VulnBudget, Vulnerability
from depsafe.exceptions import Submitted

logger = logging.getLogger(__name__)


class DockerEnvironment:
    ALLOWED_TOOLS = {"bash", "parse_deps", "apply_fix_and_verify"}

    RUNNER_SCRIPT = """
import sys, json, traceback

from depsafe.tool.utils.dep_parser import parse_deps
from depsafe.tool.apply_fix_and_verify import apply_fix_and_verify
from pydantic_core import to_jsonable_python


TOOLS = {
    "parse_deps": parse_deps,
    "apply_fix_and_verify": apply_fix_and_verify,
}

def main():
    if len(sys.argv) < 3:
        print(json.dumps({"status": "error", "message": "Runner: Missing arguments"}))
        sys.exit(1)

    tool_name = sys.argv[1]
    try:
        args = json.loads(sys.argv[2])
    except json.JSONDecodeError as e:
        print(json.dumps({"status": "error", "message": f"Runner: Invalid JSON args: {e}"}))
        sys.exit(1)

    func = TOOLS.get(tool_name)
    if not func:
        print(json.dumps({"status": "error", "message": f"Runner: Unknown tool '{tool_name}'"}))
        sys.exit(1)

    try:
        result = func(**args)
        safe_output = to_jsonable_python(result)
        print(json.dumps({"status": "success", "output": safe_output}))
        sys.exit(0)
    except Exception as e:
        exc_type = type(e).__name__
        exc_args = e.args[0] if e.args else str(e)
        print(json.dumps({
            "status": "exception",
            "exception_type": exc_type,
            "exception_args": exc_args,
            "traceback": traceback.format_exc()
        }))
        sys.exit(42)

if __name__ == "__main__":
    main()
"""  # noqa: E501

    def __init__(self, config: dict, project_root: str, vuln_budget: VulnBudget):
        self.docker_cfg = config.get("docker", {})
        self.project_root = Path(project_root).resolve()
        self.vuln_budget = vuln_budget
        self.image = self.docker_cfg.get("image", "depsafe-runner:latest")
        self.cwd = self.docker_cfg.get("cwd", "/workspace")
        self.timeout = self.docker_cfg.get("timeout", 300)
        self.docker_bin = self.docker_cfg.get("executable", "docker")
        self.run_args = self.docker_cfg.get("run_args", [])
        # 容器名：固定前缀 + 项目路径哈希，确保同项目幂等，重启时自动清理
        project_hash = hashlib.md5(str(self.project_root).encode()).hexdigest()[:8]
        self.container_name = f"vuln_agent_{project_hash}"
        self._inject_runner()
        self._init_container()

    def _inject_runner(self):
        """将 Runner 脚本写入项目根目录，以便通过 volume 挂载进容器"""
        runner_path = self.project_root / ".agent_runner.py"
        runner_path.write_text(self.RUNNER_SCRIPT, encoding="utf-8")
        logger.info(f"Runner 脚本已注入: {runner_path}")

    def _init_container(self):
        logger.info(f"清理残余容器: {self.container_name}")
        subprocess.run([self.docker_bin, "rm", "-f", self.container_name], capture_output=True, text=True)
        # 代理透传：宿主机环境变量 DEPSAFE_DOCKER_PROXY（如 http://172.27.64.1:7890）
        # 以 HTTP_PROXY/HTTPS_PROXY 传入容器，供容器内 git/pip 访问被墙站点
        proxy = os.getenv("DEPSAFE_DOCKER_PROXY")
        proxy_args: list[str] = []
        if proxy:
            proxy_args = [
                "-e",
                f"HTTP_PROXY={proxy}",
                "-e",
                f"HTTPS_PROXY={proxy}",
                "-e",
                f"http_proxy={proxy}",
                "-e",
                f"https_proxy={proxy}",
                "-e",
                "NO_PROXY=localhost,127.0.0.1",
                "-e",
                "no_proxy=localhost,127.0.0.1",
            ]
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
            *proxy_args,
            *self.run_args,
            self.image,
            "bash",
            "-c",
            "sleep infinity",
        ]
        logger.info(f"启动容器: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"容器启动失败: {result.stderr}")

    def execute(self, action: dict) -> dict:
        tool_name = action.get("name", "")
        if tool_name not in self.ALLOWED_TOOLS:
            return {
                "output": f"Error: Tool '{tool_name}' not allowed in Docker.",
                "returncode": -1,
                "exception_info": f"Tool '{tool_name}' is not in ALLOWED_TOOLS",
                "extra": {"exception_type": "ValueError", "exception": f"Disallowed tool: {tool_name}"},
            }
        args = action.get("arguments", {})
        if tool_name == "bash":
            container_cmd = ["bash", "-c", args.get("command", "")]
        else:
            args_json = json.dumps(args)
            container_cmd = ["python", ".agent_runner.py", tool_name, args_json]
        exec_cmd = [self.docker_bin, "exec", "-w", self.cwd, self.container_name, *container_cmd]
        try:
            result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=self.timeout)
            if tool_name != "bash":
                return self._handle_runner_output(tool_name, result)
            raw_output = result.stdout + result.stderr
            output = {
                "output": raw_output,
                "returncode": result.returncode,
                "exception_info": "",
                "extra": {},
            }
            lines = raw_output.lstrip().splitlines(keepends=True)
            if lines and lines[0].strip() == "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" and result.returncode == 0:
                submission = "".join(lines[1:])
                raise Submitted(
                    {
                        "role": "exit",
                        "content": submission,
                        "extra": {
                            "exit_status": "Submitted",
                            "submission": submission,
                        },
                    }
                )
            return output
        except Submitted:
            raise
        except subprocess.TimeoutExpired as e:
            raw_output = getattr(e, "output", None)
            raw_output = (
                raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else (raw_output or "")
            )
            return {
                "output": raw_output,
                "returncode": -1,
                "exception_info": f"Execution timed out ({self.timeout}s)",
                "extra": {
                    "exception_type": "TimeoutExpired",
                    "exception": str(e),
                },
            }
        except Exception as e:
            raw_output = getattr(e, "output", None)
            raw_output = (
                raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else (raw_output or "")
            )
            return {
                "output": raw_output,
                "returncode": -1,
                "exception_info": f"An error occurred while executing the command: {e}",
                "extra": {
                    "exception_type": type(e).__name__,
                    "exception": str(e),
                },
            }

    def _handle_runner_output(self, tool_name: str, result: subprocess.CompletedProcess) -> dict:
        """解析 Runner 脚本的 JSON 输出，处理异常穿透与结果解包"""
        stdout = result.stdout.strip()
        parsed = None
        last_line = ""
        if stdout:
            last_line = stdout.splitlines()[-1].strip()
            try:
                parsed = json.loads(last_line)
            except json.JSONDecodeError:
                pass
        # Runner 脚本本身崩溃（如 import 失败），没有产出 JSON
        if parsed is None:
            return {
                "output": stdout + "\n" + result.stderr,
                "returncode": result.returncode,
                "exception_info": (
                    f"Failed to parse runner output: last line is not valid JSON: {last_line[:200]}"
                    if last_line
                    else "Runner produced no stdout output"
                ),
                "extra": {
                    "exception_type": "RunnerCrash",
                    "exception": "Last line of stdout is not parseable JSON" if last_line else "Empty stdout",
                },
            }
        # 异常处理
        if parsed.get("status") == "exception":
            exc_type = parsed.get("exception_type", "Unknown")
            exc_args = parsed.get("exception_args", "")
            tb = parsed.get("traceback", "")
            return {
                "output": None,
                "returncode": 1,
                "exception_info": f"{exc_type}: {exc_args}",
                "extra": {
                    "exception_type": exc_type,
                    "exception": exc_args,
                    "traceback": tb,
                },
            }
        # 正常返回
        if parsed.get("status") == "success":
            if tool_name == "parse_deps" and len(parsed.get("output", [])) == 0:
                submission = "No more vulnerabilities are found."
                raise Submitted(
                    {
                        "role": "exit",
                        "content": submission,
                        "extra": {"exit_status": "Submitted", "submission": submission},
                    }
                )
            if tool_name == "apply_fix_and_verify":
                try:
                    from depsafe.tool.apply_fix_and_verify import FixAttemptResult

                    fix_result = FixAttemptResult.model_validate(parsed.get("output"))
                    # 设计约定：每个漏洞只尝试第一个 fixed 版本一次，失败即视为已处理；
                    # 唯一例外是依赖约束冲突（recoverable）——允许以同一目标版本补 extra_pins 后重试，
                    # 故不标记 covered，漏洞留在池中
                    if fix_result.success or not fix_result.recoverable:
                        self.vuln_budget.mark_covered(
                            [
                                Vulnerability(
                                    pkg=fix_result.pkg_name,
                                    cur_ver=fix_result.attempted_version,
                                    cve_id=fix_result.cve_id,
                                )
                            ]
                        )
                except ValidationError as e:
                    return {
                        "output": parsed.get("output"),
                        "returncode": 1,
                        "exception_info": f"Output validation failed for '{tool_name}': {e}",
                        "extra": {
                            "exception_type": "ValidationError",
                            "exception": str(e),
                        },
                    }
            return {
                "output": parsed.get("output"),
                "returncode": 0,
                "exception_info": "",
                "extra": {},
            }
        # Runner 内部错误（如未知工具名、参数解析失败）
        return {
            "output": parsed.get("message", "Unknown runner error"),
            "returncode": result.returncode,
            "exception_info": parsed.get("message", "Runner internal error"),
            "extra": {
                "exception_type": "RunnerError",
                "exception": parsed.get("message", ""),
            },
        }

    def cleanup(self):
        logger.info(f"销毁容器: {self.container_name}")
        subprocess.run([self.docker_bin, "rm", "-f", self.container_name], capture_output=True, text=True)

    def __del__(self):
        try:
            self.cleanup()
        except Exception:
            pass
