import logging
import os
import platform
import traceback
from pathlib import Path

import yaml
from jinja2 import StrictUndefined, Template

from depsafe import package_dir
from depsafe.budget import CostBudget, StepCounter, TokenBudget, VulnBudget
from depsafe.checkpointer import Trajectory
from depsafe.environment.docker import DockerEnvironment
from depsafe.environment.local import LocalEnvironment
from depsafe.exceptions import FormatError, InterruptAgentFlow, LimitsExceeded
from depsafe.model import LitellmModel
from depsafe.tool.get_changelog import ChangelogOrchestrator
from depsafe.tool.reachability_analyzer import ReachabilityAnalyzer
from depsafe.tool.vuln_scanner import VulnerabilityScanner


class DepSafeAgent:
    PROJECT_MARKERS = frozenset({".depsafe", "pyproject.toml", "requirements.txt", "Pipfile"})

    def __init__(self):
        self.config = yaml.safe_load(Path(package_dir / "config" / "default.yaml").read_text(encoding="utf-8"))["agent"]
        self.model = LitellmModel("deepseek/deepseek-v4-flash", os.getenv("DEEPSEEK_API_KEY"))
        self.token_budget = TokenBudget(self.model.model_name, usage_ratio=0.7)
        self.step_counter = StepCounter(step_limit=150)
        self.cost_budget = CostBudget(cost_limit=10.0)
        self.vuln_budget = VulnBudget(vuln_limit=5)
        self.project_root = self._verify_project_root()
        self.docker_env = DockerEnvironment(self.config, self.project_root, self.vuln_budget)
        self.local_env = LocalEnvironment()

        self.vuln_scanner = VulnerabilityScanner(self.docker_env, self.local_env, self.vuln_budget)
        self._reachability_analyzer = ReachabilityAnalyzer(
            env=self.local_env,
            model=self.model,
            step_counter=self.step_counter,
            cost_budget=self.cost_budget,
            project_root=self.project_root,
        )
        self._changelog_orchestrator = ChangelogOrchestrator(
            env=self.local_env,
            model=self.model,
            step_counter=self.step_counter,
            cost_budget=self.cost_budget,
            project_root=self.project_root,
        )

        self.trajectory = Trajectory(self.project_root)
        self.n_consecutive_format_errors = 0
        self.logger = logging.getLogger("agent")

    @staticmethod
    def _verify_project_root() -> Path:
        """验证当前 cwd 是一个合法的 agent 工作目录，即包含 .depsafe/ 或包含可识别的项目标记文件。"""
        cwd = Path.cwd().resolve()
        if not any((cwd / marker).exists() for marker in DepSafeAgent.PROJECT_MARKERS):
            raise RuntimeError(
                f"'{cwd}' is not a valid project root.\n"
                f"Please run depsafe from a directory containing one of: "
                f"{', '.join(sorted(DepSafeAgent.PROJECT_MARKERS))}"
            )
        return cwd

    def get_template_vars(self) -> dict:
        vars_dict = {
            "system": self.config.get("system", ""),
            "release": self.config.get("release", ""),
            "version": self.config.get("version", ""),
            "machine": self.config.get("machine", ""),
            "task": self.config.get("task", ""),
        }
        return vars_dict

    def _render_template(self, template: str) -> str:
        return Template(template, undefined=StrictUndefined).render(**self.get_template_vars())

    def add_messages(self, *messages: dict) -> list[dict]:
        self.logger.debug(messages)
        self.messages.extend(messages)
        return list(messages)

    def handle_uncaught_exception(self, e: Exception) -> list[dict]:
        return self.add_messages(
            self.model.format_message(
                role="exit",
                content=str(e),
                extra={
                    "exit_status": type(e).__name__,
                    "submission": "",
                    "exception_str": str(e),
                    "traceback": traceback.format_exc(),
                },
            )
        )

    def _build_budget_state(self) -> dict:
        """构建完整的预算状态快照"""
        return {
            "token": self.token_budget.to_dict(),
            "cost": self.cost_budget.to_dict(),
            "step": self.step_counter.to_dict(),
            "vuln": self.vuln_budget.to_dict(),
        }

    def _restore_budget_state(self, budget_state: dict) -> None:
        """从快照恢复所有预算状态"""
        if "token" in budget_state:
            self.token_budget = TokenBudget.from_dict(budget_state["token"])
        if "cost" in budget_state:
            self.cost_budget = CostBudget.from_dict(budget_state["cost"])
        if "step" in budget_state:
            self.step_counter = StepCounter.from_dict(budget_state["step"])
        if "vuln" in budget_state:
            self.vuln_budget = VulnBudget.from_dict(budget_state["vuln"])

    def _try_recover(self) -> bool:
        """尝试恢复轨迹，返回是否需要从头开始"""
        resumed, budget_state = self.trajectory.recover()
        if budget_state is not None:
            self._restore_budget_state(budget_state)
        if not resumed:
            return False
        checkpoint = self.trajectory.load()
        if checkpoint is None:
            return False
        self.messages = checkpoint.get("messages", [])
        return True

    def run(self, task: str | None = None):
        self.config["task"] = task or ""
        self.config.update(platform.uname()._asdict())
        resuming = self._try_recover()
        # 外层控制每次循环只处理vuln_limit个漏洞
        while True:
            if not resuming:
                self.step_counter.reset()
                self.token_budget.reset()
                self.messages = []
                self.add_messages({"role": "system", "content": self._render_template(self.config["system_template"])})
                self.add_messages({"role": "user", "content": self._render_template(self.config["instance_template"])})
            else:
                resuming = False  # 仅跳过第一次
            # 内层控制每次循环走一步，即调用一次工具
            while True:
                try:
                    self.step()
                    self.n_consecutive_format_errors = 0
                except FormatError as e:
                    self.cost_budget.consume(e.messages[0].get("extra", {}).get("cost", 0.0))
                    self.n_consecutive_format_errors += 1
                    if 0 < self.config.get("max_consecutive_format_errors", 3) <= self.n_consecutive_format_errors:
                        self.add_messages(
                            *e.messages,
                            {
                                "role": "exit",
                                "content": "RepeatedFormatError",
                                "extra": {"exit_status": "RepeatedFormatError", "submission": ""},
                            },
                        )
                    else:
                        self.add_messages(*e.messages)
                except InterruptAgentFlow as e:
                    self.add_messages(*e.messages)
                except Exception as e:
                    self.handle_uncaught_exception(e)
                finally:
                    # 唯一检查点，保存每一步状态
                    last = self.messages[-1] if self.messages else {}
                    exit_status = last.get("extra", {}).get("exit_status")
                    if exit_status:
                        status = "completed" if exit_status == "Submitted" else "error"
                    else:
                        status = "running"
                    self.trajectory.save(self.messages, self._build_budget_state(), status=status, exit_reason=exit_status)
                if self.messages[-1].get("role") == "exit":
                    break
            if self.messages[-1].get("role") == "exit":
                break
            # 再次兜住无漏洞的情况
            if self.vuln_budget.is_all_done():
                break
        self.docker_env.cleanup()
        return self.messages[-1].get("extra", {})

    def step(self):
        ai_message = self.query()
        self.execute(ai_message)

    def query(self) -> dict:
        if self.step_counter.is_exhausted() or self.token_budget.is_exhausted() or self.cost_budget.is_exhausted():
            raise LimitsExceeded(
                {
                    "role": "exit",
                    "content": "LimitsExceeded",
                    "extra": {"exit_status": "LimitsExceeded", "submission": ""},
                }
            )
        self.step_counter.consume(1)
        ai_message = self.model.query(self.messages)
        self.cost_budget.consume(ai_message.get("extra", {}).get("cost", 0.0))
        self.token_budget.record(
            ai_message.get("extra", {}).get("input_token", 0.0), ai_message.get("extra", {}).get("output_token", 0.0)
        )
        self.add_messages(ai_message)
        return ai_message

    def execute(self, ai_message: dict):
        results = []
        for action in ai_message.get("extra").get("actions"):
            tool_name = action.get("name", "")
            if tool_name == "scan_vulns":
                args = action.get("arguments", {})
                results.append(self.vuln_scanner.scan_vulns(**args))
            elif tool_name in DockerEnvironment.ALLOWED_TOOLS:
                results.append(self.docker_env.execute(action))
            else:
                results.append(self.local_env.execute(action))
        self.messages += self.model.format_toolcall_observation_results(ai_message, results)
