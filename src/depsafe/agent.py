import logging
import os
import platform
import traceback
from pathlib import Path

import yaml
from jinja2 import StrictUndefined, Template

from depsafe import package_dir
from depsafe.budget import CostBudget, StepCounter, TokenBudget
from depsafe.environment import LocalEnvironment
from depsafe.exceptions import FormatError, InterruptAgentFlow, LimitsExceeded
from depsafe.model import LitellmModel
from depsafe.tool.vuln_scanner import VulnBudget, VulnerabilityScanner


class DepSafeAgent:
    def __init__(self):
        self.config = yaml.safe_load(Path(package_dir / "config" / "default.yaml").read_text(encoding="utf-8"))["agent"]
        self.model = LitellmModel("deepseek/deepseek-v4-flash", os.getenv("DEEPSEEK_API_KEY"))
        self.env = LocalEnvironment()
        self.token_budget = TokenBudget(self.model.model_name, usage_ratio=0.7)
        self.step_counter = StepCounter(step_limit=150)
        self.cost_budget = CostBudget(cost_limit=10.0)
        self.vuln_budget = VulnBudget(vuln_limit=5)
        self.vuln_scanner = VulnerabilityScanner(self.vuln_budget, self.env)
        self.n_consecutive_format_errors = 0
        self.logger = logging.getLogger("agent")

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

    async def run(self, task: str):
        self.config["task"] = task
        self.config.update(platform.uname()._asdict())
        # 外层控制每次循环只处理vuln_limit个漏洞
        while True:
            self.step_counter.reset()
            self.token_budget.reset()
            self.messages = []
            self.add_messages(
                {
                    "role": "system",
                    "content": self._render_template(self.config["system_template"]),
                }
            )
            self.add_messages(
                {
                    "role": "user",
                    "content": self._render_template(self.config["instance_template"]),
                }
            )
            # 内层控制每次循环走一步，即调用一次工具
            while True:
                try:
                    self.step()
                    self.n_consecutive_format_errors = 0
                except FormatError as e:
                    self.cost_budget.consume(e.messages[0].get("extra", {}).get("cost", 0.0))
                    self.n_consecutive_format_errors += 1
                    if 0 < self.config.max_consecutive_format_errors <= self.n_consecutive_format_errors:
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
                    raise
                finally:
                    pass
                    # todo
                    # self.save(self.config.output_path)
                if self.messages[-1].get("role") == "exit":
                    break
            if self.messages[-1].get("role") == "exit":
                break
            # 再次兜住无漏洞的情况
            if self.vuln_budget.is_all_done():
                break
        return self.messages[-1].get("extra", {})

    async def step(self):
        ai_message = self.query()
        self.execute(ai_message)

    async def query(self) -> dict:
        if self.step_counter.is_exhausted() or self.token_budget.is_exhausted():
            raise LimitsExceeded(
                {
                    "role": "exit",
                    "content": "LimitsExceeded",
                    "extra": {"exit_status": "LimitsExceeded", "submission": ""},
                }
            )
        self.step_counter.consume(1)
        ai_message = self.model.query(self.messages, token_budget=self.token_budget)
        self.cost_budget.consume(ai_message.get("extra", {}).get("cost", 0.0))
        self.add_messages(ai_message)
        return ai_message

    async def execute(self, ai_message: dict):
        results = [self.env.execute(action) for action in ai_message.get("extra").get("actions")]
        self.messages += self.model.format_toolcall_observation_results(ai_message, results)
