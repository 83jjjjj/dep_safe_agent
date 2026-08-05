import logging
import os
import platform
from pathlib import Path
import traceback

import yaml
from jinja2 import StrictUndefined, Template

from depsafe import package_dir
from depsafe.budget import StepCounter, TokenBudget
from depsafe.environment import LocalEnvironment
from depsafe.exceptions import FormatError, InterruptAgentFlow, LimitsExceeded, Submitted
from depsafe.model import LitellmModel


class DepSafeAgent:
    def __init__(self):
        self.config = yaml.safe_load(Path(package_dir / "config" / "default.yaml").read_text(encoding="utf-8"))["agent"]
        self.model = LitellmModel("deepseek/deepseek-v4-flash", os.getenv("DEEPSEEK_API_KEY"))
        self.env = LocalEnvironment()
        self.token_budget = TokenBudget(self.model.model_name, usage_ratio=0.7)
        self.step_counter = StepCounter(global_budget=100, per_vuln_budget=15)
        self.cost = 0.0
        self.n_consecutive_format_errors = 0
        self.logger = logging.getLogger("agent")

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

    def run(self, task: str):
        self.config["task"] = task
        self.config.update(platform.uname()._asdict())
        self.messages = []
        self.add_messages(
            {
                "role": "system",
                "content": Template(self.config["system_template"], undefined=StrictUndefined).render(**self.config),
            }
        )
        self.add_messages(
            {
                "role": "user",
                "content": Template(self.config["instance_template"], undefined=StrictUndefined).render(**self.config),
            }
        )
        while True:
            try:
                self.step()
                self.n_consecutive_format_errors = 0
            except FormatError as e:
                2. per vuln step 计算 -- 限制修复的漏洞数和尝试的版本数。考虑fixed版本刚好冲突的可能，能否直接找到合适的？
                3. token & cost 无论哪个达阈值，都手动调用降级工具
                # The call was billed before parsing failed, so query() never got to charge it.
                self.cost += e.messages[0].get("extra", {}).get("cost", 0.0)
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
        return self.messages[-1].get("extra", {})

    def step(self):
        ai_message = self.query()
        self.execute(ai_message)

    def query(self) -> dict:
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
        self.add_messages(ai_message)
        return ai_message

    def execute(self, message: dict):
        results = [self.env.execute(action) for action in message.get("extra").get("actions")]
        self.messages += self.model.format_toolcall_observation_results(message, results)
