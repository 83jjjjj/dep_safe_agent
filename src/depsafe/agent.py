import logging
import os
import platform
import traceback
from pathlib import Path

import yaml
from jinja2 import StrictUndefined, Template

from depsafe import package_dir
from depsafe.budget import StepCounter, TokenBudget
from depsafe.environment import LocalEnvironment
from depsafe.exceptions import FormatError, InterruptAgentFlow, LimitsExceeded
from depsafe.model import LitellmModel


class DepSafeAgent:
    def __init__(self):
        self.config = yaml.safe_load(Path(package_dir / "config" / "default.yaml").read_text(encoding="utf-8"))["agent"]
        self.model = LitellmModel("deepseek/deepseek-v4-flash", os.getenv("DEEPSEEK_API_KEY"))
        self.env = LocalEnvironment()
        self.token_budget = TokenBudget(self.model.model_name, usage_ratio=0.7)
        self.step_counter = StepCounter(global_budget=200)
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

    async def run(self, task: str):
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

                # 3. token & cost 无论哪个达阈值，都手动调用降级工具

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
        self.add_messages(ai_message)
        return ai_message

    async def execute(self, ai_message: dict):
        results = [self.env.execute(action) for action in ai_message.get("extra").get("actions")]
        self.messages += self.model.format_toolcall_observation_results(ai_message, results)
