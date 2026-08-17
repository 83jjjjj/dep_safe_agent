from __future__ import annotations

import logging
import traceback
from typing import TYPE_CHECKING

from depsafe.exceptions import (
    FormatError,
    InterruptAgentFlow,
    LimitsExceeded,
)

if TYPE_CHECKING:
    from depsafe.budget import CostBudget, StepCounter
    from depsafe.environment.local import LocalEnvironment
    from depsafe.model import LitellmModel

logger = logging.getLogger(__name__)


class SubAgent:
    """
    通用子代理，负责执行异步工具调用循环。

    设计原则：
    - 与主 Agent 保持一致的消息格式和异常处理风格
    - 独立的 messages 列表（不污染主 Agent 上下文）
    - 共享 model、env、step_counter（全局资源管控）
    - 通过 submit_result 工具实现优雅终止
    - 封装粒度与主 Agent 对齐：run -> step -> query / execute
    """

    def __init__(
        self,
        model: LitellmModel,
        env: LocalEnvironment,
        step_counter: StepCounter,
        cost_budget: CostBudget,
        step_limit: int = 3,
    ):
        self.model = model
        self.env = env
        self.step_counter = step_counter
        self.cost_budget = cost_budget
        self.step_limit = step_limit
        self.n_calls = 0

    def add_messages(self, *messages: dict) -> list[dict]:
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

    def run(
        self,
        system_prompt: str,
        user_prompt: str,
        tools: list[dict],
    ) -> dict:
        """
        启动子代理循环。

        Args:
            system_prompt: 系统提示
            user_prompt: 用户任务提示
            tools: 可用工具列表（调用方需确保包含 submit_result）

        Returns:
            成功提交时: {"status": "submitted", "result": str, "steps": int}
            步数耗尽时: {"status": "max_steps_reached", "steps": int, "last_message": dict | None}
            全局超限时: {"status": "limits_exceeded", "steps": int}
        """
        self.messages: list[dict] = []
        self.add_messages({"role": "system", "content": system_prompt})
        self.add_messages({"role": "user", "content": user_prompt})
        while True:
            try:
                self.step(tools)
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
        return self.messages[-1].get("extra", {})

    def step(self, tools: list[dict]) -> None:
        ai_message = self.query(tools)
        self.execute(ai_message)

    def query(self, tools: list[dict]) -> dict:
        if self.step_counter.is_exhausted() or 0 < self.step_limit <= self.max_steps or self.cost_budget.is_exhausted():
            raise LimitsExceeded(
                {
                    "role": "exit",
                    "content": "SubagentLimitsExceeded",
                    "extra": {
                        "exit_status": "LimitsExceeded",
                        "submissions": "",
                        "step_counter": self.step_counter.global_used(),
                        "n_calls": self.n_calls,
                        "cost_budget": self.cost_budget.remaining(),
                    },
                }
            )
        self.n_calls += 1
        self.step_counter.consume(1)
        ai_message = self.model.query(
            self.messages,
            tools=tools,
            token_budget=None,
        )
        self.cost_budget.consume(ai_message.get("extra", {}).get("cost", 0.0))
        self.add_messages(ai_message)
        return ai_message

    def execute(self, ai_message: dict) -> None:
        results = [self.env.execute(action) for action in ai_message.get("extra").get("actions")]
        self.messages += self.model.format_toolcall_observation_results(ai_message, results)
