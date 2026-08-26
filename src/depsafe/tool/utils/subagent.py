from __future__ import annotations

import logging
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

from depsafe.checkpointer import SubTrajectory

from depsafe.exceptions import (
    FormatError,
    InterruptAgentFlow,
    LimitsExceeded,
)

if TYPE_CHECKING:
    from depsafe.budget import CostBudget, StepCounter, TokenBudget
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
        project_root: Path,
        sub_task_name: str,
        step_limit: int = 3,
    ):
        self.model = model
        self.env = env
        self.step_counter = step_counter
        self.cost_budget = cost_budget
        self.token_budget = TokenBudget(self.model.model_name, usage_ratio=0.7)
        self.step_limit = step_limit
        self.n_calls = 0
        self.max_consecutive_format_errors = 3
        self.trajectory = SubTrajectory(project_root=project_root, sub_task_name=sub_task_name)

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

    def _build_budget_state(self) -> dict:
        """SubAgent 的预算快照"""
        return {
            "token": self.token_budget.to_dict(),
            "cost": {
                "consumed_this_run": self.cost_budget.cost,
                "remaining": self.cost_budget.remaining(),
            },
            "step": {
                "global_used": self.step_counter.global_used(),
                "sub_calls": self.n_calls,
            },
        }

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
            最后一条 exit 消息的 extra 字段，典型结构：
            - 正常提交: {"exit_status": "Submitted", "submission": "..."}
            - 超限退出: {"exit_status": "LimitsExceeded", "submissions": "", ...}
            - 格式错误: {"exit_status": "RepeatedFormatError", "submission": ""}
            - 未捕获异常: {"exit_status": "<ExceptionClassName>", "submission": "", ...}        """
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
                if 0 < self.max_consecutive_format_errors <= self.n_consecutive_format_errors:
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
                last = self.messages[-1] if self.messages else {}
                exit_status = last.get("extra", {}).get("exit_status")
                if exit_status:
                    status = "completed" if exit_status == "Submitted" else "error"
                else:
                    status = "running"
                self.trajectory.save(
                    self.messages, budget_state=self._build_budget_state(), status=status, exit_reason=exit_status
                )
            if self.messages[-1].get("role") == "exit":
                break
        return self.messages[-1].get("extra", {})

    def step(self, tools: list[dict]) -> None:
        ai_message = self.query(tools)
        self.execute(ai_message)

    def query(self, tools: list[dict]) -> dict:
        if (
            self.step_counter.is_exhausted()
            or 0 < self.step_limit <= self.n_calls
            or self.cost_budget.is_exhausted()
            or self.token_budget.is_exhausted()
        ):
            raise LimitsExceeded(
                {
                    "role": "exit",
                    "content": "SubagentLimitsExceeded",
                    "extra": {
                        "exit_status": "LimitsExceeded",
                        "submissions": "",
                        "step_counter": self.step_counter.global_used(),
                        "n_calls": self.n_calls,
                        "cost_remaining": self.cost_budget.remaining(),
                        "token_remaining": self.token_budget.remaining(),
                    },
                }
            )
        self.n_calls += 1
        self.step_counter.consume(1)
        ai_message = self.model.query(self.messages, tools=tools)
        self.cost_budget.consume(ai_message.get("extra", {}).get("cost", 0.0))
        self.token_budget.record(
            ai_message.get("extra", {}).get("input_token", 0), ai_message.get("extra", {}).get("output_token", 0)
        )
        self.add_messages(ai_message)
        return ai_message

    def execute(self, ai_message: dict) -> None:
        results = [self.env.execute(action) for action in ai_message.get("extra").get("actions")]
        self.messages += self.model.format_toolcall_observation_results(ai_message, results)
