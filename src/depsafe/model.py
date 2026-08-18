import json
import logging

import litellm
from jinja2 import StrictUndefined, Template
from pydantic import BaseModel
from pydantic_core import to_jsonable_python

from depsafe.exceptions import FormatError
from depsafe.schemas import (
    ANALYZE_REACHABILITY_SCHEMA,
    APPLY_FIX_AND_VERIFY_SCHEMA,
    ASSESS_PRIORITY_SCHEMA,
    BASH_TOOL_SCHEMA,
    CREATE_GITHUB_ISSUE_SCHEMA,
    CREATE_GITHUB_PR_SCHEMA,
    CREATE_SECURITY_REPORT_SCHEMA,
    GET_CHANGELOG_SCHEMA,
    SCAN_VULNS_SCHEMA,
    AnalyzeReachabilityInput,
    ApplyFixAndVerifyInput,
    BashInput,
    CreateGithubIssueInput,
    CreateGithubPrInput,
    CreateSecurityReportInput,
    GetChangelogInput,
    PriorityInput,
    ScanVulnsInput,
)

TOOLS_SCHEMA = [
    BASH_TOOL_SCHEMA,
    SCAN_VULNS_SCHEMA,
    GET_CHANGELOG_SCHEMA,
    ANALYZE_REACHABILITY_SCHEMA,
    ASSESS_PRIORITY_SCHEMA,
    APPLY_FIX_AND_VERIFY_SCHEMA,
    CREATE_GITHUB_ISSUE_SCHEMA,
    CREATE_GITHUB_PR_SCHEMA,
    CREATE_SECURITY_REPORT_SCHEMA,
]


logger = logging.getLogger("litellm_model")


class LitellmModel:
    TOOL_INPUT_MODELS: dict[str, type[BaseModel]] = {
        "bash": BashInput,
        "scan_vulns": ScanVulnsInput,
        "get_changelog": GetChangelogInput,
        "analyze_reachability": AnalyzeReachabilityInput,
        "assess_priority": PriorityInput,
        "apply_fix_and_verify": ApplyFixAndVerifyInput,
        "create_github_issue": CreateGithubIssueInput,
        "create_github_pr": CreateGithubPrInput,
        "create_security_report": CreateSecurityReportInput,
    }

    def __init__(self, model_name: str, api_key: str):
        self.model_name = model_name
        self.api_key = api_key

    def query(
        self,
        messages: list[dict],
        response_format: type[BaseModel] | None = None,
        tools: list | None = None,
    ) -> dict:
        # 与lm交互，获取ai_message，必须有tool_calls
        tools = tools if tools else TOOLS_SCHEMA
        completion_kwargs = {
            "model": self.model_name,
            "messages": messages,
            "tools": tools,
            "base_url": "https://api.deepseek.com",
            "api_key": self.api_key,
        }
        if response_format:
            completion_kwargs["response_format"] = response_format
        try:
            response = litellm.completion(**completion_kwargs)
        except litellm.exceptions.AuthenticationError as e:
            e.message += " You can permanently set your API key with `depsafe-extra config set KEY VALUE`."
            raise e
        cost = self._calculate_cost(response)
        try:
            actions = self._parse_actions(response)
        except FormatError as e:
            try:
                e.messages[0]["extra"]["response"] = response.model_dump(mode="json")
            except Exception:
                e.messages[0]["extra"]["response"] = repr(response)
            raise
        message = response.choices[0].message.model_dump()
        message["extra"] = {
            "actions": actions,
            "cost": cost,
            "input_token": response.usage.prompt_tokens,
            "output_token": response.usage.completion_tokens,
        }
        return message

    def _calculate_cost(self, response) -> float:
        try:
            cost = litellm.cost_calculator.completion_cost(response, model=self.model_name)
            if cost < 0.0:
                logger.warning(f"Negative cost {cost} for model {self.model_name}, treating as 0")
                return 0.0
            return cost
        except Exception as e:
            logger.warning(f"Failed to calculate cost for {self.model_name}: {e}")
            return 0.0

    def _parse_actions(self, response) -> list[dict]:
        """获取tool_calls转化为合法格式"""
        tool_calls = response.choices[0].message.tool_calls
        # 协议校验
        if not tool_calls:
            raise FormatError(
                {
                    "role": "user",
                    "content": Template("{{ error }}", undefined=StrictUndefined).render(
                        error="No tool calls found in the response. Every response MUST include at least one tool call.",
                        actions=[],
                        has_tool_calls=False,
                    ),
                    "extra": {"interrupt_type": "FormatError"},
                }
            )
        # json 语法校验
        actions = []
        for tool_call in tool_calls:
            try:
                args = json.loads(tool_call.function.arguments)
            except Exception as e:
                raise FormatError(
                    {
                        "role": "user",
                        "content": Template("{{ error }}", undefined=StrictUndefined).render(
                            error=f"Error parsing tool call arguments: {e}.",
                            actions=[],
                            has_tool_calls=False,
                        ),
                        "extra": {"interrupt_type": "FormatError"},
                    }
                )
            # Schema 语义校验
            input_model = self.TOOL_INPUT_MODELS.get(tool_call.function.name)
            if input_model is None:
                raise FormatError(
                    {
                        "role": "user",
                        "content": Template("{{ error }}", undefined=StrictUndefined).render(
                            error="No tool input model found.",
                            actions=[],
                            has_tool_calls=False,
                        ),
                        "extra": {"interrupt_type": "FormatError"},
                    }
                )
            try:
                validated = input_model(**args)
                args = validated.model_dump()
            except Exception as e:
                validation_error = f"Parameter validation failed for '{tool_call.function.name}': {e}"
                raise FormatError(
                    {
                        "role": "user",
                        "content": Template("{{ error }}", undefined=StrictUndefined).render(
                            error=f"Error parsing tool call arguments: {e}.",
                            actions=[],
                            has_tool_calls=False,
                        ),
                        "extra": {"interrupt_type": "FormatError", "validation_error": validation_error},
                    }
                )
            actions.append(
                {
                    "name": tool_call.function.name,
                    "arguments": args,
                    "tool_call_id": tool_call.id,
                }
            )
        return actions

    def format_message(self, role: str, content: str, extra: dict | None = None) -> dict:
        msg = {"role": role, "content": content}
        if extra is not None:
            msg["extra"] = extra
        return msg

    def format_toolcall_observation_results(self, message: dict, outputs: list[dict]) -> list[dict]:
        # 将工具结果outputs转化为合法格式
        actions = message["extra"]["actions"]
        tool_messages = []
        for action, output in zip(actions, outputs):
            tool_message = {}
            tool_message["role"] = "tool"
            tool_message["tool_call_id"] = action["tool_call_id"]
            tool_message["content"] = json.dumps(to_jsonable_python(output), ensure_ascii=False)
            tool_messages.append(tool_message)
        return tool_messages
