import json

import litellm
from pydantic import BaseModel

BASH_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": "Execute a bash command",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The bash command to execute",
                }
            },
            "required": ["command"],
        },
    },
}

CUSTOM_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "parse_deps",
            "description": "统一读取项目依赖文件并返回依赖列表。支持 requirements.txt、pyproject.toml 或 Pipfile 中的一种。",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "包含依赖信息的文件路径，例如 'requirements.txt' 或 'pyproject.toml'。",
                    }
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_cve",
            "description": "查询指定包和版本的已知漏洞，使用 OSV API。如果该版本没有已知漏洞或 API 请求失败，则返回空列表。",
            "parameters": {
                "type": "object",
                "properties": {
                    "pkg": {
                        "type": "string",
                        "description": "依赖包的名称，例如 'requests' 或 'litellm'。",
                    },
                    "ver": {"type": "string", "description": "依赖包的精确版本号，例如 '2.25.1'。"},
                },
                "required": ["pkg", "ver"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_github_advisory",
            "description": "查询 GitHub Advisory Database 获取漏洞信息，通常作为 OSV API 的 Fallback（兜底）数据源。如果该版本没有已知漏洞或 API 请求失败，则返回空列表。",
            "parameters": {
                "type": "object",
                "properties": {
                    "pkg": {
                        "type": "string",
                        "description": "依赖包的名称，例如 'requests' 或 'litellm'。",
                    },
                    "ver": {"type": "string", "description": "依赖包的精确版本号，例如 '2.25.1'。"},
                },
                "required": ["pkg", "ver"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_changelog",
            "description": "获取指定包在两个版本之间的变更日志。",
            "parameters": {
                "type": "object",
                "properties": {
                    "pkg": {"type": "string", "description": "依赖包名称"},
                    "from_ver": {"type": "string", "description": "要查询变更日志的起始版本"},
                    "to_ver": {"type": "string", "description": "要查询变更日志的目标版本"},
                },
                "required": ["pkg", "from_ver", "to_ver"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_reachability",
            "description": "分析代码文件中对特定危险函数的调用情况，用于安全审计。",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "需要分析的代码文件的路径，例如 'app.py'",
                    },
                    "target_functions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "需要追踪的目标函数列表，例如 ['requests.get', 'os.system']",
                    },
                },
                "required": ["file_path", "target_functions"],
            },
        },
    },
    {
        "title": "assess_priority",
        "description": "评估漏洞修复的优先级。根据 CVSS 向量或公告严重性、可达性置信度以及是否存在破坏性变更，综合判定漏洞修复的优先级（P0-P4）并给出修复建议理由。",
        "type": "object",
        "properties": {
            "input": {
                "title": "PriorityInput",
                "description": "包含漏洞评估所需信息的输入对象",
                "type": "object",
                "properties": {
                    "cvss_vector": {
                        "title": "Cvss Vector",
                        "description": "CVSS 向量字符串，用于解析严重性",
                        "type": "string",
                    },
                    "advisory_severity": {
                        "title": "Advisory Severity",
                        "description": "安全公告中的严重性级别，如 CRITICAL, HIGH, MEDIUM, LOW",
                        "type": "string",
                    },
                    "reachability_confidence": {
                        "title": "Reachability Confidence",
                        "description": "漏洞可达性置信度，可选值：NONE, LOW, MEDIUM, HIGH",
                        "type": "string",
                    },
                    "has_breaking_change": {
                        "title": "Has Breaking Change",
                        "description": "修复版本是否包含破坏性变更",
                        "type": "boolean",
                    },
                },
                "required": ["reachability_confidence", "has_breaking_change"],
            }
        },
        "required": ["input"],
    },
]


class LitellmModel:
    def __init__(self, model_name: str, api_key: str):
        self.model_name = model_name
        self.api_key = api_key

    async def query(
        self,
        messages: list[dict],
        response_format: type[BaseModel] | None = None,
        tools: list | None = None,
    ) -> dict:
        # 与lm交互，获取ai_message，必须有tool_calls
        tools = tools if tools else [BASH_TOOL_SCHEMA, *CUSTOM_TOOLS_SCHEMA]
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
            response = await litellm.acompletion(**completion_kwargs)
        except litellm.exceptions.AuthenticationError as e:
            e.message += " You can permanently set your API key with `depsafe-extra config set KEY VALUE`."
            raise e
        # 获取tool_calls转化为合法格式，纳入extra部分
        # 自定义工具调用 + bash降级
        tool_calls = response.choices[0].message.tool_calls
        actions = []
        if tool_calls:
            for tool_call in tool_calls:
                args = json.loads(tool_call.function.arguments)
                actions.append(
                    {
                        "name": tool_call.function.name,
                        "arguments": args,
                        "tool_call_id": tool_call.id,
                    }
                )
        message = response.choices[0].message.model_dump()
        message["extra"] = {"actions": actions}
        return message

    def format_toolcall_observation_results(self, message: dict, outputs: list[dict]) -> list[dict]:
        # 将工具结果outputs转化为合法格式
        actions = message["extra"]["actions"]
        tool_messages = []
        for action, output in zip(actions, outputs):
            tool_message = {}
            tool_message["role"] = "tool"
            tool_message["tool_call_id"] = action["tool_call_id"]
            tool_message["content"] = json.dumps(output, ensure_ascii=False)
            tool_messages.append(tool_message)
        return tool_messages
