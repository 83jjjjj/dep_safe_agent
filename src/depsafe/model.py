
import litellm
import json

BASH_TOOL = {
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

CUSTOM_TOOLS = [
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
                        "description": "包含依赖信息的文件路径，例如 'requirements.txt' 或 'pyproject.toml'。"
                    }
                },
                "required": ["file_path"]
            }
        }
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
                        "description": "依赖包的名称，例如 'requests' 或 'litellm'。"
                    },
                    "ver": {
                        "type": "string",
                        "description": "依赖包的精确版本号，例如 '2.25.1'。"
                    }
                },
                "required": ["pkg", "ver"]
            }
        }
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
                        "description": "依赖包的名称，例如 'requests' 或 'litellm'。"
                    },
                    "ver": {
                        "type": "string",
                        "description": "依赖包的精确版本号，例如 '2.25.1'。"
                    }
                },
                "required": ["pkg", "ver"]
            }
        }
    }
  ]

class LitellmModel:
    def __init__(self, model_name: str, api_key: str):
        self.model_name = model_name
        self.api_key = api_key
    
    def query(self, messages: list[dict]) -> dict:
        # 与lm交互，获取ai_message，必须有tool_calls
        try:
            response = litellm.completion(
                model=self.model_name,
                messages=messages,
                tools=[BASH_TOOL, *CUSTOM_TOOLS],
                base_url="https://api.deepseek.com"
            )
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
                actions.append({"name": tool_call.function.name, "arguments": args, "tool_call_id": tool_call.id})
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
