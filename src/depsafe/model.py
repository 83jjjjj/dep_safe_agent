
import litellm
import json
import os

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
                tools=[BASH_TOOL],
                base_url="https://api.deepseek.com"
            )
        except litellm.exceptions.AuthenticationError as e:
            e.message += " You can permanently set your API key with `depsafe-extra config set KEY VALUE`."
            raise e
        # 获取tool_calls转化为合法格式，纳入extra部分
        tool_calls = response.choices[0].message.tool_calls
        actions = []
        for tool_call in tool_calls:
            args = json.loads(tool_call.function.arguments)
            actions.append({"command": args["command"], "tool_call_id": tool_call.id})
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
            tool_message["content"] = output # ?
            tool_messages.append(tool_message)
        return tool_messages
