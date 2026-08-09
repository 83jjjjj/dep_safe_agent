class TokenBudget:
    """Token 预算管理器"""

    # 常见模型的上下文窗口大小映射
    _CONTEXT_WINDOWS: dict[str, int] = {
        "deepseek/deepseek-v4-flash": 128_000,
        "gpt-4o": 128_000,
        "gpt-4o-mini": 128_000,
        "claude-3-5-sonnet": 200_000,
        "qwen-max": 128_000,
    }

    def __init__(self, model_name: str, usage_ratio: float = 0.7):
        """
        Args:
            model_name: 模型名称，用于查询上下文窗口大小
            usage_ratio: 安全使用比例，默认 70%（留 30% 给最后几轮降级操作）
        """
        self.model_name = model_name
        self.context_limit = self._get_context_window(model_name)
        self.token_limit = int(self.context_limit * usage_ratio)
        self.input_token = 0
        self.output_token = 0

    def _get_context_window(self, model_name: str) -> int:
        """获取模型的上下文窗口大小"""
        return self._CONTEXT_WINDOWS.get(model_name, 32_000)  # 未知模型保守给 32K

    def record(self, prompt_tokens: int, completion_tokens: int):
        """每次 API 调用后记录消耗"""
        self.input_token += prompt_tokens
        self.output_token += completion_tokens

    @property
    def total_token(self) -> int:
        return self.input_token + self.output_token

    def is_exhausted(self) -> bool:
        """总消耗是否超过预算"""
        return self.total_token >= self.token_limit

    def remaining(self) -> int:
        return max(0, self.token_limit - self.total_token)

    def reset(self):
        self.input_token = self.output_token = 0


class CostBudget:
    """费用预算管理器"""

    def __init__(self, cost_limit: float = 10.0):
        self.cost_limit = cost_limit
        self.cost = 0.0

    def consume(self, cost: float):
        self.cost += cost

    def is_exhausted(self) -> bool:
        return self.cost >= self.cost_limit

    def remaining(self) -> float:
        return max(0.0, self.cost_limit - self.cost)

    def reset(self):
        self.cost = 0.0


class StepCounter:
    """全局步数计数器"""

    def __init__(self, step_limit: int = 150):
        self.step_limit = step_limit
        self.n_step = 0

    def consume(self, n: int = 1):
        """消耗步数"""
        self.n_step += n

    def is_exhausted(self) -> bool:
        """检查是否超出任一预算"""
        return self.n_step >= self.step_limit

    def remaining_global(self) -> int:
        return max(0, self.step_limit - self.n_step)

    def reset(self):
        self.n_step = 0
