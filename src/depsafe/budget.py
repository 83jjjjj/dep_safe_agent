

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
        self.max_tokens = self._get_context_window(model_name)
        self.budget = int(self.max_tokens * usage_ratio)
        self.input_used = 0
        self.output_used = 0

    def _get_context_window(self, model_name: str) -> int:
        """获取模型的上下文窗口大小"""
        return self._CONTEXT_WINDOWS.get(model_name, 32_000)  # 未知模型保守给 32K

    def record(self, prompt_tokens: int, completion_tokens: int):
        """每次 API 调用后记录消耗"""
        self.input_used += prompt_tokens
        self.output_used += completion_tokens

    @property
    def total_used(self) -> int:
        return self.input_used + self.output_used

    def is_exhausted(self) -> bool:
        """总消耗是否超过预算"""
        return self.total_used >= self.budget

    def remaining(self) -> int:
        return max(0, self.budget - self.total_used)


class StepCounter:
    """全局步数计数器"""

    def __init__(self, global_budget: int):
        """
        Args:
            global_budget: 全局最大步数
        """
        self.global_budget = global_budget
        self.global_used = 0

    def consume(self, n: int = 1):
        """消耗步数"""
        self.global_used += n

    def is_exhausted(self) -> bool:
        """检查是否超出任一预算"""
        return self.global_used >= self.global_budget

    def remaining_global(self) -> int:
        return max(0, self.global_budget - self.global_used)
