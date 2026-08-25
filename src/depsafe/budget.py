from pydantic import BaseModel, ConfigDict, Field


class Vulnerability(BaseModel):
    model_config = ConfigDict(frozen=True)
    pkg: str = Field(..., description="依赖包的名称")
    cur_ver: str = Field(..., description="项目当前使用的依赖版本")
    cve_id: str = Field(..., description="漏洞的 CVE 编号")
    severity: str | None = Field(None, description="严重程度")
    fixed_ver: str | None = Field(None, description="修复该漏洞的版本")
    desc: str = Field("", description="漏洞描述")


class TokenBudget:
    """Token 预算管理器"""

    # 常见模型的上下文窗口大小映射
    _CONTEXT_WINDOWS: dict[str, int] = {
        "deepseek/deepseek-v4-flash": 1000000,
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

    def to_dict(self) -> dict:
        return {
            "model_name": self.model_name,
            "usage_ratio": self.token_limit / self.context_limit if self.context_limit else 0.7,
            "input_token": self.input_token,
            "output_token": self.output_token,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TokenBudget":
        budget = cls(
            model_name=data["model_name"],
            usage_ratio=data.get("usage_ratio", 0.7),
        )
        budget.input_token = data.get("input_token", 0)
        budget.output_token = data.get("output_token", 0)
        return budget


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

    def to_dict(self) -> dict:
        return {"cost_limit": self.cost_limit, "cost": self.cost}

    @classmethod
    def from_dict(cls, data: dict) -> "CostBudget":
        budget = cls(cost_limit=data.get("cost_limit", 10.0))
        budget.cost = data.get("cost", 0.0)
        return budget


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

    def global_used(self) -> int:
        return self.n_step

    def to_dict(self) -> dict:
        return {"step_limit": self.step_limit, "n_step": self.n_step}

    @classmethod
    def from_dict(cls, data: dict) -> "StepCounter":
        counter = cls(step_limit=data.get("step_limit", 150))
        counter.n_step = data.get("n_step", 0)
        return counter


class VulnBudget:
    def __init__(self, vuln_limit: int = 5):
        self.vuln_limit = vuln_limit  # 一轮循环扫描漏洞上限
        self.found = 0
        self.overflow: list[Vulnerability] = []
        self.covered: set[tuple[str, str]] = set()  # (pkg, cve_id)

    def mark_covered(self, vulns: list[Vulnerability]):
        """修复完成后调用，将漏洞标记为已解决"""
        for v in vulns:
            self.covered.add((v.pkg, v.cve_id))

    def filter_covered(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """过滤掉已修复的漏洞"""
        return [v for v in vulns if (v.pkg, v.cve_id) not in self.covered]

    def _consume_overflow(self) -> list[Vulnerability]:
        """从 overflow 中取出本轮份额"""
        batch = self.overflow[: self.vuln_limit]
        self.overflow = self.overflow[self.vuln_limit :]
        self.found = len(batch)
        return batch

    def record(self, vulns: list[Vulnerability] | list[dict]) -> list[Vulnerability]:
        """供 scanner 遍历依赖时逐个调用"""
        if vulns and isinstance(vulns[0], dict):
            vulns = [Vulnerability(**v) for v in vulns]
        vulns = self.filter_covered(vulns)
        remaining = self.vuln_limit - self.found
        if remaining <= 0:
            self.overflow.extend(vulns)
            return []
        if len(vulns) <= remaining:
            self.found += len(vulns)
            return vulns
        else:
            accepted = vulns[:remaining]
            self.overflow.extend(vulns[remaining:])
            self.found = self.vuln_limit
            return accepted

    @property
    def exhausted(self) -> bool:
        return self.found >= self.vuln_limit

    def reset_found(self):
        self.found = 0

    def is_all_done(self):
        """没有找到更多的漏洞"""
        return self.found == 0 and len(self.overflow) == 0

    def to_dict(self) -> dict:
        return {
            "vuln_limit": self.vuln_limit,
            "found": self.found,
            "covered": [list(pair) for pair in self.covered],  # set→list
            "overflow": [{"pkg": v.pkg, "cve_id": v.cve_id, "cur_ver": v.cur_ver} for v in self.overflow],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VulnBudget":
        budget = cls(vuln_limit=data["vuln_limit"])
        budget.found = data["found"]
        budget.covered = {tuple(pair) for pair in data["covered"]}  # list→set
        budget.overflow = [
            Vulnerability(pkg=v["pkg"], cve_id=v["cve_id"], cur_ver=v["cur_ver"]) for v in data.get("overflow", [])
        ]
        return budget
