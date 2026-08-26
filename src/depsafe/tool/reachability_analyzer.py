from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from depsafe.environment.local import LocalEnvironment

if TYPE_CHECKING:
    from depsafe.budget import CostBudget, StepCounter
    from depsafe.model import LitellmModel

logger = logging.getLogger(__name__)


class ReachabilityEvidence(BaseModel):
    """记录一条可达性证据"""

    file: str = Field(..., description="文件路径")
    line: int = Field(..., description="行号")
    code: str = Field(..., description="代码片段")
    confidence: str = Field(..., description="置信度: high / medium / low")
    resolved_path: str = Field(..., description="解析路径")
    evidence_type: str = Field(..., description="证据类型: call / call_resolved / semantic")


class ReachabilityResult(BaseModel):
    """可达性分析结果"""

    evidences: list[ReachabilityEvidence] = Field(default_factory=list, description="发现的调用证据列表")
    errors: dict[str, str] = Field(default_factory=dict, description="分析过程中的错误，key=文件路径，value=错误描述")


class ReachabilityAnalyzer:
    """
    基于 AST + SubAgent 的漏洞可达性分析器。

    决策树：
      Phase 1   AST Call 分析
        ├─ high 证据 → 直接返回
        ├─ low 证据（动态调用）→ Phase 1.5 SubAgent 提升置信度 → 返回
        └─ 无证据 → Phase 2
      Phase 2   语义代码搜索（仅当 target_description 非空）
        ├─ SubAgent 找到匹配 → 返回 semantic 证据
        └─ 无结果 → 返回空证据
      Phase 2 跳过（description 为空）→ 返回空证据
    """

    def __init__(self, env: LocalEnvironment, model: LitellmModel, step_counter: StepCounter, cost_budget: CostBudget, project_root: Path):
        self.env = env
        self.model = model
        self.step_counter = step_counter
        self.cost_budget = cost_budget
        self.env.local_tools["analyze_reachability"] = self.analyze_reachability
        self.project_root = project_root

    def analyze_reachability(self, file_path: str, target_functions: list[str], target_description: str = "") -> dict:
        """
        分析指定代码文件中，漏洞触发条件的可达性。

        分两阶段执行：
        1. AST 静态分析：追踪 target_functions 中所有函数的调用链
        2. 语义代码搜索（仅在 AST 无结果 + target_description 非空时启动）：
           通过代码搜索分析非函数调用类的漏洞触发条件（如属性赋值、配置变更等）

        Args:
            file_path: 待分析的代码文件路径
            target_functions: 需要追踪的目标函数列表，例如 ["requests.get", "os.system"]
            target_description: 漏洞触发条件的自然语言描述，例如
                "session.permanent 被设置为 True" 或 "yaml.load 使用了不安全的 Loader"。
                当 AST 分析未发现函数调用证据时，此描述将用于指导代码搜索。
                留空则跳过第二阶段。

        Returns:
            ReachabilityResult 的字典形式，包含 evidences 和 errors。
        """
        logger.info(
            "[Reachability] file=%s functions=%s desc=%r",
            file_path,
            target_functions,
            target_description[:80] if target_description else "",
        )
        # Phase 1: AST Call 分析
        ast_result = self.analyze_file(file_path, set(target_functions))
        high_evidences = [e for e in ast_result.evidences if e.confidence != "low"]
        low_evidences = [e for e in ast_result.evidences if e.confidence == "low"]
        # Phase 1 命中 high → 直接返回
        if high_evidences:
            logger.info("[Reachability] Phase1 HIGH hit: %d evidences", len(high_evidences))
            ast_result.evidences = high_evidences
            return ast_result.model_dump()
        # Phase 1.5: low 证据（动态调用）→ SubAgent 尝试提升
        if low_evidences:
            logger.info("[Reachability] Phase1.5: resolving %d dynamic calls", len(low_evidences))
            upgraded = self._resolve_dynamic_calls(file_path, low_evidences)
            ast_result.evidences = upgraded
            if any(e.confidence != "low" for e in upgraded):
                logger.info("[Reachability] Phase1.5 upgraded successfully")
                return ast_result.model_dump()
            logger.info("[Reachability] Phase1.5: all still low, returning")
            return ast_result.model_dump()
        # Phase 2: 语义代码搜索
        if target_description:
            logger.info("[Reachability] Phase2: semantic search for %r", target_description[:60])
            semantic_evidences = self._run_semantic_search(file_path, target_description)
            ast_result.evidences.extend(semantic_evidences)
            if semantic_evidences:
                logger.info("[Reachability] Phase2 hit: %d evidences", len(semantic_evidences))
            else:
                logger.info("[Reachability] Phase2: no semantic evidence found")
        elif not target_description:
            logger.info("[Reachability] Phase2 skipped: no target_description")
        else:
            logger.info("[Reachability] Phase2 skipped: subagent resources unavailable")
        return ast_result.model_dump()

    def analyze_file(self, file_path: str, target_functions: set[str]) -> ReachabilityResult:
        """分析单个文件的可达性"""
        if not os.path.exists(file_path):
            return ReachabilityResult(errors={file_path: "文件不存在"})
        try:
            with open(file_path, encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source)
        except Exception as e:
            return ReachabilityResult(errors={file_path: f"{type(e).__name__}: {e}"})
        # 第一遍扫描：构建符号表 (处理 Import 和 Assign)
        # 结构: { "别名": "真实路径", "func": "requests.get" }
        symbol_table: dict[str, str] = {}
        # 预置一些常见的根模块，防止相对导入解析错误
        # 这里简化处理，假设所有未限定的导入都可能是目标模块
        for target in target_functions:
            root_module = target.split(".")[0]
            symbol_table[root_module] = root_module
        self._build_symbol_table(tree, symbol_table)
        # 第二遍扫描：查找调用并匹配
        evidences = self._scan_calls(target_functions, tree, symbol_table, file_path, source.splitlines())
        return ReachabilityResult(evidences=evidences)

    def _build_symbol_table(self, tree: ast.AST, symbol_table: dict[str, str]):
        """第一遍扫描：提取 Import 和 变量赋值信息"""
        for node in ast.walk(tree):
            # 处理 import requests as req
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    symbol_table[name] = alias.name
            # 处理 from requests import get
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for alias in node.names:
                        name = alias.asname or alias.name
                        full_path = f"{node.module}.{alias.name}"
                        symbol_table[name] = full_path
            # 处理变量传递: func = requests.get
            elif isinstance(node, ast.Assign):
                # 只处理简单的赋值: target = value
                if isinstance(node.value, (ast.Name, ast.Attribute)):
                    value_path = self._get_full_name(node.value, symbol_table)
                    if value_path:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                symbol_table[target.id] = value_path

    def _scan_calls(
        self, target_functions: set[str], tree: ast.AST, symbol_table: dict[str, str], file_path: str, lines: list[str]
    ) -> list[ReachabilityEvidence]:
        """第二遍扫描：查找 Call 节点并验证"""
        evidences: list[ReachabilityEvidence] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                resolved = self._resolve_call_path(node, symbol_table)
                if resolved:
                    code_snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    # 完全动态为low
                    if "<dynamic>" in resolved:
                        confidence = "low"
                    else:
                        confidence = "high"
                    is_target = any(resolved.startswith(t) for t in target_functions)
                    if is_target or confidence == "low":
                        evidences.append(
                            ReachabilityEvidence(
                                file=file_path,
                                line=node.lineno,
                                code=code_snippet,
                                confidence=confidence,
                                resolved_path=resolved,
                                evidence_type="call",
                            )
                        )
        return evidences

    def _resolve_call_path(self, node: ast.Call, symbol_table: dict[str, str]) -> str | None:
        """尝试解析一个 Call 节点的真实路径"""
        # 场景 A: 直接调用 requests.get()
        if isinstance(node.func, ast.Attribute):
            path = self._get_full_name(node.func, symbol_table)
            if path:
                return path
        # 场景 B: 变量调用 func() -> 查表发现 func 指向 requests.get
        elif isinstance(node.func, ast.Name):
            path = symbol_table.get(node.func.id)
            if path and "." in path:
                return path
        # 场景 C: 动态调用 getattr(requests, "get")
        elif isinstance(node.func, ast.Call):
            if self._get_full_name(node.func.func) == "getattr":
                return self._handle_getattr(node.func, symbol_table)
        return None

    def _handle_getattr(self, node: ast.Call, symbol_table: dict[str, str]) -> str | None:
        """处理 getattr 调用"""
        if len(node.args) < 2:
            return None
        obj_arg = node.args[0]
        obj_path = self._get_full_name(obj_arg, symbol_table)
        if not obj_path:
            return None
        attr_arg = node.args[1]
        # L2: getattr(obj, "literal")
        if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
            return f"{obj_path}.{attr_arg.value}"
        # L2: getattr(obj, "lit" + "eral") - 简单拼接
        if isinstance(attr_arg, ast.BinOp) and isinstance(attr_arg.op, ast.Add):
            if isinstance(attr_arg.left, ast.Constant) and isinstance(attr_arg.right, ast.Constant):
                val = str(attr_arg.left.value) + str(attr_arg.right.value)
                return f"{obj_path}.{val}"
        # L3: getattr(obj, variable) - 无法静态确定
        return f"{obj_path}.<dynamic>"

    def _get_full_name(self, node: ast.AST, symbol_table: dict[str, str] | None = None) -> str | None:
        """
        递归获取属性访问的完整字符串路径 (e.g., a.b.c)
        如果提供了 symbol_table，会尝试解析变量别名
        """
        if isinstance(node, ast.Name):
            name = node.id
            if symbol_table and name in symbol_table:
                resolved = symbol_table[name]
                return resolved
            return name
        elif isinstance(node, ast.Attribute):
            value = self._get_full_name(node.value, symbol_table)
            if value:
                return f"{value}.{node.attr}"
        return None

    def _resolve_dynamic_calls(
        self, file_path: str, low_evidences: list[ReachabilityEvidence]
    ) -> list[ReachabilityEvidence]:
        """用 SubAgent 分析动态调用的实际目标，尝试将 low 提升为 high"""
        from depsafe.schemas import BASH_TOOL_SCHEMA, DYNAMIC_CALLS_SUBMIT_RESULT_SCHEMA
        from depsafe.tool.utils.subagent import SubAgent

        context_lines = [f"Line {ev.line}: {ev.code}" for ev in low_evidences]
        sub_agent = SubAgent(
            model=self.model,
            env=self.env,
            step_counter=self.step_counter,
            cost_budget=self.cost_budget,
            project_root=self.project_root,
            sub_task_name=f"explore task on {file_path} for dynamic calls",
            step_limit=5,
        )
        system_prompt = """\
你是一个专业的代码安全分析师。
请通过调用工具确认动态调用中变量的实际值，然后给出最终结论。
不要直接输出文本，必须通过调用工具来交互。
"""
        user_prompt = f"""\
文件 `{file_path}` 中存在以下动态调用：
{chr(10).join(context_lines)}

你可以使用以下工具：
1. `bash`: 执行 grep/cat 等 shell 命令搜索变量定义。
2. `submit_result`: 当你收集到足够信息后，调用此工具提交最终结论。

工作流程：
1. 使用 `bash` 执行 grep 搜索相关变量的定义（最多 3 次）。
2. 如搜索结果不完整，用 sed/cat 查看上下文确认（最多 2 次）。
3. 一旦确认动态调用实际指向哪些函数，**立即**调用 `submit_result` 提交结论，禁止继续搜索或重复相同命令。

`result` 参数必须包含以下字段：
- `resolved_calls`: 列表，每项包含：
  - `original_line`: 原始代码行号（整数）
  - `resolved_path`: 解析后的完整函数路径（字符串）
  - `confidence`: "high" / "low"

注意：不要直接输出文本，必须通过调用工具来交互。
禁止读取无关文件、重复搜索相同模式。
"""
        tools = [BASH_TOOL_SCHEMA, DYNAMIC_CALLS_SUBMIT_RESULT_SCHEMA]
        result = sub_agent.run(system_prompt, user_prompt, tools)
        upgraded: list[ReachabilityEvidence] = []
        if result.get("exit_status") == "Submitted":
            resolved_map: dict[int, dict] = {}
            for r in result.get("submission", {}).get("resolved_calls", []):
                resolved_map[r.get("original_line")] = r
            for ev in low_evidences:
                if ev.line in resolved_map:
                    r = resolved_map[ev.line]
                    new_confidence = r.get("confidence", "low")
                    new_path = r.get("resolved_path", ev.resolved_path)
                    upgraded.append(
                        ReachabilityEvidence(
                            file=ev.file,
                            line=ev.line,
                            code=ev.code,
                            confidence=new_confidence,
                            resolved_path=new_path,
                            evidence_type="call_resolved",
                        )
                    )
                    logger.debug(
                        "[Reachability] Dynamic call L%d: %s → %s (%s)", ev.line, ev.resolved_path, new_path, new_confidence
                    )
                else:
                    upgraded.append(ev)
        else:
            logger.warning("[Reachability] SubAgent dynamic resolution failed: exit=%s", result.get("exit_status"))
            upgraded = list(low_evidences)
        return upgraded

    def _run_semantic_search(self, file_path: str, target_description: str) -> list[ReachabilityEvidence]:
        """通过 SubAgent grep/cat 搜索非函数调用类的漏洞触发条件"""
        from depsafe.schemas import BASH_TOOL_SCHEMA, SEMANTIC_SEARCH_SUBMIT_RESULT_SCHEMA
        from depsafe.tool.utils.subagent import SubAgent

        sub_agent = SubAgent(
            model=self.model,
            env=self.env,
            step_counter=self.step_counter,
            cost_budget=self.cost_budget,
            project_root=self.project_root,
            sub_task_name=f"explore task on {file_path} for non-call vulns",
            step_limit=5,
        )
        system_prompt = """\
你是一个专业的代码安全分析师。
请通过调用工具确认某个漏洞触发条件是否在代码中可达，然后给出最终结论。
不要直接输出文本，必须通过调用工具来交互。
"""
        user_prompt = f"""\
分析文件 `{file_path}` 中是否存在以下漏洞触发条件：
{target_description}

你可以使用以下工具：
1. `bash`: 执行 grep/cat/find 等 shell 命令搜索代码。
2. `submit_result`: 当你收集到足够信息后，调用此工具提交最终结论。

工作流程：
1. 使用 `bash` 执行 grep 在目标文件中搜索关键词（最多 3 次）。
2. 如找到相关行，用 sed/cat 查看上下文确认（最多 2 次）。
3. 一旦确认证据（或确认不可达），**立即**调用 `submit_result` 提交结论，禁止继续搜索或重复相同命令。

`result` 参数必须包含以下字段：
- `reachable`: true / false
- `evidence_code`: 匹配的代码行（字符串，不可达时为空字符串）
- `evidence_line`: 行号（整数，不可达时为 0）
- `reasoning`: 一句话判断理由

注意：不要直接输出文本，必须通过调用工具来交互。
禁止递归搜索整个项目、读取无关文件、重复搜索相同模式。
"""
        tools = [BASH_TOOL_SCHEMA, SEMANTIC_SEARCH_SUBMIT_RESULT_SCHEMA]
        result = sub_agent.run(system_prompt, user_prompt, tools)
        if result.get("exit_status") == "Submitted":
            submission = result.get("submission", {})
            if submission.get("reachable"):
                logger.info(
                    "[Reachability] Semantic hit at L%s: %s", submission.get("evidence_line"), submission.get("reasoning")
                )
                return [
                    ReachabilityEvidence(
                        file=file_path,
                        line=submission.get("evidence_line", 0),
                        code=submission.get("evidence_code", ""),
                        confidence="medium",
                        resolved_path=target_description,
                        evidence_type="semantic",
                    )
                ]
        else:
            logger.warning("[Reachability] SubAgent semantic search failed: exit=%s", result.get("exit_status"))
        return []
