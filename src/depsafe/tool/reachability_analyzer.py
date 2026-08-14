import ast
import os

from pydantic import BaseModel, Field

from depsafe.environment.local import LocalEnvironment


class CallEvidence(BaseModel):
    """记录一次函数调用的证据"""

    file: str = Field(..., description="文件路径")
    line: int = Field(..., description="行号")
    code: str = Field(..., description="代码片段")
    confidence: str = Field(..., description="置信度")
    resolved_path: str = Field(..., description="解析路径")


class AnalyzeReachabilityInput(BaseModel):
    file_path: str = Field(..., description="待分析的代码文件路径，例如 'src/main.py'")
    target_functions: list[str] = Field(
        ...,
        description="需要追踪的目标函数完整路径列表，例如 ['requests.get', 'os.system']",
    )


_reach_params = AnalyzeReachabilityInput.model_json_schema()
_reach_params.pop("title", None)
ANALYZE_REACHABILITY_SCHEMA = {
    "type": "function",
    "function": {
        "name": "analyze_reachability",
        "description": (
            "基于 AST 静态分析指定文件中对目标函数的调用可达性。返回调用证据列表（含行号、代码片段、置信度）及分析错误信息。"
        ),
        "parameters": _reach_params,
    },
}


class ReachabilityResult(BaseModel):
    """可达性分析结果"""

    evidences: list[CallEvidence] = Field(default_factory=list, description="发现的调用证据列表")
    errors: dict[str, str] = Field(default_factory=dict, description="分析过程中的错误，key=文件路径，value=错误描述")


class ReachabilityAnalyzer:
    """基于 AST 和符号表追踪的漏洞可达性分析器"""

    def __init__(self, env: LocalEnvironment):
        self.env = env
        self.env.local_tools["analyze_reachability"] = self.analyze_reachability

    def analyze_reachability(self, file_path: str, target_functions: list[str]) -> dict:
        """
        分析指定代码文件中，对目标函数的调用可达性。
        这是一个静态代码分析工具，用于发现潜在的安全风险。

        Args:
            file_path: 待分析的代码文件路径。
            target_functions: 需要追踪的目标函数列表，例如 ["requests.get", "os.system"]。

        Returns:
            ReachabilityResult 的字典形式，包含 evidences 和 errors。
        """
        result = self.analyze_file(file_path, set(target_functions))
        return result.model_dump()

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
    ) -> list[CallEvidence]:
        """第二遍扫描：查找 Call 节点并验证"""
        evidences = []
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
                            CallEvidence(
                                file=file_path,
                                line=node.lineno,
                                code=code_snippet,
                                confidence=confidence,
                                resolved_path=resolved,
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
