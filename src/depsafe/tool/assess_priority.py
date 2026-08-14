from pydantic import BaseModel, Field

try:
    from cvss import CVSS3

    HAS_CVSS_LIB = True
except ImportError:
    HAS_CVSS_LIB = False


class PriorityInput(BaseModel):
    cvss_vector: str | None = Field(
        None, description="CVSS v3.1 向量字符串，如 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'"
    )
    advisory_severity: str | None = Field(None, description="GitHub Advisory 返回的危害等级，如 'MODERATE'、'HIGH'")
    reachability_confidence: str = Field(
        ..., description="可达性分析置信度：'high'（静态确定调用）、'low'（动态调用）、'none'（未发现调用）"
    )
    has_breaking_change: bool = Field(..., description="修复版本的 changelog 中是否包含影响当前项目的破坏性变更")


_priority_params = PriorityInput.model_json_schema()
_priority_params.pop("title", None)
ASSESS_PRIORITY_SCHEMA = {
    "type": "function",
    "function": {
        "name": "assess_priority",
        "description": (
            "综合评估漏洞修复优先级。根据 CVSS 向量/公告严重性、可达性置信度、破坏性变更三个维度，"
            "判定 P0-P4 优先级并给出标准化危害等级和判定理由。"
        ),
        "parameters": _priority_params,
    },
}


class PriorityResult(BaseModel):
    priority: str = Field(..., description="最终优先级：P0(紧急) / P1(高) / P2(中) / P3(低) / P4(建议)")
    severity: str = Field(..., description="标准化后的漏洞危害等级：CRITICAL / HIGH / MODERATE / LOW")
    reason: str = Field(..., description="优先级判定理由，便于追溯和审计")


def _severity_from_score(score: float) -> str:
    """CVSS v3.1 官方分数 → 等级映射"""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    if score > 0.0:
        return "LOW"
    return "LOW"


def _parse_cvss_severity(cvss_vector: str) -> str:
    """
    从 CVSS v3.1 向量字符串中提取危害等级。
    输入: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    输出: "CRITICAL" / "HIGH" / "MODERATE" / "LOW"
    """
    # 优先用 cvss 库精确计算
    if HAS_CVSS_LIB:
        try:
            c = CVSS3(cvss_vector)
            return _severity_from_score(c.scores()[0])
        except Exception:
            pass
    # fallback：简化规则
    metrics: dict[str, str] = {}
    for part in cvss_vector.split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    # 作用域变更时整体提升一档
    scope_changed = metrics.get("S") == "C"
    av = metrics.get("AV", "N")  # 攻击向量
    c = metrics.get("C", "N")
    i_val = metrics.get("I", "N")
    a = metrics.get("A", "N")
    high_count = sum(1 for v in [c, i_val, a] if v == "H")
    if high_count == 3 and (av == "N" or scope_changed):
        return "CRITICAL"
    if high_count >= 2 or (scope_changed and high_count >= 1):
        return "HIGH"
    if high_count >= 1:
        return "MODERATE"
    return "LOW"


def assess_priority(data: PriorityInput) -> PriorityResult:
    """
    评估漏洞修复的优先级。

    根据 CVSS 向量或公告严重性、可达性置信度以及是否存在破坏性变更，
    综合判定漏洞修复的优先级（P0-P4）并给出修复建议理由。

    Args:
        data: 包含漏洞评估所需信息的 PriorityInput 实例。

    Returns:
        PriorityResult: 包含优先级、严重性和修复理由的结果对象。
    """
    if data.cvss_vector:
        severity = _parse_cvss_severity(data.cvss_vector)
    elif data.advisory_severity:
        severity = data.advisory_severity.upper()
    else:
        severity = "LOW"
    conf = data.reachability_confidence.lower()
    if conf == "none":
        priority = "P4"
        reason = "项目中未发现该漏洞函数的调用"
    elif conf == "low":
        priority = "P3"
        reason = "调用链为动态调用，置信度低，可能为误报"
    elif severity in ("CRITICAL", "HIGH"):
        if data.has_breaking_change:
            priority = "P1"
            reason = f"高危漏洞({severity})，但修复版本含破坏性变更，需人工评估"
        else:
            priority = "P0"
            reason = f"高危漏洞({severity})，项目中存在确定调用，修复版本无破坏性变更"
    else:
        priority = "P2"
        reason = f"中低危漏洞({severity})，项目中存在调用，建议常规迭代修复"
    return PriorityResult(priority=priority, severity=severity, reason=reason)
