from depsafe.tool.assess_priority import PriorityInput, _parse_cvss_severity, assess_priority


class TestCvssParsing:
    """_parse_cvss_severity：CVSS 向量 → 严重性字符串"""

    def test_three_high_is_critical(self):
        """C:H + I:H + A:H → CRITICAL"""
        assert _parse_cvss_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "CRITICAL"

    def test_two_high_is_high(self):
        """C:H + I:H → HIGH"""
        assert _parse_cvss_severity("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L") == "HIGH"

    def test_one_high_is_moderate(self):
        """C:H only → HIGH"""
        assert _parse_cvss_severity("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N") == "HIGH"

    def test_no_high_is_low(self):
        """全部 N → LOW"""
        assert _parse_cvss_severity("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N") == "LOW"


class TestPriorityDecision:
    """assess_priority：综合判断"""

    def test_not_reachable_is_p4(self):
        """没找到调用 → P4（可忽略）"""
        r = assess_priority(
            PriorityInput(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                reachability_confidence="none",
                has_breaking_change=False,
            )
        )
        assert r.priority == "P4"

    def test_dynamic_low_confidence_is_p3(self):
        """动态调用，低置信度 → P3（观察）"""
        r = assess_priority(
            PriorityInput(
                advisory_severity="HIGH",
                reachability_confidence="low",
                has_breaking_change=False,
            )
        )
        assert r.priority == "P3"

    def test_critical_reachable_no_breaking_is_p0(self):
        """CRITICAL + 确定可达 + 无 breaking → P0（立即修）"""
        r = assess_priority(
            PriorityInput(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                reachability_confidence="high",
                has_breaking_change=False,
            )
        )
        assert r.priority == "P0"

    def test_critical_reachable_with_breaking_is_p1(self):
        """CRITICAL + 可达 + breaking → P1（人工介入）"""
        r = assess_priority(
            PriorityInput(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                reachability_confidence="high",
                has_breaking_change=True,
            )
        )
        assert r.priority == "P1"

    def test_moderate_reachable_is_p2(self):
        """MODERATE + 可达 → P2（排期修）"""
        r = assess_priority(
            PriorityInput(
                advisory_severity="MODERATE",
                reachability_confidence="high",
                has_breaking_change=False,
            )
        )
        assert r.priority == "P2"
        assert r.severity == "MODERATE"

    def test_falls_back_to_advisory_severity(self):
        """没有 CVSS → 用 advisory_severity"""
        r = assess_priority(
            PriorityInput(
                cvss_vector=None,
                advisory_severity="HIGH",
                reachability_confidence="high",
                has_breaking_change=False,
            )
        )
        assert r.severity == "HIGH"
        assert r.priority == "P0"

    def test_defaults_to_low_severity(self):
        """既无 CVSS 也无 advisory → severity 默认 LOW"""
        r = assess_priority(
            PriorityInput(
                cvss_vector=None,
                advisory_severity=None,
                reachability_confidence="none",
                has_breaking_change=False,
            )
        )
        assert r.severity == "LOW"
        assert r.priority == "P4"

    def test_reason_is_explanatory(self):
        """返回的 reason 包含可读的解释"""
        r = assess_priority(
            PriorityInput(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                reachability_confidence="high",
                has_breaking_change=True,
            )
        )
        assert len(r.reason) > 10  # 不只是空字符串
