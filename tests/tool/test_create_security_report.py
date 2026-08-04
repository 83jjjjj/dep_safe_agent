from pathlib import Path

from depsafe.tool.create_security_report import AttemptRecord, _build_report_section, create_security_report


class TestBuildReportSection:
    def test_contains_all_columns(self, tmp_path):
        """报告章节包含 CVE、包名、尝试表格、错误日志"""
        attempts = [
            AttemptRecord(
                success=False, attempted_version="2.31.0", failure_reason="TEST_FAILURE", raw_error="ImportError: ..."
            ),
            AttemptRecord(success=True, attempted_version="2.30.0"),
        ]
        section = _build_report_section(
            "flask", "CVE-2024-1234", "P0", "reachable", "升级到 2.30.0", attempts, "2026-08-01 12:00:00"
        )
        assert "CVE-2024-1234" in section
        assert "flask" in section
        assert "P0" in section
        assert "2.31.0" in section
        assert "TEST_FAILURE" in section
        assert "✅" in section
        assert "❌" in section
        assert "ImportError" in section

    def test_all_success_shows_success(self):
        """全部成功 → 显示 ✅ 自动修复成功"""
        attempts = [AttemptRecord(success=True, attempted_version="2.30.0")]
        section = _build_report_section("x", "y", "z", "a", None, attempts, "t")
        assert "自动修复成功" in section

    def test_creates_report_file(self, tmp_path, monkeypatch):
        """首次调用 → 创建文件，追加调用 → 内容累积"""
        monkeypatch.chdir(tmp_path)
        r1 = create_security_report("flask", "CVE-001", "P0", "reachable", [])
        r2 = create_security_report("requests", "CVE-002", "P1", "reachable", [])
        assert r1["success"] and r2["success"]
        content = Path("SECURITY_FIX_REPORT.md").read_text()
        assert "CVE-001" in content
        assert "CVE-002" in content
