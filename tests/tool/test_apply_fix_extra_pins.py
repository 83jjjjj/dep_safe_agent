"""apply_fix_and_verify 联动升级（extra_pins）与约束冲突可恢复性测试"""
import depsafe.tool.apply_fix_and_verify as m


class TestClassifyLockError:
    def test_resolution_impossible_is_conflict(self):
        assert m._classify_lock_error("pip-compile lock failed: ... ResolutionImpossible ...") == (
            True,
            "RETRY_WITH_PINS",
        )

    def test_conflicting_dependencies_is_conflict(self):
        assert m._classify_lock_error("ERROR: ... because these package versions have conflicting dependencies.") == (
            True,
            "RETRY_WITH_PINS",
        )

    def test_other_errors_not_conflict(self):
        assert m._classify_lock_error("uv lock failed: No such file or directory") == (False, "MANUAL_REVIEW")


class TestExtraPins:
    def test_extra_pins_applied_and_conflict_recoverable(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==2.3.1\nwerkzeug==2.2.0\n")
        monkeypatch.setattr(m, "_prepare_fix_branch", lambda pkg, cve: "fix/security-update-test")
        monkeypatch.setattr(
            m,
            "_regenerate_lockfile",
            lambda: (False, "pip-compile lock failed: ... ResolutionImpossible: conflicting dependencies"),
        )
        result = m.apply_fix_and_verify(
            "flask", "CVE-2023-30861", "2.3.2", "flask", extra_pins={"werkzeug": "2.3.0"}
        )
        assert result.success is False
        assert result.recoverable is True
        assert result.suggested_next_action == "RETRY_WITH_PINS"
        content = (tmp_path / "requirements.txt").read_text()
        assert "flask==2.3.2" in content
        assert "werkzeug==2.3.0" in content

    def test_missing_extra_pin_fails_loudly(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==2.3.1\n")
        monkeypatch.setattr(m, "_prepare_fix_branch", lambda pkg, cve: "fix/security-update-test")
        monkeypatch.setattr(m, "_regenerate_lockfile", lambda: (True, ""))
        result = m.apply_fix_and_verify(
            "flask", "CVE-2023-30861", "2.3.2", "flask", extra_pins={"werkzeug": "2.3.0"}
        )
        assert result.success is False
        assert result.recoverable is False
        assert "联动包" in result.error and "werkzeug" in result.error

    def test_non_conflict_lock_failure_not_recoverable(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==2.3.1\n")
        monkeypatch.setattr(m, "_prepare_fix_branch", lambda pkg, cve: "fix/security-update-test")
        monkeypatch.setattr(m, "_regenerate_lockfile", lambda: (False, "uv lock failed: No such file"))
        result = m.apply_fix_and_verify("flask", "CVE-2023-30861", "2.3.2", "flask")
        assert result.success is False
        assert result.recoverable is False
        assert result.suggested_next_action == "MANUAL_REVIEW"
