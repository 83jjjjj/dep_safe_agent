from depsafe.tool.apply_fix_and_verify import _has_tests, _update_pipfile, _update_pyproject, _update_requirements


class TestHasTests:
    def test_has_tests_detects_pytest(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_app.py").write_text("def test(): pass")
        assert _has_tests() is True

    def test_has_tests_no_tests_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _has_tests() is False


class TestUpdateRequirements:
    def test_update_requirements_replaces_version(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.1\nclick>=8.0\n")
        assert _update_requirements("flask", "2.3.3")
        content = req.read_text()
        assert "flask==2.3.3" in content
        assert "click>=8.0" in content

    def test_update_requirements_no_match_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        req = tmp_path / "requirements.txt"
        req.write_text("django>=4.0\n")
        assert _update_requirements("flask", "2.3.3") is False


class TestUpdatePyproject:
    def test_updates_pep621_dependency(self, tmp_path, monkeypatch):
        """PEP 621 格式：[project] dependencies = ["flask>=2.0"] → "flask==2.3.3" """
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "pyproject.toml"
        f.write_text("""
[project]
name = "test"
dependencies = [
    "flask>=2.3.0",
    "click>=8.0",
]
""")
        assert _update_pyproject("flask", "2.3.3") is True
        content = f.read_text()
        assert "flask==2.3.3" in content
        assert "click>=8.0" in content

    def test_updates_poetry_dependency(self, tmp_path, monkeypatch):
        """Poetry 格式：[tool.poetry.dependencies] flask = "^2.0" → "==2.3.3" """
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "pyproject.toml"
        f.write_text("""
[tool.poetry.dependencies]
flask = "^2.3.0"
click = "^8.0"
""")
        assert _update_pyproject("flask", "2.3.3") is True
        content = f.read_text()
        assert 'flask = "==2.3.3"' in content
        assert 'click = "^8.0"' in content


class TestUpdatePipfile:
    def test_updates_packages_section(self, tmp_path, monkeypatch):
        """[packages] 下的包被更新"""
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "Pipfile"
        f.write_text("""
[packages]
flask = "==2.3.1"
requests = ">=2.25.0"
""")
        assert _update_pipfile("flask", "2.3.3") is True
        content = f.read_text()
        assert 'flask = "==2.3.3"' in content
        assert 'requests = ">=2.25.0"' in content

    def test_updates_dev_packages_section(self, tmp_path, monkeypatch):
        """[dev-packages] 下的包也能被更新"""
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "Pipfile"
        f.write_text("""
[dev-packages]
pytest = "==7.0.0"
""")
        assert _update_pipfile("pytest", "8.0.0") is True
        content = f.read_text()
        assert 'pytest = "==8.0.0"' in content
