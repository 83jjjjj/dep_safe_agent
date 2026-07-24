
import pytest
from depsafe.tool.dep_parser import (
    _parse_poetry_lock, _parse_uv_lock, _parse_pipfile_lock, 
    parse_deps, Dependency
)

class TestLockFileParsing:
    # 锁文件解析
    def test_parse_poetry_lock(self, tmp_path):
        lock = tmp_path / "poetry.lock"
        lock.write_text("""

[[package]]
name = "flask"
version = "2.3.1"
category = "main"

[[package]]
name = "pytest"
version = "8.0.0"
category = "dev"
""")
        deps = _parse_poetry_lock(lock)
        assert len(deps) == 1
        assert deps[0].name == "flask"
        assert deps[0].version_spec == "==2.3.1"
    
    def test_parse_uv_lock(self, tmp_path):
        lock = tmp_path / "uv.lock"
        lock.write_text("""

[[package]]
name = "requests"
version = "2.31.0"
source = "registry+https://pypi.org/simple"

[[package]]
name = "urllib3"
version = "1.26.18"
""")
        deps = _parse_uv_lock(lock)
        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[1].name == "urllib3"

    def test_parse_pipfile_lock(self, tmp_path):
        lock = tmp_path / "Pipfile.lock"
        lock.write_text('''
{
    "default": {
        "flask": {
        "version": "==2.3.1",
        "markers": "python_version >= '3.8'"
        }
    },
    "develop": {
        "pytest": {"version": "==8.0.0"}
    }
}
''')
        deps = _parse_pipfile_lock(lock)
        assert len(deps) == 1
        assert deps[0].name == "flask"
        assert deps[0].version_spec == "==2.3.1"
        assert deps[0].marker == "python_version >= '3.8'"


class TestPipelineCompile:
    # pip-compile
    def test_parse_compiled_output(self, tmp_path, monkeypatch):
        # 集成测试，parse_deps流程跑通
        mock_deps = [
            Dependency(name="flask", version_spec="==2.3.3", marker=None, source_file="requirements.txt", category="production"),
            Dependency(name="requests", version_spec="==2.31.0", marker="python_version >= '3.8'", source_file="requirements.txt", category="production")
        ]
        monkeypatch.setattr(
            "depsafe.tool.dep_parser._compile_dependencies",
            lambda fp: mock_deps
        )
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.3.0\nrequests>=2.25.0\n")
        deps = parse_deps(str(req))
        assert len(deps) == 2

    def test_extracts_pinned_versions(self, tmp_path):
        """_parse_compiled_output：从 pip-compile 输出文件中正确提取版本号"""
        from depsafe.tool.dep_parser import _parse_compiled_output
        compiled = tmp_path / "compiled.txt"
        compiled.write_text("""
flask==2.3.3
requests==2.31.0 ; python_version >= '3.8'
click==8.1.7
""")
        deps = _parse_compiled_output(str(compiled), "requirements.in")
        assert len(deps) == 3
        assert deps[0].name == "flask"
        assert deps[0].version_spec == "==2.3.3"
        assert deps[0].marker is None
        assert deps[1].name == "requests"
        assert deps[1].marker == "python_version >= '3.8'"
        assert deps[2].version_spec == "==8.1.7"


class TestParseDepsEndToEnd:
    # 端到端：验证 parse_deps 的路径选择逻辑
    def test_chooses_lockfile_over_compile(self, tmp_path, monkeypatch):
        lock = tmp_path / "poetry.lock"
        lock.write_text("")
        req = tmp_path / "requirements.txt"
        req.write_text("flask\n")
        monkeypatch.setattr(
            "depsafe.tool.dep_parser._parse_poetry_lock",
            lambda p: [Dependency(name="flask", version_spec="==2.3.1", marker=None, source_file="poetry.lock", category="production")]
        )
        deps = parse_deps(str(req))
        assert deps[0].source_file == "poetry.lock"

    def test_missing_file_raises(self, tmp_path):
        """文件不存在 → FileNotFoundError"""
        with pytest.raises(FileNotFoundError):
            parse_deps(str(tmp_path / "nonexistent.txt"))
