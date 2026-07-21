

from depsafe.tool.parser import parse_deps


class TestRequirementsTxt:
    def test_parse_deps(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("flask==2.3.1\nrequests>=2.25.0\n")
        deps = parse_deps(str(path))
        assert len(deps) == 2
        assert deps[0].name == "flask"
        assert deps[0].version_spec == "==2.3.1"
        assert deps[1].name == "requests"
        assert deps[1].version_spec == ">=2.25.0"
    
    def test_skips_comments_and_options(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("""
# 这是注释
flask==2.3.1

-r base.txt
-e .
        """)
        deps = parse_deps(str(path))
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_no_version_defaults_to_star(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("requests\n")
        deps = parse_deps(str(path))
        assert deps[0].version_spec == "*"
    
class TestPyprojectToml():
    def test_parse_deps(self, tmp_path):
        path = tmp_path / "pyproject.toml"
        path.write_text("""
[project]
name = "test"
dependencies = [
"flask>=2.3.0",
"requests==2.31.0",
]
        """)
        deps = parse_deps(str(path))
        assert len(deps) == 2
        assert deps[0].name == "flask"
        assert deps[0].version_spec == ">=2.3.0"

class TestPipfile():
    def test_parse_deps(self, tmp_path):
        path = tmp_path / "Pipfile"
        path.write_text("""
[packages]
flask = "==2.3.1"
requests = {version = ">=2.25.0"}
        """)
        deps = parse_deps(str(path))
        assert len(deps) == 2
        assert deps[1].version_spec == ">=2.25.0"