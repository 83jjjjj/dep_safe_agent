
from depsafe.tool.reachability_analyzer import ReachabilityAnalyzer


class TestDirectImports:
    """直接 import 匹配"""

    def test_module_import_and_call(self, tmp_path):
        """import requests 匹配"""
        f = tmp_path / "app.py"
        f.write_text("import requests\nrequests.get('https://example.com')\n")
        analyzer = ReachabilityAnalyzer()
        evidences = analyzer.analyze_file(str(f), {"requests.get"})
        assert len(evidences) == 1
        assert evidences[0].line == 2
        assert evidences[0].confidence == "high"
        assert "requests.get" in evidences[0].resolved_path

    def test_from_import_and_call(self, tmp_path):
        """from requests import get 匹配"""
        f = tmp_path / "app.py"
        f.write_text("from requests import get\nget('https://example.com')\n")
        analyzer = ReachabilityAnalyzer()
        evidences = analyzer.analyze_file(str(f), {"requests.get"})
        assert len(evidences) == 1
        assert "requests.get" in evidences[0].resolved_path

    def test_aliased_import_and_call(self, tmp_path):
        """import requests as req 匹配"""
        f = tmp_path / "app.py"
        f.write_text("import requests as req\nreq.get('https://example.com')\n")
        analyzer = ReachabilityAnalyzer()
        evidences = analyzer.analyze_file(str(f), {"requests.get"})
        assert len(evidences) == 1
        assert evidences[0].confidence == "high"


class TestAdvancedResolution:
    """赋值别名 / getattr / 嵌套属性"""

    def test_assignment_alias(self, tmp_path):
        """别名匹配"""
        f = tmp_path / "app.py"
        f.write_text("""
import requests
fetch = requests.get
fetch('https://example.com')
""")
        analyzer = ReachabilityAnalyzer()
        evidences = analyzer.analyze_file(str(f), {"requests.get"})
        assert len(evidences) == 1

    def test_getattr_static(self, tmp_path):
        """getattr(requests, 'get') 匹配"""
        f = tmp_path / "app.py"
        f.write_text("""
import requests
func = getattr(requests, 'get')
func('https://example.com')
""")
        analyzer = ReachabilityAnalyzer()
        evidences = analyzer.analyze_file(str(f), {"requests.get"})
        assert len(evidences) == 0

    def test_getattr_dynamic_low_confidence(self, tmp_path):
        """getattr(obj, unknown_var) 匹配但标记为 low confidence"""
        f = tmp_path / "app.py"
        f.write_text("""
import requests
attr_name = input()
getattr(requests, attr_name)()
""")
        analyzer = ReachabilityAnalyzer()
        evidences = analyzer.analyze_file(str(f), {"requests.get"})
        low_conf = [e for e in evidences if e.confidence == "low"]
        assert len(low_conf) == 1


class TestEdgeCases:
    """边界：文件不存在、语法错误、不匹配的调用"""

    def test_file_not_found_returns_empty(self, tmp_path):
        analyzer = ReachabilityAnalyzer()
        evidences = analyzer.analyze_file(str(tmp_path / "nonexistent.py"), {"requests.get"})
        assert evidences == []

    def test_non_matching_call_not_flagged(self, tmp_path):
        """调了 requests.post 不匹配"""
        f = tmp_path / "app.py"
        f.write_text("import requests\nrequests.post('https://example.com')\n")
        analyzer = ReachabilityAnalyzer()
        evidences = analyzer.analyze_file(str(f), {"requests.get"})
        assert len(evidences) == 0

    def test_syntax_error_returns_empty(self, tmp_path):
        """语法错误的文件 → 不崩溃，返空"""
        f = tmp_path / "app.py"
        f.write_text("this is not valid python {{{{{\n")
        analyzer = ReachabilityAnalyzer()
        evidences = analyzer.analyze_file(str(f), {"requests.get"})
        assert evidences == []
