"""版本级回归测试：安装的 flask 必须 >= 3.1.3（CVE-2026-27205 修复版本）。

- flask==2.3.2（漏洞版本）上此测试 FAIL
- flask>=3.1.3（修复版本）上此测试 PASS
"""
import unittest

import flask


class SecurityRegressionTest(unittest.TestCase):
    def test_version_fixes_27205(self):
        version = tuple(int(x) for x in flask.__version__.split(".")[:3])
        self.assertGreaterEqual(version, (3, 1, 3))


if __name__ == "__main__":
    unittest.main()
