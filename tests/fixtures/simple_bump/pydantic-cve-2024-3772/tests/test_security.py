"""版本级回归测试：安装的 pydantic 必须 >= 1.10.13（CVE-2024-3772 修复版本）。

- pydantic==1.10.2（漏洞版本）上此测试 FAIL
- pydantic>=1.10.13（修复版本）上此测试 PASS
"""
import unittest

import pydantic


class SecurityRegressionTest(unittest.TestCase):
    def test_version_fixes_3772(self):
        version = tuple(int(x) for x in pydantic.__version__.split(".")[:3])
        self.assertGreaterEqual(version, (1, 10, 13))


if __name__ == "__main__":
    unittest.main()
