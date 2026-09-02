"""版本级回归测试：安装的 fastapi 必须 >= 0.109.1（CVE-2024-24762 修复版本）。

- fastapi==0.95.0（漏洞版本）上此测试 FAIL
- fastapi>=0.109.1（修复版本）上此测试 PASS
"""
import unittest

import fastapi


class SecurityRegressionTest(unittest.TestCase):
    def test_version_fixes_24762(self):
        version = tuple(int(x) for x in fastapi.__version__.split(".")[:3])
        self.assertGreaterEqual(version, (0, 109, 1))


if __name__ == "__main__":
    unittest.main()
