"""版本级回归测试：安装的 h11 必须 >= 0.16.0（CVE-2025-43859 修复版本）。

- h11==0.12.0（漏洞版本）上此测试 FAIL
- h11>=0.16.0（修复版本）上此测试 PASS
"""
import unittest

import h11


class SecurityRegressionTest(unittest.TestCase):
    def test_version_fixes_43859(self):
        version = tuple(int(x) for x in h11.__version__.split(".")[:3])
        self.assertGreaterEqual(version, (0, 16, 0))


if __name__ == "__main__":
    unittest.main()
