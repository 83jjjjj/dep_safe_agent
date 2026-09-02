"""版本级回归测试：安装的 wheel 必须 >= 0.38.1（CVE-2022-40898 修复版本）。

- wheel==0.38.0（漏洞版本）上此测试 FAIL
- wheel>=0.38.1（修复版本）上此测试 PASS
"""
import unittest

import wheel


class SecurityRegressionTest(unittest.TestCase):
    def test_version_fixes_40898(self):
        version = tuple(int(x) for x in wheel.__version__.split(".")[:3])
        self.assertGreaterEqual(version, (0, 38, 1))


if __name__ == "__main__":
    unittest.main()
