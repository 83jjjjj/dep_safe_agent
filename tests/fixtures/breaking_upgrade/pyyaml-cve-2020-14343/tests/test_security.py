"""版本级回归测试：安装的 pyyaml 必须 >= 6.0（CVE-2020-14343 修复版本）。

- pyyaml==5.3.1（漏洞版本）上此测试 FAIL
- pyyaml>=6.0（修复版本）上此测试 PASS
"""
import unittest

import yaml


class SecurityRegressionTest(unittest.TestCase):
    def test_version_fixes_14343(self):
        version = tuple(int(x) for x in yaml.__version__.split(".")[:3])
        self.assertGreaterEqual(version, (6, 0))


if __name__ == "__main__":
    unittest.main()
