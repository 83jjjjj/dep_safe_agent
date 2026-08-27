"""DockerEnvironment._handle_runner_output 的 mark_covered 语义：
成功或不可恢复失败 → 标记已处理；依赖约束冲突（recoverable）→ 留在池中供重试。
"""
import json
import subprocess
from unittest.mock import MagicMock

from depsafe.environment.docker import DockerEnvironment
from depsafe.tool.apply_fix_and_verify import FixAttemptResult


def _handle_fix_output(fix_result: FixAttemptResult) -> DockerEnvironment:
    env = object.__new__(DockerEnvironment)
    env.vuln_budget = MagicMock()
    stdout = json.dumps({"status": "success", "output": fix_result.model_dump(mode="json")})
    completed = subprocess.CompletedProcess(args=["python"], returncode=0, stdout=stdout, stderr="")
    env._handle_runner_output("apply_fix_and_verify", completed)
    return env


def test_success_marks_covered():
    env = _handle_fix_output(
        FixAttemptResult(pkg_name="flask", cve_id="CVE-2023-30861", success=True, attempted_version="2.3.2")
    )
    env.vuln_budget.mark_covered.assert_called_once()


def test_non_recoverable_failure_marks_covered():
    env = _handle_fix_output(
        FixAttemptResult(
            pkg_name="flask",
            cve_id="CVE-2023-30861",
            success=False,
            attempted_version="2.3.2",
            recoverable=False,
        )
    )
    env.vuln_budget.mark_covered.assert_called_once()


def test_recoverable_conflict_not_covered():
    env = _handle_fix_output(
        FixAttemptResult(
            pkg_name="flask",
            cve_id="CVE-2023-30861",
            success=False,
            attempted_version="2.3.2",
            recoverable=True,
        )
    )
    env.vuln_budget.mark_covered.assert_not_called()
