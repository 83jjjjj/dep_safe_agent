import re
import subprocess
import sys
from pathlib import Path

import tomlkit
from pydantic import BaseModel, Field


class FixAttemptResult(BaseModel):
    """单次修复尝试的结果"""

    success: bool = Field(..., description="是否修复成功")
    attempted_version: str = Field(..., description="尝试升级的目标版本")
    failure_reason: str | None = Field(
        None,
        description="失败原因分类: DEPENDENCY_CONFLICT / TEST_FAILURE / TEST_TIMEOUT / UNSUPPORTED_FORMAT / ENV_MISSING / LOCK_FAILED",
    )
    raw_error: str | None = Field(None, description="原始错误日志（供LLM深度分析）")
    branch_name: str | None = Field(None, description="创建的修复分支名（仅当修改文件成功时返回）")
    test_skipped: bool = Field(False, description="是否跳过了测试执行（因无测试套件）")
    suggested_next_action: str | None = Field(
        None, description="建议的下一步操作: TRY_NEXT_VERSION / CREATE_REPORT_AND_ISSUE / MANUAL_REVIEW"
    )


def _has_tool(tool_name: str) -> bool:
    """检查系统中是否安装了指定工具"""
    cmd = "where" if sys.platform.startswith("win") else "which"
    try:
        subprocess.run([cmd, tool_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _create_branch(pkg_name: str, cve_id: str) -> str:
    """创建修复分支"""
    safe_cve = cve_id.replace("/", "-").replace(":", "-")
    branch = f"fix/security-update-{pkg_name}-{safe_cve}"
    subprocess.run(["git", "checkout", "-b", branch], check=True, capture_output=True)
    return branch


def _update_pyproject(pkg_name: str, version: str) -> bool:
    """更新 pyproject.toml 中的依赖版本"""
    path = Path("pyproject.toml")
    if not path.exists():
        return False
    with open(path, "r", encoding="utf-8") as f:
        doc = tomlkit.load(f)
    updated = False
    # 尝试更新 PEP 621 标准格式: [project] dependencies = ["requests>=2.0"]
    if "project" in doc and "dependencies" in doc["project"]:
        deps = doc["project"]["dependencies"]
        for i, dep in enumerate(deps):
            if dep.startswith(f"{pkg_name}") and any(c in dep for c in "=<>!~"):
                deps[i] = f"{pkg_name}=={version}"
                updated = True
                break
    # 尝试更新 Poetry 格式: [tool.poetry.dependencies] requests = "^2.0"
    if not updated and "tool" in doc and "poetry" in doc["tool"]:
        poetry_deps = doc["tool"]["poetry"].get("dependencies", {})
        if pkg_name in poetry_deps:
            poetry_deps[pkg_name] = f"=={version}"
            updated = True
    if updated:
        with open(path, "w", encoding="utf-8") as f:
            tomlkit.dump(doc, f)
    return updated


def _update_requirements(pkg_name: str, version: str) -> bool:
    """更新 requirements.txt 中的依赖版本"""
    path = Path("requirements.txt")
    if not path.exists():
        return False
    lines = path.read_text().splitlines()
    updated = False
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(pkg_name)}([><=!~].*)?$", line.strip()):
            lines[i] = f"{pkg_name}=={version}"
            updated = True
            break
    if updated:
        path.write_text("\n".join(lines) + "\n")
    return updated


def _update_pipfile(pkg_name: str, version: str) -> bool:
    """更新 Pipfile 中的依赖版本"""
    path = Path("Pipfile")
    if not path.exists():
        return False
    with open(path, "r", encoding="utf-8") as f:
        doc = tomlkit.load(f)
    updated = False
    for section in ["packages", "dev-packages"]:
        if section in doc and pkg_name in doc[section]:
            doc[section][pkg_name] = f"=={version}"
            updated = True
    if updated:
        with open(path, "w", encoding="utf-8") as f:
            tomlkit.dump(doc, f)
    return updated


def _regenerate_lockfile() -> tuple[bool, str]:
    """
    尝试生成锁文件，返回 (是否成功, 错误信息)
    按优先级尝试: uv -> poetry -> pip-tools -> pipenv
    锁文件生成失败意味着依赖树不合法，必须阻断流程。
    """
    lockfile_tools = [
        ("uv", ["uv", "lock"], ["pyproject.toml", "requirements.txt"]),
        ("poetry", ["poetry", "lock", "--no-update"], ["pyproject.toml"]),
        ("pip-compile", ["pip-compile", "requirements.txt"], ["requirements.txt"]),
        ("pipenv", ["pipenv", "lock"], ["Pipfile"]),
    ]
    for tool_name, cmd, required_files in lockfile_tools:
        if _has_tool(tool_name) and any(Path(f).exists() for f in required_files):
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                return True, ""
            except subprocess.CalledProcessError as e:
                return False, f"{tool_name} lock failed: {e.stderr}"
    return False, "No lockfile tool available (uv/poetry/pip-compile/pipenv)"


def _has_tests() -> bool:
    """检测项目是否有测试套件"""
    if Path("tests").exists() or Path("test").exists():
        return True
    if Path("conftest.py").exists():
        return True
    for pattern in ["test_*.py", "*_test.py"]:
        if list(Path(".").glob(pattern)):
            return True
    return False


def _run_tests() -> tuple[bool, str]:
    """
    运行测试，返回 (是否通过, 输出日志)
    优先 pytest，兜底 unittest
    """
    if _has_tool("pytest"):
        try:
            result = subprocess.run(
                ["pytest", "--tb=short", "-q"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, "Test execution timed out (5 minutes)"
        except Exception as e:
            return False, f"pytest execution error: {str(e)}"
    if _has_tool("python"):
        try:
            result = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-v"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, f"unittest execution error: {str(e)}"
    return False, "No test runner available (pytest/python)"


def apply_fix_and_verify(pkg_name: str, cve_id: str, target_version: str) -> FixAttemptResult:
    """
    尝试将指定包升级到 target_version 并验证，仅执行单次尝试。

    Args:
        pkg_name: 待修复的包名，如 'requests'
        cve_id: CVE 编号，如 'CVE-2024-1234'
        target_version: 目标修复版本，如 '2.3.1'

    Returns:
        FixAttemptResult: 包含成功/失败状态、详细原因及建议的下一步操作
    """
    # 1. 环境自检：git 是必须的
    if not _has_tool("git"):
        return FixAttemptResult(
            success=False,
            attempted_version=target_version,
            failure_reason="ENV_MISSING",
            raw_error="git is not installed in sandbox",
            suggested_next_action="CREATE_REPORT_AND_ISSUE",
        )
    # 2. 创建修复分支
    try:
        branch_name = _create_branch(pkg_name, cve_id)
    except subprocess.CalledProcessError as e:
        return FixAttemptResult(
            success=False,
            attempted_version=target_version,
            failure_reason="ENV_MISSING",
            raw_error=f"Failed to create branch: {e.stderr.decode()}",
            suggested_next_action="CREATE_REPORT_AND_ISSUE",
        )
    # 3. 更新依赖文件
    updated = False
    if Path("pyproject.toml").exists():
        updated = _update_pyproject(pkg_name, target_version)
    elif Path("requirements.txt").exists():
        updated = _update_requirements(pkg_name, target_version)
    elif Path("Pipfile").exists():
        updated = _update_pipfile(pkg_name, target_version)
    if not updated:
        return FixAttemptResult(
            success=False,
            attempted_version=target_version,
            failure_reason="UNSUPPORTED_FORMAT",
            raw_error="No supported dependency file found (pyproject.toml/requirements.txt/Pipfile)",
            branch_name=branch_name,
            suggested_next_action="CREATE_REPORT_AND_ISSUE",
        )
    # 4. 生成锁文件（必须成功，失败则阻断流程）
    lock_success, lock_error = _regenerate_lockfile()
    if not lock_success:
        return FixAttemptResult(
            success=False,
            attempted_version=target_version,
            failure_reason="LOCK_FAILED",
            raw_error=lock_error,
            branch_name=branch_name,
            suggested_next_action="TRY_NEXT_VERSION",
        )
    # 5. 运行测试（尽力而为）
    if not _has_tests():
        return FixAttemptResult(
            success=True,
            attempted_version=target_version,
            branch_name=branch_name,
            test_skipped=True,
            suggested_next_action=None,
        )
    test_passed, test_output = _run_tests()
    if test_passed:
        return FixAttemptResult(
            success=True,
            attempted_version=target_version,
            branch_name=branch_name,
            test_skipped=False,
            suggested_next_action=None,
        )
    else:
        failure_reason = "TEST_FAILURE"
        if "ImportError" in test_output or "ModuleNotFoundError" in test_output:
            failure_reason = "DEPENDENCY_CONFLICT"
        elif "ResolutionImpossible" in test_output or "Could not find a version" in test_output:
            failure_reason = "DEPENDENCY_CONFLICT"
        elif "timed out" in test_output.lower():
            failure_reason = "TEST_TIMEOUT"
        if failure_reason == "DEPENDENCY_CONFLICT":
            suggested_next_action = "TRY_NEXT_VERSION"
        elif failure_reason == "TEST_FAILURE":
            suggested_next_action = "MANUAL_REVIEW"
        else:
            suggested_next_action = "TRY_NEXT_VERSION"
        return FixAttemptResult(
            success=False,
            attempted_version=target_version,
            failure_reason=failure_reason,
            raw_error=test_output,
            branch_name=branch_name,
            test_skipped=False,
            suggested_next_action=suggested_next_action,
        )
