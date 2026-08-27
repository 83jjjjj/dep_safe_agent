import re
import subprocess
import sys
import venv
from pathlib import Path

import tomlkit
from pydantic import BaseModel, Field


class FixAttemptResult(BaseModel):
    """单次修复尝试的结果"""

    pkg_name: str = Field(..., description="包名，如 'requests'")
    cve_id: str = Field(..., description="CVE 编号，如 'CVE-2024-1234'")
    success: bool = Field(..., description="是否修复成功")
    attempted_version: str = Field(..., description="尝试升级的目标版本")
    error: str | None = Field(None, description="错误日志")
    branch_name: str | None = Field(None, description="创建的修复分支名（仅当修改文件成功时返回）")
    test_skipped: bool = Field(False, description="是否跳过了测试执行（因无测试套件）")
    recoverable: bool = Field(
        False,
        description="失败是否可恢复：仅依赖约束冲突为 True，允许以同一目标版本补联动包后重试",
    )
    suggested_next_action: str | None = Field(
        None,
        description="建议的下一步操作: CREATE_REPORT_AND_ISSUE / RETRY_WITH_PINS / MANUAL_REVIEW",
    )


def _has_tool(tool_name: str) -> bool:
    """检查系统中是否安装了指定工具"""
    cmd = "where" if sys.platform.startswith("win") else "which"
    try:
        subprocess.run([cmd, tool_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _prepare_fix_branch(pkg_name: str, cve_id: str) -> str:
    """准备修复分支：远程存在则复用并重置，不存在则新建"""
    safe_cve = cve_id.replace("/", "-").replace(":", "-")
    branch = f"fix/security-update-{pkg_name}-{safe_cve}"
    result = subprocess.run(["git", "ls-remote", "--heads", "origin", branch], capture_output=True, text=True)
    remote_exists = bool(result.stdout.strip())
    if remote_exists:
        try:
            subprocess.run(["git", "fetch", "origin", branch], check=True, capture_output=True)
            subprocess.run(["git", "checkout", branch], check=True, capture_output=True)
            subprocess.run(["git", "reset", "--hard", "origin/main"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            subprocess.run(["git", "checkout", "main"], check=True, capture_output=True)
            subprocess.run(["git", "checkout", "-B", branch], check=True, capture_output=True)
    else:
        try:
            subprocess.run(["git", "checkout", "-b", branch], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            subprocess.run(["git", "checkout", branch], check=True, capture_output=True)
    return branch


def _push_changes(branch: str, pkg_name: str, cve_id: str) -> tuple[bool, str]:
    """封装 Commit、Rebase 和 Push 操作"""
    # 1. Commit（仅暂存依赖文件，避免把 .depsafe/、.agent_runner.py、.venv-fix-verify/ 等运行时产物提交进分支）
    try:
        dep_files = [
            f
            for f in (
                "requirements.txt",
                "requirements.lock",
                "pyproject.toml",
                "Pipfile",
                "poetry.lock",
                "uv.lock",
                "Pipfile.lock",
            )
            if Path(f).exists()
        ]
        if not dep_files:
            return False, "No dependency files found to commit"
        subprocess.run(["git", "add", *dep_files], check=True, capture_output=True, text=True)
        status = subprocess.run(["git", "diff", "--cached", "--quiet"], capture_output=True, text=True)
        if status.returncode == 0:
            return False, "No changes to commit"
        commit_msg = f"fix(security): upgrade {pkg_name} to resolve {cve_id}"
        subprocess.run(["git", "commit", "-m", commit_msg], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        return False, f"Git commit error: {e.stderr.strip()}"
    # 2. Rebase（必须先提交再 rebase，工作区有未提交变更时 git rebase 会直接拒绝）
    try:
        subprocess.run(["git", "fetch", "origin", "main"], check=True, capture_output=True, text=True)
        rebase_res = subprocess.run(["git", "rebase", "origin/main"], capture_output=True, text=True)
        if rebase_res.returncode != 0:
            subprocess.run(["git", "rebase", "--abort"], capture_output=True, text=True)
            return False, f"Rebase conflict: {rebase_res.stderr.strip()}"
    except subprocess.CalledProcessError as e:
        return False, f"Git rebase error: {e.stderr.strip()}"
    # 3. Push
    try:
        subprocess.run(
            ["git", "push", "-u", "origin", branch, "--force-with-lease"], check=True, capture_output=True, text=True
        )
        return True, ""
    except subprocess.CalledProcessError as e:
        return False, f"Git push error: {e.stderr.strip()}"


def _update_pyproject(pkg_name: str, version: str) -> tuple[bool, str | None]:
    """更新 pyproject.toml 中的依赖版本"""
    path = Path("pyproject.toml")
    if not path.exists():
        return False, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = tomlkit.load(f)
    except Exception as e:
        return False, f"Failed to parse pyproject.toml: {e}"
    updated = False
    # PEP 621 标准格式: [project] dependencies = ["requests>=2.0"]
    pattern = re.compile(rf"^{re.escape(pkg_name)}(\[.*\])?\s*([><=!~].*)?$")
    if "project" in doc and "dependencies" in doc["project"]:
        deps = doc["project"]["dependencies"]
        for i, dep in enumerate(deps):
            if pattern.match(dep.strip()):
                deps[i] = f"{pkg_name}=={version}"
                updated = True
                break
    # Poetry 格式: [tool.poetry.dependencies] requests = "^2.0"
    if not updated and "tool" in doc and "poetry" in doc["tool"]:
        poetry_deps = doc["tool"]["poetry"].get("dependencies", {})
        if pkg_name in poetry_deps:
            poetry_deps[pkg_name] = f"=={version}"
            updated = True
    if updated:
        try:
            with open(path, "w", encoding="utf-8") as f:
                tomlkit.dump(doc, f)
        except Exception as e:
            return False, f"Failed to write pyproject.toml: {e}"
        return updated, None


def _update_requirements(pkg_name: str, version: str) -> tuple[bool, str | None]:
    """更新 requirements.txt 中的依赖版本"""
    path = Path("requirements.txt")
    if not path.exists():
        return False, None
    try:
        lines = path.read_text().splitlines()
    except Exception as e:
        return False, f"Failed to write requirements.txt: {e}"
    updated = False
    pattern = re.compile(rf"^{re.escape(pkg_name)}([><=!~].*)?$")
    for i, line in enumerate(lines):
        if pattern.match(line.strip()):
            lines[i] = f"{pkg_name}=={version}"
            updated = True
            break
    if updated:
        try:
            path.write_text("\n".join(lines) + "\n")
        except Exception as e:
            return False, f"Failed to write requirements.txt: {e}"
    return updated, None


def _update_pipfile(pkg_name: str, version: str) -> tuple[bool, str | None]:
    """更新 Pipfile 中的依赖版本"""
    path = Path("Pipfile")
    if not path.exists():
        return False, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = tomlkit.load(f)
    except Exception as e:
        return False, f"Failed to write Pipfile: {e}"
    updated = False
    for section in ["packages", "dev-packages"]:
        if section in doc and pkg_name in doc[section]:
            doc[section][pkg_name] = f"=={version}"
            updated = True
    if updated:
        try:
            with open(path, "w", encoding="utf-8") as f:
                tomlkit.dump(doc, f)
        except Exception as e:
            return False, f"Failed to write Pipfile: {e}"
    return updated, None


def _regenerate_lockfile() -> tuple[bool, str]:
    """
    尝试生成锁文件，返回 (是否成功, 错误信息)
    按优先级尝试: uv -> poetry -> pip-tools -> pipenv
    """
    lockfile_tools = [
        ("uv", ["uv", "lock"], ["pyproject.toml", "requirements.txt"]),
        ("poetry", ["poetry", "lock", "--no-update"], ["pyproject.toml"]),
        ("pip-compile", ["pip-compile", "requirements.txt", "-o", "requirements.lock", "--no-header", "--no-annotate"], ["requirements.txt"]),
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


def _classify_lock_error(lock_error: str) -> tuple[bool, str]:
    """
    判断锁文件失败是否为依赖约束冲突（可恢复）。

    依赖约束冲突（如钉死的联动包不满足主包新版本的依赖要求）可以通过补
    extra_pins 重试解决；其他失败（工具缺失、网络错误等）不可恢复。

    Returns:
        (是否约束冲突, 建议的下一步操作)
    """
    is_conflict = "ResolutionImpossible" in lock_error or "conflicting dependencies" in lock_error
    return is_conflict, "RETRY_WITH_PINS" if is_conflict else "MANUAL_REVIEW"


def _ensure_venv(venv_path: Path) -> Path:
    """确保临时虚拟环境存在，返回其 python 可执行文件路径"""
    if not venv_path.exists():
        venv.create(venv_path, with_pip=True, clear=True)
    if sys.platform.startswith("win"):
        return venv_path / "Scripts" / "python.exe"
    return venv_path / "bin" / "python"


def _install_package(venv_python: Path, pkg_name: str, version: str) -> tuple[bool, str]:
    """在隔离 venv 中安装包，返回 (成功, 错误信息)"""
    try:
        result = subprocess.run(
            [str(venv_python), "-m", "pip", "install", f"{pkg_name}=={version}", "--quiet"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, f"pip install {pkg_name}=={version} timed out (2 minutes)"
    except Exception as e:
        return False, f"pip install error: {e}"


def _verify_import(venv_python: Path, pkg_name: str, module_name: str) -> tuple[bool, str]:
    """在隔离 venv 中尝试 import 包，验证是否可正常加载"""
    try:
        result = subprocess.run(
            [str(venv_python), "-c", f"import {module_name}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, f"import {module_name} timed out (30s)"
    except Exception as e:
        return False, f"import verification error: {e}"


def _run_pip_check(venv_python: Path) -> tuple[bool, str]:
    """在隔离 venv 中运行 pip check 检测依赖冲突"""
    try:
        result = subprocess.run(
            [str(venv_python), "-m", "pip", "check"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stdout.strip() or result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "pip check timed out (60s)"
    except Exception as e:
        return False, f"pip check error: {e}"


def _verify_installation(venv_python: Path, pkg_name: str, version: str, module_name: str) -> tuple[bool, str]:
    """
    递进式安装验证：install → import → pip check
    Returns: (success, error)
    """
    ok, err = _install_package(venv_python, pkg_name, version)
    if not ok:
        return False, f"pip install failed: {err}"
    ok, err = _verify_import(venv_python, pkg_name, module_name)
    if not ok:
        return False, f"Import verification failed: {err}"
    ok, err = _run_pip_check(venv_python)
    if not ok:
        return False, f"pip check failed: {err}"
    return True, ""


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
    """运行测试，返回 (是否通过, 输出日志)。优先 pytest，兜底 unittest"""
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
            return False, f"pytest execution error: {e}"
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
            return False, f"unittest execution error: {e}"
    return False, "No test runner available (pytest/python)"


def apply_fix_and_verify(
    pkg_name: str,
    cve_id: str,
    target_version: str,
    module_name: str,
    extra_pins: dict[str, str] | None = None,
) -> FixAttemptResult:
    """
    尝试将指定包升级到 target_version 并验证，仅执行单次尝试。

    Args:
        pkg_name: 待修复的包名，如 'requests'
        cve_id: CVE 编号，如 'CVE-2024-1234'
        target_version: 目标修复版本，如 '2.3.1'
        module_name: 包的导入模块名。存在当包名与 import 名不一致的情况
        extra_pins: 联动升级的钉死依赖清单，如 {'werkzeug': '2.3.0'}。
            当目标版本要求本项目其他钉死依赖升级时传入，随主包一起更新。

    Returns:
        FixAttemptResult: 包含成功/失败状态、详细原因及建议的下一步操作
    """
    # 1. 环境自检
    if not _has_tool("git"):
        return FixAttemptResult(
            pkg_name=pkg_name,
            cve_id=cve_id,
            success=False,
            attempted_version=target_version,
            error="git is not installed in sandbox",
            suggested_next_action="CREATE_REPORT_AND_ISSUE",
        )
    # 2. 创建修复分支
    try:
        branch_name = _prepare_fix_branch(pkg_name, cve_id)
    except subprocess.CalledProcessError as e:
        return FixAttemptResult(
            pkg_name=pkg_name,
            cve_id=cve_id,
            success=False,
            attempted_version=target_version,
            error=f"Failed to create branch: {e.stderr.strip()}",
            suggested_next_action="CREATE_REPORT_AND_ISSUE",
        )
    # 3. 更新依赖文件（主包 + 联动包 extra_pins）
    if Path("pyproject.toml").exists():
        update_func = _update_pyproject
    elif Path("requirements.txt").exists():
        update_func = _update_requirements
    elif Path("Pipfile").exists():
        update_func = _update_pipfile
    else:
        update_func = None
    if update_func is None:
        return FixAttemptResult(
            pkg_name=pkg_name,
            cve_id=cve_id,
            success=False,
            attempted_version=target_version,
            error="No dependency file found (pyproject.toml / requirements.txt / Pipfile)",
            branch_name=branch_name,
            suggested_next_action="CREATE_REPORT_AND_ISSUE",
        )
    pins: list[tuple[str, str]] = [(pkg_name, target_version)]
    pins += [(pin_pkg, pin_ver) for pin_pkg, pin_ver in (extra_pins or {}).items() if pin_pkg != pkg_name]
    for pin_pkg, pin_ver in pins:
        ok, err = update_func(pin_pkg, pin_ver)
        if not ok:
            label = "主包" if pin_pkg == pkg_name else "联动包"
            return FixAttemptResult(
                pkg_name=pkg_name,
                cve_id=cve_id,
                success=False,
                attempted_version=target_version,
                error=f"{label} {pin_pkg} 更新失败: {err or '未在依赖文件中找到该包的声明行'}",
                branch_name=branch_name,
                suggested_next_action="CREATE_REPORT_AND_ISSUE",
            )
    # 4. 生成锁文件
    lock_success, lock_error = _regenerate_lockfile()
    if not lock_success:
        recoverable, next_action = _classify_lock_error(lock_error)
        return FixAttemptResult(
            pkg_name=pkg_name,
            cve_id=cve_id,
            success=False,
            attempted_version=target_version,
            error=lock_error,
            branch_name=branch_name,
            recoverable=recoverable,
            suggested_next_action=next_action,
        )
    # 5. 隔离环境验证：install → import → pip check
    venv_path = Path(".venv-fix-verify")
    venv_python = _ensure_venv(venv_path)
    verify_ok, verify_err = _verify_installation(venv_python, pkg_name, target_version, module_name)
    if not verify_ok:
        return FixAttemptResult(
            pkg_name=pkg_name,
            cve_id=cve_id,
            success=False,
            attempted_version=target_version,
            error=verify_err,
            branch_name=branch_name,
            suggested_next_action="MANUAL_REVIEW",
        )
    # 6. 运行项目测试
    if not _has_tests():
        push_ok, push_err = _push_changes(branch_name, pkg_name, cve_id)
        if not push_ok:
            return FixAttemptResult(
                pkg_name=pkg_name,
                cve_id=cve_id,
                success=False,
                attempted_version=target_version,
                error=push_err,
                branch_name=branch_name,
                suggested_next_action="MANUAL_REVIEW",
            )
        return FixAttemptResult(
            pkg_name=pkg_name,
            cve_id=cve_id,
            success=True,
            attempted_version=target_version,
            branch_name=branch_name,
            test_skipped=True,
        )
    test_passed, test_output = _run_tests()
    if test_passed:
        push_ok, push_err = _push_changes(branch_name, pkg_name, cve_id)
        if not push_ok:
            return FixAttemptResult(
                pkg_name=pkg_name,
                cve_id=cve_id,
                success=False,
                attempted_version=target_version,
                error=push_err,
                branch_name=branch_name,
                suggested_next_action="MANUAL_REVIEW",
            )
        return FixAttemptResult(
            pkg_name=pkg_name,
            cve_id=cve_id,
            success=True,
            attempted_version=target_version,
            branch_name=branch_name,
            test_skipped=False,
            suggested_next_action=None,
        )
    return FixAttemptResult(
        pkg_name=pkg_name,
        cve_id=cve_id,
        success=False,
        attempted_version=target_version,
        error=test_output,
        branch_name=branch_name,
        test_skipped=False,
        suggested_next_action="MANUAL_REVIEW",
    )
