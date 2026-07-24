
import tomllib
import tempfile
import subprocess
from enum import Enum
from pathlib import Path
from pydantic import BaseModel
from typing import List, Optional
from click.testing import CliRunner
from packaging.requirements import Requirement
from piptools.scripts.compile import cli as pip_compile_cli

class DepCategory(Enum):
    PRODUCTION = "production"
    DEV = "dev"
    OPTIONAL = "optional"

class Dependency(BaseModel):
    name: str
    version_spec: str   # ">=2.0.0"
    marker: str | None  # environment marker
    source_file: str    # "pyproject.toml"
    category: DepCategory


def parse_deps(file_path: str) -> List[dict]:
    """
    统一读取项目依赖文件，优先解析锁文件，否则通过 pip-compile 构建完整依赖树。

    Args:
        file_path: 包含 requirements.txt / pyproject.toml / Pipfile 中的一种的文件路径。

    Returns:
        项目依赖包列表，仅限生产环境。
    """
    path = Path(file_path)
    project_dir = path.parent
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    # 优先解析锁文件
    poetry_lock = project_dir / "poetry.lock"
    uv_lock = project_dir / "uv.lock"
    pipfile_lock = project_dir / "Pipfile.lock"
    if poetry_lock.exists():
        return _parse_poetry_lock(poetry_lock)
    elif uv_lock.exists():
        return _parse_uv_lock(uv_lock)
    elif pipfile_lock.exists():
        return _parse_pipfile_lock(pipfile_lock)
    # 否则依据依赖文件构建依赖树
    file_name = path.name
    deps = []
    if file_name in ["requirements.txt", "requirements.in", "pyproject.toml"]:
        deps = _compile_dependencies(file_path)
    elif file_name == "Pipfile":
        deps = _compile_pipfile_dependencies(file_path)
    return [dep.model_dump(mode='json') for dep in deps]

def _compile_dependencies(file_path: str) -> List[Dependency]:
    """
    使用 pip-compile 在后台解析依赖，生成精确的依赖树
    """
    runner = CliRunner()
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False) as tmp_out:
        tmp_out_path = tmp_out.name
    try:
        # 模拟在命令行执行: pip-compile <file_path> -o <tmp_out_path> --no-header --no-annotate
        result = runner.invoke(pip_compile_cli, [
            file_path, 
            "-o", tmp_out_path, 
            "--no-header",      # 不生成头部注释
            "--no-annotate",    # 不生成依赖来源注释，保持文件干净
            "--quiet"           # 安静模式
        ])
        if result.exit_code != 0:
            print(f"pip-compile 解析失败: {result.exception}")
            return []
        return _parse_compiled_output(tmp_out_path, file_path)
    finally:
        Path(tmp_out_path).unlink(missing_ok=True)

def _parse_compiled_output(tmp_out_path: str, file_path: str) -> List[Dependency]:
    # 读取 pip-compile 生成的精确版本列表
    resolved_deps = []
    with open(tmp_out_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            marker = None
            if ";" in line:
                line, marker = line.split(";", 1)
                line, marker = line.strip(), marker.strip()
            if "==" in line:
                name, version = line.split("==", 1)
                resolved_deps.append(Dependency(
                    name=name.strip(),
                    version_spec=f"=={version.strip()}",
                    marker=marker,
                    source_file=file_path,
                    category=DepCategory.PRODUCTION
                ))
    return resolved_deps

def _compile_pipfile_dependencies(pipfile_path: Path) -> List[Dependency]:
    """
    直接使用 pipenv lock 生成 Pipfile.lock，并解析出精确依赖。
    """
    project_dir = pipfile_path.parent
    lock_file_path = project_dir / "Pipfile.lock"
    try:
        # 设置 PIPENV_IGNORE_VIRTUALENVS=1 防止 pipenv 错误继承当前 Agent 所在的虚拟环境
        env = {"PIPENV_IGNORE_VIRTUALENVS": "1"}
        subprocess.run(
            ["pipenv", "lock"], 
            cwd=project_dir, 
            check=True, 
            capture_output=True, 
            text=True,
            env=env
        )
        return _parse_pipfile_lock(lock_file_path)
    except subprocess.CalledProcessError as e:
        print(f"pipenv lock 执行失败: {e.stderr}")
        return []
    except Exception as e:
        print(f"解析 Pipfile 依赖失败: {e}")
        return []

def _parse_poetry_lock(lock_path: Path) -> List[Dependency]:
    """解析 poetry.lock 文件"""
    with open(lock_path, "rb") as f:
        data = tomllib.load(f)
    deps = []
    for pkg in data.get("package", []):
        if pkg.get("category", "main") == "main":
            deps.append(Dependency(
                name=pkg["name"],
                version_spec=f"=={pkg['version']}",
                marker=None,
                source_file=str(lock_path),
                category=DepCategory.PRODUCTION
            ))
    return deps

def _parse_uv_lock(lock_path: Path) -> List[Dependency]:
    """解析 uv.lock 文件"""
    with open(lock_path, "rb") as f:
        data = tomllib.load(f)
    deps = []
    for pkg in data.get("package", []):
        deps.append(Dependency(
            name=pkg["name"],
            version_spec=f"=={pkg['version']}",
            marker=None,
            source_file=str(lock_path),
            category=DepCategory.PRODUCTION
        ))
    return deps

def _parse_pipfile_lock(lock_path: Path) -> List[Dependency]:
    """解析 Pipfile.lock 文件"""
    import json
    with open(lock_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    deps = []
    for pkg_name, pkg_info in data.get("default", {}).items():
        version = pkg_info.get("version", "").replace("==", "")
        if version:
            deps.append(Dependency(
                name=pkg_name,
                version_spec=f"=={version}",
                marker=pkg_info.get("markers"),
                source_file=str(lock_path),
                category=DepCategory.PRODUCTION
            ))
    return deps
