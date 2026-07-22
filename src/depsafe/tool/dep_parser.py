
import tomllib
from enum import Enum
from pathlib import Path
from pydantic import BaseModel
from typing import List, Optional
from packaging.requirements import Requirement

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


def parse_deps(file_path: str) -> List[Dependency]:
    """
    统一读取项目依赖文件并返回依赖列表

    Args:
        file_path: 包含 requirements.txt / pyproject.toml / Pipfile 中的一种的文件路径。

    Returns:
        项目依赖包列表，仅限生产环境。
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    file_name = path.name
    deps = []
    if file_name in ["requirements.txt", "requirements.in"]:
        for line in path.read_text().splitlines():
            if dep := _parse_requirement_line(line, "requirements.txt", DepCategory.PRODUCTION):
                deps.append(dep)
        return deps
    elif file_name == "pyproject.toml":
        with open(path, "rb") as f:
            data = tomllib.load(f)
        raw_deps = data.get("project", {}).get("dependencies", [])
        for dep_str in raw_deps:
            if dep := _parse_requirement_line(dep_str, "pyproject.toml", DepCategory.PRODUCTION):
                deps.append(dep)
        return deps
    elif file_name == "Pipfile":
        with open(path, "rb") as f:
            data = tomllib.load(f)
        for pkg_name, pkg_spec in data.get("packages", {}).items():
            version = pkg_spec if isinstance(pkg_spec, str) else pkg_spec.get("version", "*")
            line = f"{pkg_name}{version}" if version != "*" else pkg_name
            if dep := _parse_requirement_line(line, "Pipfile", DepCategory.PRODUCTION):
                deps.append(dep)
        return deps
    return deps

def _parse_requirement_line(line: str, source_file: str, category: DepCategory = DepCategory.PRODUCTION) -> Optional[Dependency]:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    try:
        req = Requirement(line)
        return Dependency(
            name=req.name,
            version_spec=str(req.specifier) if req.specifier else "*",
            category=category,
            marker=str(req.marker) if req.marker else None,
            source_file=source_file
        )
    except Exception as e:
        print(f"解析失败: {line}, 错误: {e}")
        return None
