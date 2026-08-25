from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from depsafe.budget import VulnBudget, Vulnerability
from depsafe.environment.docker import DockerEnvironment
from depsafe.environment.local import LocalEnvironment
from depsafe.exceptions import Submitted

logger = logging.getLogger(__name__)


class ScanVulnsResult(BaseModel):
    """漏洞扫描结果集，所有错误均通过字段结构化返回，不抛出异常"""

    vulns: list[Vulnerability] = Field(default_factory=list, description="成功扫描出的漏洞列表")
    parse_deps_error: str | None = Field(
        None, description="依赖解析(parse_deps)阶段的错误信息。若不为None，说明解析失败，vulns可能为空"
    )
    failed_cves: dict[str, str] = Field(
        default_factory=dict,
        description="CVE查询失败的依赖包及其原因。Key为'pkg==ver'，Value为具体的错误信息(exception_info)",
    )


class VulnerabilityScanner:
    def __init__(self, docker_env: DockerEnvironment, local_env: LocalEnvironment, budget: VulnBudget):
        self.docker_env = docker_env
        self.local_env = local_env
        self.budget = budget

    def scan_vulns(self, dep_file_path: str) -> ScanVulnsResult:
        """
        扫描依赖文件，返回本轮要修复的漏洞，数量控制在 vuln_limit 以内。

        Args:
            dep_file_path: 依赖文件路径，支持 requirements.txt、pyproject.toml、Pipfile 等格式。

        Returns:
            ScanVulnsResult 对象，包含以下字段：
                - vulns: 本轮需要修复的漏洞列表，数量不超过 budget.vuln_limit。
                若所有依赖均已修复且 overflow 为空，则为空列表。
                - parse_deps_error: 依赖解析失败时的错误信息，成功时为 None。
                - failed_cves: CVE 查询失败的依赖包及其原因，Key 为 'pkg==ver'。
        """
        self.budget.reset_found()
        batch = self.budget._consume_overflow()
        if self.budget.exhausted:
            return ScanVulnsResult(vulns=batch)
        logger.info(f"[Docker] 解析依赖: {dep_file_path}")
        try:
            result = self.docker_env.execute({"name": "parse_deps", "arguments": {"file_path": dep_file_path}})
        except Submitted:
            raise
        if result["returncode"] != 0:
            logger.warning(f"parse_deps 失败: {result['exception_info']}")
            return ScanVulnsResult(vulns=batch, parse_deps_error=result["exception_info"])
        failed_cves: dict[str, str] = {}
        for dep in result["output"]:
            if self.budget.exhausted:
                break
            logger.info(f"[Local] 查询 CVE: {dep['pkg']}=={dep['ver']}")
            result = self.local_env.execute({"name": "check_cve", "arguments": {"pkg": dep["pkg"], "ver": dep["ver"]}})
            if result["returncode"] != 0:
                key = f"{dep['pkg']}=={dep['ver']}"
                failed_cves[key] = result["exception_info"]
                logger.warning(f"CVE 查询失败 ({key}): {result['exception_info']}")
                continue
            accepted = self.budget.record(result["output"])
            batch.extend(accepted)
        return ScanVulnsResult(vulns=batch, failed_cves=failed_cves)
