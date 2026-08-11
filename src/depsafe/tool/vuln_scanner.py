from __future__ import annotations

import logging

from depsafe.docker import DockerEnvironment
from depsafe.environment import LocalEnvironment
from depsafe.tool.utils.cve_checker import Vulnerability, check_cve
from depsafe.tool.utils.dep_parser import parse_deps

logger = logging.getLogger(__name__)


class VulnBudget:
    def __init__(self, vuln_limit: int = 5):
        self.vuln_limit = vuln_limit  # 一轮循环扫描漏洞上限
        self.found = 0
        self.overflow: list[Vulnerability] = []
        self.covered: set[tuple[str, str]] = set()  # (pkg, cve_id)

    def mark_covered(self, vulns: list[Vulnerability]):
        """修复完成后调用，将漏洞标记为已解决"""
        for v in vulns:
            self.covered.add((v.pkg, v.cve_id))

    def filter_covered(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """过滤掉已修复的漏洞"""
        return [v for v in vulns if (v.pkg, v.cve_id) not in self.covered]

    def _consume_overflow(self) -> list[Vulnerability]:
        """从 overflow 中取出本轮份额"""
        batch = self.overflow[: self.vuln_limit]
        self.overflow = self.overflow[self.vuln_limit :]
        self.found = len(batch)
        return batch

    def record(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """供 scanner 遍历依赖时逐个调用"""
        vulns = self.filter_covered(vulns)
        remaining = self.vuln_limit - self.found
        if remaining <= 0:
            self.overflow.extend(vulns)
            return []
        if len(vulns) <= remaining:
            self.found += len(vulns)
            return vulns
        else:
            accepted = vulns[:remaining]
            self.overflow.extend(vulns[remaining:])
            self.found = self.vuln_limit
            return accepted

    @property
    def exhausted(self) -> bool:
        return self.found >= self.vuln_limit

    def reset_found(self):
        self.found = 0

    def is_all_done(self):
        """没有找到更多的漏洞"""
        return self.found == 0 and len(self.overflow) == 0

    def to_dict(self) -> dict:
        return {
            "vuln_limit": self.vuln_limit,
            "found": self.found,
            "covered": [list(pair) for pair in self.covered],  # set→list
            "overflow": [{"pkg": v.pkg, "cve_id": v.cve_id, "ver": v.ver} for v in self.overflow],
        }

    @classmethod
    def from_dict(cls, data: dict) -> VulnBudget:
        budget = cls(vuln_limit=data["vuln_limit"])
        budget.found = data["found"]
        budget.covered = {tuple(pair) for pair in data["covered"]}  # list→set
        budget.overflow = [
            Vulnerability(pkg_name=v["pkg"], cve_id=v["cve_id"], ver=v["ver"]) for v in data.get("overflow", [])
        ]
        return budget


class VulnerabilityScanner:
    def __init__(self, docker_env: DockerEnvironment, local_env: LocalEnvironment, budget: VulnBudget):
        self.docker_env = docker_env
        self.local_env = local_env
        self.budget = budget

    def scan_vulns(self, dep_file_path: str) -> list[Vulnerability]:
        """
        扫描依赖文件，返回本轮要修复的漏洞，数量控制在 vuln_limit 以内。

        Args:
            dep_file_path: 依赖文件路径，支持 requirements.txt、
                pyproject.toml、Pipfile 等格式。

        Returns:
            本轮需要修复的漏洞列表，数量不超过 budget.vuln_limit。
            若所有依赖均已修复且 overflow 为空，则返回空列表。
        """
        self.budget.reset_found()
        batch = self.budget._consume_overflow()
        if self.budget.exhausted:
            return batch
        logger.info(f"[Docker] 解析依赖: {dep_file_path}")
        dependencies = self.docker_env.execute({"name": "parse_deps", "arguments": {"dep_file_path": dep_file_path}})
        # 处理parse deps的错误？
        for dep in dependencies:
            if self.budget.exhausted:
                break
            logger.info(f"[Local] 查询 CVE: {dep['pkg']}=={dep['ver']}")
            vulns = self.local_env.execute({
                "name": "check_cve",
                "arguments": {"pkg": dep["pkg"], "ver": dep["ver"]}
            })
            # 处理check cve的错误？
            accepted = self.budget.record(vulns)
            batch.extend(accepted)
        return batch
