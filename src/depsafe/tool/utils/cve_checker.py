from dotenv import load_dotenv

load_dotenv()

import logging
import os

import httpx
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import ValidationError

from depsafe.budget import Vulnerability

logger = logging.getLogger(__name__)


def _query_osv(pkg: str, ver: str) -> list[Vulnerability]:
    """
    通过 OSV API 查询指定包和版本的已知漏洞。

    Returns:
        漏洞列表。无结果时返回空列表。
    Raises:
        ConnectionError: API 请求失败时抛出，供调用方决定是否降级。
    """
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": pkg, "ecosystem": "PyPI"}, "version": ver}
    try:
        response = httpx.post(url, json=payload, timeout=10.0)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        raise ConnectionError(f"OSV API 查询失败 (pkg={pkg}, ver={ver}): {type(e).__name__}: {e}") from e

    vulnerabilities: list[Vulnerability] = []
    for vuln in data.get("vulns", []):
        cve_id = next((alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")), vuln.get("id"))
        severity = None
        if "severity" in vuln and isinstance(vuln["severity"], list):
            for s in vuln["severity"]:
                if s.get("type") == "CVSS_V3":
                    severity = s.get("score")
                    break
        if not severity and "database_specific" in vuln:
            severity = vuln["database_specific"].get("severity")
        fixed_ver = None
        fixed_versions: list[str] = []
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                if r.get("type") == "ECOSYSTEM":
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])
        if fixed_versions:
            # OSV 记录可能含多条 affected / 多段 range（如 GHSA 与 PYSEC 合并），
            # 取「大于当前版本的最小修复版本」作为该版本的真实修复版本
            try:
                current = Version(ver)
                newer = [v for v in fixed_versions if Version(v) > current]
                fixed_ver = str(min(newer, key=Version)) if newer else str(max(fixed_versions, key=Version))
            except InvalidVersion:
                fixed_ver = fixed_versions[-1]
        desc = vuln.get("summary", "") or vuln.get("details", "")
        try:
            vulnerabilities.append(
                Vulnerability(
                    pkg=pkg,
                    cur_ver=ver,
                    cve_id=cve_id,
                    severity=severity,
                    fixed_ver=fixed_ver,
                    desc=desc,
                )
            )
        except ValidationError as e:
            logger.warning(f"OSV 漏洞数据校验失败 (pkg={pkg}, cve={cve_id}): {e}")
    return vulnerabilities


def _check_github_advisory(pkg: str, ver: str) -> list[Vulnerability]:
    """
    查询 GitHub Advisory Database 获取漏洞信息 (作为 OSV 的 Fallback)

    Args:
        pkg: 依赖包的名称，例如 "requests" 或 "litellm"。
        ver: 依赖包的精确版本号，例如 "2.25.1"。

    Returns:
        包含漏洞信息的 Vulnerability 对象列表。如果该版本没有已知漏洞，
        或者 API 请求失败，则返回空列表。
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise OSError("GITHUB_TOKEN 环境变量未设置，无法查询 GitHub Advisory Database")
    url = "https://api.github.com/graphql"
    headers = {"Authorization": f"Bearer {token}"}
    query = """
    query($pkg: String!) {
      securityVulnerabilities(ecosystem: PIP, package: $pkg, first: 10) {
        nodes {
          advisory {
            ghsaId
            summary
            description
            severity
            identifiers { type value }
          }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
    """
    variables = {"pkg": pkg}
    try:
        response = httpx.post(url, json={"query": query, "variables": variables}, headers=headers, timeout=10.0)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        logger.warning(f"请求 GitHub Advisory API 失败: {e}")
        return []

    vulnerabilities: list[Vulnerability] = []
    nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
    try:
        current_ver = Version(ver)
    except InvalidVersion:
        logger.warning(f"无法解析版本号 '{ver}' (pkg={pkg})，跳过版本范围匹配")
        current_ver = None
    for node in nodes:
        vuln_range_str = node.get("vulnerableVersionRange")
        if vuln_range_str:
            try:
                spec = SpecifierSet(vuln_range_str)
                if current_ver not in spec:
                    continue
            except Exception:
                logger.warning(f"无法解析版本范围 '{vuln_range_str}' (pkg={pkg})，视为受影响")
        advisory = node.get("advisory", {})
        cve_id = next((i["value"] for i in advisory.get("identifiers", []) if i["type"] == "CVE"), None)
        patched = node.get("firstPatchedVersion")
        fixed_ver = patched.get("identifier") if patched else None
        try:
            vulnerabilities.append(
                Vulnerability(
                    pkg=pkg,
                    cur_ver=ver,
                    cve_id=cve_id,
                    severity=advisory.get("severity"),
                    fixed_ver=fixed_ver,
                    desc=advisory.get("summary", ""),
                )
            )
        except ValidationError as e:
            logger.warning(f"GitHub Advisory 数据校验失败 (pkg={pkg}): {e}")
    return vulnerabilities


def check_cve(pkg: str, ver: str) -> list[Vulnerability]:
    """
    查询指定包和版本的已知漏洞。
    优先使用 OSV API，若无结果或请求失败则降级到 GitHub Advisory Database。

    Args:
        pkg: 依赖包的名称，例如 "requests" 或 "litellm"。
        ver: 依赖包的精确版本号，例如 "2.25.1"。

    Returns:
        去重后的漏洞列表。所有数据源均无结果或不可用时返回空列表。
    """
    vulnerabilities: list[Vulnerability] = []
    try:
        vulnerabilities = _query_osv(pkg, ver)
    except ConnectionError as e:
        logger.warning(f"{e}，将降级到 GitHub Advisory")
    if not vulnerabilities:
        logger.info(f"[降级] OSV 未返回有效结果 (pkg={pkg}, ver={ver})，尝试 GitHub Advisory")
        try:
            gh_vulns = _check_github_advisory(pkg, ver)
            vulnerabilities.extend(gh_vulns)
        except Exception as e:
            logger.warning(f"GitHub Advisory 降级查询也失败 (pkg={pkg}, ver={ver}): {type(e).__name__}: {e}")
    seen: set[tuple[str, str]] = set()
    deduped: list[Vulnerability] = []
    for v in vulnerabilities:
        key = (v.pkg, v.cve_id)
        if key not in seen:
            seen.add(key)
            deduped.append(v)
    return deduped
