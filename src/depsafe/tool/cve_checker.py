
from dotenv import load_dotenv

load_dotenv()

import os
import httpx
from typing import List, Optional
from packaging.version import Version
from packaging.specifiers import SpecifierSet
from pydantic import BaseModel, Field, ValidationError, ConfigDict


class Vulnerability(BaseModel):
    model_config = ConfigDict(frozen=True) # 开启基于字段值的去重和哈希
    pkg_name: str = Field(..., description="依赖包的名称")
    cve_id: str = Field(..., description="漏洞的 CVE 编号")
    severity: Optional[str] = Field(None, description="严重程度")
    fixed_ver: Optional[str] = Field(None, description="修复该漏洞的版本")
    desc: str = Field("", description="漏洞描述")


def check_cve(pkg: str, ver: str) -> List[Vulnerability]:
    """
    查询指定包和版本的已知漏洞

    Args:
        pkg: 依赖包的名称，例如 "requests" 或 "litellm"。
        ver: 依赖包的精确版本号，例如 "2.25.1"。

    Returns:
        包含漏洞信息的 Vulnerability 对象列表。如果该版本没有已知漏洞，
        或者 API 请求失败，则返回空列表。    
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": pkg,
            "ecosystem": "PyPI"
        },
        "version": ver
    }
    try:
        response = httpx.post(url, json=payload, timeout=10.0)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"请求 OSV API 失败: {e}")
        return []
    vulnerabilities = []
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
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                if r.get("type") == "ECOSYSTEM":
                    events = r.get("events", [])
                    for event in events:
                        if "fixed" in event:
                            fixed_ver = event["fixed"]
                            break
        desc = vuln.get("summary", "") or vuln.get("details", "")
        try:
            vulnerabilities.append(Vulnerability(
                pkg_name=pkg,
                cve_id=cve_id,
                severity=severity,
                fixed_ver=fixed_ver,
                desc=desc
            ))
        except ValidationError as e:
            print(f"数据模型校验失败: {e}")
    return list(set(vulnerabilities))

def check_github_advisory(pkg: str, ver: str) -> List[Vulnerability]:
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
        print("未找到 GITHUB_TOKEN，跳过 GitHub Advisory 查询")
        return []
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
        print(f"请求 GitHub Advisory API 失败: {e}")
        return []
    vulnerabilities = []
    nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
    current_ver = Version(ver)
    for node in nodes:
        vuln_range_str = node.get("vulnerableVersionRange")
        if vuln_range_str:
            try:
                # 跳过不受影响版本规则集合
                spec = SpecifierSet(vuln_range_str)
                if current_ver not in spec:
                    continue
            except Exception:
                pass
        advisory = node.get("advisory", {})
        cve_id = next((i["value"] for i in advisory.get("identifiers", []) if i["type"] == "CVE"), None)
        patched = node.get("firstPatchedVersion")
        fixed_ver = patched.get("identifier") if patched else None
        try:
            vulnerabilities.append(Vulnerability(
                pkg_name=pkg,
                cve_id=cve_id,
                severity=advisory.get("severity"),
                fixed_ver=fixed_ver,
                desc=advisory.get("summary", "")
            ))
        except ValidationError as e:
            print(f"GitHub 数据模型校验失败: {e}")
    return vulnerabilities

if __name__ == "__main__":
    results = check_github_advisory("requests", "2.25.1")
    json_output = [vuln.model_dump(mode="json") for vuln in results]
    print(json_output)
