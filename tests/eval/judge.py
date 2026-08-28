"""DepSafe 评估判定器（确定性，无 LLM-as-judge）

用法：
    uv run python tests/eval/judge.py <case_dir> [--out <path>]

输入（case_dir 内）：
    case.json                       案例声明（behavior_class / pkg / vulnerable_version / ...）
    .depsafe/checkpoint.json        运行轨迹（messages + budget_state + status/exit_reason）
    .depsafe/sub_trajectories/      SubAgent 轨迹（健康度统计）
    SECURITY_FIX_REPORT.md          安全报告（降级路径证据）
    git 仓库（本地 fix 分支 + 远端，远端状态经 GitHub API 查询）

判定依据：
    OSV 现查（与 Agent 同源，判定时现查，不冻结版本号）
    远端 fix 分支 diff（经 GitHub API 读依赖文件）
    远端 PR/Issue 状态（标签 / draft / 状态）
    回归测试重跑（容器内对 fix 分支执行 unittest）

输出：judgment.json —— 两轴（pipeline 健康 / 决策正确）+ 证据明细。
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, Field

from depsafe.tool.utils.cve_checker import check_cve  # 复用 Agent 同源的 OSV 查询


# ---------------------------------------------------------------- 数据模型


class OsGroundTruth(BaseModel):
    cve_id: str
    min_fixed: str | None
    severity: str | None
    pkg: str = ""
    vulnerable_version: str = ""


def case_pkg_specs(case: dict) -> list[dict]:
    """归一化案例包清单：单包（pkg/vulnerable_version）或多包（pkgs 列表）"""
    if case.get("pkgs"):
        return case["pkgs"]
    return [{"pkg": case["pkg"], "vulnerable_version": case["vulnerable_version"]}]


class Judgment(BaseModel):
    case_name: str = Field(..., description="案例名")
    behavior_class: str = Field(..., description="行为类别")
    pipeline: dict = Field(..., description="轴A pipeline 健康：exit_reason / 步数 / token / 费用 / SubAgent 健康")
    detection_precheck: dict = Field(..., description="检测前置校验：scan 结果 vs OSV ground truth")
    decision: dict = Field(..., description="轴B 决策正确：verdict + 逐条证据")
    evidence: dict = Field(..., description="关键证据：所选版本 / PR / 测试重跑 / 一致性探针")


# ---------------------------------------------------------------- 数据采集


def load_case(case_dir: Path) -> dict:
    case_path = case_dir / "case.json"
    if not case_path.exists():
        raise FileNotFoundError(f"未找到 {case_path}")
    return json.loads(case_path.read_text(encoding="utf-8"))


def load_trajectory(case_dir: Path) -> dict | None:
    ck = case_dir / ".depsafe" / "checkpoint.json"
    if not ck.exists():
        return None
    return json.loads(ck.read_text(encoding="utf-8"))


def extract_scan_vulns(trajectory: dict) -> list[dict]:
    """从轨迹消息中提取 scan_vulns 结果（pkg, cve 列表）"""
    found: list[dict] = []
    for m in trajectory.get("messages", []):
        if m.get("role") != "tool":
            continue
        try:
            content = json.loads(m.get("content", "{}"))
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(content, dict) and isinstance(content.get("vulns"), list):
            found.extend(content["vulns"])
    return found


def osv_ground_truth(specs: list[dict]) -> list[OsGroundTruth]:
    """判定时现查 OSV（与 Agent 同源），得到 ground truth 漏洞集合"""
    out: list[OsGroundTruth] = []
    for spec in specs:
        for v in check_cve(spec["pkg"], spec["vulnerable_version"]):
            out.append(
                OsGroundTruth(
                    cve_id=v.cve_id,
                    min_fixed=v.fixed_ver,
                    severity=v.severity,
                    pkg=spec["pkg"],
                    vulnerable_version=spec["vulnerable_version"],
                )
            )
    return out


def subagent_health(case_dir: Path) -> dict[str, int]:
    """统计 SubAgent 轨迹的退出原因分布"""
    counts: dict[str, int] = {}
    sub_dir = case_dir / ".depsafe" / "sub_trajectories"
    if not sub_dir.exists():
        return counts
    for f in sub_dir.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        reason = d.get("exit_reason") or "unknown"
        counts[reason] = counts.get(reason, 0) + 1
    return counts


def get_case_repo_info(case_dir: Path) -> tuple[str, str]:
    """解析案例目录 git 仓库的 owner/repo（复用 github.py 的 URL 兼容规则）"""
    result = subprocess.run(
        ["git", "-C", str(case_dir), "remote", "get-url", "origin"],
        capture_output=True,
        text=True,
        check=True,
    )
    url = result.stdout.strip()
    ssh_match = re.match(r"git@github\.com:([^/]+)/([^/.]+)(\.git)?$", url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)
    # 兼容 setup_eval_env.sh 写入的内联认证 URL（https://x-access-token:TOKEN@github.com/owner/repo.git）
    https_match = re.match(r"https://(?:[^@/]+@)?github\.com/([^/]+)/([^/.]+)(\.git)?$", url)
    if https_match:
        return https_match.group(1), https_match.group(2)
    raise RuntimeError(f"Cannot parse owner/repo from remote URL: {url}")


def github_api(case_dir: Path) -> tuple[httpx.Client, str, str]:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN 未设置（判定器需查询远端 PR/分支状态）")
    owner, repo = get_case_repo_info(case_dir)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    return httpx.Client(headers=headers, timeout=20), owner, repo


def fetch_remote_state(client: httpx.Client, owner: str, repo: str) -> dict:
    """远端状态：fix 分支、PR、Issue"""
    state: dict[str, Any] = {"branches": [], "prs": [], "issues": []}
    r = client.get(f"https://api.github.com/repos/{owner}/{repo}/branches", params={"per_page": 100})
    if r.status_code == 200:
        state["branches"] = [b["name"] for b in r.json() if b["name"].startswith("fix/security-update-")]
    r = client.get(f"https://api.github.com/repos/{owner}/{repo}/pulls", params={"state": "all", "per_page": 100})
    if r.status_code == 200:
        for p in r.json():
            state["prs"].append(
                {
                    "number": p["number"],
                    "head": p["head"]["ref"],
                    "state": p["state"],
                    "draft": p["draft"],
                    "labels": [l["name"] for l in p.get("labels", [])],
                }
            )
    r = client.get(f"https://api.github.com/repos/{owner}/{repo}/issues", params={"state": "all", "per_page": 100})
    if r.status_code == 200:
        for i in r.json():
            if "pull_request" not in i:  # 排除 PR
                state["issues"].append({"number": i["number"], "title": i.get("title", ""), "state": i["state"]})
    return state


def fetch_branch_dep_file(client: httpx.Client, owner: str, repo: str, branch: str, dep_file: str) -> str | None:
    """经 GitHub API 读取 fix 分支上的依赖文件内容"""
    r = client.get(f"https://api.github.com/repos/{owner}/{repo}/contents/{dep_file}", params={"ref": branch})
    if r.status_code != 200:
        return None
    data = r.json()
    if data.get("encoding") != "base64":
        return None
    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


def parse_pinned_version(content: str, pkg: str) -> str | None:
    m = re.search(rf"^{re.escape(pkg)}==(\S+)$", content, re.MULTILINE)
    return m.group(1) if m else None


def version_tuple(ver: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", ver)[:3])


# ---------------------------------------------------------------- 回归测试重跑


def run_regression_tests(case_dir: Path, branch: str) -> dict:
    """
    在容器内对 fix 分支重跑回归测试（stdlib unittest）。

    实现：git worktree 检出分支 → 挂载进容器 → venv 安装 requirements.txt → unittest discover。
    """
    result: dict = {"ran": False, "passed": False, "output": ""}
    try:
        subprocess.run(
            ["git", "worktree", "add", "--detach", "-q", str(case_dir / "_judge_wt"), branch],
            cwd=case_dir,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        result["output"] = f"worktree 检出失败: {e.stderr.strip()}"
        return result
    worktree = case_dir / "_judge_wt"
    try:
        proxy = os.getenv("DEPSAFE_DOCKER_PROXY")
        proxy_args = (
            ["-e", f"HTTP_PROXY={proxy}", "-e", f"HTTPS_PROXY={proxy}"] if proxy else []
        )
        script = """
set -e
python -m venv /workspace/_jvenv >/dev/null 2>&1
/workspace/_jvenv/bin/pip install -q -r requirements.txt 2>/dev/null
/workspace/_jvenv/bin/python -m unittest discover -v 2>&1
"""
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{worktree}:/workspace",
            "-w", "/workspace",
            *proxy_args,
            "depsafe-runner:latest", "bash", "-c", script,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        result["ran"] = True
        result["passed"] = proc.returncode == 0
        result["output"] = (proc.stdout + proc.stderr)[-2000:]
    except subprocess.TimeoutExpired:
        result["output"] = "回归测试重跑超时（10 分钟）"
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=case_dir, capture_output=True)
        subprocess.run(["git", "worktree", "prune"], cwd=case_dir, capture_output=True)
    return result


def consistency_probe(case_dir: Path, branch: str) -> dict:
    """一致性探针：fix 分支的 requirements.txt 能否被 pip-compile 干净解析"""
    result: dict = {"ran": False, "consistent": False, "output": ""}
    worktree = case_dir / "_judge_wt_probe"
    try:
        subprocess.run(
            ["git", "worktree", "add", "--detach", "-q", str(worktree), branch],
            cwd=case_dir,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        result["output"] = f"worktree 检出失败: {e.stderr.strip()}"
        return result
    try:
        proxy = os.getenv("DEPSAFE_DOCKER_PROXY")
        proxy_args = (["-e", f"HTTP_PROXY={proxy}", "-e", f"HTTPS_PROXY={proxy}"] if proxy else [])
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{worktree}:/workspace",
            "-w", "/workspace",
            *proxy_args,
            "depsafe-runner:latest", "bash", "-c",
            "pip-compile requirements.txt -o /tmp/probe.lock --no-header --no-annotate --quiet 2>&1",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        result["ran"] = True
        result["consistent"] = proc.returncode == 0
        result["output"] = (proc.stdout + proc.stderr)[-500:]
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=case_dir, capture_output=True)
        subprocess.run(["git", "worktree", "prune"], cwd=case_dir, capture_output=True)
    return result


# ---------------------------------------------------------------- 判定规则


def judge(case: dict, trajectory: dict | None, truth: list[OsGroundTruth], remote: dict, case_dir: Path) -> Judgment:
    """执行 §4 判定规则，输出两轴结果与证据"""
    specs = case_pkg_specs(case)
    dep_file = case.get("dep_file", "requirements.txt")
    behavior = case["behavior_class"]
    client, owner, repo = github_api(case_dir)

    # ---- 轴A pipeline 健康 ----
    exit_reason = trajectory.get("exit_reason") if trajectory else "no_trajectory"
    budget = trajectory.get("budget_state", {}) if trajectory else {}
    pipeline = {
        "exit_reason": exit_reason,
        "completed": exit_reason == "Submitted",
        "steps": budget.get("step", {}).get("n_step"),
        "input_tokens": budget.get("token", {}).get("input_token"),
        "cost": budget.get("cost", {}).get("cost"),
        "subagents": subagent_health(case_dir),
    }

    # ---- 检测前置校验 ----
    scan_vulns = extract_scan_vulns(trajectory) if trajectory else []
    scan_set = {(v.get("pkg"), v.get("cve_id")) for v in scan_vulns}
    truth_set = {(t.pkg, t.cve_id) for t in truth}
    recall = len(truth_set & scan_set) / len(truth_set) if truth_set else 1.0
    precision = len(truth_set & scan_set) / len(scan_set) if scan_set else 1.0
    detection_precheck = {
        "osv_ground_truth": [t.model_dump() for t in truth],
        "scanned": sorted(scan_set),
        "recall": recall,
        "precision": precision,
        "passed": recall >= 1.0,
    }

    # ---- 远端证据 ----
    fix_branches = remote["branches"]
    branch_versions: dict[str, dict[str, str | None]] = {}
    for b in fix_branches:
        content = fetch_branch_dep_file(client, owner, repo, b, dep_file)
        branch_versions[b] = {
            spec["pkg"]: parse_pinned_version(content, spec["pkg"]) if content else None for spec in specs
        }
    evidence: dict[str, Any] = {"branch_versions": branch_versions}

    # 覆盖判定：每个 ground truth CVE 是否有分支版本 >= 其最小修复版
    covered_cves: list[dict] = []
    for t in truth:
        best = None
        for b, versions in branch_versions.items():
            bv = versions.get(t.pkg)
            if bv and t.min_fixed and version_tuple(bv) >= version_tuple(t.min_fixed):
                if best is None or version_tuple(bv) < version_tuple(best[1]):
                    best = (b, bv)
        covered_cves.append({"cve_id": t.cve_id, "pkg": t.pkg, "min_fixed": t.min_fixed, "fixed_by": best})
    all_covered = all(c["fixed_by"] is not None for c in covered_cves) and bool(covered_cves)
    evidence["covered_cves"] = covered_cves

    # no_over_major（按 CVE 粒度）：某 CVE 存在同 major 线修复版时，
    # 覆盖它的分支版本不得跨大版本（CVE 自身的最小修复版在大版本时升级大版本是必须的，不算违规）
    over_major_cves: list[str] = []
    if case.get("no_over_major"):
        for c in covered_cves:
            if not c["fixed_by"]:
                continue
            min_fixed = c["min_fixed"]
            if not min_fixed:
                continue
            entry = next(t for t in truth if t.cve_id == c["cve_id"])
            cur_major = version_tuple(entry.vulnerable_version)[0]
            if version_tuple(min_fixed)[0] != cur_major:
                continue  # 修复版本身在大版本，升级大版本是必须的
            if version_tuple(c["fixed_by"][1])[0] > cur_major:
                over_major_cves.append(c["cve_id"])
    evidence["over_major"] = bool(over_major_cves)
    evidence["over_major_cves"] = over_major_cves

    # PR 卫生
    expect_pr = case.get("expect_pr", False)
    prs_for_case = [p for p in remote["prs"] if p["head"] in fix_branches]
    pr_open = [p for p in prs_for_case if p["state"] == "open"]
    pr_ok = False
    if expect_pr:
        pr_ok = any("security" in p["labels"] for p in pr_open)
        if case.get("expect_draft"):
            pr_ok = pr_ok and any(p["draft"] for p in pr_open)
    elif pr_open:
        pr_ok = False  # 不应建 PR 却建了
    else:
        pr_ok = True  # 不应建 PR 且确实没建
    evidence["prs"] = prs_for_case

    # 报告与 Issue
    report_exists = (case_dir / "SECURITY_FIX_REPORT.md").exists()
    issues_mentioning_cve = [
        i for i in remote["issues"] if any(t.cve_id in i["title"] for t in truth)
    ]
    evidence["report_exists"] = report_exists
    evidence["issues"] = issues_mentioning_cve

    # ---- 轴B 决策判定 ----
    verdict = "FAIL"
    reasons: list[str] = []
    if not detection_precheck["passed"]:
        verdict = "detection_fail"
        reasons.append("扫描漏检 ground truth 漏洞，归因于扫描器而非 Agent")
    elif behavior == "clean":
        verdict = "PASS" if (not fix_branches and not pr_open and pipeline["completed"]) else "FAIL"
        if verdict == "FAIL":
            reasons.append("clean 案例应无修复分支/PR 且正常终止")
    elif behavior == "unreachable":
        verdict = "PASS" if (not fix_branches and not pr_open and report_exists) else "FAIL"
        if verdict == "FAIL":
            reasons.append("unreachable 案例应不改代码、不建 PR、仅报告")
    elif behavior == "dependency_hell":
        verdict = "PASS" if (not pr_open and issues_mentioning_cve and report_exists) else "FAIL"
        if verdict == "FAIL":
            reasons.append("dependency_hell 案例应无假成功 PR、有 Issue、有报告")
    else:  # simple_bump / breaking_upgrade / multi_vuln / cascade_*
        if not case.get("must_fix", True):
            # 必须修复类别的降级预期（如修复版本在当前 Python 不可安装）：
            # 不产生假成功 PR、有 Issue、有报告
            verdict = "PASS" if (not pr_open and issues_mentioning_cve and report_exists) else "FAIL"
            if verdict == "FAIL":
                reasons.append("降级预期：应无假成功 PR、有 Issue、有报告")
            return Judgment(
                case_name=case["name"],
                behavior_class=behavior,
                pipeline=pipeline,
                detection_precheck=detection_precheck,
                decision={"verdict": verdict, "reasons": reasons},
                evidence=evidence,
            )
        if not all_covered:
            reasons.append(f"存在未覆盖的 CVE: {[c['cve_id'] for c in covered_cves if c['fixed_by'] is None]}")
        if over_major:
            reasons.append("存在同 major 修复版却跨大版本升级")
        if not pr_ok:
            reasons.append("PR 卫生不达标（应建未建 / 标签缺失 / draft 状态不符 / 不应建却建了）")
        if case.get("has_tests") and (case_dir / "tests").exists():
            covering_branches = [c["fixed_by"][0] for c in covered_cves if c["fixed_by"]]
            tests: dict[str, dict] = {}
            for b in sorted(set(covering_branches)):
                tests[b] = run_regression_tests(case_dir, b)
            evidence["regression_tests"] = tests
            if not any(t["passed"] for t in tests.values()):
                reasons.append("回归测试重跑未通过")
        if behavior.startswith("cascade"):
            probe_target = covering_branches[0] if covering_branches else None
            if probe_target:
                evidence["consistency_probe"] = consistency_probe(case_dir, probe_target)
                if not evidence["consistency_probe"].get("consistent"):
                    reasons.append("一致性探针失败（fix 分支 requirements.txt 无法干净解析）")
        verdict = "PASS" if not reasons else "FAIL"

    decision = {"verdict": verdict, "reasons": reasons}
    return Judgment(
        case_name=case["name"],
        behavior_class=behavior,
        pipeline=pipeline,
        detection_precheck=detection_precheck,
        decision=decision,
        evidence=evidence,
    )


# ---------------------------------------------------------------- CLI


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    case_dir = Path(sys.argv[1]).resolve()
    out_path = Path(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[2] == "--out" else case_dir / "judgment.json"

    case = load_case(case_dir)
    trajectory = load_trajectory(case_dir)
    truth = osv_ground_truth(case_pkg_specs(case))
    client, owner, repo = github_api(case_dir)
    remote = fetch_remote_state(client, owner, repo)
    result = judge(case, trajectory, truth, remote, case_dir)
    out_path.write_text(json.dumps(result.model_dump(), ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
