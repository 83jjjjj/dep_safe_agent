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
import time
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
    traj = json.loads(ck.read_text(encoding="utf-8"))
    # 多轮运行：轮转（每批≤5漏洞一轮）时旧轮次被 archive；按时间序合并早期轮次
    # 消息，保留最新轮次的 exit_reason/budget_state（判定需要跨轮证据：
    # 各轮的 scan / fix / PR 全部计入，不因消息重置而丢失）。
    archives_dir = case_dir / ".depsafe" / "archives"
    if archives_dir.is_dir():
        parts = sorted(archives_dir.glob("checkpoint_*.json"))
        if parts:
            messages: list = []
            for p in parts:
                try:
                    messages += json.loads(p.read_text(encoding="utf-8")).get("messages", [])
                except (json.JSONDecodeError, OSError):
                    continue
            if messages:
                merged = dict(traj)
                merged["messages"] = messages + traj.get("messages", [])
                traj = merged
    return traj


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


def osv_ground_truth(specs: list[dict], target_cves: list[str] | None = None) -> list[OsGroundTruth]:
    """判定时现查 OSV（与 Agent 同源），得到 ground truth 漏洞集合。

    target_cves：案例设计时钉住的目标漏洞集合（case.json 的 target_cves 字段）。
    提供时只保留目标 CVE——OSV 数据会漂移（新增/退订），现查全量会让非设计目标的
    新增 CVE 破坏检测前置校验（假 detection_fail）。缺省 None = 现查全量（向后兼容）。
    """
    out: list[OsGroundTruth] = []
    for spec in specs:
        for v in check_cve(spec["pkg"], spec["vulnerable_version"]):
            if target_cves is not None and v.cve_id not in target_cves:
                continue
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
    """远端状态：fix 分支、PR、Issue。

    失败的调用结果置入 state["fetch_errors"]，绝不静默返回空——空远端会让 judge
    对着"空世界"给出假阴性（曾导致分支/PR 明明存在却判 FAUL）。
    """
    state: dict[str, Any] = {"branches": [], "prs": [], "issues": [], "fetch_errors": []}

    def _get(url: str, params: dict) -> httpx.Response:
        for attempt in range(3):
            try:
                r = client.get(url, params=params)
                if r.status_code == 200:
                    return r
                state["fetch_errors"].append(
                    f"{url.split('/repos/')[-1]} -> {r.status_code} (attempt {attempt + 1})"
                )
            except httpx.HTTPError:
                state["fetch_errors"].append(f"{url.split('/repos/')[-1]} -> HTTPError (attempt {attempt + 1})")
            time.sleep(5 * (attempt + 1))  # 428/429/服务抖动后小退避重试
        return None  # type: ignore[return-value]

    r = _get(f"https://api.github.com/repos/{owner}/{repo}/branches", {"per_page": 100})
    if r and r.status_code == 200:
        state["branches"] = [b["name"] for b in r.json() if b["name"].startswith("fix/security-update-")]
    r = _get(f"https://api.github.com/repos/{owner}/{repo}/pulls", {"state": "all", "per_page": 100})
    if r and r.status_code == 200:
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
    r = _get(f"https://api.github.com/repos/{owner}/{repo}/issues", {"state": "all", "per_page": 100})
    if r and r.status_code == 200:
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
    """从依赖文件内容解析包名==版本。

    兼容两种格式：
    - requirements.txt/Pipfile：`pkg==1.2.3` 行首
    - pyproject.toml dependencies：`    "pkg==1.2.3",`（缩进+引号）
    """
    # pyproject.toml dependencies：`    "pkg==1.2.3",`（缩进+引号+行尾逗号）
    m = re.search(rf'^\s*"{re.escape(pkg)}==([\d.]+)"?,\s*$', content, re.MULTILINE)
    if m:
        return m.group(1)
    # requirements.txt：`pkg==1.2.3` 行首
    m = re.search(rf'^{re.escape(pkg)}==(\S+)$', content, re.MULTILINE)
    if m:
        return m.group(1)
    # Pipfile：[packages] TOML 键值 `wheel = "==0.38.1"` 或 `wheel = "0.38.1"`
    m = re.search(rf'^{re.escape(pkg)}\s*=\s*"?(==?)?([\d.]+)', content, re.MULTILINE)
    return m.group(2) if m else None


def branch_matches_case(branch: str, pkg: str, cve_id: str) -> bool:
    """分支名是否本案例的修复分支：`fix/security-update-<pkg>-<cve>`。

    包名与连字符/下划线视为等价（agent 可能用 typing_extensions / typing-extensions）。
    唯一授权用途：并行安全锚定——同仓库并行时其他案例推的分支不能进入本案例判定。
    """
    prefix = "fix/security-update-"
    stem = branch[len(prefix):] if branch.startswith(prefix) else branch
    norm = lambda s: s.lower().replace("_", "-")  # noqa: E731
    return norm(stem) == f"{norm(pkg)}-{cve_id.lower()}"


def version_tuple(ver: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", ver)[:3])


# ---------------------------------------------------------------- 回归测试重跑


def _case_remote_url(case_dir: Path) -> str:
    """获取案例 git 仓库的 origin URL（含内联 token，供容器内 clone 使用）"""
    r = subprocess.run(
        ["git", "-C", str(case_dir), "remote", "get-url", "origin"],
        capture_output=True, text=True, check=True,
    )
    return r.stdout.strip()


def run_regression_tests(case_dir: Path, branch: str, dep_file: str = "requirements.txt") -> dict:
    """
    在容器内对 fix 分支重跑回归测试（stdlib unittest）。

    实现：容器内 git clone 远端分支 → venv 安装依赖（按 dep_file 类型）→ unittest discover。
    全部发生在容器内，不污染宿主持有的 case_dir（避免 root 属主残留与 worktree 权限问题）。
    """
    result: dict = {"ran": False, "passed": False, "output": ""}
    remote_url = _case_remote_url(case_dir)
    proxy = os.getenv("DEPSAFE_DOCKER_PROXY")
    proxy_args = ["-e", f"HTTP_PROXY={proxy}", "-e", f"HTTPS_PROXY={proxy}"] if proxy else []
    if dep_file == "pyproject.toml":
        # 不用 --no-build-isolation：venv 里没有 setuptools.build_meta，隔离构建反而会装
        install_cmd = "/tmp/jvenv/bin/pip install -q -e . 2>/dev/null"
        test_py = "/tmp/jvenv/bin/python"
    elif dep_file == "Pipfile":
        # pipenv 按 Pipfile.lock 安装（镜像已含 pipenv）；--ignore-pipfile 锁定版本确定性
        install_cmd = "cd /tmp/wt && PIPENV_VENV_IN_PROJECT=1 pipenv install --ignore-pipfile >/dev/null 2>&1"
        test_py = "/tmp/wt/.venv/bin/python"
    else:
        install_cmd = f"/tmp/jvenv/bin/pip install -q -r {dep_file} 2>/dev/null"
        test_py = "/tmp/jvenv/bin/python"
    script = f"""
set -e
rm -rf /tmp/wt /tmp/jvenv
git -c credential.helper= clone -q --depth 1 -b {branch} '{remote_url}' /tmp/wt
cd /tmp/wt
python -m venv /tmp/jvenv >/dev/null 2>&1
{install_cmd}
# 分支无 tests 目录（如陈旧基座、或本就没测试）：不算回归失败，输出标记供 judge 识别
if [ ! -d tests ]; then
    echo RUN_REGRESSION_SKIP_NO_TESTS_DIR
    exit 0
fi
{test_py} -m unittest discover -s tests -v 2>&1
"""
    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", *proxy_args, "depsafe-runner:latest", "bash", "-c", script],
            capture_output=True, text=True, timeout=900,
        )
        result["ran"] = True
        result["passed"] = proc.returncode == 0
        result["output"] = (proc.stdout + proc.stderr)[-2000:]
    except subprocess.TimeoutExpired:
        result["output"] = "回归测试重跑超时（15 分钟）"
    except Exception as e:
        result["output"] = f"回归测试重跑失败: {type(e).__name__}: {e}"
    return result


def consistency_probe(case_dir: Path, branch: str) -> dict:
    """一致性探针：fix 分支的依赖文件能否被 pip-compile 干净解析（容器内 clone 实现，同 regression）"""
    result: dict = {"ran": False, "consistent": False, "output": ""}
    remote_url = _case_remote_url(case_dir)
    proxy = os.getenv("DEPSAFE_DOCKER_PROXY")
    proxy_args = ["-e", f"HTTP_PROXY={proxy}", "-e", f"HTTPS_PROXY={proxy}"] if proxy else []
    script = f"""
set -e
rm -rf /tmp/wt
git -c credential.helper= clone -q --depth 1 -b {branch} '{remote_url}' /tmp/wt
cd /tmp/wt
pip-compile requirements.txt -o /tmp/probe.lock --no-header --no-annotate --quiet 2>&1
"""
    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", *proxy_args, "depsafe-runner:latest", "bash", "-c", script],
            capture_output=True, text=True, timeout=900,
        )
        result["ran"] = True
        result["consistent"] = proc.returncode == 0
        result["output"] = (proc.stdout + proc.stderr)[-500:]
    except subprocess.TimeoutExpired:
        result["output"] = "一致性探针超时（15 分钟）"
    except Exception as e:
        result["output"] = f"一致性探针失败: {type(e).__name__}: {e}"
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

    # ---- 并行安全锚定：只认本案例真相 (pkg, cve) 对应的修复分支 ----
    # 判定器按包名扫全部分支（聚合视图），同仓库并行时其他案例（含同包案例）推的
    # 分支若混入，覆盖/PR/回归/漏修判定都会被污染（假阳性）。锚定后与案例无关的分支
    # 天然排除；顺序跑时本案例自己的分支名恰好匹配，行为不变。
    evidence: dict[str, Any] = {}
    anchor_pairs = {(t.pkg, t.cve_id) for t in truth}
    match_branch = lambda b: any(branch_matches_case(b, p, c) for p, c in anchor_pairs)  # noqa: E731
    # 轨迹锚定：同一 (pkg, cve) 可能是不同案例的共享目标（如 pydantic-CVE-2024-3772 同时是
    # pydantic-cve 与 h11-pydantic 的目标）——远端同名分支只能算本案例自己创建的。
    # 只认「实际推送/PR 事件」中的分支名（fixer 结果 branch_name、create_github_pr 的 head_branch、
    # bash 命令里的 git push），不认文本提及——避免模型表述污染锚定集。
    traj_branches: set[str] = set()
    if trajectory:
        for m in trajectory.get("messages", []):
            content = m.get("content")
            if isinstance(content, str):
                try:
                    c = json.loads(content)
                except (json.JSONDecodeError, TypeError):
                    c = None
                if isinstance(c, dict) and c.get("branch_name"):
                    traj_branches.add(c["branch_name"])
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function", {})
                if fn.get("name") == "create_github_pr":
                    try:
                        args = json.loads(fn.get("arguments") or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    if args.get("head_branch"):
                        traj_branches.add(args["head_branch"])
                elif fn.get("name") == "bash":
                    try:
                        args = json.loads(fn.get("arguments") or "{}")
                        cmd = str(args.get("command", ""))
                    except json.JSONDecodeError:
                        cmd = ""
                    for mm in re.findall(r"git\s+push\b[^\n]*?(fix/security-update-[A-Za-z0-9_.-]+)", cmd):
                        traj_branches.add(mm)
    evidence["traj_branches"] = sorted(traj_branches)
    def _owned(branch: str) -> bool:  # noqa: E731
        return match_branch(branch) and (not traj_branches or branch in traj_branches)
    # PR 的 head 分支可能不在 branches 列表（GitHub 接口一致性抖动，见 flask-2.3.2 PR#13），
    # 但 contents API 按 ref 仍可读取 —— 一并纳入候选，避免"PR 存在但认不到分支"的误判
    pr_heads = [p["head"] for p in remote["prs"] if _owned(p["head"])]
    fix_branches = list(dict.fromkeys([b for b in remote["branches"] if _owned(b)] + pr_heads))
    evidence["anchored_branches"] = fix_branches
    evidence["pr_head_branches"] = pr_heads

    # ---- 远端证据（按 ref 拉取每个锚定分支的依赖文件）----
    branch_versions: dict[str, dict[str, str | None]] = {}
    for b in fix_branches:
        content = fetch_branch_dep_file(client, owner, repo, b, dep_file)
        branch_versions[b] = {
            spec["pkg"]: parse_pinned_version(content, spec["pkg"]) if content else None for spec in specs
        }
    evidence["branch_versions"] = branch_versions
    anchored_versions = dict(branch_versions)

    # 覆盖判定：每个 ground truth CVE 是否有分支版本 >= 其最小修复版
    covered_cves: list[dict] = []
    for t in truth:
        best = None
        for b, versions in anchored_versions.items():
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
    over_major = bool(over_major_cves)
    evidence["over_major"] = over_major
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
        # covering_branches 需在 cascade 探针前定义（has_tests 不存在时也要有值）
        covering_branches = [c["fixed_by"][0] for c in covered_cves if c["fixed_by"]]
        if case.get("has_tests") and (case_dir / "tests").exists():
            tests: dict[str, dict] = {}
            for b in sorted(set(covering_branches)):
                reg = run_regression_tests(case_dir, b, dep_file)
                if "RUN_REGRESSION_SKIP_NO_TESTS_DIR" in reg.get("output", ""):
                    reg["skipped"] = True  # 分支无 tests 目录：不判回归失败
                tests[b] = reg
            evidence["regression_tests"] = tests
            if tests and not any(t.get("passed") for t in tests.values()):
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
    truth = osv_ground_truth(case_pkg_specs(case), case.get("target_cves"))
    client, owner, repo = github_api(case_dir)
    remote = fetch_remote_state(client, owner, repo)
    result = judge(case, trajectory, truth, remote, case_dir)
    out_path.write_text(json.dumps(result.model_dump(), ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
