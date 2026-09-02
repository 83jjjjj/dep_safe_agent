#!/usr/bin/env python3
"""DepSafe 评估运行器：自动化每个案例的完整评估生命周期。

用法：
    uv run python tests/eval/run_eval.py [--cases NAME,...] [--repeat N] [--keep-prs] [--remote owner/repo]

生命周期（每案例 × 每 repeat）：
    1. 清理本地（root 属主文件经容器删）
    2. setup_eval_env.sh 绑定沙箱（git init + 强推模板 main + 推 fixtures/<case> 预置分支）
    3. 在案例目录执行 `uv run depsafe`
    4. 采集轨迹副本（checkpoint + sub_trajectories）与日志
    5. 判定（judge.py，确定性）
    6. 远端默认保留（PR/修复分支即评估记录，人工审核合并）；--clean 才清场

产物（全部保留，不删除）：
    tests/eval/results/<case>_<ts>/judgment.json   判定结果（期望 vs 实际 + 证据）
    tests/eval/trajectories/<case>_<ts>/           轨迹副本（可回放）
    tests/eval/logs/<case>_<ts>.log                完整运行日志
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
EVAL_DIR = REPO_ROOT / "tests" / "eval"
RESULTS = EVAL_DIR / "results"
TRAJECTORIES = EVAL_DIR / "trajectories"
LOGS = EVAL_DIR / "logs"
IMAGE = "depsafe-runner:latest"

sys.path.insert(0, str(EVAL_DIR))
from judge import (  # noqa: E402
    case_pkg_specs,
    fetch_remote_state,
    judge as judge_fn,
    load_case,
    load_trajectory,
    osv_ground_truth,
)

# 加载 .env（GITHUB_TOKEN / DEEPSEEK_API_KEY / DEPSAFE_DOCKER_PROXY 等），
# 子进程 uv run depsafe 也继承此环境
from dotenv import load_dotenv

load_dotenv(REPO_ROOT / ".env")

# 宿主侧 git 操作也走代理（github.com 直连不稳定）；与容器同源
if _proxy := os.getenv("DEPSAFE_DOCKER_PROXY"):
    os.environ["HTTP_PROXY"] = os.environ["http_proxy"] = _proxy
    os.environ["HTTPS_PROXY"] = os.environ["https_proxy"] = _proxy
RUNTIME_ARTIFACTS = [
    ".git", ".depsafe", ".agent_runner.py", ".venv-fix-verify",
    "requirements.lock", "SECURITY_FIX_REPORT.md", "judgment.json",
    "uv.lock", "*.egg-info",
]

# 并行调度状态：RUNNING_PKGS 记录正在运行案例的真相包集合（同包互斥）；
# SETUP_LOCK 保护 setup 对 main 的快进推送（并发 setup 基于同一 base 提交会互相非快进拒绝）
RUNNING_PKGS: list[set[str]] = []
PKG_COND = threading.Condition()
SETUP_LOCK = threading.Lock()


def discover_cases(names: list[str] | None) -> list[Path]:
    """按行为类别一级目录发现案例（含 case.json 的二级目录）"""
    cases = sorted(p for p in FIXTURES.glob("*/*/case.json") if p.parent.name != "__pycache__")
    if names:
        wanted = set(names)
        cases = [p for p in cases if p.parent.name in wanted]
        missing = wanted - {p.parent.name for p in cases}
        if missing:
            print(f"⚠️ 未找到案例: {sorted(missing)}")
    return [p.parent for p in cases]


def case_pkgs(case_dir: Path) -> set[str]:
    """案例的真相包集合（多包案例取全部包）。

    同包案例不能并行：判定器按包名扫全部分支（聚合视图），同包并行会互相污染
    判定（先推完的案例会把修复分支落入后跑案例的增量窗口）。
    """
    return {spec["pkg"] for spec in case_pkg_specs(load_case(case_dir))}


def acquire_pkg_slot(pkgs: set[str]) -> None:
    """占用包集合：等待直到仓库中没有任何同包案例在运行"""
    with PKG_COND:
        while any(pkgs & rp for rp in RUNNING_PKGS):
            PKG_COND.wait()
        RUNNING_PKGS.append(set(pkgs))


def release_pkg_slot(pkgs: set[str]) -> None:
    with PKG_COND:
        RUNNING_PKGS.remove(set(pkgs))
        PKG_COND.notify_all()


def container_cleanup(case_dir: Path) -> None:
    """用 root 容器删除运行时产物（处理容器产生的 root 属主文件，含嵌套 __pycache__）"""
    targets = " ".join(RUNTIME_ARTIFACTS)
    # 先还原跟踪文件到 main（agent 可能把工作区留在修复分支/脏状态），再删 .git 等运行时产物。
    # 注意不能用 git clean -x：case.json 在沙箱中未跟踪（git rm --cached），clean 会误删案例定义。
    script = (
        "git -c safe.directory=/workspace -C /workspace checkout -f main 2>/dev/null; "
        f"rm -rf {targets}; "
        "find /workspace \\( -name __pycache__ -o -name '*.egg-info' -o -name '*.dist-info' \\) "
        "-type d -exec rm -rf {} + 2>/dev/null; "
        # 容器 root 属主的残留文件（tests/ 等被容器写过的），宿主无法删、也让下次 setup 的 cp 失败
        "find /workspace -user root -depth -exec rm -rf {} + 2>/dev/null || true"
    )
    subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "-v", f"{case_dir}:/workspace", "-w", "/workspace",
         IMAGE, "bash", "-c", script],
        capture_output=True, text=True, timeout=120,
    )


def github_client() -> tuple[httpx.Client, str, str]:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN 未设置（远程清理与判定需要）")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    return httpx.Client(headers=headers, timeout=20), headers


def remote_cleanup(client: httpx.Client, remote: str) -> dict:
    """关闭沙箱全部 open PR、删除全部 fix 分支，恢复干净靶场"""
    owner, repo = remote.split("/")
    summary = {"closed_prs": [], "deleted_branches": []}
    r = client.get(f"https://api.github.com/repos/{owner}/{repo}/pulls", params={"state": "open", "per_page": 100})
    for p in r.json() if r.status_code == 200 else []:
        client.patch(f"https://api.github.com/repos/{owner}/{repo}/pulls/{p['number']}", json={"state": "closed"})
        summary["closed_prs"].append(p["number"])
    r = client.get(f"https://api.github.com/repos/{owner}/{repo}/branches", params={"per_page": 100})
    for b in r.json() if r.status_code == 200 else []:
        if b["name"].startswith("fix/security-update-"):
            client.delete(f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{b['name']}")
            summary["deleted_branches"].append(b["name"])
    return summary


def setup_case(case_dir: Path, remote: str) -> None:
    """绑定案例到沙箱仓库（复用 setup_eval_env.sh 逻辑），并推 fixtures/<case> 预置分支

    - main：当前评估案例的样本（强推，需 ruleset bypass 放行）
    - fixtures/<case>：该案例样本的持久分支（沙箱即 fixtures 的正式存放处）
    """
    env = dict(os.environ)
    proc = subprocess.run(
        ["bash", str(FIXTURES / "setup_eval_env.sh"), str(case_dir), remote],
        capture_output=True, text=True, timeout=300, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"setup 失败: {proc.stdout[-300:]} {proc.stderr[-300:]}")
    fixture_branch = f"fixtures/{case_dir.name}"
    proc = subprocess.run(
        ["git", "-c", "credential.helper=", "push", "origin", f"main:refs/heads/{fixture_branch}", "--force"],
        cwd=case_dir, capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"推送 {fixture_branch} 失败: {proc.stderr[-300:]}")


def restore_template(case_dir: Path, remote: str) -> None:
    """setup 前用沙箱模板分支重建案例目录——绝不信任目录遗留状态。

    背景（曾导致夹具损坏与分支持久污染）：
    - 容器内 git 操作以 root 写入，运行时模板文件变为 root 属主；container_cleanup
      会删除 root 属主文件 → 目录残缺；
    - 若 setup 在残缺目录上执行，归档内容被写入 main 与 fixtures/<case>（分支持久污染）；
    - 若目录残留的是 agent 修复后的文件（checkout 残留），同理会被推上模板分支。
    因此每次 setup 前都从 fixtures/<case> 重建文件树（首次运行分支不存在 → 跳过，
    以手工准备的目录为模板）。
    """
    name = case_dir.name
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN 未设置，无法恢复模板")
    url = f"https://x-access-token:{token}@github.com/{remote}.git"
    tmp = Path(tempfile.mkdtemp(prefix="depsafe-restore-"))
    repo = tmp / "repo"
    try:
        proc = subprocess.run(
            ["git", "-c", "credential.helper=", "clone", "-q", "--depth", "1", "-b", f"fixtures/{name}", url, str(repo)],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0:
            print(f"  ℹ️ 模板分支 fixtures/{name} 不存在（首次运行？），沿用当前目录: "
                  f"{proc.stderr.strip()[:120]}")
            return
        # case.json 在沙箱未跟踪（仅本地），先备份再删目录
        cj = case_dir / "case.json"
        saved = cj.read_bytes() if cj.exists() else None
        # 容器（root）清空目录，避免 root 属主残留影响宿主覆盖
        subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "-v", f"{case_dir}:/workspace", IMAGE,
             "bash", "-c", "find /workspace -mindepth 1 -maxdepth 1 -exec rm -rf {} +"],
            capture_output=True, text=True, timeout=180,
        )
        shutil.copytree(repo, case_dir, dirs_exist_ok=True)
        # .git 由 setup_eval_env.sh 按链式历史重新 init，先移除外来浅克隆的 .git
        shutil.rmtree(case_dir / ".git", ignore_errors=True)
        if saved is not None:
            cj.write_bytes(saved)
        print(f"  ✔ 模板恢复: fixtures/{name}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_agent(case_dir: Path, log_file: Path) -> dict:
    """在案例目录执行 uv run depsafe，返回运行统计

    注意：--project 显式指向主仓库——案例目录自带的 pyproject.toml 会让 uv
    把案例目录当成项目（depsafe 命令不存在），必须绕开。
    """
    start = time.time()
    with open(log_file, "w", encoding="utf-8") as f:
        proc = subprocess.run(
            ["uv", "run", "--project", str(REPO_ROOT), "depsafe"],
            cwd=case_dir, stdout=f, stderr=subprocess.STDOUT, timeout=3600,
        )
    duration = time.time() - start
    checkpoint = case_dir / ".depsafe" / "checkpoint.json"
    exit_reason = None
    if checkpoint.exists():
        try:
            exit_reason = json.loads(checkpoint.read_text(encoding="utf-8")).get("exit_reason")
        except (json.JSONDecodeError, OSError):
            pass
    return {"returncode": proc.returncode, "duration_s": round(duration, 1), "exit_reason": exit_reason}


def collect_trajectory(case_dir: Path, ts_dir: Path) -> None:
    for sub in ["checkpoint.json", "sub_trajectories", "archives"]:
        src = case_dir / ".depsafe" / sub
        if src.exists():
            dst = ts_dir / sub
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)


def run_case(case_dir: Path, remote: str, clean: bool, ts: str) -> dict:
    """单案例完整生命周期"""
    name = case_dir.parent.name + "/" + case_dir.name
    print(f"\n{'=' * 60}\n▶ {name}")
    out: dict = {"case": name, "ts": ts}

    # 1a. 模板恢复（每次 setup 前强制从 fixtures/<case> 重建，杜绝目录遗留污染）
    print("  恢复模板（fixtures 分支）...")
    restore_template(case_dir, remote)
    # 1. 清理本地
    print("  清理本地...")
    container_cleanup(case_dir)
    client, _ = github_client()

    # 2. 绑定沙箱（默认不清远端：PR/修复分支即评估记录）
    print("  绑定沙箱（setup_eval_env.sh + fixtures 分支）...")
    # setup 快进推 main：全局互斥，并行下并发 setup 会基于同一 base 提交、后者非快进被拒
    with SETUP_LOCK:
        setup_case(case_dir, remote)

        # 4. 运行（前先快照远端状态，判定时只统计本次运行新增的分支/PR，隔离历史案例的遗留记录）
        pre_state = fetch_remote_state(client, *remote.split("/"))
    log_file = LOGS / f"{case_dir.name}_{ts}.log"
    LOGS.mkdir(parents=True, exist_ok=True)
    print("  运行 uv run depsafe ...")
    run_stats = run_agent(case_dir, log_file)
    out["run"] = run_stats
    print(f"  → returncode={run_stats['returncode']} exit_reason={run_stats['exit_reason']} 用时 {run_stats['duration_s']}s")

    # 5. 采集轨迹
    ts_dir = TRAJECTORIES / f"{case_dir.name}_{ts}"
    collect_trajectory(case_dir, ts_dir)
    out["trajectory"] = str(ts_dir.relative_to(REPO_ROOT))

    # 6. 判定（远端状态只取本次运行新增的分支/PR）
    print("  判定（judge.py）...")
    case = load_case(case_dir)
    truth = osv_ground_truth(case_pkg_specs(case), case.get("target_cves"))
    traj = load_trajectory(case_dir)
    post_state = fetch_remote_state(client, *remote.split("/"))
    pre_branches = set(pre_state["branches"])
    pre_prs = {p["number"] for p in pre_state["prs"]}
    pre_issues = {i["number"] for i in pre_state["issues"]}
    remote_state = {
        "branches": [b for b in post_state["branches"] if b not in pre_branches],
        "prs": [p for p in post_state["prs"] if p["number"] not in pre_prs],
        "issues": [i for i in post_state["issues"] if i["number"] not in pre_issues],
    }
    out["remote_delta"] = remote_state
    judgment = judge_fn(case, traj, truth, remote_state, case_dir)
    out["judgment"] = judgment.model_dump()

    result_dir = RESULTS / f"{case_dir.name}_{ts}"
    result_dir.mkdir(parents=True, exist_ok=True)
    (result_dir / "judgment.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    verdict = out["judgment"]["decision"]["verdict"]
    pipeline_ok = out["judgment"]["pipeline"]["completed"]
    print(f"  → 判定: {verdict}（pipeline: {out['judgment']['pipeline']['exit_reason']}）")

    # 7. 清场（仅 --clean）
    if clean:
        print("  清场远端...")
        out["remote_postclean"] = remote_cleanup(client, remote)
    print("  清理本地...")
    container_cleanup(case_dir)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="DepSafe 评估运行器")
    parser.add_argument("--cases", help="逗号分隔的案例名（默认全部）")
    parser.add_argument("--repeat", type=int, default=1, help="每案例重复次数（默认 1）")
    parser.add_argument("--parallel", type=int, default=1, help="并行案例数（>1 时同包案例自动互斥串行）")
    parser.add_argument("--clean", action="store_true", help="判定后清场远端（默认保留 PR/分支作为评估记录）")
    parser.add_argument("--remote", default="83jjjjj/depsafe_eval_sandbox", help="沙箱仓库 owner/repo")
    args = parser.parse_args()

    case_dirs = discover_cases(args.cases.split(",") if args.cases else None)
    if not case_dirs:
        print("❌ 没有可评估的案例")
        return 1
    print(f"发现 {len(case_dirs)} 个案例 × {args.repeat} repeat")

    all_results: list[dict] = []
    if args.parallel > 1:
        # 并行：泳道内按包互斥（acquire_pkg_slot）；setup 推 main 已全局互斥（SETUP_LOCK）
        order = [cd for cd in case_dirs for _ in range(args.repeat)]
        results: list[dict | None] = [None] * len(order)
        out_lock = threading.Lock()

        def worker(idx: int, case_dir: Path) -> None:
            ts = time.strftime("%Y%m%d_%H%M%S")
            try:
                pkgs = case_pkgs(case_dir)
                acquire_pkg_slot(pkgs)
                try:
                    r = run_case(case_dir, args.remote, args.clean, ts)
                finally:
                    release_pkg_slot(pkgs)
            except Exception as e:
                print(f"❌ {case_dir.name} 运行失败: {type(e).__name__}: {e}")
                r = {"case": str(case_dir), "error": f"{type(e).__name__}: {e}"}
            with out_lock:
                results[idx] = r

        with ThreadPoolExecutor(max_workers=args.parallel) as ex:
            for idx, cd in enumerate(order):
                ex.submit(worker, idx, cd)
        all_results = [r for r in results if r is not None]
    else:
        # 顺序路径（行为不变）
        for case_dir in case_dirs:
            for i in range(args.repeat):
                ts = time.strftime("%Y%m%d_%H%M%S")
                try:
                    all_results.append(run_case(case_dir, args.remote, args.clean, ts))
                except Exception as e:
                    print(f"❌ {case_dir.name} 运行失败: {type(e).__name__}: {e}")
                    all_results.append({"case": str(case_dir), "error": f"{type(e).__name__}: {e}"})

    # 汇总
    print(f"\n{'=' * 60}\n汇总")
    print(f"{'案例':<42} {'verdict':<16} pipeline")
    for r in all_results:
        j = r.get("judgment", {})
        print(
            f"{r['case']:<42} {j.get('decision', {}).get('verdict', r.get('error', 'ERR')):<16} "
            f"{j.get('pipeline', {}).get('exit_reason', '-')}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
