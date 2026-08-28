#!/usr/bin/env python3
"""DepSafe 评估运行器：自动化每个案例的完整评估生命周期。

用法：
    uv run python tests/eval/run_eval.py [--cases NAME,...] [--repeat N] [--keep-prs] [--remote owner/repo]

生命周期（每案例 × 每 repeat）：
    1. 清理本地（root 属主文件经容器删）
    2. 清理远端（关闭所有 PR、删除 fix 分支）
    3. setup_eval_env.sh 绑定沙箱（git init + 强推模板 main）
    4. 在案例目录执行 `uv run depsafe`
    5. 采集轨迹副本（checkpoint + sub_trajectories）与日志
    6. 判定（judge.py，确定性）
    7. 清场（除非 --keep-prs），案例目录恢复模板态

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
import time
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
EVAL_DIR = REPO_ROOT / "tests" / "eval"
RESULTS = EVAL_DIR / "results"
TRAJECTORIES = EVAL_DIR / "trajectories"
LOGS = EVAL_DIR / "logs"
IMAGE = "depsafe-runner:latest"

# 加载 .env（GITHUB_TOKEN / DEEPSEEK_API_KEY / DEPSAFE_DOCKER_PROXY 等），
# 子进程 uv run depsafe 也继承此环境
from dotenv import load_dotenv

load_dotenv(REPO_ROOT / ".env")
RUNTIME_ARTIFACTS = [
    ".git", ".depsafe", ".agent_runner.py", ".venv-fix-verify",
    "requirements.lock", "SECURITY_FIX_REPORT.md", "judgment.json",
]


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


def container_cleanup(case_dir: Path) -> None:
    """用 root 容器删除运行时产物（处理容器产生的 root 属主文件）"""
    targets = " ".join(RUNTIME_ARTIFACTS)
    subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "-v", f"{case_dir}:/workspace", "-w", "/workspace",
         IMAGE, "bash", "-c", f"rm -rf {targets}"],
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
    """绑定案例到沙箱仓库（复用 setup_eval_env.sh 逻辑）"""
    env = dict(os.environ)
    proc = subprocess.run(
        ["bash", str(FIXTURES / "setup_eval_env.sh"), str(case_dir), remote],
        capture_output=True, text=True, timeout=300, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"setup 失败: {proc.stdout[-300:]} {proc.stderr[-300:]}")


def run_agent(case_dir: Path, log_file: Path) -> dict:
    """在案例目录执行 uv run depsafe，返回运行统计"""
    start = time.time()
    with open(log_file, "w", encoding="utf-8") as f:
        proc = subprocess.run(["uv", "run", "depsafe"], cwd=case_dir, stdout=f, stderr=subprocess.STDOUT, timeout=3600)
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


def run_case(case_dir: Path, remote: str, keep_prs: bool, ts: str) -> dict:
    """单案例完整生命周期"""
    name = case_dir.parent.name + "/" + case_dir.name
    print(f"\n{'=' * 60}\n▶ {name}")
    out: dict = {"case": name, "ts": ts}

    # 1. 清理本地 + 2. 清理远端（每次 repeat 前，保证靶场干净）
    print("  清理本地与远端...")
    container_cleanup(case_dir)
    client, _ = github_client()
    remote_summary = remote_cleanup(client, remote)
    out["remote_preclean"] = remote_summary

    # 3. 绑定沙箱
    print("  绑定沙箱（setup_eval_env.sh）...")
    setup_case(case_dir, remote)

    # 4. 运行
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

    # 6. 判定
    print("  判定（judge.py）...")
    sys.path.insert(0, str(EVAL_DIR))
    from judge import judge as judge_fn, load_case, load_trajectory, osv_ground_truth, case_pkg_specs, fetch_remote_state
    case = load_case(case_dir)
    truth = osv_ground_truth(case_pkg_specs(case))
    traj = load_trajectory(case_dir)
    remote_state = fetch_remote_state(client, *remote.split("/"))
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

    # 7. 清场
    if not keep_prs:
        print("  清场远端...")
        out["remote_postclean"] = remote_cleanup(client, remote)
    print("  清理本地...")
    container_cleanup(case_dir)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="DepSafe 评估运行器")
    parser.add_argument("--cases", help="逗号分隔的案例名（默认全部）")
    parser.add_argument("--repeat", type=int, default=1, help="每案例重复次数（默认 1）")
    parser.add_argument("--keep-prs", action="store_true", help="保留远端 PR/分支供人工审核")
    parser.add_argument("--remote", default="83jjjjj/depsafe_eval_sandbox", help="沙箱仓库 owner/repo")
    args = parser.parse_args()

    case_dirs = discover_cases(args.cases.split(",") if args.cases else None)
    if not case_dirs:
        print("❌ 没有可评估的案例")
        return 1
    print(f"发现 {len(case_dirs)} 个案例 × {args.repeat} repeat")

    all_results: list[dict] = []
    for case_dir in case_dirs:
        for i in range(args.repeat):
            ts = time.strftime("%Y%m%d_%H%M%S")
            try:
                all_results.append(run_case(case_dir, args.remote, args.keep_prs, ts))
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
