#!/usr/bin/env bash
# 批量恢复 27 个夹具案例目录（当前处于运行后脏状态）：
# 以远端 fixtures/<case> 分支的模板内容覆盖（保留本地 case.json——沙箱中未跟踪），
# 并清理 root 属主运行时产物。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FIXTURES="$REPO_ROOT/tests/fixtures"
REMOTE="${1:-83jjjjj/depsafe_eval_sandbox}"

# 读取 token（不打印）
declare token=""
if [ -f "$REPO_ROOT/.env" ]; then
  token="$(grep -E '^GITHUB_TOKEN=' "$REPO_ROOT/.env" | head -1 | cut -d= -f2-)"
fi
[ -n "$token" ] || { echo "GITHUB_TOKEN 未在 .env 找到"; exit 1; }
URL="https://x-access-token:${token}@github.com/${REMOTE}.git"

count=0
for case_dir in "$FIXTURES"/*/*/; do
  name="$(basename "$case_dir")"
  tmp="$(mktemp -d)"
  # 1. 取远端模板（fixtures/<case> 分支）
  git -c credential.helper= clone -q --depth 1 -b "fixtures/$name" "$URL" "$tmp/repo" 2>&1 || {
    echo "!! $name 克隆失败（分支可能不存在），跳过"; rm -rf "$tmp"; continue; }
  # 2. 容器清理 root 残留（含 root 属主的 tracked 文件——宿主无法覆盖它们）
  docker run --rm --network none -v "$case_dir:/workspace" depsafe-runner:latest bash -c \
    "rm -rf .git .depsafe .agent_runner.py .venv-fix-verify requirements.lock SECURITY_FIX_REPORT.md judgment.json uv.lock *.egg-info; find /workspace \( -name __pycache__ -o -name '*.egg-info' -o -name '*.dist-info' \) -type d -exec rm -rf {} + 2>/dev/null; find /workspace -user root -depth -exec rm -rf {} + 2>/dev/null" >/dev/null 2>&1
  # 3. 模板覆盖（排除 .git；case.json 不在模板分支上且为用户属主，本地保留）
  tar -C "$tmp/repo" --exclude=.git -cf - . | tar -C "$case_dir" -xf -
  rm -rf "$tmp"
  count=$((count + 1))
  echo "restored: $name"
done
echo "共恢复 $count 个案例"
