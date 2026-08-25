#!/bin/bash
set -euo pipefail

FIXTURE_DIR="${1:?用法: $0 <fixture_dir> [owner/repo]}"
REMOTE_REPO="${2:-83jjjjj/depsafe_eval_sandbox}"

if [ ! -d "$FIXTURE_DIR" ]; then
    echo "❌ 目录不存在: $FIXTURE_DIR"
    exit 1
fi

cd "$FIXTURE_DIR"

# 防止重复初始化
if [ -d ".git" ]; then
    echo "⚠️  $FIXTURE_DIR 已是 Git 仓库，跳过初始化。如需重置请先 rm -rf .git"
    exit 0
fi

echo "🔧 初始化 Git 仓库..."
git init -b main
git config user.name "DepSafe Eval Bot"
git config user.email "eval@depsafe.local"
git add -A
git commit -m "init: vulnerable project for eval ($(basename "$FIXTURE_DIR"))"

# ✅ 关键修改：使用 x-access-token 内联认证，绕过 credential helper
echo "🔗 绑定远程仓库: $REMOTE_REPO"
git remote add origin "https://x-access-token:${GITHUB_TOKEN}@github.com/${REMOTE_REPO}.git"

echo "📤 推送到远程 main 分支..."
git push -u origin main --force

echo ""
echo "✅ Eval environment ready!"
echo "   Fixture: $FIXTURE_DIR"
echo "   Remote:  https://github.com/${REMOTE_REPO}"