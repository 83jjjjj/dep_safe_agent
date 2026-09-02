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

echo "🔧 初始化 Git 仓库（链式历史：模板提交叠在远端 main 之上，保持 PR 可比较/可重开）..."
git init -b main
git config user.name "DepSafe Eval Bot"
git config user.email "eval@depsafe.local"

echo "🔗 绑定远程仓库: $REMOTE_REPO"
git remote add origin "https://x-access-token:${GITHUB_TOKEN}@github.com/${REMOTE_REPO}.git"

# 先暂存模板文件（排除 .git，复制后即删），否则 checkout 会因工作区文件冲突被拒
TMP_TEMPLATE="$(mktemp -d)"
for f in ./* ./.[!.]*; do
    case "$f" in ./.git) continue ;; esac
    [ -e "$f" ] && cp -a "$f" "$TMP_TEMPLATE/" 2>/dev/null && rm -rf "$f" || true
done

# 基于远端 main 现有历史继续（快进式），而非新根提交强推——保证旧 PR 与 main 始终同源
git -c credential.helper= fetch -q origin main
git checkout -q -B main origin/main

# 用模板内容替换仓库内容：清空 tracked 内容，放回模板
git rm -qrf . 2>/dev/null || true
cp -a "$TMP_TEMPLATE"/. .
rm -rf "$TMP_TEMPLATE"

git add -A
# case.json 是评估元数据而非项目文件，不进沙箱
git rm -q --cached case.json 2>/dev/null || true
if git diff --cached --quiet; then
    echo "ℹ️ 模板与当前 main 内容一致，跳过提交"
else
    git commit -q -m "init: vulnerable project for eval ($(basename "$FIXTURE_DIR"))"
fi

echo "📤 推送 main（快进，无需强推）..."
# 禁用 credential helper：宿主机可能存有 github.com 旧凭据，会覆盖 URL 内联 token 导致 401
git -c credential.helper= push -u origin main

echo ""
echo "✅ Eval environment ready!"
echo "   Fixture: $FIXTURE_DIR"
echo "   Remote:  https://github.com/${REMOTE_REPO}"
