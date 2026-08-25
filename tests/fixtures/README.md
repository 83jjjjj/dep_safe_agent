# Eval Fixtures

本目录包含 DepSafe Agent 端到端评估所需的预置项目样本。

## 使用方式

每个 fixture 目录是一个**未初始化 Git 的纯文件模板**。
运行评估前，必须先执行 `setup_eval_env.sh` 将其绑定到 `depsafe-eval-sandbox` 仓库。

## 场景列表

| 目录 | CVE | 包名 | 预期行为 |
|------|-----|------|----------|
| `flask-cve-2023-30861` | CVE-2023-30861 | flask==2.3.1 | 可达性 high → P0/P1 → 自动修复成功 → PR |