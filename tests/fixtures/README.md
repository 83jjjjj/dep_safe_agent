# Eval Fixtures

本目录包含 DepSafe Agent 端到端评估所需的预置项目样本。

## 目录结构

一级目录按**行为类别**分类，二级目录为 `包-cve编号` 案例：

```
fixtures/
├── simple_bump/          # 单 CVE，同 minor 线有修复版，触发可达 → P0 修复 + PR
├── breaking_upgrade/     # 修复必须跨大版本 → P1 Draft PR + breaking 说明
├── multi_vuln/           # 多个漏洞包（不同包各有 CVE）→ 预算轮转逐个处理
├── cascade_vuln/         # 两个有漏洞的钉死依赖需协同升级
├── cascade_constraint/   # A 的修复版要求 B 升级，B 无漏洞（纯约束驱动）
├── dependency_hell/      # 约束不可调和 → 正确降级：Issue + 报告
├── unreachable/          # 漏洞存在但触发未使用 → P4 不改代码仅报告
└── clean/                # 无漏洞 → 空报告正常终止
```

每个案例目录包含：

- `case.json` — 案例声明（判定器的唯一人工输入）
- `app.py` — 触发代码（供可达性分析匹配）
- `requirements.txt` — 钉住的漏洞版本（及必要的兼容伴随 pin）
- `tests/test_security.py` — 回归测试（漏洞版本 FAIL / 修复版本 PASS）

## 使用方式

每个案例目录是一个**未初始化 Git 的纯文件模板**。
运行评估前，必须先执行 `setup_eval_env.sh <fixture_dir>` 将其绑定到 `depsafe-eval-sandbox` 仓库。

## 场景列表

| 类别 | 案例 | CVE | 预期行为 |
|------|------|-----|----------|
| multi_vuln | flask-cve-2023-30861 | 30861 + 27205 | 双 CVE 各修复各提 PR |
| simple_bump | requests-cve-2023-32681 | CVE-2023-32681 | P0 修复 + PR（脚手架待生成） |
