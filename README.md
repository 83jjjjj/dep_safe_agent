# depsafe —— Python 依赖安全修复 Agent

检测 CVE 漏洞 → 评估风险与破坏性 → 自动修复 → 提交真实 PR/Issue 的安全修复 Agent。

依赖升级最大的成本不是"改版本号"，而是**判断这一升级安全吗**：漏洞是否真的可达、跨大版本升级是否有破坏性变更、约束冲突怎么解。depsafe 把这一判断交给一个可审计的工具化 Agent：流程标准化（每步有工具、有记录、有验证），结果可验证（真实 PR + 回归测试 + 确定性判定器）。

## 特性

- **完整安全修复工作流**：漏洞扫描 → 可达性分析 → 版本破坏性分析 → 优先级评估（P0-P4）→ 修复/验证 → 创建 PR 或 Issue → 生成安全报告
- **真实交付**：在真实 GitHub 仓库上创建 PR/Issue（带 security 标签），修复结果经回归测试验证，不是幻觉补丁
- **预算与轮次控制**：step/token/cost/漏洞数四重预算；每轮 ≤5 个漏洞，多漏洞问题跨轮消化，预算耗尽不是终止而是轮转
- **确定性评估体系**：27 个真实案例 × 8 类行为（simple_bump / breaking_upgrade / multi_vuln / cascade_* / dependency_hell / unreachable / clean），判定器不用 LLM 当裁判——版本对错现查 OSV、功能对错重跑回归、PR 卫生看标签与状态，全部确定性

## Agent 工作流

| 步骤 | 工具 | 做什么 |
|---|---|---|
| 1. 漏洞扫描 | `scan_vulns` | 扫描依赖文件，每轮 ≤5 个；处理完重扫直至空 |
| 2. 可达性分析 | `analyze_reachability` | 从 CVE 触发条件定位危险函数可及性（high/low/none） |
| 3. 变更分析 | `get_changelog` | 当前版本→修复版本的破坏性变更判定 |
| 4. 优先级评估 | `assess_priority` | 置信度 + breaking + 严重性 → 标准化 P0-P4 |
| 5. 修复与验证 | `apply_fix_and_verify` | 升级 + 回归测试；约束冲突联动升级；失败走降级路径 |
| 6. PR / Issue | `create_github_pr` / `create_github_issue` | 修复成功建 PR，失败建 Issue 附修复建议 |
| 7. 安全报告 | `create_security_report` | 每个漏洞处理流程的终点 |
| 8. 结束 | `echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT` | 仅当扫描为空才允许结束 |

## 快速开始

```bash
git clone git@github.com:83jjjjj/dep_safe_agent.git && cd dep_safe_agent
uv sync                      # 或 pip install -e .
cp .env.example .env         # 填入：
#   DEPSAFE_API_KEY / DEEPSEEK_API_KEY   ← 模型 API Key
#   DEPSAFE_MODEL=deepseek/deepseek-v4-flash
#   GITHUB_TOKEN                            ← 创建 PR/Issue 用
#   DEPSAFE_DOCKER_PROXY                     ← 可选，容器内代理

docker build -t depsafe-runner:latest .      # 修复/验证容器（Agent 在容器内操作项目）
cd 你的项目                  # 含 requirements.txt/pyproject.toml/Pipfile/.depsafe
uv run --project /path/to/dep_safe_agent depsafe -t "扫描并修复依赖漏洞"
# 或省略 -t：自动扫描当前项目
```

核心依赖：Docker（修复/验证运行环境）、litellm（统一模型调用）、OSV API。模型默认为 DeepSeek，可通过 `DEPSAFE_MODEL` 换任何 litellm 支持的模型。

## 评估体系

```bash
uv run python tests/eval/run_eval.py [--cases flask-pyyaml,...] [--repeat N] [--parallel N]
```

- **双仓库靶场**：主仓库放框架与案例模板；`depsafe_eval_sandbox` 每个案例一个 `fixtures/<case>` 分支，Agent 在真实 GitHub 上产生真实 PR/分支/Issue
- **案例结构**：`app.py`（触发代码）+ 依赖文件 + `case.json`（machine-readable ground truth）+ 回归测试（漏洞版本 FAIL / 修复版本 PASS）
- **判定**：确定性三态 PASS / FAIL / detection_fail（扫描器没把漏洞交给 Agent 的归因），无关 LLM-as-judge 的模糊投票
- **两轴**：轴A 流程健康（完整终止）；轴B 决策正确（版本/回归/PR 卫生/报告）
- **产物**：`tests/eval/results/<case>_<ts>/judgment.json` + 轨迹副本 + 日志，全部保留可回放
- **结果**：27 例全量报告见 [`docs/eval-results/评估报告.md`](docs/eval-results/评估报告.md)（含判定口径、已知边界）

## 目录结构

```
src/depsafe/
  agent.py             # 主循环：轮次/预算/轨迹/收尾
  budget.py            # step/token/cost/vuln 预算与轮转状态
  model.py             # litellm 封装（query / 工具调用解析）
  checkpointer.py      # 轨迹落盘与恢复（断点续跑）
  tool/                # 8 个内置工具（扫描/可达性/变更/修复/PR/Issue/报告…）
  environment/         # docker（修复与验证运行） + local（宿主命令）
  config/default.yaml  # 工作流提示词 + 模型/容器配置
  run/hello_world.py   # CLI 入口（depsafe）
tests/
  fixtures/            # 27 个评估案例（案例目录 + 回归测试 + case.json）
  eval/                # run_eval.py 运行器 + judge.py 确定性判定器
docs/eval-results/     # 全量评估报告与 27 案例明细
```

## 文档

- [评估报告（27 例全量）](docs/eval-results/评估报告.md)
- [评估体系设计](评估体系设计-depsafe-agent.md) · [实施计划](实施计划-depsafe-agent.md)
- `HANDOFF.md`：任务状态快照与下一步

## License

MIT
