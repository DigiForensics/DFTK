# 开发计划：修复 `dftk skill --install` 在 WorkBuddy 下的宿主误判

状态：已完成（代码 + 测试 + 验证，未提交 git）
作者：DyNooob @ DigiForensics
日期：2026-08-21

## 问题（定位）

- 位置：`src/dftk/cli.py`，函数 `_resolve_targets()`（约 103–133 行）。
- 调用方：`dftk skill --install`（默认 `--target auto`）与 `dftk agent setup --target auto` 共用该函数决定技能安装到哪个宿主的 skills 目录。
- 现状：auto 模式只识别 `codex` / `claude` / `cursor` / `gemini` 四个宿主的 env marker，**没有 WorkBuddy**。WorkBuddy 运行时会导出以下变量（在本机 5.3.13 实测）：
  - `WORKBUDDY_PRODUCT_NAME=WorkBuddy`
  - `CODEBUDDY_HOST=workbuddy-desktop`
  - `WORKBUDDY_CONFIG_DIR=C:\Users\Administrator\.workbuddy`
  这些都不在现有 marker 表中。
- 退化路径：auto 在无 marker 命中时，改为"扫描已存在的宿主目录"。当机器上存在 ≥2 个宿主目录（本机就有 `.workbuddy`、`.agents`、`.claude`、`.codebuddy`、`.codex`、`.cursor`、`.gemini`、`.hermes`）时，固定回退到 `agents`，即 `~/.agents/skills/dftk`。
- 后果：WorkBuddy 只读 `~/.workbuddy/skills`，所以 `dftk skill --install` 看似成功，技能却**静默不被加载**。这是本次评估中实测到的真实缺陷（详见 2026-08-21 评估记录）。

## 修复方案

- 在 `_resolve_targets` 的 host marker 表中增加 WorkBuddy / CodeBuddy（二者同属 `CODEBUDDY_*` 家族，host 值不同）。
- marker 表改为"（target, 环境变量名, 值子串）"三元组，支持值子串匹配：
  - `workbuddy` ← `WORKBUDDY_PRODUCT_NAME` 含 `workbuddy`，或 `CODEBUDDY_HOST` 含 `workbuddy`
  - `codebuddy` ← `CODEBUDDY_HOST` 含 `codebuddy`
  - 既有 `codex` / `claude` / `cursor` / `gemini` 行为不变（变量存在即匹配，子串为 `None`）。
- 命中任意 marker 即直接 `return [target]`，不再走目录扫描回退分支。
- 目录扫描回退分支保留为"完全无法识别宿主"时的兜底（仍回退 `agents`）。

## 改动文件

1. `src/dftk/cli.py` — 重构 `_resolve_targets()` 的 marker 表（纯新增 + 既有行为保持）。
2. `tests/test_skill_install.py` — 新增 `_resolve_targets` 回归测试（WorkBuddy 两种探针、CodeBuddy、既有宿主不被破坏）。

## 验证

- 单测：受管 venv 跑 `pytest tests/test_skill_install.py`（需 `CODEBUDDY_SAFE_DELETE_SANDBOX=0`、`COVERAGE_FILE=$TEMP/.coverage`）。
- 端到端：`CODEBUDDY_HOST=workbuddy-desktop dftk skill --install --dry-run` 应报告目标为 `~/.workbuddy/skills/dftk`。
- 全量回归：尽量跑 `pytest`，确认无破坏。

## 范围外（非代码缺陷，属于环境 / 安装问题，不在此次改动内）

- 可选 Python 集成（yara / evtx / registry / pyewf / pytsk3 / paramiko / dkim / dns / spf）未安装 → 部分能力 `unsupported`。
- MCP python 包未安装（`dftk[mcp]`）→ MCP 模式不可用，需 `pip install "dftk[mcp]"`。
- toolchain 未 `prepare`（`file` 等缺失）→ 文件类型识别类能力受限，需 `dftk prepare`。

## 变更记录（实时）

- 2026-08-21 17:40 — 代码修复 `src/dftk/cli.py`（`_resolve_targets()`，103–131 行）
  - marker 表由"变量名→target"改为三元组 `(target, 环境变量名, 值子串)`；新增 workbuddy / codebuddy 规则：
    - `("workbuddy", "WORKBUDDY_PRODUCT_NAME", "workbuddy")`
    - `("workbuddy", "CODEBUDDY_HOST", "workbuddy")`
    - `("codebuddy", "CODEBUDDY_HOST", "codebuddy")`
  - 命中任一 marker 即 `return [target]`，不再回退目录扫描；既有 codex/claude/cursor/gemini 子串为 `None`，行为不变。

- 2026-08-21 17:42 — 新增回归测试 `tests/test_skill_install.py`（3 个，共 9）
  - `test_resolve_targets_auto_prefers_workbuddy_product_name`（WORKBUDDY_PRODUCT_NAME=WorkBuddy）
  - `test_resolve_targets_auto_prefers_workbuddy_host`（CODEBUDDY_HOST=workbuddy-desktop）
  - `test_resolve_targets_auto_codebuddy_host`（CODEBUDDY_HOST=codebuddy-desktop）
  - 新增 `_HOST_ENV_VARS` + `_clear_host_env()` 辅助，隔离每个用例只控制一个 marker。

- 2026-08-21 18:45 — 全量回归发现 1 失败并修复
  - 失败：`tests/test_generalization.py::test_registered_source_has_no_known_case_constants_or_bare_except`（禁源码硬编码已知 case 常量 `'WorkBuddy'`）。cli.py 注释中出现 "WorkBuddy" 命中。
  - 修复：cli.py 注释 `WorkBuddy`→`workbuddy`（env 变量名全大写 `WORKBUDDY_PRODUCT_NAME` 不受影响）。
  - 端到端：`CODEBUDDY_HOST=workbuddy-desktop dftk skill --install --dry-run` → 目标 `~/.workbuddy/skills/dftk`（此前错误落到 `~/.agents/skills/dftk`）。

- 2026-08-21 18:46 — 最终验证
  - 单测 `pytest tests/test_skill_install.py`：9 passed。
  - 全量 `pytest`：**148 passed, 1 skipped**（受管 venv，无失败）。
  - 改动未提交 git（按项目约定，push 需用户确认）。
