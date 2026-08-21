# 开发计划：修复 `dftk doctor` 的 `ok` 死常量 + 增加技能安装位置自检

状态：进行中
作者：DyNooob @ DigiForensics
日期：2026-08-21

## 问题（定位）

- 文件：`src/dftk/doctor.py`，函数 `doctor_report()`（51–109 行）。
- 现状：`"ok": True` 是**硬编码常量**（第 81 行）。`doctor_report` 拼装了 `mcp` / `optional` / `external` / `toolchain` 等详细诊断信息，却从不据其判定健康度。
- 调用方：`_cmd_doctor`（`cli.py` 396–401 行）用 `report.get("ok")` 决定退出码。因为 `ok` 恒为 `True`，**任何环境下 `dftk doctor` 都退出 0 并报 `ok: true`**。
- 后果（实测，见 2026-08-21 评估）：
  1. **误导性绿灯**：即便 MCP 包未装、optional 集成全 False、external 工具 7/11、`file` 缺失，依然 `ok: true`。用户与 Agent 据此误判环境健康。
  2. **不验证技能安装位置**：本会话刚修复的 host 误判 bug（`cli._resolve_targets` 曾把技能装到 `~/.agents/skills` 而非 `~/.workbuddy/skills`）在存量安装里不会告警，无法防复发。
- 根因判断：这是"健康判定逻辑未实现/留 TODO"的真实缺陷，不是设计选择——否则不会一边拼装详尽诊断、一边把 `ok` 写成常量。

## 修复方案

1. **`ok` 改为派生值**（不再是常量）：
   - `ok = False` 当：加载到 0 个工具（registry 加载失败）；或 MCP 已安装但版本不支持（`_mcp_version_supported` 为 False，即装了 1.x/3.x，会破坏 MCP 模式）。
   - `ok = True` 其余情况（核心 CLI 可用）。
2. **新增 `warnings` 列表**（advisory，不强制 `ok=False`，但暴露给用户/Agent）：
   - `mcp-not-installed`：Agent 集成（MCP 工具面）不可用，附 remediation `pip install "dftk[mcp]"`。
   - `optional-missing`：列出不可用的 optional 集成（yara/evtx/registry/…）。
   - `external-missing`：列出不可用的 external 工具。
3. **新增 `skill_install` 段**（防 host 误判 bug 复发）：
   - 检测当前宿主（env marker：`WORKBUDDY_PRODUCT_NAME` / `CODEBUDDY_HOST` / `CLAUDE_CODE` / `CODEX_HOME` / …，与 `cli._resolve_targets` 同源规则），得到期望 skills 目录。
   - 检查 `<期望目录>/dftk/SKILL.md` 是否存在（`installed`）。
   - 扫描其它已知宿主目录是否也存在 `dftk/SKILL.md`（`misplaced`）。
   - 报告字段：`expected_host`、`expected_dir`、`installed`（bool）、`misplaced`（bool）。
   - 当（识别到当前宿主且 `not installed`）或 `misplaced` 时，加入 `warnings`（`skill-not-installed` / `skill-misplaced`）。

## 改动文件

1. `src/dftk/doctor.py` — `doctor_report()` 重构 `ok` 判定 + 新增 `warnings` + 新增 `skill_install` 段（含轻量宿主检测，避免 import `cli` 造成循环依赖）。
2. `tests/test_doctor.py`（新建）— `ok` 派生逻辑、warnings 内容、`skill_install` 自检（monkeypatch env + tmp HOME 模拟安装位置）。

## 验证

- 单测：`pytest tests/test_doctor.py -q`（受管 venv，需 `CODEBUDDY_SAFE_DELETE_SANDBOX=0`、`COVERAGE_FILE=$TEMP/.coverage`）。
- 全量：尽量跑 `pytest` 确认无破坏（尤其 `_cmd_doctor` 退出码依赖 `ok`）。
- 端到端：
  - WorkBuddy 环境、技能已在 `~/.workbuddy/skills/dftk` → `ok: true` 且无 skill warning。
  - 故意把技能移到 `~/.agents/skills/dftk`（模拟已修 bug 的存量错误）→ 出现 `skill-misplaced` warning。

## 范围外（非代码缺陷，属环境/安装问题，不在本次改动内）

- 实际安装/下载依赖（MCP 包、optional、external 工具）——本会话不改。
- `doctor` 是否应把 `mcp-not-installed` 算作 `ok=False`：本计划保持 `ok` 只反映核心 CLI 可用，MCP 缺失走 `warnings`。若后续认为 Agent 集成是关键路径可再调。

## 变更记录（实时）

- 2026-08-21 21:30 — 代码修复 `src/dftk/doctor.py`（`doctor_report()`，51 行起）
  - `ok` 由硬编码 `True`（原第 81 行常量）改为派生值：`ok = bool(specs) and (not mcp_installed or mcp_ready)`（registry 空或 MCP 版本不兼容 → False）。
  - 新增 `warnings` 列表：`mcp-not-installed` / `optional-missing` / `external-missing`，含 `remediation` 字段。
  - 新增 `_current_agent_host()` + `_skill_install_status(home=None)`：检测当前宿主期望 skills 目录并校验主技能 `dftk/SKILL.md` 是否装对位置 / 装错位置（`misplaced`）。`_AGENT_SKILL_DIRS` / `_HOST_MARKERS` 与 `cli` 同源，故意不 import `cli` 以避循环依赖。
  - 报告新增 `skill_install` 段；`skill-not-installed` / `skill-misplaced` 进 `warnings`。
- 2026-08-21 21:35 — 新增回归测试 `tests/test_doctor.py`（9 个）
  - ok 派生：tools 加载且 mcp 未装 → True；mcp 版本 1.x/3.x → False；mcp 2.x → True。
  - warnings 含 `mcp-not-installed` / `optional-missing` / `external-missing`。
  - skill_install 自检：workbuddy 正确位置 / agents 装错(misplaced) / 完全未装 / misplaced warning 进 report（用 `home=` 与 monkeypatch `Path.home` 隔离）。
- 2026-08-21 21:40 — 验证
  - 单测 `pytest tests/test_doctor.py`：9 passed。
  - 全量 `pytest`：**157 passed, 1 skipped**（较修复前 148 再 +9，无失败）。
  - 端到端 `dftk doctor`（真实 WorkBuddy 环境）：`ok=True`，`skill_install.installed=true`（~/.workbuddy/skills/dftk），`warnings=[mcp-not-installed, optional-missing, external-missing]`（均为真实环境缺口，非代码缺陷）。
- 状态：改动已写入本地 main，未 commit（按提交规则，push 需用户确认）。
