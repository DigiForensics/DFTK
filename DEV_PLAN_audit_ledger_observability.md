# DEV_PLAN: 审计台账（chain-of-custody）失败可观测性

状态：进行中

## 背景 / 问题

DFTK 的审计台账（`core/audit.py::ToolAuditLog`）是"证据链（chain-of-custody）"的核心
能力：每次 `registry.run` 都可把调用记录（脱敏参数、结果状态、证据哈希）追加到 JSONL。
对取证工作而言，这套台账必须**可信**——分析师要能相信"记录存在 = 记录被写盘"。

但当前实现把两类失败**完全静默吞掉**（`record()` 的两个 except 分支只 `return`）：

1. 序列化失败（`except Exception`）
2. 写入失败（`except OSError`：磁盘满、权限不足、`DFTK_AUDIT_LOG` 指向不可写路径、
   目录被删等）

后果：一旦 always-on 台账（`DFTK_AUDIT_LOG`）因上述任一原因失效，取证运行**照常成功返回**，
但审计台账**静默丢失记录**，分析师**毫无察觉**地误以为证据链完整。这正是 Agent 集成里
最不该有的"黑箱失败"——而审计台账恰是 DFTK 对 Agent 的核心卖点之一。

> 注意：保持"**不打断取证运行**"的设计意图不变（失败的台账绝不能让工具调用崩溃或返回错误），
> 本计划只把失败从"静默"变为"**可观测**"。

## 修复方案

1. **`src/dftk/core/audit.py`**
   - `ToolAuditLog.__init__` 增加 `self.dropped = 0` 与 `self.last_error: str | None = None`。
   - `record()` 的两个失败分支改为：记录 `self.last_error`、自增 `self.dropped`，**仍 return**
     （不破坏取证运行）。
   - 新增 `health() -> dict`：返回 `{"ok": dropped==0, "path": ..., "dropped": int, "last_error": ...}`。
   - 模块级新增 `_DEFAULT_AUDIT_LOG_ERROR: str | None = None`。
   - `_get_default_audit_log()`：构造 `ToolAuditLog` 失败时（OSError）除置 None 外，
     写入 `_DEFAULT_AUDIT_LOG_ERROR`（含路径与原因），供 doctor 告警。

2. **`src/dftk/doctor.py`**
   - `doctor_report()` 末尾新增审计台账自检段：若 `DFTK_AUDIT_LOG` 已设置但
     `_get_default_audit_log()` 返回 None 或存在 `_DEFAULT_AUDIT_LOG_ERROR`
     → 告警 `audit-ledger-unavailable`（附 detail / remediation）；
     若已构造但 `log.dropped > 0` → 告警 `audit-ledger-dropping`。
   - 复用既有 `warnings` 列表结构（code / detail / remediation）。

3. **测试**
   - `tests/test_audit.py`：目录作为路径 → `record()` 写入失败计入 `dropped`、`health()["ok"]` 为 False；
     `registry.run` 在台账丢弃时仍返回 `ok`（验证"不打断"）。
   - `tests/test_doctor.py`：`DFTK_AUDIT_LOG` 指向不可构造路径 → doctor 返回 `audit-ledger-unavailable`。

## 改动文件

- `src/dftk/core/audit.py`（失败计数 / health / 构造错误暴露）
- `src/dftk/doctor.py`（台账自检告警）
- `tests/test_audit.py`、`tests/test_doctor.py`（回归）
- 本计划文档 `DEV_PLAN_audit_ledger_observability.md`

## 验证方式

- `pytest tests/test_audit.py tests/test_doctor.py -q`
- 全量 `pytest -q`（确认无回归，尤其 `test_generalization` 不触发禁用词/裸 except）
- 端到端：`DFTK_AUDIT_LOG=/bad/path dftk doctor` 应含 `audit-ledger-unavailable` 告警；
  正常路径 `ok=True` 且 `warnings` 不含该告警。

## 范围外（本次不做）

- 不把告警改为"阻断运行"——保持取证运行不被台账 I/O 影响。
- 不改 MCP gateway 的 `audit=True` 路径（其台账在 worker 内构造；如需，后续单独加 doctor 钩子）。
- 不引入日志/告警通道（沿用 doctor 的 `warnings` 契约）。

## 变更记录（实时追加）

- _(变更在此追加，含文件 + 行号 + 摘要 + 验证结果)_
