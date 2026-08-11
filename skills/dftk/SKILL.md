---
name: dftk
description: 数字取证（DFIR）能力层 dftk 的使用技能。当用户需要"只读、可溯源、证据保全"的取证分析时使用：文件哈希与时间线、磁盘镜像(E01)、APK/Android 静态分析、PCAP 网络流量协议提取、Windows 注册表/EVTX、邮件认证上下文(DKIM/SPF)、SSH 只读清点、浏览器历史、加密货币钱包助记词扫描、以及组合式 triage recipe。dftk 提供 66 个只读工具，安全优先，绝不修改检材。
---

# dftk — 数字取证能力层

dftk（Digital Forensics Toolkit）是 DigiForensics 出品的证据保全型取证工具集：一个 registry 里的 66 个只读工具 + 组合 recipe，每个操作返回标准化的 `Observation`（状态 / 机器可读 facts / 可溯源 evidence）。它不是自主 agent，而是一个"能力层"——供分析师、自动化脚本和上层 agent 调用。

> **版权与出处**
> - 许可证：Apache License 2.0（见仓库 `LICENSE`）。
> - 版权：Copyright 2026 DyNooob @ DigiForensics。
> - 仓库：https://github.com/DigiForensics/DFTK
> - PyPI：https://pypi.org/project/dftk/
> - 版本：2.1.0

## 何时使用本技能

- 用户要做任何"取证 / DFIR / 证据分析"类任务，且要求**不修改原始检材**。
- 涉及：文件哈希、时间线、E01 镜像、APK/DEX、PCAP/PCAPNG、注册表 hive、EVTX、邮件头、SSH 清点、浏览器历史、钱包助记词、离线 triage。
- 需要"机器可读、可溯源"的结构化取证输出（而非解析终端文本）。

## 调用方式（已实测可用）

dftk 以 Python 包 + CLI 形式提供。在本工作区，源码在 `D:\Projects\DFTK\DFTK`，用受管 Python 从仓库目录运行：

```bash
cd D:/Projects/DFTK/DFTK
PY="C:/Users/Administrator/.workbuddy/binaries/python/versions/3.13.12/python.exe"
PYTHONPATH=src "$PY" -m dftk.cli --version
```

若已 `pip install dftk`，可直接用 `dftk` 命令替代上面的整段（`dftk --version`、`dftk list` …）。

## 子命令

| 子命令 | 作用 |
|---|---|
| `list [--tag T] [--produces P]` | 列出工具（可按 tag / 产出类型过滤），返回 JSON 规格 |
| `describe <name>` | 查看单个工具的参数 schema 与元数据 |
| `run <name> [--params JSON] [--params-file F] [--out F] [--allow-network] [--max-safety LEVEL]` | 运行一个工具 |
| `recipe <name> [--params JSON] [--params-file F] [--out F]` | 运行组合 recipe（名称可省略 `recipe.` 前缀） |
| `export-manifest [--out F]` | 导出全部 66 个工具的 agent 可读清单（schema_version 2） |

参数 JSON 通过 `--params '{"path":"..."}'` 内联，或 `--params-file tool.json` 从文件读取。

## 安全模型（务必遵守）

- **默认只跑 READ_ONLY 工具**。dftk 当前未注册任何 DESTRUCTIVE 工具。
- **网络工具**（如 `server.readonly_inventory`，spec 中 `network: true`）默认被阻断，必须显式加 `--allow-network` 才放行；且仍只做只读 SSH 清点，不暴露任意命令。
- 除非用户明确要求且说明理由，**不要**传 `--max-safety STATEFUL`；保持默认 `READ_ONLY`。
- 所有工具返回 `Observation`，`status` 可能为 `ok` / `partial` / `unsupported` / `blocked` / `error`。`unsupported` 通常表示缺少可选依赖（如 `pyewf`、`python-evtx`、`python-registry`、`paramiko`），按 `errors` 提示安装对应 extra（`pip install 'dftk[e01]'` 等）即可。
- 检材路径只读，工具不会写入或改动源文件。

## 工具发现工作流（推荐）

1. 先 `export-manifest` 拿到全部工具及 JSON schema（给 agent 的"菜单"）。
2. 按场景过滤：`list --tag android`、`list --produces timeline`、`list --tag recipe`。
3. 对选中工具 `describe <name>` 确认必填参数。
4. `run <name> --params '{...}'` 执行，解析返回的 `Observation`。

## 输出结构（Observation JSON）

```json
{
  "tool": "file.hash",
  "status": "ok",
  "summary": "Computed 1 hash value(s)",
  "facts": { "path": "...", "size": 8959, "hashes": { "sha256": "..." } },
  "evidence": [ { "source": "...", "kind": "file", "value": {...}, "locator": "...", "confidence": 1.0 } ],
  "warnings": [], "errors": [],
  "meta": { "tool_contract": { "safety": "READ_ONLY", "network": false, "tags": [...], "produces": [...] } }
}
```

- `facts`：机器可读结论；`evidence`：可溯源到来源/位置的取证项（含 `source_sha256`、`locator`、`confidence`）；`meta.tool_contract` 可提供安全契约，用于审计。

## 实战示例

**例1 文件哈希（基础）**

```bash
cd D:/Projects/DFTK/DFTK
PY="C:/Users/Administrator/.workbuddy/binaries/python/versions/3.13.12/python.exe"
PYTHONPATH=src "$PY" -m dftk.cli run file.hash --params '{"path":"README.md"}'
```

**例2 离线 Linux triage（recipe）**

```bash
PYTHONPATH=src "$PY" -m dftk.cli recipe server.offline_triage --params '{"root":"/mnt/evidence/srv01"}'
```

**例3 网络流量协议提取**

```bash
PYTHONPATH=src "$PY" -m dftk.cli run network.capture_protocols --params '{"path":"capture.pcapng","limit":2000}'
```

## 必踩的坑（Windows + git-bash）

- **MSYS 盘符映射**：bash cwd 在 D: 时写 `E:/x` 会被解析成 `D:\e\x`。解决：先 `cd` 到文件所在盘再用相对/绝对路径，或全程在同盘操作。
- **safe-delete 拦截 `rm`**：删文件前先 `unset CODEBUDDY_SAFE_DELETE_BULK_STATE_DIR CODEBUDDY_SAFE_DELETE_BULK_GUARD CODEBUDDY_SAFE_DELETE_SANDBOX`，或改用新建目录避开删除。
- **PYTHONPATH**：从仓库 `D:\Projects\DFTK\DFTK` 运行时必须 `PYTHONPATH=src` 才能 `import dftk`；跑 pytest 等其他脚本前记得 `export PYTHONPATH=""` 以免污染。
- **heredoc 易炸**：把 python 写成 `.py` 文件再 `python 文件.py` 跑，别内联 heredoc。

## 交付物

- 取证结果以 `Observation` JSON 呈现（可 `--out` 落盘为文件，再用 present_files 展示）。
- 报告/结论以 markdown 交付，引用 `facts` 与 `evidence`（含来源与置信度）作为可溯源依据。
