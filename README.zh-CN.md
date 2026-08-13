# DFTK — 数字取证工具包（Digital Forensics Toolkit）

[![CI](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml/badge.svg)](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![PyPI](https://img.shields.io/badge/PyPI-dftk%20%C2%B7%20soon-lightgrey.svg)](#安装)

DFTK 是数字取证领域的一层能力封装。它提供默认只读、结构化的取证操作，既可以直接在命令行调用，也能由上层 Agent / TaskGraph 运行时组合使用。每次操作都返回一个 `Observation`，里面带有明确的状态、机器可读的事实，以及可回溯到来源的证据。

> 🇺🇸 English: [README.md](README.md)

- **发布名：** `dftk` · **导入包名：** `dftk` · **命令行命令：** `dftk`
- **维护者：** [DyNooob](https://github.com/DyNooob) — DigiForensics
- **所属组织：** [DigiForensics](https://www.digiforensics.cn) · [LLMCN](https://www.llmcn.org)
- **许可证：** [Apache-2.0](LICENSE)

---

## DFTK 是什么（以及不是什么）

DFTK 不是一个自主取证智能体，而是一组稳定、结构化的操作库。由你驱动它，它不会自己开展调查。每次操作返回一个标准化的 `Observation`，调用方拿到的是事实与可溯源证据，而不是需要再去解析的终端文本。

## 为什么用 DFTK

- **默认只读。** 除非你显式提升安全级别，否则任何操作都不会改动原始证据。
- **零强制依赖。** 基础包可在任何环境干净安装，无需第三方运行依赖。专业解析器（E01/TSK、Windows 注册表/EVTX、DKIM/SPF、SSH）在依赖缺失时返回 `unsupported`，而不是替你瞎猜。
- **一个注册表，68 个工具。** 每个工具都声明了参数、安全级别、语义标签、网络需求与产出证据类型，规划器可以据此按证据需求挑选工具。
- **安全集中管控。** `READ_ONLY < STATEFUL < DESTRUCTIVE`；所有已注册工具中没有任何一个是 `DESTRUCTIVE`。网络访问独立受控，必须显式开启。

## 目录

- [安装](#安装)
- [快速上手](#快速上手)
- [Python / 智能体 API](#python--智能体-api)
- [Observation 结果契约](#observation-结果契约)
- [能力模型](#能力模型)
- [安全模型](#安全模型)
- [支持的 Python 版本](#支持的-python-版本)
- [开发](#开发)
- [文档](#文档)
- [贡献](#贡献)
- [安全](#安全)
- [许可证](#许可证)
- [免责声明](#免责声明)

## 安装

```bash
pip install dftk
```

可选集成以 extras 方式安装：

```bash
pip install "dftk[email]"     # DKIM / SPF / DNS 邮件认证
pip install "dftk[ssh]"       # 固定命令的只读 SSH 清单
pip install "dftk[windows]"   # Windows 注册表 / EVTX 解析器
pip install "dftk[all]"       # 全部可选解析器
```

基础包**刻意保持零强制运行依赖**。E01 文件系统遍历还需取证环境提供 `pyewf` / libewf 绑定以及 `pytsk3`。

## 快速上手

列出所有已注册能力：

```bash
dftk list
```

查看某个工具的契约（参数、安全级别、标签、产出证据）：

```bash
dftk describe android.apk_manifest
```

分析一个取证对象：

```bash
dftk run artifact.inspect --params '{"path":"sample.apk"}'
```

提取 Android Manifest 证据：

```bash
dftk run android.apk_manifest --params '{"path":"sample.apk"}'
```

在 APK 中搜索网络端点：

```bash
dftk run android.apk_endpoints --params '{"path":"sample.apk"}'
```

从抓包文件中提取协议层观测：

```bash
dftk run network.capture_protocols --params '{"path":"traffic.pcapng"}'
```

在不以读写方式打开数据库的前提下搜索 SQLite：

```bash
dftk run database.sqlite_search --params '{"path":"app.db","query":"example"}'
```

运行有边界的第一轮处置配方：

```bash
dftk recipe artifact.auto_triage --params '{"path":"unknown.bin"}'
```

导出完整工具清单（供智能体读取）：

```bash
dftk export-manifest --out manifest.json
```

检查当前运行环境与可选集成：

```bash
dftk doctor
```

建立一个调查案例，并将其各次运行关联为一条统一时间线：

```bash
dftk case new --name intake
dftk case run <case_id> timeline.file_metadata --params '{"root":"mnt/evidence"}'
dftk case timeline <case_id>
```

### 原生 MCP（Agent 接入）

DFTK 3.1 新增原生本地 **stdio MCP** 接口。它只是现有 Registry / Observation / CaseSession 之上的协议适配层，不实现另一套 Agent 运行时。

```bash
pip install "dftk[mcp]"
cd <授权检材根目录>
dftk doctor
dftk mcp
```

MCP 默认 `READ_ONLY`、禁止网络、仅使用 stdio，并只暴露 6 个元工具：环境检查、能力发现、能力描述、运行、Case 管理、读取已持久化的 Case Observation。模型不能自行提高安全等级、开启网络或修改 evidence root；这些只能由启动 MCP 的人员设置。

对于多步调查，先建一个普通 DFTK case，再把 `case_id` 传给 MCP 的 `dftk_run` 工具；Observation 会以 CLI 相同的 `CaseSession` 格式落盘。

### Agent Skill

独立的取证推理指引位于 `DigiForensics/DFTK-skill`。DFTK 3.1 内置了对齐版本的快照，并会安装**整个**渐进式 skill 目录（不只 `SKILL.md`）：

```bash
dftk skill --install
dftk skill --install --target kimi,workbuddy,agents
```

Skill 只承载文档与推理指引，真正的执行能力仍在 DFTK 内。

## Python / 智能体 API

```python
import dftk

registry = dftk.get_registry()

observation = dftk.run_tool(
    "artifact.inspect",
    {"path": "evidence.bin"},
)

print(observation.status)   # ok | partial | error | unsupported | blocked
print(observation.facts)    # 机器可读的发现
print(observation.evidence) # 来源 + 定位 + 取值 + 置信度
```

`get_registry()` 与 `run_tool()` 是稳定的公开集成入口。调用方无需为了注册副作用而导入各原语模块。

## Observation 结果契约

每个工具都返回一个结构化的 `Observation`，具有明确的执行状态：

```text
status       ok | partial | error | unsupported | blocked
facts        机器可读的发现
evidence[]   来源 + 定位 + 取值 + 置信度 / 方法 / 来源哈希
warnings[]   不会抹除有用证据的局限性说明
errors[]     执行或解析失败
meta         工具与运行元数据
```

`unsupported`、`error`、`blocked` 与真正的"无发现（negative finding）"是**不同**的状态。解析器缺失不等于"没有发现"。

## 能力模型

DFTK 3.1.0 包含 **68 个工具**（67 个 `READ_ONLY`、1 个 `STATEFUL`）和 **14 个配方**，覆盖：

- 取证对象识别、哈希、字符串、搜索与时间线；
- APK、DEX、二进制 AXML、Android 应用数据与端点提取；
- ELF 与 PE 清单及原生指标；
- SQLite 与 SQL dump 分析；
- PCAP / PCAPNG、DNS、HTTP 与 TLS SNI 提取；
- Linux 根文件系统、认证与持久化痕迹；
- Docker 元数据与日志；
- Web 配置与访问日志；
- 通过可选解析器的 Windows 注册表、USB 痕迹与 EVTX；
- 通过专业取证绑定的 E01 / TSK 文件系统清单；
- Chromium / Edge 与 Firefox 痕迹；
- MIME / 邮件认证分析；
- BIP39、熵分析与可逆编码辅助；
- 统一时间线关联与调查案例会话：将多个事件源合并为按来源归类的统一时间线，并在隔离的 `dftk case` 工作区中累积工具运行。

### 案例关联与统一时间线

`timeline.merge` 把来自多个 dftk 工具输出（或内联来源）的时间相关事件归一化、关联为一条已排序、按来源归类的时间线——适用于融合文件系统元数据、认证日志与浏览器历史。

`dftk case` 把只读工具封装成隔离的调查会话。它在工作区（`.dftk/cases/<id>/`）下记录每次运行的 `Observation`，并可关联为单一时间线或导出报告：

```bash
dftk case new --name phishing-intake
dftk case run <case_id> timeline.file_metadata --params '{"root":"mnt/phone"}'
dftk case run <case_id> linux.auth_events      --params '{"root":"mnt/server"}'
dftk case timeline <case_id>     # 统一、按来源归类的时间线
dftk case export <case_id> --format md
```

详细能力地图见 [`CAPABILITIES.md`](CAPABILITIES.md)。

## 安全模型

DFTK 把"执行安全"与"取证推理"分开：

| 级别 | 行为 |
|------|------|
| `READ_ONLY` | 读取证据或不可变 / 只读视图 |
| `STATEFUL` | 可写入派生的临时工作区，但不修改原始证据 |
| `DESTRUCTIVE` | 保留给会修改目标的操作；**3.1.0 中未注册任何此类工具** |

默认策略只允许 `READ_ONLY` 操作。网络访问独立受控，必须通过 `--allow-network` 显式开启。受控的归档解压（`archive.extract_safe`）为 `STATEFUL`，除非调用方显式提升安全上限，否则会被拦截：

```bash
dftk run archive.extract_safe \
  --max-safety STATEFUL \
  --params '{"path":"evidence.zip","output_dir":"workspace/extracted"}'
```

完整细节——数据库访问、归档防护、专业解析器语义、遗留脚本策略——见 [`SAFETY.md`](SAFETY.md)。

## 支持的 Python 版本

DFTK 支持跨平台的 **CPython 3.10+**。已在 3.10、3.11、3.12、3.13 上验证。

## 开发

```bash
git clone https://github.com/DigiForensics/DFTK.git
cd DFTK
python -m venv .venv
python -m pip install -e ".[dev]"
pytest -q
```

构建分发包（供维护者）：

```bash
python -m build
python -m twine check --strict dist/*
```

## 文档

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — 公开工具边界、证据契约、原语与配方之别、晋升规则。
- [`CAPABILITIES.md`](CAPABILITIES.md) — 按领域划分的完整能力地图。
- [`SAFETY.md`](SAFETY.md) — 安全级别、网络隔离、数据库/归档防护、专业解析器语义。
- [`AGENT_INTEGRATION.md`](AGENT_INTEGRATION.md) — 原生 stdio MCP 与宿主 Agent 接入示例。
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — 如何新增能力并提交 PR。
- [`SECURITY.md`](SECURITY.md) — 漏洞披露政策。
- [`CHANGELOG.md`](CHANGELOG.md) — 重要公开变更。
- [`PUBLISHING.md`](PUBLISHING.md) — 发布 / PyPI 可信发布工作流。

## 贡献

我们更偏好小而确定的取证原语，而不是针对特定题目的答案脚本。完整指南见 [`CONTRIBUTING.md`](CONTRIBUTING.md)，然后提交 Pull Request。

## 安全

请**私下**报告漏洞，不要公开提 Issue。详见 [`SECURITY.md`](SECURITY.md)。

## 许可证

基于 [Apache License 2.0](LICENSE) 发布。Copyright 2026 DyNooob @ DigiForensics。

## 免责声明

DFTK 是一个技术工具包，不构成法律建议。它旨在支持对你拥有或明确获授权分析的取证证据进行合法、授权的检验。你须自行遵守所在司法辖区的适用法律、授权要求与证据链（chain-of-custody）规范。维护者不对任何滥用行为承担责任。
