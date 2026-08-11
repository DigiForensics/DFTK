# DFTK — 数字取证工具包（Digital Forensics Toolkit）

[![CI](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml/badge.svg)](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![PyPI](https://img.shields.io/badge/PyPI-dftk%20%C2%B7%20soon-lightgrey.svg)](#安装)

**面向取证分析师、自动化系统与自主智能体的、保留证据完整性的取证原语与可组合工作流。**

> 🇺🇸 English: [README.md](README.md)

- **发布名：** `dftk` · **导入包名：** `dftk` · **命令行命令：** `dftk`
- **维护者：** [DyNooob](https://github.com/DyNooob) — DigiForensics
- **所属组织：** [DigiForensics](https://www.digiforensics.cn) · [LLMCN](https://www.llmcn.org)
- **许可证：** [Apache-2.0](LICENSE)

---

DFTK 是一个**能力层（capability layer）**，而不是一个自主取证智能体。它对外提供稳定、结构化的取证操作，既可以直接通过命令行调用，也可以由上层 Agent / TaskGraph 运行时进行组合。每次操作都会返回一个标准化的 `Observation`，其中包含明确的状态、机器可读的事实，以及可溯源到来源的证据——这样上层系统就能基于结果进行推理，而不必再去解析终端输出。

## 为什么选择 DFTK

- **以证据为先。** 默认只读；除非你显式提升安全级别，否则任何操作都不会修改原始证据。
- **零强制依赖。** 基础包可在任何环境干净安装，无需任何第三方运行依赖。专业解析器（E01/TSK、Windows 注册表/EVTX、DKIM/SPF、SSH）为可选扩展；缺失时返回 `unsupported`，而非静默猜测。
- **面向智能体。** 统一的 66 个工具注册表，带有 JSON 契约、语义标签、声明的安全级别、网络开关，以及所产出证据的类型——便于规划器根据证据需求选择工具。
- **默认安全。** `READ_ONLY < STATEFUL < DESTRUCTIVE`；所有注册工具中没有任何一个是 `DESTRUCTIVE`。网络流量需显式开启，独立受控。

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

## WorkBuddy 技能（Skill）

dftk 附带一个开箱即用的 [WorkBuddy 技能](skills/dftk/SKILL.md)，让智能体能在对话中直接发现并驱动本工具集。将其目录复制到技能目录即可安装：

```bash
# 用户级
cp -r skills/dftk ~/.workbuddy/skills/dftk
# 或项目级（与团队共享）
cp -r skills/dftk .workbuddy/skills/dftk
```

加载后，智能体即可通过 CLI 执行 `list` / `describe` / `run` / `recipe`，并解读结构化的 `Observation` 输出。该技能固化了经过验证的调用方式（`PYTHONPATH=src python -m dftk.cli …`）、安全模型（默认 READ_ONLY、网络受控）与结果契约，使取证在结构上保持证据保全。

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

`unsupported`、`error`、`blocked` 与真正的“无发现（negative finding）”是**不同**的状态——解析器缺失不等于“没有发现”。

## 能力模型

DFTK 2.1.0 包含 **66 个工具**（65 个 `READ_ONLY`、1 个 `STATEFUL`）和 **13 个配方**，覆盖：

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
- BIP39、熵分析与可逆编码辅助。

详细能力地图见 [`CAPABILITIES.md`](CAPABILITIES.md)。

## 安全模型

DFTK 将“执行安全”与“取证推理”分离：

| 级别 | 行为 |
|------|------|
| `READ_ONLY` | 读取证据或不可变 / 只读视图 |
| `STATEFUL` | 可写入派生的临时工作区，但不修改原始证据 |
| `DESTRUCTIVE` | 保留给会修改目标的操作；**2.1.0 中未注册任何此类工具** |

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
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — 如何新增能力并提交 PR。
- [`SECURITY.md`](SECURITY.md) — 漏洞披露政策。
- [`CHANGELOG.md`](CHANGELOG.md) — 重要公开变更。
- [`PUBLISHING.md`](PUBLISHING.md) — 发布 / PyPI 可信发布工作流。

## 贡献

我们更倾向于小而确定的取证原语，而不是针对特定题目的答案脚本。完整指南见 [`CONTRIBUTING.md`](CONTRIBUTING.md)，然后提交 Pull Request。

## 安全

请**私下**报告漏洞，不要公开提 Issue。详见 [`SECURITY.md`](SECURITY.md)。

## 许可证

基于 [Apache License 2.0](LICENSE) 发布。Copyright 2026 DyNooob @ DigiForensics。

## 免责声明

DFTK 是一个技术工具包，不构成法律建议。它旨在支持对你拥有或明确获授权分析的取证证据进行合法、授权的检验。用户须自行遵守所在司法辖区的适用法律、授权要求与证据链（chain-of-custody）规范。维护者不对任何滥用行为承担责任。
