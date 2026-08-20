# DFTK — 数字取证工具包

[![CI](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml/badge.svg)](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![PyPI](https://img.shields.io/pypi/v/dftk.svg)](https://pypi.org/project/dftk/)

DFTK 是一个面向证据保全的 Python 数字取证工具包，提供文件、归档、移动端
制品、数据库、流量、浏览器、邮件、主机痕迹和时间线的结构化分析能力。

English: [README.md](README.md)

## 安装

```bash
pip install dftk
```

可选集成：

```bash
pip install "dftk[email]"    # DKIM / SPF / DNS
pip install "dftk[ssh]"      # 只读 SSH 清单
pip install "dftk[windows]"  # 注册表 / EVTX 解析器
pip install "dftk[yara]"     # YARA 规则扫描
pip install "dftk[mcp]"      # 本地 MCP 服务
pip install "dftk[all]"      # 全部可选 Python 集成
```

核心包没有强制第三方运行时依赖。E01 文件系统遍历还需要 `pyewf` / libewf
绑定和 `pytsk3`。

## 快速开始

```bash
# 查看可用能力
dftk list

# 生成供 Agent 使用的证据清单和下一步调查计划
dftk run evidence.intake --params '{"path":"/evidence/acquisition"}'

# 按调查目标查找能力
dftk search "浏览器下载记录"

# 运行前查看参数和安全要求
dftk describe artifact.inspect

# 分析一个制品
dftk run artifact.inspect --params '{"path":"sample.apk"}'

# 将相关结果记录到 Case 中
dftk case --workspace /cases/intake new --name intake
dftk case --workspace /cases/intake run <case_id> artifact.inspect --params '{"path":"sample.apk"}'
dftk case --workspace /cases/intake export <case_id> --format md
```

每次调用返回一个 `Observation`，包括状态、事实、证据、警告和错误。`unsupported`、
`error`、`blocked` 表示限制或失败，不能据此认定“没有发现”。

## Agent 与 MCP

面向 Agent 的推荐入口是本 **DFTK 主仓库**：直接将仓库地址交给 Agent。它先安装
DFTK，再通过 `dftk agent setup --install-skill` 自动拉取匹配的完整
[DFTK-skill](https://github.com/DigiForensics/DFTK-skill) 到当前 Agent 宿主。
具体步骤见 [INSTALL_AGENT.md](INSTALL_AGENT.md)。

DFTK 提供本地 stdio MCP 服务。应将采集证据保持只读，并使用独立、可写的 Case
工作区：

```bash
pip install "dftk[mcp]"
dftk mcp --root /evidence/acquisition --workspace /cases/intake --check
dftk mcp --root /evidence/acquisition --workspace /cases/intake
```

服务默认 `READ_ONLY` 且禁止网络。证据根目录、安全上限、网络权限和超时由启动
参数确定。详细配置见英文 [MCP guide](docs/mcp.md)。

如需手动安装，可为一个明确的宿主安装匹配版本的
[DFTK-skill](https://github.com/DigiForensics/DFTK-skill)：

```bash
dftk agent setup --root /evidence/acquisition --workspace /cases/intake --install-skill
# 广泛安装前先查看所有目标目录
dftk skill --install --target all --dry-run
```

## 文档

- [用户指南](docs/user-guide.md) — CLI、Python API、Case、Observation 和审计日志。
- [MCP 指南](docs/mcp.md) — 本地服务策略和宿主配置。
- [能力地图](CAPABILITIES.md) — 能力领域和分组。
- [架构](ARCHITECTURE.md) — 注册表、证据契约和运行时边界。
- [安全策略](SAFETY.md) — 执行级别、网络门控和源证据保护。
- [外部工具链部署](DEPLOY-TOOLCHAIN.md) — 外部取证二进制工具。
- [开发指南](docs/development.md) — 环境、测试和贡献流程。

## 项目信息

- 发布名：`dftk`；Python 包：`dftk`；命令：`dftk`。
- Python：CPython 3.10+。
- 许可证：[Apache-2.0](LICENSE)。
- 维护者：[DyNooob](https://github.com/DyNooob) · [DigiForensics](https://www.digiforensics.cn)。

DFTK 用于合法、已获授权的证据检验，不构成法律建议。
