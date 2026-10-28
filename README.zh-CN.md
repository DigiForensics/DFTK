# DFTK — 数字取证工具包

[![CI](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml/badge.svg)](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/dftk.svg)](https://pypi.org/project/dftk/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

DFTK 为调查 Agent 提供证据访问、媒体感知、有界操作和带来源的案件记忆。
Agent 决定调查方向、选择工具、关联证据并判断结论；分析人员也可以通过 CLI
和 Python API 使用同一套能力。

**当前源码版本：3.7.0 · 136 个能力 · 29 个领域 · 8 个 MCP 入口。**
一个注册表，136 个工具（131 个 READ_ONLY、5 个 STATEFUL），包含 121 个原语和
15 个配方，没有 DESTRUCTIVE 工具。[English](README.md)

## 目前能做什么

| 证据需求 | DFTK 提供的能力 |
|---|---|
| 找到证据 | 目录分页、签名识别、哈希、文本窗口与字面/正则搜索；清单保留媒体及不可访问内容的线索 |
| 查看图片和视频 | 元数据/EXIF、经授权的原生图片、编号缩略图、原图坐标裁剪、带时间位置的视频抽帧 |
| 读取图片文字 | 本地单图/批量 OCR，优先 CUDA/MPS，返回原始文字、坐标、置信度和来源哈希；CPU 须获明确同意 |
| 继续读取容器内部 | ZIP/TAR 清单与工作区解包、单候选 OpenSSL 解密；同一 Case 内的已登记产物可交给后续工具分析 |
| 解析取证制品 | SQLite/WAL/恢复、Android、浏览器、Windows/Linux、PCAP/PCAPNG、邮件、二进制、文件系统及部分外部引擎适配 |
| 保留和核验调查过程 | Observation 持久化、结果分页、制品处理状态、中断记录、时间线、实体关联、结论引用和审计校验 |

支持范围与限制见[能力地图](CAPABILITIES.md)。配方和下一步建议都是可选助手，
调查不需要固定经过某条工作流。

## 让 Agent 接入

需要 Python 3.10+。在一个长期保留的环境中安装运行时：

```bash
python -m pip install --upgrade "dftk[mcp]"
dftk agent setup \
  --root /evidence/acquisition \
  --workspace /cases/investigation \
  --install-skill \
  --config-out /cases/investigation/dftk-agent-config.json
```

证据目录必须已经存在，应保持只读；可写案件工作区放在证据目录之外。setup 会安装
与运行时版本匹配的完整 [DFTK-skill](https://github.com/DigiForensics/DFTK-skill)，
绑定当前 Python 解释器、默认开启工作区审计账本，并生成 JSON/TOML MCP 配置片段。
按宿主的配置方式导入，再开启新会话；setup 不会自行改写宿主的全局 MCP 配置。

宿主识别不确定时使用 `--target <host>`；`--dry-run` 可预览目标与配置。接入前检查：

```bash
dftk mcp --root /evidence/acquisition --workspace /cases/investigation --check
```

MCP 默认 READ_ONLY、禁止网络，单次工作进程超时为 180 秒。解包、解密、HTTP
响应体导出和 HTML 报告生成需要启动时允许 STATEFUL 操作。详见
[安装指南](INSTALL_AGENT.md)、[Agent 接入](AGENT_INTEGRATION.md)和 [MCP 指南](docs/mcp.md)。

## 图片、视频与 OCR

图片预览/缩略图需要在 MCP 之外安装 `dftk[media]`，本地 OCR 安装 `dftk[ocr]`。
GPU 对应的 PyTorch 和可信 EasyOCR 模型权重需要单独准备，模型目录通过
`DFTK_OCR_MODEL_DIR` 指定。视频元数据和抽帧还需要 PATH 中的 FFmpeg/FFprobe。
取证调用不会临时下载 OCR 模型。

只有当前模型支持图像，且用户已对文件或范围授权时，才向模型提供图片；否则告知
发现了哪些媒体，并保留未查看状态。本地 OCR 与模型视觉分开。GPU 不可用或失败
时，不会静默转 CPU；须说明 CPU 可能非常慢，获得明确同意后才使用 `allow_cpu=true`。

视频目前按时间位置抽帧，每次最多 8 帧，不分析音频或未抽到的内容。缩略图、局部
裁剪、OCR 没识别到文字，都不能证明整份媒体已充分检查。[媒体感知契约](docs/media-perception.md)

## CLI 与 Python

核心包没有强制第三方运行时依赖：

```bash
python -m pip install dftk
dftk suggest /evidence/acquisition/History
dftk search "图片文字识别"
dftk describe database.sqlite_query
dftk run artifact.inspect --params '{"path":"/evidence/acquisition/sample.bin"}'
dftk case --workspace /cases/investigation new --name investigation
dftk case --workspace /cases/investigation run CASE_ID artifact.inspect --params '{"path":"/evidence/acquisition/sample.bin"}'
dftk case --workspace /cases/investigation coverage CASE_ID
```

`CASE_ID` 替换为 `case new` 返回的实际 ID。以上 JSON 引号适用于 POSIX shell；
跨平台或含敏感参数时使用 `--params-file`。直接 CLI 调用不继承 MCP 的根目录和进程超时。

```python
import dftk

result = dftk.run_tool("artifact.inspect", {"path": "/evidence/sample.bin"})
print(result.to_dict())
```

每次能力调用返回 Observation，包含状态、事实、证据及限制。`partial` 仍需检查
警告；`unsupported`、`blocked`、`error` 都不能解释为“目标行为不存在”。[用户指南](docs/user-guide.md)

## 可选集成

| Extra | 用途 |
|---|---|
| `mcp` | 本地 stdio MCP 服务，SDK 范围为 `>=2.0.0,<3` |
| `media` / `ocr` | Pillow 图片预览 / EasyOCR 及其依赖 |
| `windows` | 可选注册表/EVTX 解析器；另有多种原生主机痕迹解析器 |
| `image` / `ese` | EWF/TSK 绑定 / SRUM ESE 读取，可能需要本地库或编译环境 |
| `email` / `ssh` / `yara` | DKIM/SPF/DNS / 固定 SSH 采集 / YARA 扫描 |
| `all` | 全部可选 Python 依赖，包含 OCR 和原生绑定；外部程序、模型权重仍需另行准备 |

`dftk doctor` 显示依赖就绪情况和安装缺口。发现某个外部工具，不代表 DFTK 已封装
它的全部命令。[外部工具链部署](DEPLOY-TOOLCHAIN.md)

## 文档与能力边界

- [用户指南](docs/user-guide.md)：发现能力、Case、结果、Python 和审计。
- [能力地图](CAPABILITIES.md)与[静态清单](docs/capabilities.json)。
- [架构](ARCHITECTURE.md)、[安全策略](SAFETY.md)和[漏洞报告](SECURITY.md)。
- [事件链狩猎](docs/sequence-hunting.md)与[可靠性验证](docs/agent-reliability.md)。
- [开发指南](docs/development.md)、[文档维护](docs/documentation.md)和[发布流程](PUBLISHING.md)。
- [3.7.0 发布说明](RELEASE_NOTES_3.7.md)与[更新记录](CHANGELOG.md)。

DFTK 不保证完整采集或真实案件的证据召回率。部分加密 ZIP 方法与 RAR/7z 解包
仍不支持。OpenSSL 解密需要给定候选和明确参数，不会猜测，也不会对主 Agent
施加跨调用的全局重试预算。MCP 路径检查约束 DFTK 调用，不能限制宿主拥有的其他
工具。应保留原始证据，并在形成结论前检查覆盖缺口。

发布名、导入包和命令均为 `dftk`。维护者：[DyNooob](https://github.com/DyNooob)
（[DigiForensics](https://www.digiforensics.cn)）。许可证：[Apache-2.0](LICENSE)。
