# DFTK Skill

这是 [DigiForensics/DFTK](https://github.com/DigiForensics/DFTK) 的独立 Agent Skill。

DFTK 提供确定性的取证能力与结构化的 `Observation / Evidence` 输出。本仓库教 Agent 如何把一个取证问题转成证据需求、选对 DFTK 能力、核验发现，并写出能回溯到来源的结论。

## 版本

`3.1.0`，与 DFTK `3.1.x` 对齐。

## 安装

请安装**整个 Skill 目录**，不要只复制 `SKILL.md`。Skill 按需加载 `references/`，少了这个目录指引就断了。

常见目录：

```text
~/.agents/skills/dftk/
~/.kimi-code/skills/dftk/
~/.workbuddy/skills/dftk/
~/.claude/skills/dftk/
~/.codex/skills/dftk/
~/.hermes/skills/dftk/
```

或安装 DFTK 3.1 发行版内置的快照：

```bash
dftk skill --install
```

## 目录结构

```text
dftk/
  SKILL.md            # 入口：何时用 DFTK、如何界定调查范围
  references/         # 各领域操作手册，按需加载
  examples/           # 已完成的调查片段示例
  templates/          # 输出报告模板
```

## 设计边界

本仓库不含取证解析器，也不实现 Agent 运行时。它只放 Agent 指令、references、examples 和 templates。执行能力仍在 `DFTK` 主仓库 / PyPI 包中。
