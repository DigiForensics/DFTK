# DFTK Skill

这是 [DigiForensics/DFTK](https://github.com/DigiForensics/DFTK) 的独立 Agent Skill。

DFTK 负责确定性的电子数据取证能力与结构化 `Observation / Evidence`；本仓库只负责告诉 Agent 如何从问题建立证据需求、发现并选择 DFTK 能力、判断证据是否足够、避免错误关联和错误否定，并输出可复核结论。

## 版本

`3.1.0`，与 DFTK `3.1.x` 对齐。

## 安装

请安装**整个 Skill 目录**，不要只复制 `SKILL.md`，因为详细取证知识位于 `references/` 中并按需加载。

常见目录：

```text
~/.agents/skills/dftk/
~/.kimi-code/skills/dftk/
~/.workbuddy/skills/dftk/
~/.claude/skills/dftk/
~/.codex/skills/dftk/
~/.hermes/skills/dftk/
```

DFTK 3.1 也可以安装其发行版内置快照：

```bash
dftk skill --install
```

本仓库不包含取证解析器，也不实现另一个 Agent Runtime；执行能力仍属于 DFTK 主项目。
