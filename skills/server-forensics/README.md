# Server Forensics Skill

A standalone Agent Skill for **live Linux server and web-application forensics**. It teaches an Agent how to investigate a running server (typically reached over SSH) using standard read-only system tooling, and how to report conclusions that trace back to source.

This skill complements [DigiForensics/DFTK](https://github.com/DigiForensics/DFTK): prefer DFTK when the evidence is a local file or disk image; use this skill when the evidence is a running server whose answers live in config files, live databases, process/port state, or encrypted archives.

## Version

`1.0.0`

## What it covers

- Disk partition identity (PARTUUID / filesystem UUID)
- Service and port enumeration, and the meaning of "对外端口" (host-published vs container port)
- Web-application configuration and embedded credential review
- Live RDBMS forensics: MySQL/MariaDB enumeration, PII lookup by stable key, amount aggregation, password-hash format detection
- OpenSSL encrypted-archive identification and password recovery
- Containerized evidence access (`docker inspect`/`exec`, volume MySQL, bridge-auth gotcha)
- SSH live-forensics workflow (read-only, provenance-preserving)

## Install

Install the **whole `server-forensics/` skill directory**, not just `SKILL.md`. The skill loads `references/` on demand, so omitting that folder breaks the guidance.

Common user-level locations:

```text
~/.workbuddy/skills/server-forensics/
~/.agents/skills/server-forensics/
~/.kimi-code/skills/server-forensics/
~/.claude/skills/server-forensics/
~/.codex/skills/server-forensics/
~/.hermes/skills/server-forensics/
```

Manual install (copy the directory):

```bash
git clone https://github.com/DigiForensics/DFTK
cp -r DFTK/skills/server-forensics ~/.workbuddy/skills/server-forensics
```

Or, if you already have the DFTK repo locally:

```bash
cp -r /path/to/DFTK/skills/server-forensics ~/.workbuddy/skills/server-forensics
```

Then restart/refresh the Agent so it loads the new skill.

## Structure

```text
server-forensics/
  SKILL.md            # entry point: when to use, how to scope a server investigation
  references/         # domain playbooks, loaded progressively
  examples/           # worked investigations (method only; keep exam questions/answers separate)
  templates/          # output report templates (claim-card, finding, case-report)
  LICENSE
```

## Design boundary

This repository contains no forensic parser and no Agent runtime. It holds Agent instructions, references, examples, and templates. The executable capabilities are the target server's own CLI tools. The skill is a read-only investigation methodology; it never authorizes writing to or mutating evidence unless the user explicitly instructs otherwise.
