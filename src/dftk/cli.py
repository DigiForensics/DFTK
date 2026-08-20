# Copyright 2026 DyNooob @ DigiForensics
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import annotations

import argparse
import json
import os
import shutil
from types import SimpleNamespace
from pathlib import Path

from .catalog import load_builtin_tools
from .core.models import SafetyLevel
from .core.registry import registry
from .core.safety import SafetyPolicy
from .core.audit import ToolAuditLog
from .skill_bundle import (
    SKILL_REPO_WEB,
    fetch_skill_repo,
    install_from_repo_root,
    install_skill,
)
from .manifest import capability_manifest

from . import __version__ as TOOLKIT_VERSION  # single source of truth; never hardcode

# Known user-level Agent skill directories. `agents` is the generic shared
# Agent Skills location used by multiple products; product-specific locations
# are included only where DFTK has a stable directory contract.
AGENT_SKILL_DIRS = {
    "workbuddy": ".workbuddy/skills",
    "codebuddy": ".codebuddy/skills",
    "kimi": ".kimi-code/skills",
    "claude": ".claude/skills",
    "codex": ".codex/skills",
    "hermes": ".hermes/skills",
    "agents": ".agents/skills",
    "cursor": ".cursor/skills",
    "gemini": ".gemini/skills",
}


def _load_params(args):
    if getattr(args, "params_file", None):
        return json.loads(Path(args.params_file).read_text(encoding="utf-8"))
    if getattr(args, "params", None):
        return json.loads(args.params)
    return {}


def _emit(data, out=None, *, force: bool = False):
    text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    if out:
        target = Path(out)
        if target.exists() and not force:
            raise FileExistsError(f"refusing to overwrite existing output: {target} (pass --force to replace it)")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    print(text)


def _observation_exit_code(status) -> int:
    """Map an Observation status to a shell-friendly exit code.

    Exit code 2 means the requested operation did not run to a usable result because
    it was unsupported or blocked. This lets automation distinguish that condition
    from a successful, possibly partial result (0) and an execution error (1).
    """
    value = getattr(status, "value", status)
    if value in ("ok", "partial"):
        return 0
    if value in ("unsupported", "blocked"):
        return 2
    return 1


def _spec_dict(spec):
    return {
        "name": spec.name,
        "description": spec.description,
        "safety": spec.safety.name,
        "network": spec.network,
        "parameters": spec.parameters,
        "tags": list(spec.tags),
        "produces": list(spec.produces),
        "requires": list(spec.requires),
        "deterministic": spec.deterministic,
        "cost_hint": spec.cost_hint,
    }


def _resolve_targets(spec):
    normalized = (spec or "auto").strip().lower()
    if normalized == "auto":
        # Prefer an explicit host runtime marker. Falling back to exactly one
        # existing host directory supports local Agents without requiring users
        # to know an installation target; ambiguous machines use the portable
        # AgentSkills directory instead of writing into multiple hosts.
        markers = {
            "codex": ("CODEX_HOME",), "claude": ("CLAUDE_CODE", "CLAUDECODE"),
            "cursor": ("CURSOR_TRACE_ID",), "gemini": ("GEMINI_CLI",),
        }
        for target, names in markers.items():
            if any(os.environ.get(name) for name in names):
                return [target]
        home = Path.home()
        present = [target for target, relative in AGENT_SKILL_DIRS.items() if (home / relative).parent.exists()]
        return present if len(present) == 1 else ["agents"]
    if normalized == "all":
        return list(AGENT_SKILL_DIRS.keys())
    out = []
    for target in normalized.split(","):
        target = target.strip().lower()
        if not target:
            continue
        if target not in AGENT_SKILL_DIRS:
            raise ValueError(
                f"unknown agent target: {target!r} "
                f"(known: {', '.join(AGENT_SKILL_DIRS)})"
            )
        out.append(target)
    return out


def _cmd_skill(args):
    if not getattr(args, "install", False):
        print(SKILL_REPO_WEB)
        print("Install with: dftk skill --install   (use --ref to pin a version)")
        return 0

    ref = getattr(args, "ref", None)
    custom = getattr(args, "dir", None)

    if custom:
        if getattr(args, "dry_run", False):
            _emit({
                "action": "install_dftk_skill",
                "targets": {"custom": str(Path(custom).expanduser())},
                "ref": ref or f"v{TOOLKIT_VERSION}",
                "writes": False,
            })
            return 0
        try:
            installed = install_skill(ref, custom)
        except Exception as exc:  # noqa: BLE001
            _emit({"error": f"failed to fetch/install DFTK skill: {exc}"})
            return 2
        for path in installed:
            print(f"installed -> {path}")
        print(f"\nInstalled DFTK skill + standalone skills into {custom}")
        return 0

    try:
        targets = _resolve_targets(args.target)
    except ValueError as exc:
        _emit({"error": str(exc)})
        return 2

    home = Path.home()
    if getattr(args, "dry_run", False):
        _emit({
            "action": "install_dftk_skill",
            "targets": {target: str(home / AGENT_SKILL_DIRS[target]) for target in targets},
            "ref": ref or f"v{TOOLKIT_VERSION}",
            "writes": False,
        })
        return 0

    installed_all: list[Path] = []
    failures: dict[str, str] = {}
    repo_root = None
    try:
        repo_root = fetch_skill_repo(ref)
        for target in targets:
            base = home / AGENT_SKILL_DIRS[target]
            try:
                installed_all.extend(install_from_repo_root(repo_root, base))
            except Exception as exc:  # noqa: BLE001
                failures[target] = str(exc)
    except Exception as exc:  # noqa: BLE001
        _emit({"error": f"failed to fetch/install DFTK skill: {exc}"})
        return 2
    finally:
        if repo_root is not None:
            shutil.rmtree(repo_root, ignore_errors=True)

    for path in installed_all:
        print(f"installed -> {path}")
    if not installed_all:
        _emit({"error": "no skill directories could be written"})
        return 1
    print(
        f"\nInstalled DFTK skill + standalone skills for {len(targets)} "
        f"agent target(s): {', '.join(targets)}"
    )
    if failures:
        _emit({"status": "partial", "failed_targets": failures})
        return 1
    return 0


def _agent_mcp_config(args):
    """Build a portable, reviewable MCP launch entry for an Agent host.

    This deliberately returns a fragment instead of editing a host's global
    configuration file. Host configuration formats and trust prompts differ,
    and an investigation Agent must not overwrite unrelated MCP connections.
    """
    root = Path(args.root).expanduser().resolve()
    workspace = Path(args.workspace).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"evidence root is not a directory: {root}")
    if root == workspace or root in workspace.parents:
        raise ValueError("workspace must be outside the evidence root")
    launch_args = [
        "mcp", "--root", str(root), "--workspace", str(workspace),
        "--max-safety", args.max_safety, "--timeout", str(args.timeout),
    ]
    if args.allow_network:
        launch_args.append("--allow-network")
    if args.audit:
        launch_args.extend(["--audit", str(Path(args.audit).expanduser().resolve())])
    json_fragment = {"mcpServers": {"dftk": {"command": "dftk", "args": launch_args}}}
    toml_args = ", ".join(json.dumps(item) for item in launch_args)
    return {
        "schema_version": "1",
        "toolkit_version": TOOLKIT_VERSION,
        "host_target": args.target,
        "evidence_root": str(root),
        "case_workspace": str(workspace),
        "mcp_json": json_fragment,
        "codex_toml": "[mcp_servers.dftk]\ncommand = \"dftk\"\nargs = [" + toml_args + "]\n",
        "verification": [
            "dftk mcp --root " + str(root) + " --workspace " + str(workspace) + " --check",
            "Start a new Agent session after importing and approving the MCP entry.",
        ],
        "safety_note": "The server is READ_ONLY by default; only the host owner can raise policy or enable network access.",
    }


def _cmd_agent(args):
    if args.agent_cmd != "setup":
        _emit({"error": "unknown agent subcommand"})
        return 2
    try:
        config = _agent_mcp_config(args)
    except ValueError as exc:
        _emit({"error": str(exc)})
        return 2

    workspace = Path(args.workspace).expanduser()
    if args.dry_run:
        config["writes"] = {"workspace": False, "config": False, "skills": False}
        _emit(config)
        return 0

    workspace.mkdir(parents=True, exist_ok=True)
    config["writes"] = {"workspace": True, "config": bool(args.config_out), "skills": bool(args.install_skill)}
    if args.config_out:
        try:
            _emit(config, args.config_out, force=args.force)
        except OSError as exc:
            _emit({"error": str(exc)})
            return 2
    else:
        _emit(config)

    if args.install_skill:
        # Reuse the hardened, version-pinned installer rather than duplicating
        # fetch/extraction logic here.
        skill_args = SimpleNamespace(
            install=True, ref=args.ref, dir=None, target=args.target, dry_run=False,
        )
        result = _cmd_skill(skill_args)
        if result:
            return result
    return 0


def _cmd_case(args):
    from .core.case import CaseError, CaseSession

    session = CaseSession(getattr(args, "workspace", None))
    cmd = getattr(args, "case_cmd", None)
    if cmd == "new":
        _emit(session.new(args.name))
        return 0
    if cmd == "list":
        _emit(session.list())
        return 0
    if cmd == "run":
        try:
            params = _load_params(args)
        except Exception as exc:
            _emit({"error": f"invalid params JSON: {exc}"})
            return 2
        audit = ToolAuditLog(args.audit) if args.audit else None
        obs = session.run(
            args.case_id,
            args.tool,
            params,
            allow_network=args.allow_network,
            max_safety=args.max_safety,
            audit=audit,
            caller=f"case:{args.case_id}",
        )
        _emit(obs.to_dict())
        return _observation_exit_code(obs.status)
    if cmd == "timeline":
        try:
            obs = session.timeline(args.case_id)
        except CaseError as exc:
            _emit({"error": str(exc)})
            return 2
        try:
            _emit(obs.to_dict(), args.out, force=args.force)
        except OSError as exc:
            _emit({"error": str(exc)})
            return 2
        return 0
    if cmd == "graph":
        try:
            _emit(session.entity_graph(args.case_id).to_dict())
        except CaseError as exc:
            _emit({"error": str(exc)})
            return 2
        return 0
    if cmd == "next":
        try:
            _emit(session.next_actions(args.case_id))
        except CaseError as exc:
            _emit({"error": str(exc)})
            return 2
        return 0
    if cmd == "guided-intake":
        try:
            _emit(session.guided_intake(args.case_id, args.path, objective=args.objective, max_steps=args.max_steps))
        except CaseError as exc:
            _emit({"error": str(exc)})
            return 2
        return 0
    if cmd == "brief":
        try:
            _emit(session.brief(args.case_id))
        except CaseError as exc:
            _emit({"error": str(exc)})
            return 2
        return 0
    if cmd == "export":
        try:
            text = session.export(args.case_id, fmt=args.format)
        except CaseError as exc:
            _emit({"error": str(exc)})
            return 2
        if args.out:
            target = Path(args.out)
            if target.exists() and not args.force:
                _emit({"error": f"refusing to overwrite existing output: {target} (pass --force to replace it)"})
                return 2
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            print(f"exported -> {target}")
        else:
            print(text)
        return 0
    _emit({"error": "unknown case subcommand"})
    return 2


def _cmd_doctor(_args):
    from .doctor import doctor_report

    report = doctor_report()
    _emit(report)
    return 0 if report.get("ok") else 1


def _cmd_prepare(args):
    from .core import toolchain

    if getattr(args, "show", False):
        _emit(
            {
                "toolchain": toolchain.load_toolchain(),
                "config_path": str(toolchain.toolchain_config_path()),
            }
        )
        return 0

    root = getattr(args, "toolkit_root", None) or os.environ.get("DFTK_TOOLS")
    if not root:
        _emit({"error": "no toolkit root given; pass a path or set DFTK_TOOLS"})
        return 2
    try:
        report = toolchain.prepare(
            root,
            bin_dir=getattr(args, "bin_dir", None),
            rewrite_from=getattr(args, "rewrite_from", None),
            make_shims=not getattr(args, "no_shims", False),
        )
    except Exception as exc:  # noqa: BLE001
        _emit({"error": f"dftk prepare failed: {exc}"})
        return 2
    _emit(report)
    if report.get("found"):
        print("\nTools are now discoverable by DFTK (verify with: dftk doctor).")
        print("To also call them by bare name in a plain terminal, source the helper:")
        print(f"  Windows:  {report['bin_dir']}\\set_path.bat")
        print(f'  Bash:     . "{report["bin_dir"]}/set_path.sh"')
    else:
        print("\nNo known external tools were found under that root.")
    return 0


def _cmd_mcp(args):
    try:
        from .mcp_server import DFTKMCPGateway, run_mcp_server

        if getattr(args, "check", False):
            gateway = DFTKMCPGateway(
                root=args.root,
                workspace=args.workspace,
                allow_workspace_in_root=args.allow_workspace_in_root,
                max_safety=args.max_safety,
                allow_network=args.allow_network,
                timeout_seconds=args.timeout,
                audit=args.audit,
            )
            report = gateway.preflight()
            report["preflight"] = {
                "root_readable": True,
                "workspace_writable": True,
                "workspace_inside_root": gateway.workspace_inside_root,
                "safe_evidence_isolation": not gateway.workspace_inside_root,
            }
            _emit(report)
            return 0

        run_mcp_server(
            root=args.root,
            workspace=args.workspace,
            allow_workspace_in_root=args.allow_workspace_in_root,
            max_safety=args.max_safety,
            allow_network=args.allow_network,
            timeout_seconds=args.timeout,
            audit=args.audit,
        )
        return 0
    except Exception as exc:
        # MCP stdio reserves stdout for protocol traffic once serving begins;
        # startup failures occur before serving and are intentionally explicit.
        import sys

        print(f"dftk mcp: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


def main(argv=None):
    load_builtin_tools()
    parser = argparse.ArgumentParser(prog="dftk")
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOLKIT_VERSION}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ls = sub.add_parser("list", help="list registered tools")
    ls.add_argument("--tag", action="append")
    ls.add_argument("--produces")

    describe = sub.add_parser("describe")
    describe.add_argument("name")

    search = sub.add_parser("search", help="find capabilities from an evidence task or keyword")
    search.add_argument("query", nargs="?", default="")
    search.add_argument("--tag", action="append")
    search.add_argument("--produces")
    search.add_argument("--limit", type=int, default=12)

    run = sub.add_parser("run")
    run.add_argument("name")
    run.add_argument("--params")
    run.add_argument("--params-file")
    run.add_argument("--out")
    run.add_argument("--force", action="store_true", help="allow --out to replace an existing file")
    run.add_argument("--allow-network", action="store_true")
    run.add_argument(
        "--max-safety",
        choices=["READ_ONLY", "STATEFUL", "DESTRUCTIVE"],
        default="READ_ONLY",
    )
    run.add_argument("--audit", metavar="PATH", help="append a JSONL chain-of-custody record of this run to PATH")

    recipe = sub.add_parser("recipe")
    recipe.add_argument("name")
    recipe.add_argument("--params")
    recipe.add_argument("--params-file")
    recipe.add_argument("--out")
    recipe.add_argument("--force", action="store_true", help="allow --out to replace an existing file")
    recipe.add_argument("--audit", metavar="PATH", help="append a JSONL chain-of-custody record of this run to PATH")

    export = sub.add_parser("export-manifest")
    export.add_argument("--out")
    export.add_argument("--force", action="store_true", help="allow --out to replace an existing file")

    doctor = sub.add_parser("doctor", help="check DFTK runtime, capabilities and optional integrations")

    prepare = sub.add_parser(
        "prepare",
        help="prepare an extracted forensic-toolkit directory so DFTK can find its tools",
    )
    prepare.add_argument(
        "toolkit_root",
        nargs="?",
        help="extracted toolkit root (default: $DFTK_TOOLS)",
    )
    prepare.add_argument(
        "--bin-dir",
        metavar="DIR",
        help="shim directory for launchers (default: ~/.dftk/bin)",
    )
    prepare.add_argument(
        "--rewrite-from",
        metavar="OLD_ROOT",
        help="rewrite this hardcoded root inside the bundle to the toolkit root",
    )
    prepare.add_argument(
        "--no-shims",
        action="store_true",
        help="only record the toolkit root; skip shim generation",
    )
    prepare.add_argument(
        "--show",
        action="store_true",
        help="print the current toolchain config and exit",
    )

    skill = sub.add_parser("skill", help="show/install the DFTK Agent Skill (fetched from GitHub)")
    skill.add_argument("--install", action="store_true", help="fetch the DFTK-skill repo and install the main skill + standalone analysis skills")
    skill.add_argument(
        "--target",
        default="auto",
        metavar="LIST",
        help=(
            '"auto" (default), comma-separated targets, or "all" '
            "(workbuddy,codebuddy,kimi,claude,codex,hermes,agents,cursor,gemini)"
        ),
    )
    skill.add_argument("--dir", metavar="DIR", help="install into a custom skills base directory instead of known Agent targets")
    skill.add_argument("--ref", metavar="REF", help="pin the DFTK-skill ref (tag/branch/sha); default: v<dftk version>")
    skill.add_argument("--dry-run", action="store_true", help="show target directories without fetching or writing")

    agent = sub.add_parser("agent", help="prepare a reviewable Agent Skill + MCP integration")
    agent_sub = agent.add_subparsers(dest="agent_cmd", required=True)
    agent_setup = agent_sub.add_parser("setup", help="create a bounded MCP config fragment and optionally install the matching Skill")
    agent_setup.add_argument("--root", required=True, metavar="DIR", help="read-only evidence root exposed to MCP")
    agent_setup.add_argument("--workspace", required=True, metavar="DIR", help="separate writable case workspace")
    agent_setup.add_argument("--target", default="auto", help="Skill target for --install-skill (default: auto)")
    agent_setup.add_argument("--install-skill", action="store_true", help="install the version-matched DFTK-skill bundle after setup")
    agent_setup.add_argument("--ref", metavar="REF", help="pin DFTK-skill ref; default: v<dftk version>")
    agent_setup.add_argument("--config-out", metavar="PATH", help="write the generated config JSON without replacing an existing file")
    agent_setup.add_argument("--force", action="store_true", help="allow --config-out to replace an existing file")
    agent_setup.add_argument("--dry-run", action="store_true", help="validate and show planned writes without creating files or installing skills")
    agent_setup.add_argument("--max-safety", choices=["READ_ONLY", "STATEFUL"], default="READ_ONLY")
    agent_setup.add_argument("--allow-network", action="store_true", help="include an authorized network opt-in in the launch fragment")
    agent_setup.add_argument("--timeout", type=int, default=180, metavar="SECONDS")
    agent_setup.add_argument("--audit", metavar="PATH", help="include a chain-of-custody audit ledger path in the launch fragment")

    case = sub.add_parser("case", help="build and correlate an investigation case / unified timeline")
    case.add_argument("--workspace", metavar="DIR", help="case workspace root (default: $DFTK_WORKSPACE or ~/.dftk, outside evidence)")
    case_sub = case.add_subparsers(dest="case_cmd", required=True)
    case_new = case_sub.add_parser("new", help="create a new case and print its manifest")
    case_new.add_argument("--name")
    case_sub.add_parser("list", help="list cases in the workspace")
    case_graph = case_sub.add_parser("graph", help="correlate entities across persisted Case Observations")
    case_graph.add_argument("case_id")
    case_next = case_sub.add_parser("next", help="show compact, deterministic Agent next actions for a Case")
    case_next.add_argument("case_id")
    case_guided = case_sub.add_parser("guided-intake", help="persist a controlled Agent first response as separate Case runs")
    case_guided.add_argument("case_id")
    case_guided.add_argument("path")
    case_guided.add_argument("--objective")
    case_guided.add_argument("--max-steps", type=int, default=2)
    case_brief = case_sub.add_parser("brief", help="return a bounded Agent-context checkpoint for a Case")
    case_brief.add_argument("case_id")
    case_run = case_sub.add_parser("run", help="run a tool and record its Observation in the case")
    case_run.add_argument("case_id")
    case_run.add_argument("tool")
    case_run.add_argument("--params")
    case_run.add_argument("--params-file")
    case_run.add_argument("--allow-network", action="store_true")
    case_run.add_argument(
        "--max-safety",
        choices=["READ_ONLY", "STATEFUL", "DESTRUCTIVE"],
        default="READ_ONLY",
    )
    case_run.add_argument("--audit", metavar="PATH", help="append a JSONL chain-of-custody record of this run to PATH")
    case_timeline = case_sub.add_parser("timeline", help="merge all recorded Observations into one timeline")
    case_timeline.add_argument("case_id")
    case_timeline.add_argument("--out")
    case_timeline.add_argument("--force", action="store_true", help="allow --out to replace an existing file")
    case_export = case_sub.add_parser("export", help="export a case report (json or markdown)")
    case_export.add_argument("case_id")
    case_export.add_argument("--format", choices=["json", "md"], default="json")
    case_export.add_argument("--out")
    case_export.add_argument("--force", action="store_true", help="allow --out to replace an existing file")

    mcp = sub.add_parser("mcp", help="run the native local DFTK MCP server over stdio")
    mcp.add_argument("--root", default=".", metavar="DIR", help="filesystem evidence root visible to DFTK MCP (default: current directory)")
    mcp.add_argument("--workspace", metavar="DIR", help="writable case workspace outside --root (default: $DFTK_WORKSPACE or ~/.dftk)")
    mcp.add_argument("--allow-workspace-in-root", action="store_true", help="allow derived case data inside the evidence root (not recommended)")
    mcp.add_argument("--check", action="store_true", help="validate root, workspace, dependencies, and policy without starting the stdio server")
    mcp.add_argument("--max-safety", choices=["READ_ONLY", "STATEFUL"], default="READ_ONLY", help="server-owned capability safety ceiling")
    mcp.add_argument("--allow-network", action="store_true", help="server-owned opt-in for capabilities that declare network access")
    mcp.add_argument("--timeout", type=int, default=180, metavar="SECONDS", help="hard timeout for one capability run (default: 180)")
    mcp.add_argument("--audit", nargs="?", const="audit.jsonl", metavar="PATH",
                     help="record a JSONL chain-of-custody ledger of every MCP capability run "
                          "(default location: <workspace>/audit.jsonl when flag is given without a path)")

    args = parser.parse_args(argv)

    if args.cmd == "skill":
        return _cmd_skill(args)
    if args.cmd == "agent":
        return _cmd_agent(args)
    if args.cmd == "case":
        return _cmd_case(args)
    if args.cmd == "doctor":
        return _cmd_doctor(args)
    if args.cmd == "prepare":
        return _cmd_prepare(args)
    if args.cmd == "mcp":
        return _cmd_mcp(args)
    if args.cmd == "list":
        _emit([_spec_dict(spec) for spec in registry.find(tags=args.tag, produces=args.produces)])
        return 0
    if args.cmd == "describe":
        try:
            _emit(_spec_dict(registry.get(args.name)))
            return 0
        except KeyError:
            _emit({"error": f"unknown tool: {args.name}"})
            return 2
    if args.cmd == "search":
        # The MCP gateway owns the same human-language matching vocabulary.
        # Constructing it does not create a workspace or start an MCP server.
        from .mcp_server import DFTKMCPGateway

        gateway = DFTKMCPGateway(root=Path.cwd())
        _emit(gateway.search(args.query, tags=args.tag, produces=args.produces, limit=args.limit))
        return 0
    if args.cmd == "export-manifest":
        try:
            _emit(capability_manifest(), args.out, force=args.force)
        except OSError as exc:
            _emit({"error": str(exc)})
            return 2
        return 0

    try:
        params = _load_params(args)
    except Exception as exc:
        _emit({"error": f"invalid params JSON: {exc}"})
        return 2
    if args.cmd == "recipe":
        name = args.name if args.name.startswith("recipe.") else "recipe." + args.name
        audit = ToolAuditLog(args.audit) if args.audit else None
        obs = registry.run(name, params, SafetyPolicy(), audit=audit, caller="cli")
        try:
            _emit(obs.to_dict(), args.out, force=args.force)
        except OSError as exc:
            _emit({"error": str(exc)})
            return 2
        return _observation_exit_code(obs.status)

    policy = SafetyPolicy(
        max_level=SafetyLevel[args.max_safety],
        allow_network=args.allow_network,
    )
    audit = ToolAuditLog(args.audit) if args.audit else None
    obs = registry.run(args.name, params, policy, audit=audit, caller="cli")
    try:
        _emit(obs.to_dict(), args.out, force=args.force)
    except OSError as exc:
        _emit({"error": str(exc)})
        return 2
    return _observation_exit_code(obs.status)


if __name__ == "__main__":
    raise SystemExit(main())
