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
from pathlib import Path

from .catalog import load_builtin_tools
from .core.models import SafetyLevel
from .core.registry import registry
from .core.safety import SafetyPolicy
from .skill_bundle import bundled_skill_root, install_bundled_skill

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


def _emit(data, out=None):
    text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")
    print(text)


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
    if spec is None or spec.strip().lower() == "all":
        return list(AGENT_SKILL_DIRS.keys())
    out = []
    for target in spec.split(","):
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
    skill_root = bundled_skill_root()
    try:
        main_skill = skill_root / "SKILL.md"
        if not main_skill.is_file():
            raise FileNotFoundError("SKILL.md missing")
    except Exception:
        _emit({"error": "DFTK skill bundle is not present in this install"})
        return 2

    if not getattr(args, "install", False):
        print(str(main_skill))
        return 0

    custom = getattr(args, "dir", None)
    if custom:
        dest = install_bundled_skill(custom)
        print(f"installed DFTK skill bundle -> {dest}")
        return 0

    try:
        targets = _resolve_targets(args.target)
    except ValueError as exc:
        _emit({"error": str(exc)})
        return 2

    home = Path.home()
    installed = []
    for target in targets:
        dest = home / AGENT_SKILL_DIRS[target] / "dftk"
        try:
            install_bundled_skill(dest)
            installed.append(str(dest))
        except OSError as exc:
            print(f"  skipped {target}: {exc}")
    for path in installed:
        print(f"installed -> {path}")
    if not installed:
        _emit({"error": "no skill directories could be written"})
        return 1
    print(
        f"\nInstalled complete DFTK skill bundle for {len(installed)} "
        f"agent target(s): {', '.join(targets)}"
    )
    return 0


def _cmd_case(args):
    from .core.case import CaseError, CaseSession

    session = CaseSession(getattr(args, "workspace", ".dftk") or ".dftk")
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
        obs = session.run(
            args.case_id,
            args.tool,
            params,
            allow_network=args.allow_network,
            max_safety=args.max_safety,
        )
        _emit(obs.to_dict())
        return 0 if obs.status.value in ("ok", "partial", "unsupported") else 1
    if cmd == "timeline":
        try:
            obs = session.timeline(args.case_id)
        except CaseError as exc:
            _emit({"error": str(exc)})
            return 2
        _emit(obs.to_dict(), args.out)
        return 0
    if cmd == "export":
        try:
            text = session.export(args.case_id, fmt=args.format)
        except CaseError as exc:
            _emit({"error": str(exc)})
            return 2
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"exported -> {args.out}")
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


def _cmd_mcp(args):
    try:
        from .mcp_server import run_mcp_server

        run_mcp_server(
            root=args.root,
            workspace=args.workspace,
            max_safety=args.max_safety,
            allow_network=args.allow_network,
            timeout_seconds=args.timeout,
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

    run = sub.add_parser("run")
    run.add_argument("name")
    run.add_argument("--params")
    run.add_argument("--params-file")
    run.add_argument("--out")
    run.add_argument("--allow-network", action="store_true")
    run.add_argument(
        "--max-safety",
        choices=["READ_ONLY", "STATEFUL", "DESTRUCTIVE"],
        default="READ_ONLY",
    )

    recipe = sub.add_parser("recipe")
    recipe.add_argument("name")
    recipe.add_argument("--params")
    recipe.add_argument("--params-file")
    recipe.add_argument("--out")

    export = sub.add_parser("export-manifest")
    export.add_argument("--out")

    doctor = sub.add_parser("doctor", help="check DFTK runtime, capabilities and optional integrations")

    skill = sub.add_parser("skill", help="show/install the complete bundled DFTK Agent Skill")
    skill.add_argument("--install", action="store_true", help="install the whole skill bundle into Agent skill directories")
    skill.add_argument(
        "--target",
        default="all",
        metavar="LIST",
        help=(
            'comma-separated targets or "all" '
            "(workbuddy,codebuddy,kimi,claude,codex,hermes,agents,cursor,gemini)"
        ),
    )
    skill.add_argument("--dir", metavar="DIR", help="install into a custom directory instead of known Agent targets")

    case = sub.add_parser("case", help="build and correlate an investigation case / unified timeline")
    case.add_argument("--workspace", default=".dftk", metavar="DIR", help="case workspace root (default: .dftk)")
    case_sub = case.add_subparsers(dest="case_cmd", required=True)
    case_new = case_sub.add_parser("new", help="create a new case and print its manifest")
    case_new.add_argument("--name")
    case_sub.add_parser("list", help="list cases in the workspace")
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
    case_timeline = case_sub.add_parser("timeline", help="merge all recorded Observations into one timeline")
    case_timeline.add_argument("case_id")
    case_timeline.add_argument("--out")
    case_export = case_sub.add_parser("export", help="export a case report (json or markdown)")
    case_export.add_argument("case_id")
    case_export.add_argument("--format", choices=["json", "md"], default="json")
    case_export.add_argument("--out")

    mcp = sub.add_parser("mcp", help="run the native local DFTK MCP server over stdio")
    mcp.add_argument("--root", default=".", metavar="DIR", help="filesystem evidence root visible to DFTK MCP (default: current directory)")
    mcp.add_argument("--workspace", default=".dftk", metavar="DIR", help="DFTK case workspace inside --root (default: .dftk)")
    mcp.add_argument("--max-safety", choices=["READ_ONLY", "STATEFUL"], default="READ_ONLY", help="server-owned capability safety ceiling")
    mcp.add_argument("--allow-network", action="store_true", help="server-owned opt-in for capabilities that declare network access")
    mcp.add_argument("--timeout", type=int, default=180, metavar="SECONDS", help="hard timeout for one capability run (default: 180)")

    args = parser.parse_args(argv)

    if args.cmd == "skill":
        return _cmd_skill(args)
    if args.cmd == "case":
        return _cmd_case(args)
    if args.cmd == "doctor":
        return _cmd_doctor(args)
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
    if args.cmd == "export-manifest":
        data = {
            "schema_version": "2",
            "toolkit_version": TOOLKIT_VERSION,
            "tools": [_spec_dict(spec) for spec in registry.specs()],
        }
        _emit(data, args.out)
        return 0

    try:
        params = _load_params(args)
    except Exception as exc:
        _emit({"error": f"invalid params JSON: {exc}"})
        return 2
    if args.cmd == "recipe":
        name = args.name if args.name.startswith("recipe.") else "recipe." + args.name
        obs = registry.run(name, params, SafetyPolicy())
        _emit(obs.to_dict(), args.out)
        return 0 if obs.status.value in ("ok", "partial", "unsupported") else 1

    policy = SafetyPolicy(
        max_level=SafetyLevel[args.max_safety],
        allow_network=args.allow_network,
    )
    obs = registry.run(args.name, params, policy)
    _emit(obs.to_dict(), args.out)
    return 0 if obs.status.value in ("ok", "partial", "unsupported") else 1


if __name__ == "__main__":
    raise SystemExit(main())
