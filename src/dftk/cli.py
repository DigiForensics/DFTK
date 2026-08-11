from __future__ import annotations
import argparse,json
from pathlib import Path
from .catalog import load_builtin_tools
from .core.registry import registry
from .core.models import SafetyLevel
from .core.safety import SafetyPolicy
from importlib.resources import files as _pkg_files

try:
    _SKILL_FILE = _pkg_files("dftk") / "SKILL.md"
except Exception:
    _SKILL_FILE = None

TOOLKIT_VERSION = "2.1.0"

def _load_params(args):
    if getattr(args,'params_file',None): return json.loads(Path(args.params_file).read_text(encoding='utf-8'))
    if getattr(args,'params',None): return json.loads(args.params)
    return {}

def _emit(data,out=None):
    text=json.dumps(data,ensure_ascii=False,indent=2,default=str)
    if out: Path(out).write_text(text+'\n',encoding='utf-8')
    print(text)

def _spec_dict(s):
    return {
        "name":s.name,"description":s.description,"safety":s.safety.name,
        "network":s.network,"parameters":s.parameters,"tags":list(s.tags),
        "produces":list(s.produces),"requires":list(s.requires),
        "deterministic":s.deterministic,"cost_hint":s.cost_hint,
    }

# Known agent skill directories (user-level). Every entry follows the same
# SKILL.md-in-<slug>/ convention, so one bundled SKILL.md serves them all.
# `agents` is the Anthropic Agent Skills open standard (~/.agents/skills) shared
# by Codex, Cursor, Gemini CLI, GitHub Copilot and 70+ others.
AGENT_SKILL_DIRS = {
    "workbuddy": ".workbuddy/skills",
    "claude":    ".claude/skills",
    "codex":     ".codex/skills",
    "hermes":    ".hermes/skills",
    "agents":    ".agents/skills",
    "cursor":    ".cursor/skills",
    "gemini":    ".gemini/skills",
}

def _resolve_targets(spec):
    if spec is None or spec.strip().lower() == "all":
        return list(AGENT_SKILL_DIRS.keys())
    out=[]
    for t in spec.split(","):
        t=t.strip().lower()
        if not t: continue
        if t not in AGENT_SKILL_DIRS:
            raise ValueError(f"unknown agent target: {t!r} (known: {', '.join(AGENT_SKILL_DIRS)})")
        out.append(t)
    return out

def _cmd_skill(args):
    if _SKILL_FILE is None:
        _emit({"error":"SKILL.md not bundled in this install"}); return 2
    if not getattr(args,'install',False):
        print(str(_SKILL_FILE)); return 0
    import shutil
    # Custom directory mode (overrides agent targets).
    custom = getattr(args,'dir',None)
    if custom:
        dest = Path(custom)
        if dest.name != "dftk":
            dest = dest / "dftk"
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(_SKILL_FILE), dest / "SKILL.md")
        print(f"installed skill -> {dest / 'SKILL.md'}")
        return 0
    # Multi-agent install mode.
    try:
        targets = _resolve_targets(args.target)
    except ValueError as e:
        _emit({"error":str(e)}); return 2
    home = Path.home()
    installed=[]
    for t in targets:
        dest = home / AGENT_SKILL_DIRS[t] / "dftk"
        try:
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(_SKILL_FILE), dest / "SKILL.md")
            installed.append(str(dest / "SKILL.md"))
        except OSError as e:
            print(f"  skipped {t}: {e}")
    for p in installed:
        print(f"installed -> {p}")
    if not installed:
        _emit({"error":"no skill directories could be written"}); return 1
    print(f"\nInstalled dftk skill for {len(installed)} agent target(s): {', '.join(targets)}")
    return 0

def main(argv=None):
    load_builtin_tools()
    ap=argparse.ArgumentParser(prog='dftk')
    ap.add_argument('--version', action='version', version=f'%(prog)s {TOOLKIT_VERSION}')
    sub=ap.add_subparsers(dest='cmd',required=True)
    l=sub.add_parser('list',help='list registered tools'); l.add_argument('--tag',action='append'); l.add_argument('--produces')
    d=sub.add_parser('describe'); d.add_argument('name')
    r=sub.add_parser('run'); r.add_argument('name'); r.add_argument('--params'); r.add_argument('--params-file'); r.add_argument('--out'); r.add_argument('--allow-network',action='store_true'); r.add_argument('--max-safety',choices=['READ_ONLY','STATEFUL','DESTRUCTIVE'],default='READ_ONLY')
    rec=sub.add_parser('recipe'); rec.add_argument('name'); rec.add_argument('--params'); rec.add_argument('--params-file'); rec.add_argument('--out')
    ex=sub.add_parser('export-manifest'); ex.add_argument('--out')
    sk=sub.add_parser('skill',help='show/install the bundled agent skill (SKILL.md)')
    sk.add_argument('--install',action='store_true',help='install the skill into agent skill directories')
    sk.add_argument('--target',default='all',metavar='LIST',help='comma-separated agent targets or "all" (options: workbuddy,claude,codex,hermes,agents,cursor,gemini)')
    sk.add_argument('--dir',metavar='DIR',help='install into a custom directory instead of known agent targets')
    args=ap.parse_args(argv)
    if args.cmd=='skill': return _cmd_skill(args)
    if args.cmd=='list':
        _emit([_spec_dict(s) for s in registry.find(tags=args.tag,produces=args.produces)]); return 0
    if args.cmd=='describe':
        try:_emit(_spec_dict(registry.get(args.name)));return 0
        except KeyError:_emit({"error":f"unknown tool: {args.name}"});return 2
    if args.cmd=='export-manifest':
        data={"schema_version":"2","toolkit_version":TOOLKIT_VERSION,"tools":[_spec_dict(s) for s in registry.specs()]}; _emit(data,args.out); return 0
    try: params=_load_params(args)
    except Exception as e: _emit({"error":f"invalid params JSON: {e}"}); return 2
    if args.cmd=='recipe':
        name=args.name if args.name.startswith('recipe.') else 'recipe.'+args.name
        obs=registry.run(name,params,SafetyPolicy()); _emit(obs.to_dict(),args.out); return 0 if obs.status.value in ('ok','partial','unsupported') else 1
    policy=SafetyPolicy(max_level=SafetyLevel[args.max_safety],allow_network=args.allow_network)
    obs=registry.run(args.name,params,policy); _emit(obs.to_dict(),args.out); return 0 if obs.status.value in ('ok','partial','unsupported') else 1

if __name__=='__main__': raise SystemExit(main())
