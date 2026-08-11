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

def _cmd_skill(args):
    if _SKILL_FILE is None:
        _emit({"error":"SKILL.md not bundled in this install"}); return 2
    if getattr(args,'install',None) is None:
        print(str(_SKILL_FILE)); return 0
    import shutil
    dest = args.install
    if dest is True:
        dest = Path.home() / ".workbuddy" / "skills" / "dftk"
    else:
        dest = Path(dest)
        if dest.name != "dftk":
            dest = dest / "dftk"
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / "SKILL.md"
    shutil.copyfile(str(_SKILL_FILE), target)
    print(f"installed skill -> {target}")
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
    sk.add_argument('--install',nargs='?',const=True,default=None,metavar='DIR',help='copy SKILL.md into an agent skills dir (default: ~/.workbuddy/skills/dftk)')
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
