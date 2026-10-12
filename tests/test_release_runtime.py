"""Cross-domain runtime invariants and case evidence integrity."""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
import dftk
from dftk.core.case import CaseSession
from dftk.core.models import Observation, Status, SafetyLevel
from dftk.core.registry import ToolRegistry
from dftk.core.safety import SafetyPolicy
from dftk.core.readiness import _requirement_status
from dftk.core.audit import ToolAuditLog, compute_record_hash, verify_ledger


def test_all_contracts_bind_and_declare_host_paths():
    import inspect
    reg=dftk.get_registry()
    for spec in reg.specs():
        params=inspect.signature(reg._funcs[spec.name]).parameters
        props=spec.parameters.get('properties',{})
        assert set(props)==set(params), spec.name
        for key in ('path','root','image','system_hive','evtx','wal_path','db_path','mft_path','identity_file','output_dir','files','extra_sources'):
            if key in props and props[key].get('type') in ('string','array'):
                assert key in spec.path_roles, (spec.name,key)


@pytest.mark.parametrize('wrong', ['bad', True, 1.5, None])
def test_every_integer_contract_rejects_wrong_types(wrong):
    reg=dftk.get_registry()
    checked=0
    for spec in reg.specs():
        keys=[k for k,p in spec.parameters.get('properties',{}).items() if p.get('type')=='integer']
        if not keys or spec.safety!=SafetyLevel.READ_ONLY or spec.network:
            continue
        key=keys[0]
        values={name:'/missing/evidence' for name in spec.parameters.get('required',[])}
        values[key]=wrong
        result=reg.run(spec.name,values)
        assert result.status==Status.ERROR, spec.name
        assert result.summary=='Invalid parameters', spec.name
        checked+=1
    assert checked>50


def test_child_calls_cannot_escalate_or_escape_and_inputs_not_mutated(tmp_path):
    root=tmp_path/'evidence';root.mkdir();(root/'ok').write_bytes(b'ok')
    workspace=tmp_path/'workspace';workspace.mkdir()
    outside=tmp_path/'outside';outside.write_bytes(b'secret')
    reg=ToolRegistry()
    @reg.tool(name='demo.read', description='reader',parameters={'type':'object','properties':{'path':{'type':'string'}},'required':['path']})
    def read(path):
        return Observation('demo.read',Status.OK,'read',facts={'path':path})
    @reg.tool(name='demo.write',description='writer',safety=SafetyLevel.STATEFUL,parameters={'type':'object','properties':{}})
    def write():
        pytest.fail('child escalation must never execute')
    @reg.tool(name='demo.recipe',description='recipe',parameters={'type':'object','properties':{}})
    def recipe():
        permissive=SafetyPolicy(max_level=SafetyLevel.DESTRUCTIVE,allow_network=True)
        assert reg.run('demo.write',{},permissive).status==Status.BLOCKED
        assert reg.run('demo.read',{'path':str(outside)},permissive).status==Status.BLOCKED
        return reg.run('demo.read',{'path':'ok'},permissive)
    args={'path':'ok'}
    policy=SafetyPolicy(evidence_root=root,workspace_root=workspace)
    assert reg.run('demo.read',args,policy).facts['path']==str((root/'ok').resolve())
    assert args=={'path':'ok'}
    assert reg.run('demo.recipe',{},policy).status==Status.OK
    assert reg.run('demo.read',{'path':str(outside)}).status==Status.OK  # context does not leak


def test_mcp_stateful_output_and_analysis_files_stay_in_workspace(tmp_path):
    from dftk.mcp_server import DFTKMCPGateway
    root=tmp_path/'evidence';root.mkdir();workspace=tmp_path/'case'
    gateway=DFTKMCPGateway(root=root,workspace=workspace,max_safety='STATEFUL')
    gateway.preflight()
    report=gateway.run('case.report_html',{'output_dir':str(workspace/'report'),'observations':[]})
    assert report['ok'], report
    forbidden=gateway.run('case.report_html',{'output_dir':str(root/'report'),'observations':[]})
    assert not forbidden['ok']
    assert not (root/'report').exists()
    artifact=workspace/'observation.json';artifact.write_text(json.dumps({'tool':'demo','facts':{'events':[{'time':'2024-01-01T00:00:00Z','kind':'test'}]}}))
    timeline=gateway.run('timeline.merge',{'files':[str(artifact)]})
    assert timeline['ok'], timeline
    assert len(timeline['observation']['facts']['events'])==1


def test_case_artifact_and_finding_digest_detect_value_only_tamper(tmp_path):
    source=tmp_path/'source';source.write_bytes(b'original')
    session=CaseSession(tmp_path/'workspace');case=session.new('integrity')['case_id']
    session.run(case,'file.hash',{'path':str(source)})
    session.add_finding(case,'Hash observed','VERIFIED',[{'run_seq':1,'evidence_index':0}])
    assert session.verify(case)['valid']
    path=session._run_artifact_path(case,session.show(case)['runs'][0])
    value=json.loads(path.read_text());value['evidence'][0]['value']='forged value';path.write_text(json.dumps(value))
    assert not session.verify(case)['valid']
    assert session.findings_report(case)['stale_citation_count']==1


def test_concurrent_case_findings_do_not_drop_conclusions(tmp_path):
    source=tmp_path/'source';source.write_bytes(b'original')
    session=CaseSession(tmp_path/'workspace');case=session.new('concurrent')['case_id']
    session.run(case,'file.hash',{'path':str(source)})
    def add(i):
        local=CaseSession(tmp_path/'workspace')
        return local.add_finding(case,f'Claim {i}','SUPPORTED',[{'run_seq':1,'evidence_index':0}])
    with ThreadPoolExecutor(max_workers=4) as pool:
        findings=list(pool.map(add,range(12)))
    assert len({f['id'] for f in findings})==12
    assert len(session.list_findings(case))==12


def test_external_readiness_uses_toolchain_not_python_import(monkeypatch):
    monkeypatch.setattr('dftk.core.readiness.external_tool_available',lambda name:name=='jadx')
    monkeypatch.setattr('dftk.core.readiness._import_available',lambda name:False)
    assert _requirement_status('jadx')['available']
    assert not _requirement_status('volatility')['available']


def test_old_hash_chain_can_be_verified_and_extended(tmp_path):
    import hashlib
    path=tmp_path/'ledger.jsonl'
    record={'sequence':1,'previous_hash':'0'*64,'status':'ok','tool':'legacy','params':{}}
    record['record_hash']=hashlib.sha256(('0'*64+'|'+json.dumps(record,ensure_ascii=False,sort_keys=True,default=str)).encode()).hexdigest()
    path.write_text(json.dumps(record)+'\n')
    assert verify_ledger(path)['verdict']=='intact'
    log=ToolAuditLog(path);log.record(tool='next',params={},observation=Observation('next',Status.OK,'ran'))
    assert verify_ledger(path)['verdict']=='intact'
    assert verify_ledger(path)['records']==2


def test_directory_scans_do_not_follow_outside_symlink(tmp_path):
    from dftk.core.helpers import bounded_files
    root=tmp_path/'root';root.mkdir();inside=root/'inside';inside.write_bytes(b'ok')
    outside=tmp_path/'outside';outside.write_bytes(b'secret')
    (root/'escape').symlink_to(outside)
    assert list(bounded_files(root))==[inside]


def test_static_manifest_is_independent_of_runtime_requirements(monkeypatch):
    from dftk.manifest import capability_manifest
    first=capability_manifest(include_readiness=False)
    monkeypatch.setattr('dftk.core.readiness._import_available',lambda name:False)
    monkeypatch.setattr('dftk.core.readiness.external_tool_available',lambda name:False)
    assert first==capability_manifest(include_readiness=False)
    assert all('path_roles' in tool and 'readiness' not in tool for tool in first['tools'])


def test_case_verifier_checks_full_audited_observation(tmp_path):
    from dftk.primitives.case_verify import case_verify
    source=tmp_path/'source';source.write_bytes(b'input')
    log=ToolAuditLog(tmp_path/'audit.jsonl')
    obs=dftk.run_tool('file.hash',{'path':str(source)})
    log.record(tool=obs.tool,params={},observation=obs)
    assert case_verify(str(log.path),[obs.to_dict()]).facts['verdict']=='VALID'
    altered=obs.to_dict();altered['facts']['extra']='changed'
    assert case_verify(str(log.path),[altered]).facts['verdict']=='BROKEN'
