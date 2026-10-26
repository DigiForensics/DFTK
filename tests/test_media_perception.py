"""Consent, actual MCP image transport, GPU/CPU dispatch and media evidence flow."""
from __future__ import annotations

import asyncio
import base64
from contextlib import closing
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

from dftk.catalog import load_builtin_tools
from dftk.core.case import CaseSession
from dftk.core.models import Status
from dftk.core.registry import registry
from dftk.mcp_server import DFTKMCPGateway, create_server, _bounded, _fact_path
from dftk.primitives import media


@pytest.fixture
def setup(tmp_path):
    load_builtin_tools()
    root, workspace = tmp_path / 'evidence with spaces', tmp_path / 'case workspace'
    root.mkdir()
    Image = pytest.importorskip('PIL.Image')
    image = root / 'screenshot.png'
    Image.new('RGB', (240, 120), '#cc4422').save(image)
    gateway = DFTKMCPGateway(root=root, workspace=workspace, max_safety='STATEFUL')
    cid = gateway.case('new')['case']['case_id']
    return root, workspace, image, gateway, cid


@pytest.mark.parametrize('authorized,supported', [(False, False), (False, True), (True, False)])
def test_no_pixels_are_decoded_without_both_attestations(monkeypatch, authorized, supported):
    monkeypatch.setattr(media, '_kind', lambda *_: pytest.fail('media was opened without consent/model support'))
    obs = media.media_preview('never-open-this.png', user_authorized=authorized, model_supports_images=supported)
    assert obs.status == Status.BLOCKED
    assert obs.facts['pixels_disclosed'] is False
    assert not obs.presentation


def test_preview_is_native_image_and_pixels_are_not_replayed_from_case(setup):
    from mcp import Client
    root, workspace, image, gateway, cid = setup
    original = image.read_bytes()

    async def check():
        async with Client(create_server(gateway)) as client:
            tools = await client.list_tools()
            native = [tool for tool in tools.tools if tool.name in {'dftk_run', 'dftk_view_media'}]
            assert len(native) == 2 and all(tool.output_schema is None for tool in native)
            denied = await client.call_tool('dftk_view_media', {'path': image.name})
            assert denied.is_error
            assert all(item.type == 'text' for item in denied.content)
            viewed = await client.call_tool('dftk_view_media', {
                'path': image.name, 'user_authorized': True, 'model_supports_images': True, 'case_id': cid})
            assert not viewed.is_error
            images = [item for item in viewed.content if item.type == 'image']
            assert len(images) == 1 and images[0].mime_type == 'image/jpeg'
            assert base64.b64decode(images[0].data).startswith(b'\xff\xd8')
            assert 'presentation' not in viewed.structured_content
            assert 'data' not in viewed.structured_content['observation']['facts']
            seq = viewed.structured_content['case_run']['seq']
            replay = await client.call_tool('dftk_read_case_run', {'case_id': cid, 'seq': seq})
            assert all(item.type != 'image' for item in replay.content)
            # The generic run entry point also preserves structured results.
            run = await client.call_tool('dftk_run', {'name': 'media.inspect', 'params': {'path': image.name}})
            assert run.structured_content['observation']['facts']['content_examined'] is False

    asyncio.run(check())
    stored = list((workspace / 'cases' / cid / 'artifacts').glob('*.json'))
    assert len(stored) == 1
    assert 'presentation' not in json.loads(stored[0].read_text())
    assert image.read_bytes() == original


def test_video_sampling_is_timestamped_and_scope_is_explicit(setup):
    if not shutil.which('ffmpeg'):
        pytest.skip('FFmpeg not installed')
    root, _, _, gateway, cid = setup
    video = root / 'camera recording.mp4'
    subprocess.run([shutil.which('ffmpeg'), '-v', 'error', '-f', 'lavfi', '-i',
        'color=c=blue:s=160x90:r=2', '-t', '2', '-c:v', 'mpeg4', str(video)], check=True, timeout=20)
    before = hashlib.sha256(video.read_bytes()).hexdigest()
    result = gateway.run('media.preview', {'path': str(video), 'user_authorized': True,
        'model_supports_images': True, 'frame_count': 2, 'interval_seconds': 1}, case_id=cid, include_presentation=True)
    assert result['ok'], result
    assert len(result['presentation']) == 2
    assert [frame['timestamp_seconds'] for frame in result['observation']['facts']['frames']] == [0, 1]
    assert 'audio' in result['observation']['facts']['scope']
    assert hashlib.sha256(video.read_bytes()).hexdigest() == before


def test_extension_only_video_cannot_launch_a_playlist_decoder(setup, monkeypatch):
    root, _, _, _, _ = setup
    playlist = root / 'disguised.mp4'
    playlist.write_text('#EXTM3U\nfile:///outside/evidence/private-video.mp4\n')
    monkeypatch.setattr(media.subprocess, 'run', lambda *_args, **_kw: pytest.fail('unverified video invoked FFmpeg'))
    obs = media.media_preview(str(playlist), user_authorized=True, model_supports_images=True)
    assert not obs.presentation
    assert obs.status == Status.UNSUPPORTED


def test_browse_and_text_windows_are_composable_without_visual_disclosure(setup):
    root, _, image, gateway, _ = setup
    text = root / 'notes.txt'
    text.write_text('first line\nsecond line\n')
    first = gateway.run('evidence.browse', {'path': str(root), 'limit': 1})['observation']['facts']
    assert first['next_offset'] == 1
    second = gateway.run('evidence.browse', {'path': str(root), 'offset': first['next_offset'], 'limit': 1})['observation']['facts']
    assert {first['entries'][0]['name'], second['entries'][0]['name']} == {'notes.txt', image.name}
    window = gateway.run('file.read_text', {'path': str(text), 'length': 11})['observation']['facts']
    assert window['text'] == 'first line\n'
    tail = gateway.run('file.read_text', {'path': str(text), 'offset': window['next_offset']})['observation']['facts']
    assert tail['text'] == 'second line\n'
    assert gateway.run('file.read_text', {'path': str(image)})['observation']['status'] == 'blocked'


def test_chinese_discovery_and_runtime_readiness_do_not_silently_misroute(setup):
    _, _, _, gateway, _ = setup
    assert gateway.search('完全不认识的词语')['results'] == []
    assert any(row['name'] == 'media.ocr' for row in gateway.search('图片文字识别')['results'])
    matches = gateway.suggest('照片')
    assert any(row['name'] == 'media.inspect' for row in matches['results'])
    assert all('readiness' in row for row in matches['results'])


def test_gpu_absence_does_not_start_cpu_or_open_media(monkeypatch):
    monkeypatch.setattr(media, '_gpu_device', lambda: None)
    monkeypatch.setattr(media, '_ocr_reader', lambda *_: pytest.fail('CPU engine started without consent'))
    obs = media.media_ocr('never-open-this.png')
    assert obs.status == Status.BLOCKED
    assert obs.facts['reason_code'] == 'cpu_consent_required'
    assert 'very slow' in obs.facts['required_action']


@pytest.mark.parametrize('allow_cpu,expected_device', [(False, 'cuda'), (True, 'cpu')])
def test_ocr_device_choice_boxes_and_provenance(setup, monkeypatch, allow_cpu, expected_device):
    _, _, image, _, _ = setup
    devices = []
    monkeypatch.setattr(media, '_gpu_device', lambda: 'cuda')
    monkeypatch.setitem(sys.modules, 'numpy', SimpleNamespace(asarray=lambda image: image))

    class Reader:
        def readtext(self, pixels, **kwargs):
            return [([[0, 0], [100, 0], [100, 20], [0, 20]], '密码线索', .93)]

    def backend(languages, device):
        devices.append(device)
        assert languages == ['ch_sim', 'en']
        return Reader()

    monkeypatch.setattr(media, '_ocr_reader', backend)
    obs = media.media_ocr(str(image), allow_cpu=allow_cpu)
    assert devices == [expected_device]
    assert obs.status == Status.OK
    assert obs.facts['text'] == '密码线索'
    assert obs.evidence[0].source_sha256 == ''  # registry propagates the source hash
    assert obs.meta['source_sha256'] == hashlib.sha256(image.read_bytes()).hexdigest()
    assert obs.facts['frames_examined'][0]['box_coordinates'].startswith('processed pixels')


def test_gpu_inference_failure_never_falls_back_to_cpu(setup, monkeypatch):
    _, _, image, _, _ = setup
    devices = []
    monkeypatch.setattr(media, '_gpu_device', lambda: 'cuda')
    monkeypatch.setitem(sys.modules, 'numpy', SimpleNamespace(asarray=lambda image: image))

    class Reader:
        def readtext(self, *args, **kwargs):
            raise RuntimeError('GPU out of memory')

    def backend(languages, device):
        devices.append(device)
        return Reader()

    monkeypatch.setattr(media, '_ocr_reader', backend)
    obs = media.media_ocr(str(image))
    assert devices == ['cuda']
    assert obs.status == Status.ERROR
    assert obs.facts['reason_code'] == 'gpu_ocr_failed'
    assert 'ask before CPU' in obs.facts['required_action']


def test_ocr_never_downloads_models(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setenv('DFTK_OCR_MODEL_DIR', str(tmp_path))
    monkeypatch.setitem(sys.modules, 'easyocr', SimpleNamespace(Reader=lambda *a, **kw: calls.append(kw)))
    media._ocr_reader(['ch_sim', 'en'], 'cuda')
    assert calls[0]['gpu'] == 'cuda'
    assert calls[0]['download_enabled'] is False


def test_media_and_encryption_stay_visible_after_intake(setup):
    root, _, image, gateway, cid = setup
    (root / 'backup.enc').write_bytes(b'Salted__' + bytes(range(64)))
    gateway.case('guided_intake', case_id=cid, path=str(root), max_steps=2)
    coverage = gateway.case('coverage', case_id=cid)['coverage']
    assert coverage['assessment'] == 'limitations_present'
    unexamined = {Path(item['path']).name: item for item in coverage['unexamined_artifacts']}
    assert {'screenshot.png', 'backup.enc'} <= set(unexamined)
    assert unexamined['backup.enc']['kind'] == 'openssl_salted'
    assert unexamined['screenshot.png']['media_type'] == 'image'
    gateway.case('note_artifact', case_id=cid, path=str(image), disposition='user_declined', reason='User declined visual disclosure')
    # Declining a review preserves the known coverage gap and its reason.
    assert any(item.get('disposition') == 'user_declined' for item in gateway.case('artifacts', case_id=cid)['artifacts']['items'])
    assert gateway.case('coverage', case_id=cid)['coverage']['unexamined_artifact_count'] == 2


def test_changed_source_does_not_inherit_prior_review_disposition(setup):
    _, _, image, gateway, cid = setup
    gateway.run('evidence.intake', {'path': str(image)}, case_id=cid)
    gateway.case('note_artifact', case_id=cid, path=str(image), disposition='reviewed', reason='Reviewed earlier bytes')
    from PIL import Image
    Image.new('RGB', (240, 120), 'blue').save(image)
    gateway.run('evidence.intake', {'path': str(image)}, case_id=cid)
    item = gateway.case('artifacts', case_id=cid)['artifacts']['items'][0]
    assert 'disposition' not in item
    assert gateway.case('coverage', case_id=cid)['coverage']['unexamined_artifact_count'] == 1


def test_image_after_default_inspection_limit_is_still_discovered(setup):
    root, _, image, gateway, _ = setup
    for index in range(200):
        (root / f'a{index:03d}.txt').write_text('ordinary evidence')
    result = gateway.run('evidence.intake', {'path': str(root)})['observation']
    row = next(row for row in result['facts']['candidates'] if row['path'].endswith(image.name))
    assert row['inspection_status'] == 'not_attempted'
    assert row['media_type'] == 'image'
    assert row['identified'] is False
    assert result['facts']['next_inspection']


def test_derived_database_can_be_consumed_but_unregistered_and_changed_outputs_are_blocked(setup):
    root, workspace, _, gateway, cid = setup
    db = root / 'accounts.db'
    with closing(sqlite3.connect(db)) as con, con:
        con.execute('create table accounts(name text, phone text)')
        con.execute("insert into accounts values('Alice','13800000000')")
    archive = root / 'phone.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.write(db, 'accounts.db')
    source_bytes = archive.read_bytes()
    extract = gateway.run('archive.extract_safe', {'path': str(archive), 'output_dir': 'unpacked'}, case_id=cid)
    assert extract['ok']
    output = workspace / 'unpacked' / 'accounts.db'
    result = gateway.run('database.sqlite_query', {'path': str(output), 'sql': "select phone from accounts where name='Alice'"}, case_id=cid)
    assert result['observation']['facts']['rows'] == [['13800000000']]
    unregistered = workspace / 'unregistered.db'
    unregistered.write_bytes(db.read_bytes())
    assert gateway.run('database.sqlite_inventory', {'path': str(unregistered)}, case_id=cid)['observation']['status'] == 'blocked'
    output.write_bytes(b'changed')
    assert gateway.run('database.sqlite_inventory', {'path': str(output)}, case_id=cid)['observation']['status'] == 'blocked'
    assert archive.read_bytes() == source_bytes


def test_encrypted_zip_preserves_plain_members_and_accepts_one_supplied_password(setup):
    binary = shutil.which('zip')
    if binary is None:
        pytest.skip('ZIP fixture generator unavailable')
    root, workspace, _, gateway, cid = setup
    plain, secret = root / 'public.txt', root / 'secret.txt'
    plain.write_text('public evidence'); secret.write_text('protected evidence')
    archive = root / 'mixed.zip'
    subprocess.run([binary, '-q', '-j', str(archive), str(plain)], check=True)
    subprocess.run([binary, '-q', '-j', '-P', 'fixture-password', str(archive), str(secret)], check=True)
    inventory = gateway.run('archive.inventory', {'path': str(archive)})['observation']
    assert inventory['facts']['encrypted_members'] == ['secret.txt']
    partial = gateway.run('archive.extract_safe', {'path': str(archive), 'output_dir': 'mixed'}, case_id=cid)['observation']
    assert partial['status'] == 'partial'
    assert partial['facts']['blocked_members'][0]['reason_code'] == 'password_required'
    assert partial['facts']['extracted'][0]['relative'] == 'public.txt'
    assert gateway.run('file.read_text', {'path': str(workspace / 'mixed' / 'public.txt')}, case_id=cid)['ok']
    recovered = gateway.run('archive.extract_safe', {'path': str(archive), 'output_dir': 'recovered', 'password': 'fixture-password'}, case_id=cid)
    assert recovered['ok']
    assert (workspace / 'recovered' / 'secret.txt').read_text() == 'protected evidence'
    assert 'fixture-password' not in json.dumps(gateway.case('show', case_id=cid))


def test_large_recipe_results_remain_pageable_with_dotted_keys(setup):
    root, _, _, gateway, cid = setup
    db = root / 'History'
    with closing(sqlite3.connect(db)) as con, con:
        con.execute('create table urls(id integer primary key,url text,title text,visit_count int,typed_count int,last_visit_time int)')
        con.executemany('insert into urls values(?,?,?,?,?,?)', [(i, 'https://example.test/' + str(i) + 'x' * 1800,
            'visit', 1, 1, 13300000000000000 + i) for i in range(400)])
    result = gateway.run('recipe.browser.history_triage', {'path': str(db)}, case_id=cid)
    assert result['truncated']
    seq = result['case_run']['seq']
    page = gateway.read_case_run(cid, seq, fact_path='/browser.chromium_history/visits', value_limit=1, evidence_limit=1)
    assert not page.get('truncated')
    assert page['fact']['total'] == 400 and len(page['fact']['items']) == 1
    assert 'children' not in page['observation']['meta']
    assert _fact_path({'a.b': {'x/y': [42]}}, '/a.b/x~1y/0') == 42
    assert _bounded({'ok': False, 'status': 'error', 'data': 'x' * 600000})['ok'] is False


def test_large_provenance_is_pageable_without_bloating_every_reply(setup, monkeypatch):
    from dftk.core.models import Observation
    _, workspace, image, gateway, cid = setup
    monkeypatch.setitem(registry._funcs, 'file.hash', lambda path: Observation('file.hash', Status.OK, 'fixture',
        facts={'value': 42}, meta={'provenance': {'artifacts': [{'locator': 'x' * 1500, 'id': index} for index in range(500)]}}))
    session = CaseSession(workspace)
    session.run(cid, 'file.hash', {'path': str(image)})
    page = gateway.read_case_run(cid, 1, fact_path='/provenance/artifacts', section='meta', value_limit=1)
    assert not page.get('truncated')
    assert page['fact']['total'] == 500
    assert len(page['fact']['items']) == 1
    assert 'provenance' not in page['observation']['meta']


def test_timeout_is_preserved_even_without_an_observation(setup):
    root, _, _, gateway, cid = setup
    db = root / 'empty.db'
    with closing(sqlite3.connect(db)) as con, con:
        con.execute('create table demo(id int)')
    gateway.timeout_seconds = 1
    with pytest.raises(TimeoutError):
        gateway.run('database.sqlite_query', {'path': str(db),
            'sql': 'WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt) SELECT sum(x) FROM cnt'}, case_id=cid)
    attempts = gateway.case('coverage', case_id=cid)['coverage']['interrupted_attempts']
    assert len(attempts) == 1 and attempts[0]['status'] == 'failed'


def test_views_do_not_repeat_and_new_intakes_do_not_erase_old_routes(setup):
    root, _, image, gateway, cid = setup
    (root / 'a.eml').write_text('From: alice@example.test\n\nhello')
    gateway.run('evidence.intake', {'path': str(root / 'a.eml')}, case_id=cid)
    gateway.run('evidence.intake', {'path': str(image)}, case_id=cid)
    tools = {item.get('tool') for item in gateway.case('next', case_id=cid)['next_actions']['actions']}
    assert {'media.inspect', 'recipe.email.full_offline_triage'} <= tools
    gateway.case('graph', case_id=cid); gateway.case('timeline', case_id=cid)
    assert not any(item.get('operation') in {'graph', 'timeline'} for item in gateway.case('next', case_id=cid)['next_actions']['actions'])
