"""Perception-to-action workflows and their consent/failure boundaries."""
from contextlib import closing
import asyncio
import base64
import gzip
import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

from dftk.catalog import load_builtin_tools
from dftk.core.case import CaseSession
from dftk.core.models import Status
from dftk.core.registry import registry
from dftk.mcp_server import DFTKMCPGateway, create_server
from dftk.primitives import media, decrypt


@pytest.fixture
def case(tmp_path):
    load_builtin_tools()
    Image = pytest.importorskip('PIL.Image')
    root, workspace = tmp_path / 'evidence', tmp_path / 'workspace'
    root.mkdir()
    for index, colour in enumerate(['red', 'blue', 'green']):
        Image.new('RGB', (600, 300), colour).save(root / f'image{index}.png')
    gateway = DFTKMCPGateway(root=root, workspace=workspace, max_safety='STATEFUL')
    cid = gateway.case('new')['case']['case_id']
    return root, workspace, gateway, cid


@pytest.fixture
def ocr(monkeypatch):
    calls = {'initialisations': [], 'inferences': 0, 'fail_at': None}
    monkeypatch.setattr(media, '_gpu_device', lambda: 'cuda')
    monkeypatch.setitem(sys.modules, 'numpy', SimpleNamespace(asarray=lambda image: image))

    class Reader:
        def readtext(self, pixels, **kwargs):
            calls['inferences'] += 1
            if calls['inferences'] == calls['fail_at']:
                raise RuntimeError('GPU memory exhausted')
            width, height = pixels.size
            return [([[0, 0], [width, 0], [width, height], [0, height]], 'KEY: CASE7429', .99)]

    def load(languages, device):
        calls['initialisations'].append(device)
        return Reader()

    monkeypatch.setattr(media, '_ocr_reader', load)
    return calls


def test_crop_returns_selected_pixels_and_original_coordinates(case):
    from PIL import Image, ImageDraw
    root, _, gateway, cid = case
    image = root / 'image0.png'
    with Image.open(image) as pixels:
        ImageDraw.Draw(pixels).rectangle((100, 50, 299, 149), fill='lime')
        pixels.save(image)
    before = image.read_bytes()
    result = gateway.run('media.preview', {'path': str(image), 'crop_box': [100, 50, 300, 150],
        'user_authorized': True, 'model_supports_images': True}, case_id=cid, include_presentation=True)
    assert result['ok']
    frame = result['observation']['facts']['frames'][0]
    assert frame['source_size'] == [600, 300] and frame['crop_box'] == [100, 50, 300, 150]
    with Image.open(io.BytesIO(base64.b64decode(result['presentation'][0]['data']))) as shown:
        assert shown.size == (200, 100)
        assert shown.getpixel((100, 50))[1] > 200
    assert image.read_bytes() == before


def test_invalid_crop_is_not_clamped_into_a_different_region(case):
    root, _, gateway, _ = case
    result = gateway.run('media.preview', {'path': str(root / 'image0.png'), 'crop_box': [500, 100, 900, 200],
        'user_authorized': True, 'model_supports_images': True}, include_presentation=True)
    assert not result['ok'] and not result.get('presentation')


def test_contact_sheet_gates_before_decoding_and_preserves_file_outcomes(case, monkeypatch):
    root, _, _, _ = case
    monkeypatch.setattr(media, '_pillow', lambda: pytest.fail('Image decoder opened before consent'))
    denied = media.media_contact_sheet([str(root / 'image0.png')], model_supports_images=True)
    assert denied.status == Status.BLOCKED and not denied.presentation


def test_native_contact_sheet_maps_indices_to_case_sources_and_does_not_replay_pixels(case):
    from mcp import Client
    root, workspace, gateway, cid = case
    (root / 'broken.png').write_bytes(b'not a PNG')

    async def check():
        async with Client(create_server(gateway)) as client:
            result = await client.call_tool('dftk_view_media', {'paths': ['image0.png', 'broken.png', 'image1.png'],
                'case_id': cid, 'user_authorized': True, 'model_supports_images': True})
            assert not result.is_error
            assert len([item for item in result.content if item.type == 'image']) == 1
            files = result.structured_content['observation']['facts']['files']
            assert [item['status'] for item in files] == ['ok', 'error', 'ok']
            assert [item['index'] for item in files] == [0, 1, 2]
            assert files[0]['path'].endswith('image0.png')
            assert files[2]['path'].endswith('image1.png')
            assert len(files[0]['source_sha256']) == 64
    asyncio.run(check())
    items = gateway.case('artifacts', case_id=cid)['artifacts']['items']
    assert len(items) == 3
    assert sum(item['perception']['media.contact_sheet']['pixels_provided'] for item in items) == 2
    assert all('presentation' not in json.loads(path.read_text()) for path in (workspace / 'cases' / cid / 'artifacts').glob('*.json'))


def test_batch_ocr_reuses_gpu_model_and_retains_individual_source_hashes(case, ocr):
    root, workspace, _, cid = case
    session = CaseSession(workspace)
    obs = session.run(cid, 'media.ocr_batch', {'paths': [str(root / 'image0.png'), str(root / 'image1.png')]},
        evidence_root=root, workspace_root=workspace)
    assert obs.status == Status.OK
    assert ocr['initialisations'] == ['cuda'] and ocr['inferences'] == 2
    assert len(obs.facts['rows']) == 2
    assert obs.evidence[0].source_sha256 != obs.evidence[1].source_sha256
    assert obs.facts['rows'][0]['source'].endswith('image0.png')
    assert len(session.artifacts(cid)['items']) == 2


def test_batch_ocr_skips_bad_image_but_stops_on_gpu_inference_failure(case, ocr):
    root, _, _, _ = case
    (root / 'broken.png').write_bytes(b'broken')
    result = registry.run('media.ocr_batch', {'paths': [str(root / 'image0.png'), str(root / 'broken.png'), str(root / 'image1.png')]})
    assert result.status == Status.PARTIAL
    assert [item['status'] for item in result.facts['files']] == ['ok', 'error', 'ok']
    ocr['inferences'] = 0; ocr['fail_at'] = 2
    result = registry.run('media.ocr_batch', {'paths': [str(root / f'image{index}.png') for index in range(3)]})
    assert [item['status'] for item in result.facts['files']] == ['ok', 'error', 'not_attempted']
    assert ocr['initialisations'] == ['cuda', 'cuda']
    assert result.facts['reason_code'] == 'gpu_ocr_failed'


def test_batch_ocr_does_not_initialise_cpu_without_consent(monkeypatch):
    monkeypatch.setattr(media, '_gpu_device', lambda: None)
    monkeypatch.setattr(media, '_ocr_reader', lambda *_: pytest.fail('CPU model initialised without consent'))
    result = media.media_ocr_batch(['never-open.png'])
    assert result.status == Status.BLOCKED
    assert result.facts['reason_code'] == 'cpu_consent_required'
    assert result.facts['remaining_paths'] == ['never-open.png']
    assert result.facts['files'][0]['status'] == 'not_attempted'


def test_batch_budget_returns_completed_results_and_explicit_continuation(case, ocr, monkeypatch):
    root, _, _, _ = case
    ticks = iter([0, 0, 2, 3, 4])
    monkeypatch.setattr(media, '_monotonic', lambda: next(ticks))
    paths = [str(root / f'image{index}.png') for index in range(3)]
    result = media.media_ocr_batch(paths, time_budget_seconds=1)
    assert result.status == Status.PARTIAL
    assert len(result.facts['rows']) == 1
    assert result.facts['remaining_paths'] == paths[1:]
    assert result.facts['files'][1]['reason_code'] == 'time_budget_exhausted'


@pytest.mark.parametrize('kind', ['sqlite', 'gzip'])
def test_empty_plaintext_is_not_a_structurally_valid_decryption(tmp_path, kind):
    empty = tmp_path / 'empty'
    empty.write_bytes(b'')
    with pytest.raises(ValueError):
        decrypt._validate_plaintext(empty, kind)


def test_plaintext_validation_checks_real_structure_and_gzip_crc(tmp_path):
    db = tmp_path / 'records.db'
    with closing(sqlite3.connect(db)) as con, con:
        con.execute('create table records(value text)')
    assert decrypt._validate_plaintext(db, 'sqlite')['level'] == 'sqlite_quick_check'
    compressed = tmp_path / 'records.gz'
    compressed.write_bytes(gzip.compress(b'actual recovered bytes'))
    assert decrypt._validate_plaintext(compressed, 'gzip')['expanded_bytes'] == 22
    damaged = bytearray(compressed.read_bytes())
    damaged[-8] ^= 1
    compressed.write_bytes(damaged)
    with pytest.raises(gzip.BadGzipFile):
        decrypt._validate_plaintext(compressed, 'gzip')
    archive = tmp_path / 'records.tar'
    with tarfile.open(archive, 'w') as output:
        output.add(db, arcname='records.db')
    assert decrypt._validate_plaintext(archive, 'tar')['member_count'] == 1
    archive.write_bytes(archive.read_bytes()[:2048])
    with pytest.raises((ValueError, tarfile.TarError)):
        decrypt._validate_plaintext(archive, 'tar')


def test_cropped_ocr_boxes_map_back_to_source_pixels(case, ocr):
    root, _, _, _ = case
    obs = media.media_ocr(str(root / 'image0.png'), crop_box=[100, 50, 500, 250], max_dimension=200)
    assert obs.status == Status.OK
    assert obs.facts['rows'][0]['source_box'] == [[100, 50], [500, 50], [500, 250], [100, 250]]
    assert obs.facts['frames_examined'][0]['processed_size'] == [200, 100]


@pytest.fixture
def encrypted(case):
    binary = shutil.which('openssl')
    if binary is None:
        pytest.skip('OpenSSL unavailable')
    root, _, _, _ = case
    db = root / 'chat.db'
    with closing(sqlite3.connect(db)) as con, con:
        con.execute('create table people(name text, phone text)')
        con.execute("insert into people values('Alice','13800000000')")
    archive = root / 'backup.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.write(db, 'chat.db')
    source = root / 'backup.enc'
    subprocess.run([binary, 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '10000', '-md', 'sha256',
        '-in', str(archive), '-out', str(source), '-pass', 'stdin'], input=b'CASE7429\n', check=True, capture_output=True)
    return source


def test_ocr_clue_to_decryption_to_nested_sqlite_query(case, encrypted, ocr):
    root, workspace, gateway, cid = case
    source_bytes = encrypted.read_bytes()
    session = CaseSession(workspace)
    text = session.run(cid, 'media.ocr_batch', {'paths': [str(root / 'image0.png'), str(root / 'image1.png')]},
        evidence_root=root, workspace_root=workspace)
    candidate = text.facts['rows'][0]['text'].split('KEY: ', 1)[1]
    result = gateway.run('crypto.openssl_decrypt', {'path': str(encrypted), 'output_dir': 'decrypted',
        'password': candidate, 'key_evidence': 'run:1;evidence:0', 'cipher': 'aes-256-cbc', 'kdf': 'pbkdf2',
        'expected_kind': 'zip'}, case_id=cid)
    assert result['ok'], result
    assert result['observation']['facts']['attempt_count'] == 1
    plaintext = result['observation']['facts']['output_path']
    extracted = gateway.run('archive.extract_safe', {'path': plaintext, 'output_dir': 'unpacked'}, case_id=cid)
    assert extracted['ok'], extracted
    query = gateway.run('database.sqlite_query', {'path': str(workspace / 'unpacked' / 'chat.db'),
        'sql': "select phone from people where name='Alice'"}, case_id=cid)
    assert query['observation']['facts']['rows'] == [['13800000000']]
    manifest = session.show(cid)
    decrypt_run = next(item for item in manifest['runs'] if item['tool'] == 'crypto.openssl_decrypt')
    assert decrypt_run['params']['password'] == '<redacted>'
    assert encrypted.read_bytes() == source_bytes


@pytest.mark.parametrize('password,kind', [('WRONG-CANDIDATE', 'zip'), ('CASE7429', 'sqlite'),
    ('/opaque/credential', 'zip'), ('../opaque-credential', 'zip')])
def test_failed_or_structurally_invalid_decryption_does_not_publish_output(case, encrypted, password, kind):
    _, workspace, gateway, cid = case
    result = gateway.run('crypto.openssl_decrypt', {'path': str(encrypted), 'output_dir': 'failed',
        'password': password, 'key_evidence': 'user-provided candidate', 'cipher': 'aes-256-cbc',
        'kdf': 'pbkdf2', 'expected_kind': kind}, case_id=cid)
    assert not result['ok']
    assert result['observation']['facts']['attempt_count'] == 1
    assert result['observation']['facts']['plaintext_published'] is False
    assert not list((workspace / 'failed').iterdir())
    assert password not in json.dumps(result)
    assert password not in json.dumps(gateway.case('show', case_id=cid))


def test_decryption_is_blocked_before_workspace_writes_under_read_only_policy(case, encrypted):
    root, workspace, _, cid = case
    gateway = DFTKMCPGateway(root=root, workspace=workspace)
    result = gateway.run('crypto.openssl_decrypt', {'path': str(encrypted), 'output_dir': 'blocked',
        'password': 'CASE7429', 'key_evidence': 'user-provided candidate', 'cipher': 'aes-256-cbc',
        'kdf': 'pbkdf2', 'expected_kind': 'zip'}, case_id=cid)
    assert not result['ok'] and result['status'] == 'blocked'
    assert not (workspace / 'blocked').exists()


def test_password_is_transmitted_to_openssl_only_through_stdin(case, encrypted, monkeypatch):
    _, workspace, _, _ = case
    seen = []

    def command(args, **kwargs):
        seen.append((args, kwargs['input']))
        return SimpleNamespace(returncode=1, stderr=b'bad decrypt')

    monkeypatch.setattr(decrypt.subprocess, 'run', command)
    result = decrypt.openssl_decrypt(str(encrypted), str(workspace / 'attempt'), 'PRIVATE-PASSWORD',
        'user-provided', 'aes-256-cbc', 'pbkdf2', 'zip')
    assert result.status == Status.ERROR
    assert len(seen) == 1
    assert 'PRIVATE-PASSWORD' not in str(seen[0][0])
    assert seen[0][1] == b'PRIVATE-PASSWORD\n'
