"""A bounded decryption hand, with no candidate generation or retry loop."""
from __future__ import annotations

from contextlib import closing
import gzip
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import zipfile

from dftk.core.external_tools import resolve_external_tool
from dftk.core.helpers import sha256_file
from dftk.core.models import Evidence, Observation, SafetyLevel, Status
from dftk.core.provenance import ProvenanceIndex
from dftk.core.registry import registry

_CIPHERS = ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc', 'aes-128-ctr', 'aes-256-ctr']
_KINDS = ['zip', 'sqlite', 'gzip', 'tar']


def _validate_plaintext(path: Path, kind: str) -> dict:
    """Validate the expected inner structure; never decompress without a bound."""
    if kind == 'zip':
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > 20000:
                raise ValueError('ZIP validation member budget exceeded')
            # A directory check is explicitly weaker than CRC/content validation.
            return {'kind': kind, 'level': 'central_directory', 'member_count': len(members),
                    'member_contents_validated': False}
    if kind == 'sqlite':
        with path.open('rb') as stream:
            if stream.read(16) != b'SQLite format 3\0':
                raise ValueError('Decrypted bytes do not have a SQLite database header')
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as con:
            if con.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise ValueError('Decrypted SQLite quick_check failed')
        return {'kind': kind, 'level': 'sqlite_quick_check', 'sidecars_examined': False}
    if kind == 'gzip':
        with path.open('rb') as stream:
            if stream.read(3) != b'\x1f\x8b\x08':
                raise ValueError('Decrypted bytes do not have a GZIP stream header')
        expanded = 0
        with gzip.open(path, 'rb') as stream:
            while chunk := stream.read(1024 * 1024):
                expanded += len(chunk)
                if expanded > 64 * 1024 * 1024:
                    raise ValueError('GZIP validation expansion budget exceeded (64 MiB)')
        return {'kind': kind, 'level': 'gzip_stream_crc', 'expanded_bytes': expanded}
    if kind == 'tar':
        count = 0
        with tarfile.open(path, mode='r:') as archive:
            while member := archive.next():
                count += 1
                if count > 20000:
                    raise ValueError('TAR validation member budget exceeded')
                if member.offset_data + member.size > path.stat().st_size:
                    raise ValueError('Decrypted TAR contains a truncated member')
        return {'kind': kind, 'level': 'tar_member_headers', 'member_count': count,
                'member_contents_validated': False}
    raise ValueError('Unsupported expected_kind')


@registry.tool(name='crypto.openssl_decrypt', description='Perform ONE supplied-password OpenSSL enc decryption with explicit cipher, KDF and expected inner format. Password is passed through stdin, never argv. Publish a derived workspace artifact only after structural validation. No algorithm/password guessing or automatic retries.',
    safety=SafetyLevel.STATEFUL, tags=('crypto', 'encrypted', 'openssl', 'decrypt', 'archive'),
    produces=('decrypted_artifact', 'derived_artifacts', 'decryption_validation'), requires=('openssl',), cost_hint='medium',
    path_roles={'path': 'EVIDENCE_INPUT', 'output_dir': 'WORKSPACE_OUTPUT'},
    parameters={'type': 'object', 'properties': {
        'path': {'type': 'string'}, 'output_dir': {'type': 'string'},
        'password': {'type': 'string', 'minLength': 1, 'maxLength': 4096},
        'key_evidence': {'type': 'string', 'minLength': 1, 'maxLength': 2048, 'description': 'Source citation for the candidate or explicit user-provided credential reference; never the password itself.'},
        'cipher': {'type': 'string', 'enum': _CIPHERS},
        'kdf': {'type': 'string', 'enum': ['pbkdf2', 'legacy']},
        'expected_kind': {'type': 'string', 'enum': _KINDS},
        'digest': {'type': 'string', 'enum': ['sha256', 'sha512', 'md5'], 'default': 'sha256'},
        'iterations': {'type': 'integer', 'minimum': 1000, 'maximum': 10000000, 'default': 10000},
        'base64_encoded': {'type': 'boolean', 'default': False},
        'max_bytes': {'type': 'integer', 'minimum': 1, 'maximum': 268435456, 'default': 67108864},
        'timeout_seconds': {'type': 'integer', 'minimum': 1, 'maximum': 120, 'default': 30}},
        'required': ['path', 'output_dir', 'password', 'key_evidence', 'cipher', 'kdf', 'expected_kind']})
def openssl_decrypt(path: str, output_dir: str, password: str, key_evidence: str, cipher: str,
                    kdf: str, expected_kind: str, digest: str = 'sha256', iterations: int = 10000,
                    base64_encoded: bool = False, max_bytes: int = 67108864, timeout_seconds: int = 30) -> Observation:
    from dftk import __version__
    tool = 'crypto.openssl_decrypt'
    src, root = Path(path), Path(output_dir).resolve()
    facts = {'path': path, 'key_evidence': key_evidence, 'cipher': cipher, 'kdf': kdf,
        'digest': digest, 'iterations': iterations if kdf == 'pbkdf2' else None,
        'expected_kind': expected_kind, 'attempt_count': 0, 'plaintext_published': False}
    if not src.is_file() or src.stat().st_size > max_bytes:
        return Observation(tool, Status.BLOCKED, 'Encrypted input is missing or exceeds the input/output byte budget', facts=facts)
    if '\n' in password or '\r' in password or '\0' in password:
        return Observation(tool, Status.ERROR, 'This password transport does not support newline or NUL characters', facts=facts)
    binary = resolve_external_tool('openssl')
    if binary is None:
        return Observation(tool, Status.UNSUPPORTED, 'OpenSSL is unavailable', facts=facts)
    root.mkdir(parents=True, exist_ok=True)
    source_sha = sha256_file(src)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.dftk-decrypt-', dir=root, delete=False) as output:
            temporary = Path(output.name)
        command = [binary, 'enc', '-' + cipher, '-d', '-in', str(src.resolve()), '-out', str(temporary),
                   '-pass', 'stdin', '-md', digest]
        if kdf == 'pbkdf2':
            command += ['-pbkdf2', '-iter', str(iterations)]
        if base64_encoded:
            command += ['-a']
        facts['attempt_count'] = 1
        result = subprocess.run(command, input=(password + '\n').encode('utf-8'),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=timeout_seconds, check=False)
        if result.returncode:
            facts['reason_code'] = 'password_parameters_or_ciphertext_invalid'
            return Observation(tool, Status.ERROR, 'Decryption attempt failed; no plaintext published', facts=facts,
                errors=[result.stderr.decode('utf-8', 'replace')[-2000:]], meta={'source_sha256': source_sha})
        if temporary.stat().st_size > max_bytes:
            raise ValueError('Decrypted output exceeds the byte budget')
        try:
            validation = _validate_plaintext(temporary, expected_kind)
        except (ValueError, OSError, sqlite3.DatabaseError, zipfile.BadZipFile, tarfile.TarError, EOFError) as exc:
            facts['reason_code'] = 'plaintext_validation_failed'
            return Observation(tool, Status.ERROR, 'Decryption returned bytes but expected structure did not validate; no plaintext published',
                facts=facts, errors=[str(exc)], meta={'source_sha256': source_sha})
        if sha256_file(src) != source_sha:
            raise ValueError('Encrypted source changed during decryption; reacquire stable evidence')
        output_sha = sha256_file(temporary)
        extension = {'sqlite': 'db', 'zip': 'zip', 'gzip': 'gz', 'tar': 'tar'}[expected_kind]
        destination = root / f'decrypted_{source_sha[:12]}_{output_sha[:12]}.{extension}'
        if destination.is_symlink():
            raise ValueError('Refusing an existing symlink as the decryption output')
        try:
            os.link(temporary, destination)  # no replacement of an existing file
        except FileExistsError:
            if not destination.is_file() or sha256_file(destination) != output_sha:
                raise ValueError('Existing output has different content; no file overwritten')
        prov = ProvenanceIndex()
        source = prov.add(source_artifact='', locator=f'file:{src.name}', tool=tool, version=__version__,
            sha256=source_sha, size=src.stat().st_size, kind='evidence')
        artifact = prov.add(source_artifact=source.artifact_id, locator=f'openssl:{cipher}:{kdf}', tool=tool,
            version=__version__, sha256=output_sha, size=destination.stat().st_size, path=str(destination),
            params={key: value for key, value in facts.items() if key not in {'path', 'plaintext_published'}})
        facts.update(plaintext_published=True, output_path=str(destination), output_sha256=output_sha,
                     validation=validation)
        return Observation(tool, Status.OK, 'Published one structurally validated decrypted artifact', facts=facts,
            evidence=[Evidence(path, 'decryption', {'output_path': str(destination), 'validation': validation},
                locator=f'openssl:{cipher}:{kdf}', source_sha256=source_sha, artifact_id=artifact.artifact_id,
                method='single supplied-password OpenSSL enc attempt', note='Inner structure validation does not independently authenticate acquisition origin or encryption parameters')],
            derived_artifacts=prov.all(), meta={'source_sha256': source_sha, 'provenance': prov.to_dict()})
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        facts['reason_code'] = 'decrypt_timeout' if isinstance(exc, subprocess.TimeoutExpired) else 'decrypt_failed'
        return Observation(tool, Status.ERROR, 'Decryption did not publish a validated output', facts=facts,
                           errors=[str(exc)], meta={'source_sha256': source_sha})
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
