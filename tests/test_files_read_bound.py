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

from pathlib import Path

from dftk.core.helpers import read_file_bounded_observation, sha256_file
from dftk.primitives.files import file_strings, file_strings_unicode
from dftk.core.models import Observation, Status


def test_read_file_bounded_observation_oversize_returns_unsupported(tmp_path: Path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 100)
    data, err, src = read_file_bounded_observation("t", str(f), max_bytes=10)
    assert data is None
    assert isinstance(err, Observation)
    assert err.status.value == "unsupported"
    # On oversize we deliberately do NOT hash: hashing would force the very full
    # read we are trying to avoid. Chain-of-custody still gets the hash on the
    # normal (in-memory) path.
    assert err.meta.get("source_sha256") is None


def test_read_file_bounded_observation_success(tmp_path: Path):
    f = tmp_path / "ok.bin"
    f.write_bytes(b"hello world")
    data, err, src = read_file_bounded_observation("t", str(f), max_bytes=1024)
    assert err is None
    assert data == b"hello world"
    assert src == sha256_file(str(f))


def test_file_strings_normal_file_ok(tmp_path: Path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"password=secret123\nadmin::token\n")
    obs = file_strings(str(f))
    assert obs.status.value == "ok"
    joined = " ".join(s["value"] for s in obs.facts["strings"])
    assert "password=secret123" in joined or "secret123" in joined


def test_file_strings_oversize_routes_to_unsupported(tmp_path: Path, monkeypatch):
    f = tmp_path / "big.bin"
    f.write_bytes(b"hello")
    from dftk.primitives import files as files_mod

    def _fake(name, p, max_bytes=None):
        return None, Observation(name, Status.UNSUPPORTED, "oversize for test"), None

    monkeypatch.setattr(files_mod, "read_file_bounded_observation", _fake)
    obs = file_strings(str(f))
    assert obs.status.value == "unsupported"


def test_file_strings_unicode_oversize_routes_to_unsupported(tmp_path: Path, monkeypatch):
    f = tmp_path / "big.bin"
    f.write_bytes(b"hello")
    from dftk.primitives import files as files_mod

    def _fake(name, p, max_bytes=None):
        return None, Observation(name, Status.UNSUPPORTED, "oversize for test"), None

    monkeypatch.setattr(files_mod, "read_file_bounded_observation", _fake)
    obs = file_strings_unicode(str(f))
    assert obs.status.value == "unsupported"
