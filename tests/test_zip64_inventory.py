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

import zipfile

from pathlib import Path

from dftk.primitives.files import archive_inventory


def test_zip64_large_member_count_inventory(tmp_path: Path):
    # A1 regression: archives whose member count forces a Zip64 end-of-central-
    # directory record must still inventory every member (the manual central-
    # directory walker must parse the Zip64 EOCD, not silently report 0 members).
    z = tmp_path / "big.zip"
    n = 70000
    with zipfile.ZipFile(z, "w", zipfile.ZIP_STORED) as zf:
        for i in range(n):
            zf.writestr(f"f{i:06d}.txt", b"x")

    obs = archive_inventory(str(z), limit=n + 10)
    assert obs.status.value == "ok"
    assert obs.facts["format"] == "zip"
    assert obs.facts["member_count"] == n


def test_classic_zip_inventory_unchanged(tmp_path: Path):
    z = tmp_path / "small.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", b"hello")
        zf.writestr("b.txt", b"world")

    obs = archive_inventory(str(z))
    assert obs.status.value == "ok"
    names = {m["name"] for m in obs.facts["members"]}
    assert names == {"a.txt", "b.txt"}
