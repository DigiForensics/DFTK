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

"""Cross-platform advisory file locking shared by the case store and the ledger."""

from __future__ import annotations

from contextlib import contextmanager
import os
import time
from pathlib import Path
from typing import Iterator


@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive advisory lock on ``path`` for the duration of the block.

    ``path`` must be a dedicated lock file, not the resource being protected: on
    Windows a byte-range lock needs the locked region to exist, so an empty lock
    file is seeded with a sentinel byte. Locking a data file that way would
    corrupt its first byte.

    The lock is advisory (every DFTK writer must take it) and is released by the
    OS if the owning process exits.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as fh:
        fh.seek(0, os.SEEK_END)
        if fh.tell() == 0:
            fh.write(b"0")
            fh.flush()
        fh.seek(0)
        if os.name == "nt":
            import msvcrt

            # LK_LOCK itself retries only for a bounded period on Windows. Use
            # non-blocking acquisition in a loop so a legitimate long-running
            # forensic parser does not make a concurrent caller fail merely
            # because the resource is busy. The OS releases the byte-range lock
            # automatically if the owning process exits.
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
                finally:
                    fh.seek(0)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
