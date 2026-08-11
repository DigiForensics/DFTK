from dftk.primitives.windows import registry_inventory,evtx_summary
from dftk.primitives.e01 import e01_filesystem_inventory
from dftk.core.models import Status


def test_windows_registry_dependency_is_explicit(tmp_path):
    p=tmp_path/'SYSTEM'; p.write_bytes(b'regf'+b'\0'*4096)
    obs=registry_inventory(str(p))
    assert obs.status in (Status.UNSUPPORTED,Status.ERROR)
    if obs.status==Status.UNSUPPORTED: assert any('python-registry' in e for e in obs.errors)


def test_evtx_dependency_is_explicit(tmp_path):
    p=tmp_path/'a.evtx'; p.write_bytes(b'ElfFile\0'+b'\0'*4096)
    obs=evtx_summary(str(p))
    assert obs.status in (Status.UNSUPPORTED,Status.ERROR)


def test_e01_filesystem_dependency_is_explicit(tmp_path):
    p=tmp_path/'x.E01'; p.write_bytes(b'EVF\x09\r\n\xff\x00'+b'\0'*128)
    obs=e01_filesystem_inventory(str(p))
    assert obs.status==Status.UNSUPPORTED
