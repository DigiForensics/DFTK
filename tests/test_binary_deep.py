# Copyright 2026 DyNooob @ DigiForensics
# Test for deep binary forensic parsers (PE imports/exports/resources/rich/signing,
# ELF dynamic). Fixtures are hand-built minimal-but-structurally-valid binaries.

import struct

import pytest

from dftk.primitives import binary_deep as bd


# ---------------------------------------------------------------------------
# Minimal valid PE32+ builder
# ---------------------------------------------------------------------------
def _build_pe32plus():
    sec = bytearray(0x500)          # section ".text" data, VA 0x1000 / file 0x400
    sec_va = 0x1000
    sec_raw = 0x400

    def rva(o):
        return sec_va + o

    # --- import by-name strings (section offset 0x00) ---
    kname = b"KERNEL32.dll\x00"
    sec[0:len(kname)] = kname
    name_rva = rva(0x00)
    # CreateFileA preceded by 2-byte hint at 0x40
    struct.pack_into("<H", sec, 0x40, 0)
    cf = b"CreateFileA\x00"
    sec[0x42:0x42 + len(cf)] = cf
    ibn_rva = rva(0x40)
    # IAT/INT thunks at 0x100
    struct.pack_into("<Q", sec, 0x100, ibn_rva)        # by name
    struct.pack_into("<Q", sec, 0x108, 0x8000000000000123)  # ordinal 0x123
    struct.pack_into("<Q", sec, 0x110, 0)              # terminator
    iat_rva = rva(0x100)
    # IID table at 0x200
    struct.pack_into("<I", sec, 0x200, iat_rva)        # OriginalFirstThunk
    struct.pack_into("<I", sec, 0x204, 0)              # TimeDateStamp
    struct.pack_into("<I", sec, 0x208, 0)              # ForwarderChain
    struct.pack_into("<I", sec, 0x20C, name_rva)       # Name
    struct.pack_into("<I", sec, 0x210, iat_rva)        # FirstThunk
    struct.pack_into("<Q", sec, 0x214, 0)              # terminating IID
    iid_rva = rva(0x200)

    # --- resource tree at 0x300 (RVA 0x1300) ---
    res = 0x300
    struct.pack_into("<I", sec, res + 0, 0)      # Characteristics
    struct.pack_into("<I", sec, res + 4, 0)      # TimeDateStamp
    struct.pack_into("<H", sec, res + 8, 0)      # MajorVersion
    struct.pack_into("<H", sec, res + 10, 0)     # MinorVersion
    struct.pack_into("<H", sec, res + 12, 0)     # NamedEntries
    struct.pack_into("<H", sec, res + 14, 1)     # IdEntries (type 24)
    struct.pack_into("<I", sec, res + 16, 24)    # type RT_MANIFEST
    struct.pack_into("<I", sec, res + 20, 0x80000000 | (0x40))  # -> level1
    # level1 dir at res+0x40
    l1 = res + 0x40
    struct.pack_into("<I", sec, l1 + 0, 0)
    struct.pack_into("<I", sec, l1 + 4, 0)
    struct.pack_into("<H", sec, l1 + 8, 0)
    struct.pack_into("<H", sec, l1 + 10, 0)
    struct.pack_into("<H", sec, l1 + 12, 0)
    struct.pack_into("<H", sec, l1 + 14, 1)      # IdEntries (name id 1)
    struct.pack_into("<I", sec, l1 + 16, 1)      # name id 1
    struct.pack_into("<I", sec, l1 + 20, 0x80000000 | (0x80))  # -> level2
    # level2 dir at res+0x80
    l2 = res + 0x80
    struct.pack_into("<I", sec, l2 + 0, 0)
    struct.pack_into("<I", sec, l2 + 4, 0)
    struct.pack_into("<H", sec, l2 + 8, 0)
    struct.pack_into("<H", sec, l2 + 10, 0)
    struct.pack_into("<H", sec, l2 + 12, 0)
    struct.pack_into("<H", sec, l2 + 14, 1)      # IdEntries (lang 1033)
    struct.pack_into("<I", sec, l2 + 16, 1033)   # lang id
    data_entry = res + 0xC0
    struct.pack_into("<I", sec, l2 + 20, (data_entry - res))  # -> data entry
    # data entry
    manifest = b'<?xml version="1.0"?><assembly><manifestVersion>1.0</manifestVersion></assembly>'
    moff = res + 0x100
    sec[moff:moff + len(manifest)] = manifest
    struct.pack_into("<I", sec, data_entry + 0, rva(moff))   # OffsetToData RVA
    struct.pack_into("<I", sec, data_entry + 4, len(manifest))
    struct.pack_into("<I", sec, data_entry + 8, 0)
    struct.pack_into("<I", sec, data_entry + 12, 0)
    res_rva = rva(res)

    # --- DOS + stub + PE headers ---
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    e_lfanew = 0x200
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    stub = bytearray(e_lfanew - 0x40)
    key = 0x12345678
    struct.pack_into("<4s", stub, 0, b"DanS")
    struct.pack_into("<I", stub, 4, key)
    prodid = 0x78  # LINK
    ver = 14
    struct.pack_into("<I", stub, 8, ((prodid << 16) | ver) ^ key)
    struct.pack_into("<I", stub, 12, 5 ^ key)
    stub[16:20] = b"Rich"
    struct.pack_into("<I", stub, 20, key)

    pe = bytearray(0x200)
    po = 0
    pe[po:po + 4] = b"PE\x00\x00"
    po += 4
    struct.pack_into("<H", pe, po, 0x8664)   # machine x86-64
    po += 2
    struct.pack_into("<H", pe, po, 1)        # nsec
    po += 2
    struct.pack_into("<I", pe, po, 0)        # tstamp
    po += 4
    struct.pack_into("<I", pe, po, 0)        # symtab
    po += 4
    struct.pack_into("<I", pe, po, 0)        # nsyms
    po += 4
    opt_size = 0xF0
    struct.pack_into("<H", pe, po, opt_size)  # COFF opt_size (at pe[20])
    # optional header (PE32+) base: COFF is 20 bytes from pe[4] -> starts at pe[24]
    op = 24

    def opt(o, fmt, val):
        struct.pack_into("<" + fmt, pe, op + o, val)

    opt(0, "H", 0x20B)        # magic
    opt(2, "B", 14)           # MajorLinkerVersion
    opt(3, "B", 0)            # MinorLinkerVersion
    opt(4, "I", 0)            # SizeOfCode
    opt(8, "I", 0)            # SizeOfInitializedData
    opt(12, "I", 0)           # SizeOfUninitializedData
    opt(16, "I", 0)           # AddressOfEntryPoint
    opt(20, "I", 0)           # BaseOfCode
    opt(24, "Q", 0x140000000) # ImageBase
    opt(32, "I", 0x1000)      # SectionAlignment
    opt(36, "I", 0x200)       # FileAlignment
    opt(40, "H", 6)           # OSMajor
    opt(42, "H", 0)           # OSMinor
    opt(44, "H", 0)           # ImageMajor
    opt(46, "H", 0)           # ImageMinor
    opt(48, "H", 6)           # SubsysMajor
    opt(50, "H", 0)           # SubsysMinor
    opt(52, "I", 0)           # Win32Version
    opt(56, "I", 0x3000)      # SizeOfImage
    opt(60, "I", 0x400)       # SizeOfHeaders
    opt(64, "I", 0)           # CheckSum
    opt(68, "H", 2)           # Subsystem GUI
    opt(70, "H", 0x8160)      # DllCharacteristics
    opt(72, "Q", 0x100000)    # StackReserve
    opt(80, "Q", 0x1000)      # StackCommit
    opt(88, "Q", 0x100000)    # HeapReserve
    opt(96, "Q", 0x1000)      # HeapCommit
    opt(104, "I", 0)          # LoaderFlags
    opt(108, "I", 16)         # NumberOfRvaAndSizes
    dd = 112
    # data directory 1 Import
    opt(dd + 8, "I", iid_rva)
    opt(dd + 12, "I", 0x28)
    # data directory 2 Resource
    opt(dd + 16, "I", res_rva)
    opt(dd + 20, "I", 0x200)
    # section table at opt_off + opt_size
    st = op + opt_size
    name = b".text\x00\x00\x00"
    struct.pack_into("<8s", pe, st, name)
    struct.pack_into("<I", pe, st + 8, 0x500)        # VirtualSize
    struct.pack_into("<I", pe, st + 12, 0x1000)      # VirtualAddress
    struct.pack_into("<I", pe, st + 16, 0x500)       # SizeOfRawData
    struct.pack_into("<I", pe, st + 20, 0x400)       # PointerToRawData
    struct.pack_into("<I", pe, st + 24, 0)
    struct.pack_into("<I", pe, st + 28, 0)
    struct.pack_into("<H", pe, st + 32, 0)
    struct.pack_into("<H", pe, st + 34, 0)
    struct.pack_into("<I", pe, st + 36, 0x60000020)  # CODE|EXEC|READ

    return bytes(dos) + bytes(stub) + bytes(pe) + bytes(sec)


def _build_authenticode(pe_bytes):
    """Wrap the PE with a Security directory containing a single X.509 cert."""
    # Minimal self-signed-like certificate DER (serial, sig alg, issuer, validity,
    # subject, spki). Sufficient to exercise parse_pkcs7_certificates.
    def tlv(tag, content):
        l = len(content)
        if l < 0x80:
            ln = bytes([l])
        elif l < 0x100:
            ln = bytes([0x81, l])
        else:
            ln = bytes([0x82, (l >> 8) & 0xFF, l & 0xFF])
        return bytes([tag]) + ln + content

    def oid_dotted(s):
        parts = [int(x) for x in s.split(".")]
        first = parts[0] * 40 + parts[1]
        out = bytes([first]) + b"".join(
            _base128(p) for p in parts[2:])
        return out

    def _base128(n):
        if n == 0:
            return bytes([0])
        bits = []
        while n:
            bits.append(n & 0x7F)
            n >>= 7
        bits.reverse()
        out = bytearray()
        for i, b in enumerate(bits):
            if i != len(bits) - 1:
                out.append(b | 0x80)
            else:
                out.append(b)
        return bytes(out)

    def oid_tlv(s):
        return tlv(0x06, oid_dotted(s))

    def ia5(s):
        return tlv(0x16, s.encode())

    def printable(s):
        return tlv(0x13, s.encode())

    def integer(b):
        return tlv(0x02, b)

    def seq(*items):
        return tlv(0x30, b"".join(items))

    def dn(attrs):
        rdn = []
        for oid, val in attrs:
            rdn.append(tlv(0x31, tlv(0x30, oid_tlv(oid) + printable(val))))
        return seq(*rdn)

    serial = integer(b"\x01\x02\x03\x04")
    sig_alg = seq(oid_tlv("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    issuer = dn([("2.5.4.3", "Test CA"), ("2.5.4.10", "DigiForensics")])
    validity = seq(tlv(0x17, b"250101000000Z"), tlv(0x17, b"300101000000Z"))
    subject = dn([("2.5.4.3", "Test Signer"), ("2.5.4.10", "DigiForensics")])
    spki_alg = seq(oid_tlv("1.2.840.113549.1.1.1"), tlv(0x05, b""))
    spki = seq(spki_alg, tlv(0x03, b"\x00\x01\x00\x01"))  # BIT STRING
    tbs = seq(integer(b"\x02"), sig_alg, issuer, validity, subject, spki)
    cert = seq(tbs, sig_alg, tlv(0x03, b"\x00\xaa"))
    # wrap in a PKCS7-style container: ContentInfo -> SignedData -> cert set
    cert_set = tlv(0x31, cert)            # SET OF Certificate
    signed_data = seq(integer(b"\x01"), tlv(0x31, b""), tlv(0x30, b""), cert_set)
    content_info = seq(oid_tlv("1.2.840.113549.1.7.2"), tlv(0xA0, signed_data))

    # append security directory at end of file
    blob = content_info
    sec_len = 8 + len(blob)
    out = bytearray(pe_bytes)
    sec_off = len(out)
    while len(out) % 8:
        out.append(0)
    sec_off = len(out)
    out.extend(bytearray(sec_len))
    struct.pack_into("<I", out, sec_off, sec_len)   # WIN_CERTIFICATE.dwLength
    struct.pack_into("<H", out, sec_off + 4, 0x0200)  # wRevision
    struct.pack_into("<H", out, sec_off + 6, 0x0001)  # wCertificateType X509
    out[sec_off + 8:sec_off + 8 + len(blob)] = blob
    # point Security data directory (index 4) at sec_off (file offset)
    e_lfanew = struct.unpack_from("<I", out, 0x3C)[0]
    opt_off = e_lfanew + 24
    dd4 = opt_off + 112 + 4 * 8
    struct.pack_into("<I", out, dd4, sec_off)
    struct.pack_into("<I", out, dd4 + 4, sec_len)
    return bytes(out)


# ---------------------------------------------------------------------------
# Multi-DLL PE32+ builder (USER32 listed BEFORE KERNEL32 — non-alphabetical)
# Used to lock imphash *ordering* behaviour. The expected imphash below was
# obtained from pefile 2024.8.26 (independent oracle) on this exact byte
# pattern, NOT hand-computed, so it guards against reintroduction of the
# sort-by-DLL-name bug.
# ---------------------------------------------------------------------------
def _build_pe_imphash_multidll():
    sec = bytearray(0x800)
    def r2f(r): return r - 0x1000  # VA 0x1000 -> section-internal offset
    sec[r2f(0x1000):r2f(0x1000) + 11] = b"USER32.dll\x00"
    struct.pack_into("<H", sec, r2f(0x1040), 0); sec[r2f(0x1042):r2f(0x1042) + 12] = b"MessageBoxA\x00"
    struct.pack_into("<H", sec, r2f(0x1060), 0); sec[r2f(0x1062):r2f(0x1062) + 12] = b"MessageBoxW\x00"
    sec[r2f(0x1080):r2f(0x1080) + 12] = b"KERNEL32.dll\x00"
    struct.pack_into("<H", sec, r2f(0x10C0), 0); sec[r2f(0x10C2):r2f(0x10C2) + 12] = b"CreateFileA\x00"
    struct.pack_into("<H", sec, r2f(0x10E0), 0); sec[r2f(0x10E2):r2f(0x10E2) + 9] = b"ReadFile\x00"
    # USER32 thunks @ rva 0x1200
    struct.pack_into("<Q", sec, r2f(0x1200), 0x1042)
    struct.pack_into("<Q", sec, r2f(0x1208), 0x1062)
    struct.pack_into("<Q", sec, r2f(0x1210), 0)
    # KERNEL32 thunks @ rva 0x1220
    struct.pack_into("<Q", sec, r2f(0x1220), 0x10C2)
    struct.pack_into("<Q", sec, r2f(0x1228), 0x10E2)
    struct.pack_into("<Q", sec, r2f(0x1230), 0)
    # IID @ rva 0x1300 — USER32 FIRST (proves ordering matters)
    iid = 0x1300
    struct.pack_into("<IIIII", sec, r2f(iid), 0x1200, 0, 0, 0x1000, 0x1200)   # USER32
    struct.pack_into("<IIIII", sec, r2f(iid + 20), 0x1220, 0, 0, 0x1080, 0x1220)  # KERNEL32
    struct.pack_into("<Q", sec, r2f(iid + 40), 0)
    dos = bytearray(0x40); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3C, 0x200)
    stub = bytearray(0x1C0)
    pe = bytearray(0x200); po = 0
    pe[po:po + 4] = b"PE\x00\x00"; po += 4
    struct.pack_into("<H", pe, po, 0x8664); po += 2
    struct.pack_into("<H", pe, po, 1); po += 2
    po += 4; po += 4; po += 4
    opt_size = 0xF0; struct.pack_into("<H", pe, po, opt_size); po += 2
    op = 24
    def opt(o, fmt, v): struct.pack_into("<" + fmt, pe, op + o, v)
    opt(0, "H", 0x20B); opt(2, "B", 14); opt(3, "B", 0)
    opt(24, "Q", 0x140000000); opt(32, "I", 0x1000); opt(36, "I", 0x200)
    opt(56, "I", 0x3000); opt(60, "I", 0x400); opt(68, "H", 2); opt(70, "H", 0x8160)
    opt(108, "I", 16)
    dd = 112
    opt(dd + 8, "I", 0x1300); opt(dd + 12, "I", 0x30)   # Import dir
    st = op + opt_size
    struct.pack_into("<8s", pe, st, b".text\x00\x00\x00")
    struct.pack_into("<I", pe, st + 8, 0x400); struct.pack_into("<I", pe, st + 12, 0x1000)
    struct.pack_into("<I", pe, st + 16, 0x800); struct.pack_into("<I", pe, st + 20, 0x400)
    struct.pack_into("<I", pe, st + 36, 0x60000020)
    return bytes(dos) + bytes(stub) + bytes(pe) + bytes(sec)


# ---------------------------------------------------------------------------
# Export-bearing PE32+ builder. Expected export table below obtained from
# pefile 2024.8.26 (independent oracle) on this exact pattern.
# ---------------------------------------------------------------------------
def _build_pe_with_exports():
    sec = bytearray(0x500)
    sec_va = 0x1000
    def rva(o): return sec_va + o
    nm = b"mylib.dll\x00"; sec[0:len(nm)] = nm; name_rva = rva(0x00)
    off = 0x20
    for n in [b"ExportA\x00", b"ExportB\x00", b"ExportC\x00"]:
        sec[off:off + len(n)] = n; off += 0x10
    name_rvas = [rva(0x20), rva(0x30), rva(0x40)]
    exp_rva = rva(0xA0)
    fwd = b"other.dll.OtherFunc\x00"; sec[0xD0:0xD0 + len(fwd)] = fwd; fwd_rva = rva(0xD0)
    aof_o = 0x60
    for i, v in enumerate([0x2000, 0x2100, 0x2200, fwd_rva]):
        struct.pack_into("<I", sec, aof_o + i * 4, v)
    aon_o = 0x70
    for i, v in enumerate(name_rvas):
        struct.pack_into("<I", sec, aon_o + i * 4, v)
    aono_o = 0x80
    for i in range(3):
        struct.pack_into("<H", sec, aono_o + i * 2, i)
    eo = 0xA0
    struct.pack_into("<I", sec, eo + 0, 0); struct.pack_into("<I", sec, eo + 4, 0)
    struct.pack_into("<H", sec, eo + 8, 0); struct.pack_into("<H", sec, eo + 10, 0)
    struct.pack_into("<I", sec, eo + 12, name_rva); struct.pack_into("<I", sec, eo + 16, 1)
    struct.pack_into("<I", sec, eo + 20, 4); struct.pack_into("<I", sec, eo + 24, 3)
    struct.pack_into("<I", sec, eo + 28, rva(0x60)); struct.pack_into("<I", sec, eo + 32, rva(0x70)); struct.pack_into("<I", sec, eo + 36, rva(0x80))
    dos = bytearray(0x40); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3C, 0x200)
    stub = bytearray(0x1C0)
    pe = bytearray(0x200); po = 0
    pe[po:po + 4] = b"PE\x00\x00"; po += 4
    struct.pack_into("<H", pe, po, 0x8664); po += 2
    struct.pack_into("<H", pe, po, 1); po += 2; po += 4; po += 4; po += 4
    opt_size = 0xF0; struct.pack_into("<H", pe, po, opt_size); po += 2
    op = 24
    def opt(o, fmt, v): struct.pack_into("<" + fmt, pe, op + o, v)
    opt(0, "H", 0x20B); opt(2, "B", 14); opt(3, "B", 0)
    opt(24, "Q", 0x140000000); opt(32, "I", 0x1000); opt(36, "I", 0x200)
    opt(56, "I", 0x3000); opt(60, "I", 0x400); opt(68, "H", 2); opt(70, "H", 0x8160)
    opt(108, "I", 16); dd = 112
    opt(dd + 0, "I", exp_rva); opt(dd + 4, "I", 0x40)
    st = op + opt_size
    struct.pack_into("<8s", pe, st, b".text\x00\x00\x00")
    struct.pack_into("<I", pe, st + 8, 0x500); struct.pack_into("<I", pe, st + 12, 0x1000)
    struct.pack_into("<I", pe, st + 16, 0x500); struct.pack_into("<I", pe, st + 20, 0x400)
    struct.pack_into("<I", pe, st + 36, 0x60000020)
    return bytes(dos) + bytes(stub) + bytes(pe) + bytes(sec)


@pytest.fixture
def pe_multidll_file(tmp_path):
    p = tmp_path / "multidll.exe"
    p.write_bytes(_build_pe_imphash_multidll())
    return str(p)


@pytest.fixture
def pe_exports_file(tmp_path):
    p = tmp_path / "withexports.exe"
    p.write_bytes(_build_pe_with_exports())
    return str(p)


@pytest.fixture
def pe_file(tmp_path):
    p = tmp_path / "sample.exe"
    p.write_bytes(_build_pe32plus())
    return str(p)


@pytest.fixture
def pe_signed_file(tmp_path):
    p = tmp_path / "signed.exe"
    p.write_bytes(_build_authenticode(_build_pe32plus()))
    return str(p)


# ---------------------------------------------------------------------------
# PE tests
# ---------------------------------------------------------------------------
def test_pe_headers(pe_file):
    obs = bd.pe_headers(pe_file)
    assert obs.status.value == "ok"
    f = obs.facts
    assert f["machine"] == "x86-64"
    assert f["bitness"] == 64
    assert f["subsystem"] == "WINDOWS_GUI"
    assert f["rich_header"]["record_count"] == 1
    assert f["section_count"] == 1


def test_pe_imports(pe_file):
    obs = bd.pe_imports(pe_file)
    assert obs.status.value == "ok"
    assert obs.facts["import_count"] == 1
    imp = obs.facts["imports"][0]
    assert imp["dll"] == "KERNEL32.dll"
    names = [x["name"] for x in imp["functions"] if x["name"]]
    ords = [x["ordinal"] for x in imp["functions"] if x["ordinal"] is not None]
    assert "CreateFileA" in names
    assert 0x123 in ords
    assert obs.facts["imphash"] and len(obs.facts["imphash"]) == 32


def test_pe_resources(pe_file):
    obs = bd.pe_resources(pe_file)
    assert obs.status.value == "ok"
    assert obs.facts["entry_count"] == 1
    assert obs.facts["manifest"] and "manifestVersion" in obs.facts["manifest"]


def test_pe_rich_header(pe_file):
    obs = bd.pe_rich_header(pe_file)
    assert obs.facts["present"] is True
    assert obs.facts["xor_key"] == "0x12345678"
    assert obs.facts["toolchain_summary"][0]["prodid_name"] == "LINK"


def test_pe_signing(pe_signed_file):
    obs = bd.pe_signing(pe_signed_file)
    assert obs.facts["signed"] is True
    assert obs.facts["certificate_count"] >= 1
    cert = obs.facts["certificates"][0]
    assert cert["subject"] == "CN=Test Signer, O=DigiForensics"
    assert cert["issuer"] == "CN=Test CA, O=DigiForensics"
    assert cert["signature_algorithm"] == "sha256WithRSAEncryption"


def test_pe_signing_unsigned(pe_file):
    obs = bd.pe_signing(pe_file)
    assert obs.facts["signed"] is False


# Golden imphash below is the output of pefile 2024.8.26 on the byte pattern
# produced by _build_pe_imphash_multidll (USER32 listed before KERNEL32). It is
# an independent-oracle value, not hand-computed — it pins the Mandiant/pefile
# imphash contract (import-table order, case-insensitive, .dll/.sys/.ocx strip).
IMPHASH_GOLDEN = "5807df5b4a2aadab73f73224a3a19c5d"


def test_pe_imphash_matches_reference(pe_multidll_file):
    obs = bd.pe_imports(pe_multidll_file)
    assert obs.status.value == "ok"
    # import order must be preserved: USER32 before KERNEL32
    dlls = [i["dll"] for i in obs.facts["imports"]]
    assert dlls == ["USER32.dll", "KERNEL32.dll"]
    assert obs.facts["imphash"] == IMPHASH_GOLDEN


def test_pe_imphash_not_sorted(pe_multidll_file):
    data = open(pe_multidll_file, "rb").read()
    base = bd.parse_pe(data)
    imports = bd.parse_imports(data, base)
    ordered = bd.compute_imphash(imports)
    assert ordered == IMPHASH_GOLDEN
    # If we sorted the DLLs alphabetically the hash MUST change — this locks in
    # the "no sort" behaviour that matches pefile/Mandiant. A regression that
    # re-sorts would make both values equal.
    sorted_imports = sorted(imports, key=lambda x: (x["dll"] or "").lower())
    assert bd.compute_imphash(sorted_imports) != ordered


# Golden exports below are pefile 2024.8.26 output on _build_pe_with_exports.
EXPORTS_GOLDEN = {
    ("ExportA", 1, 0x2000),
    ("ExportB", 2, 0x2100),
    ("ExportC", 3, 0x2200),
}


def test_pe_exports(pe_exports_file):
    obs = bd.pe_exports(pe_exports_file)
    assert obs.status.value == "ok"
    assert obs.facts["export_count"] == 3
    assert obs.facts["forwarder_count"] == 0
    assert obs.facts["module_name"] == "mylib.dll"
    got = {(e["name"], e["ordinal"], e["address"]) for e in obs.facts["exports"]}
    assert got == EXPORTS_GOLDEN


# ---------------------------------------------------------------------------
# Minimal valid ELF64 builder
# ---------------------------------------------------------------------------
def _build_elf64():
    endian = "<"
    interp = b"/lib64/ld-linux-x86-64.so.2\x00"
    dynstr = b"\x00libc.so.6\x00printf\x00malloc\x00testlib.so\x00/opt/lib\x00/usr/lib\x00"
    # offsets within dynstr
    off_libc = 1
    off_printf = 1 + 10          # 11
    off_malloc = off_printf + 7   # 18
    off_soname = off_malloc + 7   # 25
    off_rpath = off_soname + 11   # 36
    off_runpath = off_rpath + 9   # 45
    dynstr_len = len(dynstr)

    # dynsym: null, printf, malloc
    sym0 = struct.pack(endian + "IBBHQQ", 0, 0, 0, 0, 0, 0)
    sym_printf = struct.pack(endian + "IBBHQQ", off_printf, (1 << 4) | 2, 0, 0, 0, 0)
    sym_malloc = struct.pack(endian + "IBBHQQ", off_malloc, (1 << 4) | 2, 0, 0, 0, 0)
    dynsym = sym0 + sym_printf + sym_malloc

    # dynamic entries
    def dyn(tag, val):
        return struct.pack(endian + "qQ", tag, val)
    dynamic = b"".join([
        dyn(1, off_libc),       # DT_NEEDED
        dyn(5, 0x1000),         # DT_STRTAB (vaddr; unused for string resolution)
        dyn(6, 0x2000),         # DT_SYMTAB
        dyn(10, dynstr_len),    # DT_STRSZ
        dyn(11, 24),            # DT_SYMENT
        dyn(14, off_soname),    # DT_SONAME
        dyn(15, off_rpath),     # DT_RPATH
        dyn(29, off_runpath),   # DT_RUNPATH
        dyn(30, 1),             # DT_FLAGS DF_BIND_NOW
        dyn(0x6FFFFFFB, 1),     # DT_FLAGS_1 DF_1_NOW
        dyn(0, 0),
    ])

    # .note.gnu.build-id
    build_id = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\x00" + build_id
    # pad note to 4-byte alignment
    while len(note) % 4:
        note += b"\x00"

    shstr = b"\x00" + b".interp\x00" + b".dynsym\x00" + b".dynstr\x00" + \
            b".dynamic\x00" + b".note.gnu.build-id\x00" + b".shstrtab\x00"
    # section name offsets
    n_interp = 1
    n_dynsym = n_interp + 8
    n_dynstr = n_dynsym + 8
    n_dynamic = n_dynstr + 8
    n_note = n_dynamic + 9
    n_shstr = n_note + 18

    # layout: Ehdr(64) + Phdrs(3*56) + interp + dynsym + dynstr + dynamic + note + shstr + shdrs
    ehsize = 64
    phentsize = 56
    nph = 3
    shentsize = 64
    # compute offsets
    off_phdr = ehsize
    off_interp = off_phdr + nph * phentsize
    off_dynsym = off_interp + len(interp)
    off_dynstr = off_dynsym + len(dynsym)
    off_dynamic = off_dynstr + len(dynstr)
    off_note = off_dynamic + len(dynamic)
    off_shstr = off_note + len(note)
    off_shdr = off_shstr + len(shstr)
    nsh = 7
    total = off_shdr + nsh * shentsize

    buf = bytearray(total)
    # Ehdr
    buf[0:4] = b"\x7fELF"
    buf[4] = 2   # ELFCLASS64
    buf[5] = 1   # ELFDATA2LSB
    buf[6] = 1
    struct.pack_into("<H", buf, 16, 3)        # e_type ET_DYN
    struct.pack_into("<H", buf, 18, 0x3E)     # e_machine x86-64
    struct.pack_into("<I", buf, 20, 1)        # e_version
    struct.pack_into("<Q", buf, 24, 0)        # e_entry
    struct.pack_into("<Q", buf, 32, off_phdr) # e_phoff
    struct.pack_into("<Q", buf, 40, off_shdr) # e_shoff
    struct.pack_into("<I", buf, 48, 0)        # e_flags
    struct.pack_into("<H", buf, 52, ehsize)
    struct.pack_into("<H", buf, 54, phentsize)
    struct.pack_into("<H", buf, 56, nph)
    struct.pack_into("<H", buf, 58, shentsize)
    struct.pack_into("<H", buf, 60, nsh)
    struct.pack_into("<H", buf, 62, 6)        # e_shstrndx

    # Phdrs
    def phdr(base, p_type, p_flags, p_offset, p_vaddr, p_filesz):
        struct.pack_into("<I", buf, base, p_type)
        struct.pack_into("<I", buf, base + 4, p_flags)
        struct.pack_into("<Q", buf, base + 8, p_offset)
        struct.pack_into("<Q", buf, base + 16, p_vaddr)
        struct.pack_into("<Q", buf, base + 24, p_vaddr)
        struct.pack_into("<Q", buf, base + 32, p_filesz)
        struct.pack_into("<Q", buf, base + 40, p_filesz)
        struct.pack_into("<Q", buf, base + 48, 0x1000)
    phdr(off_phdr, 3, 4, off_interp, 0, len(interp))        # PT_INTERP
    phdr(off_phdr + 56, 1, 5, 0, 0, total)                 # PT_LOAD
    phdr(off_phdr + 112, 2, 6, off_dynamic, 0, len(dynamic))  # PT_DYNAMIC

    # section data
    buf[off_interp:off_interp + len(interp)] = interp
    buf[off_dynsym:off_dynsym + len(dynsym)] = dynsym
    buf[off_dynstr:off_dynstr + len(dynstr)] = dynstr
    buf[off_dynamic:off_dynamic + len(dynamic)] = dynamic
    buf[off_note:off_note + len(note)] = note
    buf[off_shstr:off_shstr + len(shstr)] = shstr

    def shdr(base, name_off, sh_type, sh_offset, sh_size, sh_link, sh_entsize):
        struct.pack_into("<I", buf, base, name_off)
        struct.pack_into("<I", buf, base + 4, sh_type)
        struct.pack_into("<Q", buf, base + 8, 0)          # flags
        struct.pack_into("<Q", buf, base + 16, 0)         # addr
        struct.pack_into("<Q", buf, base + 24, sh_offset)
        struct.pack_into("<Q", buf, base + 32, sh_size)
        struct.pack_into("<I", buf, base + 40, sh_link)
        struct.pack_into("<I", buf, base + 44, 0)         # info
        struct.pack_into("<Q", buf, base + 48, 0)         # addralign
        struct.pack_into("<Q", buf, base + 56, sh_entsize)

    # null section
    shdr(off_shdr, 0, 0, 0, 0, 0, 0)
    # .interp
    shdr(off_shdr + 64, n_interp, 1, off_interp, len(interp), 0, 0)
    # .dynsym
    shdr(off_shdr + 128, n_dynsym, 11, off_dynsym, len(dynsym), 4, 24)
    # .dynstr
    shdr(off_shdr + 192, n_dynstr, 3, off_dynstr, len(dynstr), 0, 0)
    # .dynamic
    shdr(off_shdr + 256, n_dynamic, 6, off_dynamic, len(dynamic), 4, 16)
    # .note.gnu.build-id
    shdr(off_shdr + 320, n_note, 7, off_note, len(note), 0, 0)
    # .shstrtab
    shdr(off_shdr + 384, n_shstr, 3, off_shstr, len(shstr), 0, 0)

    return bytes(buf)


@pytest.fixture
def elf_file(tmp_path):
    p = tmp_path / "sample.so"
    p.write_bytes(_build_elf64())
    return str(p)


def test_elf_dynamic(elf_file):
    obs = bd.elf_dynamic(elf_file)
    assert obs.status.value == "ok"
    f = obs.facts
    assert f["class"] == 64
    assert f["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert "libc.so.6" in f["needed"]
    assert f["soname"] == "testlib.so"
    assert f["rpath"] == "/opt/lib"
    assert f["runpath"] == "/usr/lib"
    assert "DF_BIND_NOW" in f["dt_flags"]
    assert "DF_1_NOW" in f["dt_flags_1"]
    assert f["build_id"] == "deadbeefcafebabe"
    names = {s["name"] for s in f["symbols"]}
    assert "printf" in names and "malloc" in names
    defined = {s["name"]: s["defined"] for s in f["symbols"]}
    assert defined["printf"] is False  # undefined (imported)
