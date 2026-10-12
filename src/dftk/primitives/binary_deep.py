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

"""Deep binary forensics — PE structure/imports/exports/resources/Authenticode
and ELF dynamic metadata. All parsers are pure-Python, bounded and read-only.

These complement the inventory-level ``binary.pe_inventory`` /
``binary.elf_inventory`` tools: the inventory gives a top-down view, these
tools extract the structural links an investigator needs (imported APIs,
exported symbols, embedded manifest, code-signing chain, build provenance).
"""

from __future__ import annotations
from pathlib import Path
import struct, re, hashlib
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel
from dftk.core.helpers import sha256_file, read_file_bounded_observation

MAX_IMPORT_FUNCS = 200_000
MAX_EXPORTS = 200_000
MAX_RESOURCE_ENTRIES = 10_000
MAX_RICH_RECORDS = 4_096
MAX_ELF_SYMBOLS = 5_000

PE_MACHINES = {0x014c: "x86", 0x0166: "MIPS", 0x01c0: "ARM", 0x01c4: "ARMv7",
               0xaa64: "ARM64", 0x8664: "x86-64", 0x2000: "R3000", 0x9041: "alpha"}
SUBSYSTEMS = {0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
              7: "WIN9X_CUI", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION",
              11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER",
              14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION"}
DD_NAMES = ["Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
            "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig",
            "BoundImport", "IAT", "DelayImport", "COMDescriptor", "Reserved"]

DLL_CHAR_BITS = [(0x0040, "DYNAMIC_BASE"), (0x0080, "FORCE_INTEGRITY"),
                (0x0100, "NX_COMPAT"), (0x0200, "NO_ISOLATION"),
                (0x0400, "NO_SEH"), (0x0800, "NO_BIND"), (0x1000, "APPCONTAINER"),
                (0x2000, "WDM_DRIVER"), (0x4000, "GUARD_CF"), (0x8000, "TERMINAL_SERVER_AWARE")]
SEC_CHAR_BITS = [(0x20, "CODE"), (0x40, "INITIALIZED_DATA"), (0x80, "UNINITIALIZED_DATA"),
                (0x20000000, "LNK_INFO"), (0x40000000, "LNK_REMOVE"),
                (0x80000000, "LNK_COMDAT"), (0x1000000, "MEM_DISCARDABLE"),
                (0x2000000, "MEM_EXECUTE"), (0x4000000, "MEM_READ"),
                (0x8000000, "MEM_WRITE")]

RT_NAMES = {1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU", 5: "RT_DIALOG",
            6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT", 9: "RT_ACCELERATOR",
            10: "RT_RCDATA", 11: "RT_MESSAGETABLE", 12: "RT_GROUP_CURSOR",
            14: "RT_GROUP_ICON", 16: "RT_VERSION", 24: "RT_MANIFEST"}
PRODID_NAMES = {0x78: "LINK", 0x79: "LINK", 0x8b: "MASM", 0x8c: "MASM", 0x8d: "MASM",
                0x8e: "MASM", 0x8f: "MASM", 0x90: "MASM", 0x91: "MASM", 0x92: "MASM",
                0x93: "MASM", 0x94: "CVTOMF", 0x95: "LINK", 0x96: "CVTRES",
                0x97: "LINK", 0x98: "MASM", 0x99: "MASM", 0x9a: "MASM", 0x9b: "MASM",
                0x9c: "MASM", 0x9d: "MASM", 0x9e: "MASM", 0x9f: "MASM", 0xa0: "MASM",
                0xa1: "MASM", 0xa2: "MASM", 0xa3: "MASM", 0xa4: "MASM", 0xa5: "MASM",
                0xb2: "CVTOMF", 0xb3: "LIB", 0xb4: "LINK", 0xb5: "LINK", 0xb6: "LINK",
                0xb7: "LINK", 0xb8: "LINK", 0xb9: "LINK", 0xba: "LINK", 0xbb: "LINK",
                0xbc: "LINK", 0xbd: "LIB", 0xbe: "LINK", 0xbf: "LINK", 0xc0: "LINK",
                0xc1: "LINK", 0xc2: "LINK", 0xc3: "LINK", 0xc4: "LINK", 0xc5: "LINK",
                0xc6: "LINK", 0xc7: "LINK", 0xc8: "LINK", 0xc9: "LINK", 0xca: "LINK",
                0x101: "Implib", 0x102: "ImportLib", 0x103: "ImportLib",
                0x104: "ImportLib", 0x105: "ImportLib", 0x106: "ImportLib",
                0x107: "ImportLib", 0x108: "ImportLib", 0x109: "ImportLib",
                0x10a: "ImportLib", 0x10b: "ImportLib", 0x10c: "ImportLib",
                0x10d: "ImportLib", 0x10e: "ImportLib", 0x10f: "ImportLib",
                0x110: "ImportLib", 0x111: "ImportLib", 0x112: "ImportLib",
                0x113: "ImportLib", 0x114: "ImportLib", 0x115: "ImportLib",
                0x116: "ImportLib", 0x117: "ImportLib", 0x118: "ImportLib",
                0x119: "ImportLib", 0x11a: "ImportLib", 0x11b: "ImportLib",
                0x11c: "ImportLib", 0x11d: "ImportLib", 0x11e: "ImportLib",
                0x11f: "ImportLib", 0x120: "ImportLib", 0x121: "ImportLib",
                0x122: "ImportLib", 0x123: "ImportLib", 0x124: "ImportLib",
                0x125: "ImportLib", 0x126: "ImportLib", 0x127: "ImportLib",
                0x128: "ImportLib", 0x129: "ImportLib", 0x12a: "ImportLib",
                0x12b: "ImportLib", 0x12c: "ImportLib", 0x12d: "ImportLib",
                0x12e: "ImportLib", 0x12f: "ImportLib", 0x130: "ImportLib",
                0x131: "ImportLib", 0x132: "ImportLib", 0x133: "ImportLib",
                0x134: "ImportLib", 0x135: "ImportLib", 0x136: "ImportLib",
                0x137: "ImportLib", 0x138: "ImportLib", 0x139: "ImportLib",
                0x13a: "ImportLib", 0x13b: "ImportLib", 0x13c: "ImportLib",
                0x13d: "ImportLib", 0x13e: "ImportLib", 0x13f: "ImportLib"}


# --------------------------------------------------------------------------
# Shared PE structure parsing
# --------------------------------------------------------------------------
def parse_pe(data: bytes) -> dict | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    peoff = struct.unpack_from("<I", data, 0x3C)[0]
    if peoff + 24 > len(data) or data[peoff:peoff + 4] != b"PE\0\0":
        return None
    machine, nsec, tstamp, _symtab, _nsyms, opt_size, chars = struct.unpack_from(
        "<HHIIIHH", data, peoff + 4)
    opt_off = peoff + 24
    magic = struct.unpack_from("<H", data, opt_off)[0] if opt_off + 2 <= len(data) else 0
    bitness = 64 if magic == 0x20B else 32 if magic in (0x10B, 0x107) else None
    if bitness is None:
        return None

    def u(off, fmt):
        try:
            return struct.unpack_from(fmt, data, off)[0]
        except struct.error:
            return None

    opt = {}
    if bitness == 32:
        opt["image_base"] = u(opt_off + 28, "<I")
        dd_start = opt_off + 96
        ndd = u(opt_off + 92, "<I")
    else:
        opt["image_base"] = u(opt_off + 24, "<Q")
        dd_start = opt_off + 112
        ndd = u(opt_off + 108, "<I")
    ndd = ndd or 0
    opt.update({
        "magic": f"0x{magic:04x}",
        "linker_version": f"{u(opt_off+2,'<B') or 0}.{u(opt_off+3,'<B') or 0}",
        "size_of_code": u(opt_off + 4, "<I"),
        "size_of_initialized_data": u(opt_off + 8, "<I"),
        "address_of_entry_point": u(opt_off + 16, "<I"),
        "base_of_code": u(opt_off + 20, "<I"),
        "section_alignment": u(opt_off + (32 if bitness == 32 else 32), "<I"),
        "file_alignment": u(opt_off + (36 if bitness == 32 else 36), "<I"),
        "subsystem": u(opt_off + (68 if bitness == 32 else 68), "<H"),
        "dll_characteristics_raw": u(opt_off + (70 if bitness == 32 else 70), "<H"),
        "size_of_image": u(opt_off + (56 if bitness == 32 else 56), "<I"),
        "checksum": u(opt_off + (64 if bitness == 32 else 64), "<I"),
    })

    data_dirs = []
    for i in range(min(ndd, 16)):
        va, size = struct.unpack_from("<II", data, dd_start + i * 8)
        data_dirs.append({"index": i, "name": DD_NAMES[i] if i < len(DD_NAMES) else f"Dir{i}",
                          "va": va, "size": size})

    sec_base = opt_off + opt_size
    sections = []
    for i in range(nsec):
        off = sec_base + i * 40
        if off + 40 > len(data):
            break
        raw_name = data[off:off + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", "replace")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
        schars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({"name": name, "vaddr": vaddr, "vsize": vsize,
                         "raw_off": roff, "raw_size": rsize, "chars": schars})

    return {"peoff": peoff, "machine": machine, "nsec": nsec, "tstamp": tstamp,
            "chars": chars, "bitness": bitness, "opt": opt,
            "data_directories": data_dirs, "sections": sections, "opt_size": opt_size}


def rva_to_off(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        va = s["vaddr"]
        vsize = max(s["vsize"], s["raw_size"])
        if va <= rva < va + vsize:
            return s["raw_off"] + (rva - va)
    return None


def cstr_at(data: bytes, off: int) -> str | None:
    if off is None or off < 0 or off >= len(data):
        return None
    end = data.find(b"\0", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("utf-8", "replace")


def cstr_at_rva(data: bytes, rva: int, base: dict) -> str | None:
    if not rva:
        return None
    return cstr_at(data, rva_to_off(rva, base["sections"]))


def _decode_flags(bits, raw):
    return [name for mask, name in bits if raw & mask]


def _find_dd(base: dict, name):
    for d in base["data_directories"]:
        if d["name"] == name:
            return d
    return None


# --------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------
def parse_imports(data: bytes, base: dict) -> list[dict] | None:
    dd = _find_dd(base, "Import")
    if not dd or not dd["va"] or not dd["size"]:
        return None
    off = rva_to_off(dd["va"], base["sections"])
    if off is None:
        return None
    ptr_size = 8 if base["bitness"] == 64 else 4
    ord_mask = 0x8000000000000000 if base["bitness"] == 64 else 0x80000000
    imports = []
    i = 0
    while True:
        at = off + i * 20
        if at + 20 > len(data):
            break
        oft, tstamp, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, at)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        dll = cstr_at_rva(data, name_rva, base)
        funcs = []
        iat_rva = oft or ft
        if iat_rva:
            p = rva_to_off(iat_rva, base["sections"])
            if p is not None:
                for j in range(MAX_IMPORT_FUNCS):
                    if p + j * ptr_size + ptr_size > len(data):
                        break
                    val = struct.unpack_from("<Q" if ptr_size == 8 else "<I", data, p + j * ptr_size)[0]
                    if val == 0:
                        break
                    if val & ord_mask:
                        funcs.append({"name": None, "ordinal": val & 0xFFFF})
                    else:
                        no = rva_to_off(val, base["sections"])
                        fname = cstr_at(data, no + 2) if no is not None else None
                        funcs.append({"name": fname, "ordinal": None})
        imports.append({"dll": dll, "function_count": len(funcs), "functions": funcs,
                        "first_thunk_rva": ft, "original_first_thunk_rva": oft})
        i += 1
        if i > MAX_IMPORT_FUNCS:
            break
    return imports


def compute_imphash(imports: list[dict]) -> str | None:
    # Mandiant/pefile imphash preserves IMPORT-TABLE ORDER (no sorting) and
    # strips the module extension for .dll/.sys/.ocx.
    parts = []
    for imp in imports:
        dll = (imp["dll"] or "").lower()
        for ext in (".dll", ".sys", ".ocx"):
            if dll.endswith(ext):
                dll = dll[: -len(ext)]
                break
        for f in imp["functions"]:
            fn = f["name"].lower() if f["name"] else f"ord{f['ordinal']}"
            parts.append(f"{dll}.{fn}")
    return hashlib.md5(",".join(parts).encode()).hexdigest() if parts else None


# --------------------------------------------------------------------------
# Exports
# --------------------------------------------------------------------------
def parse_exports(data: bytes, base: dict) -> dict | None:
    dd = _find_dd(base, "Export")
    if not dd or not dd["va"] or not dd["size"]:
        return None
    off = rva_to_off(dd["va"], base["sections"])
    if off is None or off + 40 > len(data):
        return None
    _, tstamp, _mj, _mn, name_rva, base_ord, nfuncs, nnames, aof, aon, aono = \
        struct.unpack_from("<IIHHIIIIIII", data, off)
    module_name = cstr_at_rva(data, name_rva, base)
    if nfuncs == 0:
        return {"module_name": module_name, "base_ordinal": base_ord,
                "exports": [], "forwarders": []}
    if nfuncs > MAX_EXPORTS:
        nfuncs = MAX_EXPORTS
    aof_o = rva_to_off(aof, base["sections"])
    aon_o = rva_to_off(aon, base["sections"])
    aono_o = rva_to_off(aono, base["sections"])
    if None in (aof_o, aon_o, aono_o):
        return None
    func_rvas = [struct.unpack_from("<I", data, aof_o + k * 4)[0] for k in range(nfuncs)]
    name_rvas = [struct.unpack_from("<I", data, aon_o + k * 4)[0] for k in range(nnames)]
    ordinals = [struct.unpack_from("<H", data, aono_o + k * 2)[0] for k in range(nnames)]
    exports = []
    forwarders = []
    for k in range(nnames):
        name = cstr_at_rva(data, name_rvas[k], base)
        # AddressOfNameOrdinals holds an INDEX into AddressOfFunctions, not the
        # ordinal value. The real ordinal is base_ord + index.
        idx = ordinals[k]
        if idx < 0 or idx >= len(func_rvas):
            continue
        fva = func_rvas[idx]
        actual_ordinal = base_ord + idx
        # forwarder if the address falls inside the export directory itself
        is_fwd = dd["va"] <= fva < dd["va"] + dd["size"]
        entry = {"name": name, "ordinal": actual_ordinal, "address": fva}
        if is_fwd:
            target = cstr_at_rva(data, fva, base)
            entry["forwarder"] = target
            forwarders.append(entry)
        else:
            exports.append(entry)
    return {"module_name": module_name, "base_ordinal": base_ord,
            "export_count": len(exports), "forwarder_count": len(forwarders),
            "exports": exports, "forwarders": forwarders}


# --------------------------------------------------------------------------
# Resources
# --------------------------------------------------------------------------
RT_NAME = {v: k for k, v in RT_NAMES.items()}


def parse_resources(data: bytes, base: dict):
    dd = _find_dd(base, "Resource")
    if not dd or not dd["va"] or not dd["size"]:
        return None
    root = rva_to_off(dd["va"], base["sections"])
    if root is None:
        return None
    entries = []
    manifest = None

    def resolve_id(nameord):
        if nameord & 0x80000000:
            sp = root + (nameord & 0x7FFFFFFF)
            slen = struct.unpack_from("<H", data, sp)[0]
            return data[sp + 2:sp + 2 + slen * 2].decode("utf-16-le", "replace")
        return nameord

    def walk(off, depth, cur):
        nonlocal manifest
        if depth > 6 or len(entries) >= MAX_RESOURCE_ENTRIES:
            return
        if off + 16 > len(data):
            return
        _c, _ts, _mv, _mn, nnamed, nid = struct.unpack_from("<IIHHHH", data, off)
        count = nnamed + nid
        p = off + 16
        for i in range(count):
            if p + 8 > len(data):
                return
            nameord, offset = struct.unpack_from("<II", data, p + i * 8)
            is_sub = bool(offset & 0x80000000)
            child = root + (offset & 0x7FFFFFFF)
            ident = resolve_id(nameord)
            if depth == 0:
                cur = {"type": ident, "name": None, "lang": None}
            elif depth == 1:
                cur = {"type": cur["type"], "name": ident, "lang": None}
            else:
                cur = {"type": cur["type"], "name": cur["name"], "lang": ident}
            if is_sub:
                walk(child, depth + 1, cur)
            else:
                doff, dsize, _cp, _res = struct.unpack_from("<IIII", data, child)
                foff = rva_to_off(doff, base["sections"])
                type_name = RT_NAMES.get(cur["type"], cur["type"])
                if foff is not None and 0 <= foff < len(data):
                    blob = data[foff:foff + dsize]
                    if cur["type"] == 24 or type_name == "RT_MANIFEST":
                        manifest = blob.decode("utf-8", "replace")
                entries.append({"type": cur["type"], "type_name": type_name,
                                "name": cur["name"], "lang": cur["lang"],
                                "size": dsize, "offset": foff})

    walk(root, 0, {})
    return {"entry_count": len(entries), "entries": entries, "manifest": manifest}


# --------------------------------------------------------------------------
# Rich Header
# --------------------------------------------------------------------------
def parse_rich_header(data: bytes) -> dict | None:
    idx = data.find(b"DanS")
    if idx < 0 or idx + 8 > len(data):
        return None
    key = struct.unpack_from("<I", data, idx + 4)[0]
    records = []
    p = idx + 8
    while p + 8 <= len(data) and len(records) < MAX_RICH_RECORDS:
        if data[p:p + 4] == b"Rich":
            break
        compid, minor = struct.unpack_from("<II", data, p)
        compid ^= key
        minor ^= key
        prodid = (compid >> 16) & 0xFFFF
        version = compid & 0xFFFF
        records.append({"prodid": prodid, "prodid_name": PRODID_NAMES.get(prodid, "UNKNOWN"),
                        "version": version, "count": minor})
        p += 8
    return {"xor_key": f"0x{key:08x}", "record_count": len(records), "records": records}


# --------------------------------------------------------------------------
# Authenticode / PKCS#7 (minimal DER X.509 extraction)
# --------------------------------------------------------------------------
OID_NAMES = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.840.113549.1.9.1": "emailAddress",
    "2.16.840.1.101.3.4.2.1": "sha-256",
    "2.16.840.1.101.3.4.2.2": "sha-384",
    "2.16.840.1.101.3.4.2.3": "sha-512",
}
DN_ATTR = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "2.5.4.9": "STREET", "2.5.4.12": "TITLE", "2.5.4.42": "GIVENNAME",
    "2.5.4.4": "SN", "2.5.4.41": "NAME", "2.5.4.97": "OID.2.5.4.97",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "2.5.4.97": "organizationIdentifier",
}


def _read_tlv(data, off):
    if off < 0 or off >= len(data):
        return None
    tag = data[off]
    off1 = off + 1
    first = data[off1]
    off1 += 1
    if first & 0x80:
        nbytes = first & 0x7F
        length = 0
        for _ in range(nbytes):
            if off1 >= len(data):
                return None
            length = (length << 8) | data[off1]
            off1 += 1
    else:
        length = first
    vs = off1
    ne = vs + length
    if ne > len(data):
        ne = len(data)
    return (tag, length, vs, ne)


def _oid_to_str(data, off, length):
    if length == 0 or off + length > len(data):
        return ""
    first = data[off]
    vals = [first // 40, first % 40]
    acc = 0
    for i in range(1, length):
        b = data[off + i]
        acc = (acc << 7) | (b & 0x7F)
        if not (b & 0x80):
            vals.append(acc)
            acc = 0
    return ".".join(str(v) for v in vals)


def _oid_name(oid):
    return OID_NAMES.get(oid, oid)


def _parse_dn(data, vs, ve):
    parts = []
    pos = vs
    while pos < ve:
        tlv = _read_tlv(data, pos)
        if not tlv:
            break
        tag, _l, cvs, cve = tlv
        if tag == 0x31:  # SET -> relative DN
            p2 = cvs
            while p2 < cve:
                inner = _read_tlv(data, p2)
                if not inner:
                    break
                it, _il, ivs, ive = inner
                if it == 0x30:  # SEQUENCE { OID, value }
                    otlv = _read_tlv(data, ivs)
                    vtlv = _read_tlv(data, otlv[3]) if otlv else None
                    if otlv and vtlv:
                        oid = _oid_to_str(data, otlv[2], otlv[1])
                        raw = data[vtlv[2]:vtlv[3]]
                        val = raw.decode("utf-8", "replace")
                        parts.append(f"{DN_ATTR.get(oid, oid)}={val}")
                p2 = ive
        pos = cve
    return ", ".join(parts)


def _time_str(blob, tlv):
    if tlv is None or tlv[0] not in (0x17, 0x18):
        return None
    s = blob[tlv[2]:tlv[3]].decode("ascii", "replace").rstrip("Z")
    try:
        if tlv[0] == 0x17:  # UTCTime YYMMDDHHMMSS
            yy = int(s[0:2]); mm = int(s[2:4]); dd = int(s[4:6])
            hh = int(s[6:8]); mi = int(s[8:10]); ss = int(s[10:12])
            year = 2000 + yy if yy < 50 else 1900 + yy
        else:  # GeneralizedTime YYYYMMDDHHMMSS
            yy = int(s[0:4]); mm = int(s[4:6]); dd = int(s[6:8])
            hh = int(s[8:10]); mi = int(s[10:12]); ss = int(s[12:14])
            year = yy
        return f"{year:04d}-{mm:02d}-{dd:02d}T{hh:02d}:{mi:02d}:{ss:02d}Z"
    except Exception:
        return s


def _find_basic_constraints_ca(blob, vs, ve):
    marker = bytes([0x55, 0x1D, 0x13])  # OID 2.5.29.19
    pos = blob.find(marker, vs, ve)
    if pos < 0:
        return None
    # search for a BOOLEAN TRUE (01 01 FF) within the next ~64 bytes
    return True if b"\x01\x01\xff" in blob[pos:pos + 64] else False


def _parse_certificate(blob, vs, ve):
    tbs = _read_tlv(blob, vs)
    if not tbs or tbs[0] != 0x30:
        return None
    pos = tbs[2]
    # optional [0] version (EXPLICIT)
    first = _read_tlv(blob, pos)
    if first and first[0] == 0xA0:
        pos = first[3]
    serial = _read_tlv(blob, pos)
    if not serial or serial[0] != 0x02:
        return None
    serial_hex = blob[serial[2]:serial[3]].hex()
    pos = serial[3]
    sigalg = _read_tlv(blob, pos)
    if not sigalg or sigalg[0] != 0x30:
        return None
    salg_oid = _read_tlv(blob, sigalg[2])
    sig_alg = _oid_name(_oid_to_str(blob, salg_oid[2], salg_oid[1])) if salg_oid else None
    pos = sigalg[3]
    issuer = _read_tlv(blob, pos)
    if not issuer or issuer[0] != 0x30:
        return None
    issuer_dn = _parse_dn(blob, issuer[2], issuer[3])
    pos = issuer[3]
    valid = _read_tlv(blob, pos)
    notbefore = notafter = None
    if valid and valid[0] == 0x30:
        nb = _read_tlv(blob, valid[2])
        na = _read_tlv(blob, valid[2] + (nb[3] - valid[2])) if nb else None
        notbefore = _time_str(blob, nb)
        notafter = _time_str(blob, na)
    pos = valid[3]
    subj = _read_tlv(blob, pos)
    subject_dn = _parse_dn(blob, subj[2], subj[3]) if subj and subj[0] == 0x30 else None
    pos = subj[3]
    spki = _read_tlv(blob, pos)
    pub_alg = None
    if spki and spki[0] == 0x30:
        alg = _read_tlv(blob, spki[2])
        if alg:
            o = _read_tlv(blob, alg[2])
            pub_alg = _oid_name(_oid_to_str(blob, o[2], o[1])) if o else None
    is_ca = _find_basic_constraints_ca(blob, tbs[2], tbs[3])
    return {"serial": serial_hex, "issuer": issuer_dn, "subject": subject_dn,
            "not_before": notbefore, "not_after": notafter,
            "signature_algorithm": sig_alg, "public_key_algorithm": pub_alg,
            "ca": is_ca}


def parse_pkcs7_certificates(blob: bytes):
    out = []
    seen = set()

    def walk(off, end):
        while off < end:
            tlv = _read_tlv(blob, off)
            if not tlv:
                break
            tag, _l, vs, ne = tlv
            if tag == 0x30:
                c = _parse_certificate(blob, vs, ne)
                if c:
                    key = (c["serial"], c["subject"])
                    if key not in seen:
                        seen.add(key)
                        out.append(c)
                walk(vs, ne)
            elif tag in (0x31, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5):
                walk(vs, ne)
            off = ne

    walk(0, len(blob))
    return out


# --------------------------------------------------------------------------
# Tool: pe_headers
# --------------------------------------------------------------------------
@registry.tool(name="binary.pe_headers", description="Dump PE/COFF header structure: DOS/COFF/optional header fields, data directories and section summary. Read-only structural view.",
 safety=SafetyLevel.READ_ONLY, tags=("binary", "windows", "pe", "headers"), produces=("pe_headers",),
 parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
def pe_headers(path: str) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("binary.pe_headers", Status.ERROR, "PE file not found", errors=[str(p)])
    data, err, src = read_file_bounded_observation("binary.pe_headers", p, 512 * 1024 * 1024)
    if err:
        return err
    h = src
    base = parse_pe(data)
    if not base:
        return Observation("binary.pe_headers", Status.UNSUPPORTED, "Not an MZ/PE file", meta={"source_sha256": h})
    opt = base["opt"]
    try:
        import datetime as _dt
        ts_iso = _dt.datetime.fromtimestamp(base["tstamp"], _dt.timezone.utc).isoformat()
    except Exception:
        ts_iso = None
    facts = {
        "machine": PE_MACHINES.get(base["machine"], f"0x{base['machine']:04x}"),
        "machine_id": base["machine"],
        "bitness": base["bitness"],
        "coff_timestamp": base["tstamp"],
        "coff_timestamp_iso": ts_iso,
        "characteristics": f"0x{base['chars']:04x}",
        "optional_magic": opt["magic"],
        "linker_version": opt["linker_version"],
        "subsystem": SUBSYSTEMS.get(opt["subsystem"], f"0x{opt['subsystem']:x}"),
        "subsystem_id": opt["subsystem"],
        "dll_characteristics": _decode_flags(DLL_CHAR_BITS, opt["dll_characteristics_raw"] or 0),
        "image_base": f"0x{opt['image_base']:x}" if opt["image_base"] is not None else None,
        "address_of_entry_point": opt["address_of_entry_point"],
        "size_of_image": opt["size_of_image"],
        "checksum": f"0x{opt['checksum']:08x}" if opt["checksum"] is not None else None,
        "data_directories": [{"name": d["name"], "va": d["va"], "size": d["size"]} for d in base["data_directories"]],
        "section_count": base["nsec"],
        "sections": [{"name": s["name"], "vaddr": s["vaddr"], "vsize": s["vsize"],
                      "raw_off": s["raw_off"], "raw_size": s["raw_size"],
                      "characteristics": _decode_flags(SEC_CHAR_BITS, s["chars"])} for s in base["sections"]],
    }
    rich = parse_rich_header(data)
    if rich:
        facts["rich_header"] = {"xor_key": rich["xor_key"], "record_count": rich["record_count"]}
    return Observation("binary.pe_headers", Status.OK,
                       f"Parsed PE{base['bitness']} headers ({base['nsec']} sections)",
                       facts=facts, meta={"source_sha256": h})


# --------------------------------------------------------------------------
# Tool: pe_imports
# --------------------------------------------------------------------------
@registry.tool(name="binary.pe_imports", description="Parse the PE import table: DLLs and imported symbols (by name or ordinal). Computes Mandiant-compatible imphash. Read-only.",
 safety=SafetyLevel.READ_ONLY, tags=("binary", "windows", "pe", "imports"), produces=("pe_imports", "imphash"),
 parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
def pe_imports(path: str) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("binary.pe_imports", Status.ERROR, "PE file not found", errors=[str(p)])
    data, err, src = read_file_bounded_observation("binary.pe_imports", p, 512 * 1024 * 1024)
    if err:
        return err
    h = src
    base = parse_pe(data)
    if not base:
        return Observation("binary.pe_imports", Status.UNSUPPORTED, "Not an MZ/PE file", meta={"source_sha256": h})
    imports = parse_imports(data, base)
    if imports is None:
        return Observation("binary.pe_imports", Status.OK, "No import table present",
                           facts={"import_count": 0, "imports": []}, meta={"source_sha256": h})
    imphash = compute_imphash(imports)
    total = sum(i["function_count"] for i in imports)
    ev = [Evidence(str(p), "pe_import", f"{i['dll']}", locator=f"import_count:{i['function_count']}",
                   method="PE import-table parser") for i in imports if i["dll"]]
    return Observation("binary.pe_imports", Status.OK,
                       f"Parsed {len(imports)} imported DLL(s) / {total} symbol(s)",
                       facts={"import_count": len(imports), "total_symbols": total,
                              "imphash": imphash, "imports": imports},
                       evidence=ev[:300], meta={"source_sha256": h})


# --------------------------------------------------------------------------
# Tool: pe_exports
# --------------------------------------------------------------------------
@registry.tool(name="binary.pe_exports", description="Parse the PE export table: exported symbols with ordinals and addresses, plus forwarded exports. Read-only.",
 safety=SafetyLevel.READ_ONLY, tags=("binary", "windows", "pe", "exports"), produces=("pe_exports",),
 parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
def pe_exports(path: str) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("binary.pe_exports", Status.ERROR, "PE file not found", errors=[str(p)])
    data, err, src = read_file_bounded_observation("binary.pe_exports", p, 512 * 1024 * 1024)
    if err:
        return err
    h = src
    base = parse_pe(data)
    if not base:
        return Observation("binary.pe_exports", Status.UNSUPPORTED, "Not an MZ/PE file", meta={"source_sha256": h})
    ex = parse_exports(data, base)
    if ex is None:
        return Observation("binary.pe_exports", Status.OK, "No export table present",
                           facts={"export_count": 0, "forwarder_count": 0, "exports": [],
                                  "forwarders": []}, meta={"source_sha256": h})
    return Observation("binary.pe_exports", Status.OK,
                       f"Parsed {ex['export_count']} export(s), {ex['forwarder_count']} forwarder(s)",
                       facts=ex, meta={"source_sha256": h})


# --------------------------------------------------------------------------
# Tool: pe_resources
# --------------------------------------------------------------------------
@registry.tool(name="binary.pe_resources", description="Walk the PE resource tree (type/name/language) and extract the embedded application manifest (RT_MANIFEST). Read-only.",
 safety=SafetyLevel.READ_ONLY, tags=("binary", "windows", "pe", "resources"), produces=("pe_resources", "manifest"),
 parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
def pe_resources(path: str) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("binary.pe_resources", Status.ERROR, "PE file not found", errors=[str(p)])
    data, err, src = read_file_bounded_observation("binary.pe_resources", p, 512 * 1024 * 1024)
    if err:
        return err
    h = src
    base = parse_pe(data)
    if not base:
        return Observation("binary.pe_resources", Status.UNSUPPORTED, "Not an MZ/PE file", meta={"source_sha256": h})
    res = parse_resources(data, base)
    if res is None:
        return Observation("binary.pe_resources", Status.OK, "No resource directory present",
                           facts={"entry_count": 0, "entries": [], "manifest": None}, meta={"source_sha256": h})
    facts = {"entry_count": res["entry_count"], "entries": res["entries"]}
    if res["manifest"]:
        facts["manifest"] = res["manifest"]
    return Observation("binary.pe_resources", Status.OK,
                       f"Walked {res['entry_count']} resource entr(y/ies)"
                       + ("; manifest extracted" if res["manifest"] else ""),
                       facts=facts, meta={"source_sha256": h})


# --------------------------------------------------------------------------
# Tool: pe_rich_header
# --------------------------------------------------------------------------
@registry.tool(name="binary.pe_rich_header", description="Decode the PE Rich Header: compiler/toolchain product IDs, versions and counts (linker, MASM, ImportLib). Read-only.",
 safety=SafetyLevel.READ_ONLY, tags=("binary", "windows", "pe", "rich_header", "provenance"), produces=("pe_rich_header",),
 parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
def pe_rich_header(path: str) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("binary.pe_rich_header", Status.ERROR, "PE file not found", errors=[str(p)])
    data, err, src = read_file_bounded_observation("binary.pe_rich_header", p, 512 * 1024 * 1024)
    if err:
        return err
    h = src
    if data[:2] != b"MZ":
        return Observation("binary.pe_rich_header", Status.UNSUPPORTED, "Not an MZ/PE file", meta={"source_sha256": h})
    rich = parse_rich_header(data)
    if not rich:
        return Observation("binary.pe_rich_header", Status.OK, "No Rich Header present",
                           facts={"present": False, "records": []}, meta={"source_sha256": h})
    # collapse duplicate (prodid,version) into summed counts for readability
    summary = {}
    for r in rich["records"]:
        k = (r["prodid"], r["prodid_name"], r["version"])
        summary[k] = summary.get(k, 0) + r["count"]
    collapsed = [{"prodid": k[0], "prodid_name": k[1], "version": k[2], "count": v}
                 for k, v in sorted(summary.items())]
    return Observation("binary.pe_rich_header", Status.OK,
                       f"Decoded Rich Header ({rich['record_count']} record(s), XOR {rich['xor_key']})",
                       facts={"present": True, "xor_key": rich["xor_key"],
                              "record_count": rich["record_count"],
                              "toolchain_summary": collapsed},
                       meta={"source_sha256": h})


# --------------------------------------------------------------------------
# Tool: pe_signing
# --------------------------------------------------------------------------
@registry.tool(name="binary.pe_signing", description="Inspect Authenticode signature (WIN_CERTIFICATE / PKCS#7). Extracts embedded certificate chain issuer/subject/validity without external crypto libraries. Absence of a signature is reported, not assumed malicious.",
 safety=SafetyLevel.READ_ONLY, tags=("binary", "windows", "pe", "signing", "authenticode"), produces=("pe_signing", "certificates"),
 parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
def pe_signing(path: str) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("binary.pe_signing", Status.ERROR, "PE file not found", errors=[str(p)])
    data, err, src = read_file_bounded_observation("binary.pe_signing", p, 512 * 1024 * 1024)
    if err:
        return err
    h = src
    base = parse_pe(data)
    if not base:
        return Observation("binary.pe_signing", Status.UNSUPPORTED, "Not an MZ/PE file", meta={"source_sha256": h})
    dd = _find_dd(base, "Security")
    if not dd or not dd["va"] or not dd["size"]:
        return Observation("binary.pe_signing", Status.OK, "No Authenticode signature present",
                           facts={"signed": False}, warnings=[
                               "absence of a signature is not by itself evidence of malice; "
                               "many legitimate binaries are unsigned"], meta={"source_sha256": h})
    # Security directory VirtualAddress is a FILE offset, not an RVA
    sec_off = dd["va"]
    sec_size = dd["size"]
    if sec_off + sec_size > len(data) or sec_off < 0:
        return Observation("binary.pe_signing", Status.ERROR, "Security directory outside file",
                           meta={"source_sha256": h})
    certs = []
    warnings = []
    try:
        dwlen, rev, ctype = struct.unpack_from("<IHH", data, sec_off)
        blob = data[sec_off + 8:sec_off + dwlen] if dwlen <= sec_size else data[sec_off + 8:sec_off + sec_size]
        certs = parse_pkcs7_certificates(blob)
    except Exception as e:
        warnings.append(f"certificate parse failed: {e}")
    facts = {"signed": True, "certificate_type": f"0x{ctype:04x}",
             "revision": f"0x{rev:04x}", "win_cert_length": sec_size,
             "certificate_count": len(certs), "certificates": certs}
    if not certs and not warnings:
        warnings.append("PKCS#7 present but no parseable X.509 certificate found")
    return Observation("binary.pe_signing",
                       Status.PARTIAL if warnings else Status.OK,
                       f"Authenticode present with {len(certs)} certificate(s)",
                       facts=facts, warnings=warnings, meta={"source_sha256": h})


# --------------------------------------------------------------------------
# ELF dynamic
# --------------------------------------------------------------------------
ELF_DYN_TAGS = {0: "DT_NULL", 1: "DT_NEEDED", 2: "DT_PLTRELSZ", 3: "DT_PLTGOT",
                4: "DT_HASH", 5: "DT_STRTAB", 6: "DT_SYMTAB", 7: "DT_RELA",
                8: "DT_RELASZ", 10: "DT_STRSZ", 11: "DT_SYMENT", 14: "DT_SONAME",
                15: "DT_RPATH", 16: "DT_SYMBOLIC", 17: "DT_REL", 18: "DT_RELSZ",
                20: "DT_PLTREL", 21: "DT_DEBUG", 22: "DT_TEXTREL", 23: "DT_JMPREL",
                25: "DT_BIND_NOW", 26: "DT_INIT_ARRAY", 27: "DT_FINI_ARRAY",
                28: "DT_INIT_ARRAYSZ", 29: "DT_FINI_ARRAYSZ", 30: "DT_FLAGS",
                0x6FFFFFF0: "DT_VERSYM", 0x6FFFFFF9: "DT_RELACOUNT",
                0x6FFFFFFA: "DT_RELCOUNT", 0x6FFFFFFB: "DT_FLAGS_1",
                0x6FFFFFFE: "DT_VERNEED", 0x6FFFFFFF: "DT_VERNEEDNUM",
                0x70000000: "DT_LOPROC", 0x7FFFFFFD: "DT_AUXILIARY",
                0x7FFFFFFE: "DT_FILTER"}
DT_FLAGS = {0x1: "DF_BIND_NOW", 0x2: "DF_TEXTREL", 0x4: "DF_SYMBOLIC"}
DT_FLAGS_1 = {0x1: "DF_1_NOW", 0x2: "DF_1_GLOBAL", 0x4: "DF_1_GROUP", 0x8: "DF_1_NODELETE",
              0x10: "DF_1_LOADFLTR", 0x20: "DF_1_INITFIRST", 0x40: "DF_1_NOOPEN",
              0x80: "DF_1_ORIGIN", 0x100: "DF_1_INTERPOSE", 0x200: "DF_1_NODEFLIB",
              0x400: "DF_1_NODUMP", 0x800: "DF_1_CONFALT", 0x1000: "DF_1_ENDFILTEE",
              0x2000: "DF_1_DISPRELDNE", 0x4000: "DF_1_DISPRELPND",
              0x8000: "DF_1_NODIRECT", 0x10000: "DF_1_IGNMULDEF", 0x20000: "DF_1_NOKSYMS",
              0x40000: "DF_1_NOHDR", 0x80000: "DF_1_EDITED", 0x100000: "DF_1_NOREF",
              0x200000: "DF_1_NORPATH", 0x400000: "DF_1_SYMBOLIC"}


def parse_elf_dynamic(data: bytes) -> dict:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return {"error": "not an ELF file"}
    cls = data[4]
    enc = data[5]
    if cls not in (1, 2) or enc not in (1, 2):
        return {"error": "unsupported ELF class/encoding"}
    endian = "<" if enc == 1 else ">"
    is64 = cls == 2

    def u(off, fmt):
        try:
            return struct.unpack_from(endian + fmt, data, off)[0]
        except struct.error:
            return None

    e_phoff = u(0x20, "Q" if is64 else "I")
    e_phentsize = u(0x36, "H")
    e_phnum = u(0x38, "H")
    e_shoff = u(0x28, "Q" if is64 else "I")
    e_shentsize = u(0x3A, "H")
    e_shnum = u(0x3C, "H")
    e_shstrndx = u(0x3E, "H")

    # program headers
    phdrs = []
    if e_phoff and e_phentsize:
        for i in range(e_phnum or 0):
            off = e_phoff + i * e_phentsize
            if off + (56 if is64 else 32) > len(data):
                break
            if is64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                    struct.unpack_from(endian + "IIQQQQQQ", data, off)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                    struct.unpack_from(endian + "IIIIIIII", data, off)
            phdrs.append({"type": p_type, "offset": p_offset, "vaddr": p_vaddr,
                          "filesz": p_filesz, "memsz": p_memsz, "flags": p_flags})

    def vaddr_to_off(va):
        for ph in phdrs:
            if ph["type"] == 1 and ph["vaddr"] <= va < ph["vaddr"] + ph["filesz"]:
                return ph["offset"] + (va - ph["vaddr"])
        return None

    # section headers (for .dynsym/.dynstr/.note)
    shdrs = []
    if e_shoff and e_shentsize:
        for i in range(e_shnum or 0):
            off = e_shoff + i * e_shentsize
            if off + (64 if is64 else 40) > len(data):
                break
            if is64:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = \
                    struct.unpack_from(endian + "IIQQQQIIQQ", data, off)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = \
                    struct.unpack_from(endian + "IIIIIIIIII", data, off)
            shdrs.append({"name_off": sh_name, "type": sh_type, "offset": sh_offset,
                          "size": sh_size, "link": sh_link, "entsize": sh_entsize, "addr": sh_addr})

    # string table for section names
    sec_names = b""
    if e_shstrndx < len(shdrs):
        s = shdrs[e_shstrndx]
        sec_names = data[s["offset"]:s["offset"] + s["size"]]

    def sh_name(idx):
        if idx >= len(sec_names):
            return ""
        e = sec_names.find(b"\0", idx)
        return sec_names[idx:e if e > 0 else idx].decode("utf-8", "replace")

    for s in shdrs:
        s["name"] = sh_name(s["name_off"])

    # locate dynamic-string / dynamic-symbol sections (used by .dynamic string
    # resolution and symbol parsing below)
    dynsym = next((s for s in shdrs if s["name"] == ".dynsym"), None)
    dynstr = next((s for s in shdrs if s["name"] == ".dynstr"), None)

    # parse .dynamic
    dyn = None
    for ph in phdrs:
        if ph["type"] == 2:  # PT_DYNAMIC
            dyn = ph
            break
    # Collect all dynamic tags first so string resolution does not depend on
    # tag ordering (DT_STRTAB may appear after DT_NEEDED in the table).
    tags = []
    if dyn:
        ent = 16 if is64 else 8
        ptr_fmt = "Q" if is64 else "I"
        pos = dyn["offset"]
        n = 0
        while pos + ent <= len(data) and n < 20000:
            tag, val = struct.unpack_from(endian + ("q" if is64 else "i") + ptr_fmt, data, pos)
            tag &= 0xFFFFFFFF
            if tag == 0:
                break
            tags.append((tag, val))
            pos += ent
            n += 1

    # DT_NEEDED / SONAME / RPATH / RUNPATH values are *offsets* into the dynamic
    # string table, resolved against the .dynstr section base (not as vaddrs).
    strtab_base = dynstr["offset"] if dynstr else None

    def _str_at(val):
        if strtab_base is None:
            return None
        so = strtab_base + val
        if so < 0 or so >= len(data):
            return None
        e = data.find(b"\0", so)
        return data[so:e if e > 0 else so].decode("utf-8", "replace")

    needed, soname, rpath, runpath = [], None, None, None
    dt_flags_raw = dt_flags_1_raw = 0
    interp = None
    all_tags = [{"tag": ELF_DYN_TAGS.get(t, f"DT_0x{t:x}"), "value": v} for t, v in tags]
    for tag, val in tags:
        sval = _str_at(val)
        if tag == 1 and sval:
            needed.append(sval)
        elif tag == 14 and sval:
            soname = sval
        elif tag == 15 and sval:
            rpath = sval
        elif tag == 29 and sval:
            runpath = sval
        elif tag == 30:
            dt_flags_raw = val
        elif tag == 0x6FFFFFFB:
            dt_flags_1_raw = val

    # PT_INTERP -> interpreter
    for ph in phdrs:
        if ph["type"] == 3:  # PT_INTERP
            e = data.find(b"\0", ph["offset"])
            interp = data[ph["offset"]:e if e > 0 else ph["offset"]].decode("utf-8", "replace")
            break

    # GNU build-id from .note.gnu.build-id section, else PT_NOTE
    build_id = None
    for s in shdrs:
        if s["name"] == ".note.gnu.build-id" and s["size"] >= 12:
            build_id = _parse_build_id(data, s["offset"], s["size"])
            break
    if not build_id:
        for ph in phdrs:
            if ph["type"] == 4:  # PT_NOTE
                build_id = _scan_note_build_id(data, ph["offset"], ph["filesz"])
                if build_id:
                    break

    # dynamic symbols from .dynsym + .dynstr
    symbols = []
    if dynsym and dynstr and dynstr["size"] and dynsym["entsize"]:
        sym_off = dynsym["offset"]
        str_off = dynstr["offset"]
        str_size = dynstr["size"]
        esz = dynsym["entsize"]
        count = min(dynsym["size"] // esz, MAX_ELF_SYMBOLS)
        for i in range(count):
            base_off = sym_off + i * esz
            if is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from(endian + "IBBHQQ", data, base_off)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = \
                    struct.unpack_from(endian + "IIIBBH", data, base_off)
            if st_name == 0 or st_name >= str_size:
                continue
            e = data.find(b"\0", str_off + st_name)
            name = data[str_off + st_name:e if e > 0 else str_off + st_name].decode("utf-8", "replace")
            bind = (st_info >> 4) & 0xF
            typ = st_info & 0xF
            symbols.append({"name": name, "bind": bind, "type": typ,
                            "defined": st_shndx != 0, "value": st_value})

    return {
        "class": 64 if is64 else 32,
        "endianness": "little" if enc == 1 else "big",
        "interpreter": interp,
        "soname": soname,
        "needed": needed,
        "rpath": rpath,
        "runpath": runpath,
        "dt_flags": [n for m, n in DT_FLAGS.items() if dt_flags_raw & m],
        "dt_flags_1": [n for m, n in DT_FLAGS_1.items() if dt_flags_1_raw & m],
        "build_id": build_id,
        "symbol_count": len(symbols),
        "symbols": symbols,
        "dynamic_tags": all_tags[:200],
    }


def _parse_build_id(data, off, size):
    namesz, descsz, ntype = struct.unpack_from("<III", data, off)
    if ntype != 3 or descsz == 0:
        return None
    desc_off = off + 12
    if namesz:
        desc_off += ((namesz + 3) // 4) * 4
    if desc_off + descsz > len(data):
        return None
    return data[desc_off:desc_off + descsz].hex()


def _scan_note_build_id(data, off, size):
    pos = off
    end = off + size
    while pos + 12 <= end and pos + 12 <= len(data):
        namesz, descsz, ntype = struct.unpack_from("<III", data, pos)
        if namesz == 0 and descsz == 0:
            break
        desc_off = pos + 12
        if namesz:
            desc_off += ((namesz + 3) // 4) * 4
        if ntype == 3 and descsz:
            if desc_off + descsz <= len(data):
                return data[desc_off:desc_off + descsz].hex()
        pos = desc_off + ((descsz + 3) // 4) * 4
    return None


@registry.tool(name="binary.elf_dynamic", description="Parse ELF dynamic metadata: NEEDED libraries, interpreter, RPATH/RUNPATH, GNU build-id, and dynamic symbol table. Read-only.",
 safety=SafetyLevel.READ_ONLY, tags=("binary", "linux", "elf", "dynamic"), produces=("elf_dynamic",),
 parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
def elf_dynamic(path: str) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("binary.elf_dynamic", Status.ERROR, "ELF file not found", errors=[str(p)])
    data, err, src = read_file_bounded_observation("binary.elf_dynamic", p, 512 * 1024 * 1024)
    if err:
        return err
    h = src
    if data[:4] != b"\x7fELF":
        return Observation("binary.elf_dynamic", Status.UNSUPPORTED, "Not an ELF file", meta={"source_sha256": h})
    try:
        info = parse_elf_dynamic(data)
    except Exception as e:
        return Observation("binary.elf_dynamic", Status.ERROR, "ELF dynamic parsing failed",
                           errors=[str(e)], meta={"source_sha256": h})
    if info.get("error"):
        return Observation("binary.elf_dynamic", Status.UNSUPPORTED, info["error"], meta={"source_sha256": h})
    ev = [Evidence(str(p), "elf_needed", lib, method="ELF dynamic-section parser") for lib in info["needed"]]
    if info.get("build_id"):
        ev.append(Evidence(str(p), "elf_build_id", info["build_id"], method=".note.gnu.build-id"))
    return Observation("binary.elf_dynamic", Status.OK,
                       f"Parsed ELF{info['class']} dynamic: {len(info['needed'])} NEEDED, "
                       f"{info['symbol_count']} symbol(s), build-id={'yes' if info['build_id'] else 'no'}",
                       facts=info, evidence=ev[:300], meta={"source_sha256": h})
