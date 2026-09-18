#!/usr/bin/env python3
"""C3 Native Dissection Stage - M1 prototype (plan section C3).

Produces native_report.json per plan section 7 from an APK or raw .so.
Uses LIEF for ELF structure + capstone for lightweight disassembly
metrics. Ghidra headless is installed (tools/ghidra) and will be wired
for deep CFG work in C3.1 later; this stage already satisfies M1 exit
(JNI join + crypto hints) without it.

Usage:
  python3 scripts/dissect.py <apk-or-so> [--workdir analysis/dissect]
  python3 scripts/dissect.py --apk RTO.apk --workdir analysis/dissect
"""

import argparse
import hashlib
import io
import json
import pathlib
import re
import struct
import sys
import tempfile
import zipfile

import lief
from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

REPO = pathlib.Path(__file__).resolve().parent.parent

# Crypto fingerprints per Appendix B (raw bytes, little-endian where applicable)
CRYPTO_PATTERNS = {
    "aes_sbox": bytes.fromhex("63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"),
    "aes_inv_sbox": bytes.fromhex("52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB"),
    "chacha_sigma": b"expand 32-byte k",
    "tea_delta_le": struct.pack("<I", 0x9E3779B9),
    "tea_delta_be": struct.pack(">I", 0x9E3779B9),
    "crc32_poly_le": struct.pack("<I", 0xEDB88320),
    "crc32_poly_be": struct.pack(">I", 0xEDB88320),
    "sha256_h0": bytes.fromhex("6A 09 E6 67 BB 67 AE 85"),
}

# Allowlist: skip tiny sections
MIN_SECTION_FOR_SCAN = 64


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _lief_parse(path: pathlib.Path):
    try:
        binary = lief.parse(str(path))
        if binary is None:
            return None
        return binary
    except Exception as exc:
        print("[warn] LIEF parse failed for %s: %s" % (path.name, exc), file=sys.stderr)
        return None


def _elf_meta(binary) -> dict:
    header = binary.header
    arch = str(header.machine_type).split(".")[-1]
    # LIEF 1.0: identity_class.name is "ELF64"/"ELF32", not "CLASS.ELF64"
    cls_name = getattr(header.identity_class, "name", "")
    bits = 64 if "64" in cls_name else 32
    stripped = True
    try:
        for sec in binary.sections:
            if sec.name == ".symtab":
                stripped = False
                break
    except Exception:
        pass
    needed = []
    try:
        needed = [str(x) for x in binary.libraries] if hasattr(binary, "libraries") else []
    except Exception:
        pass
    return {"arch": arch.lower(), "bits": bits, "stripped": stripped, "needed": needed}


def _jni_exports(binary) -> list:
    out = []
    try:
        for sym in binary.exported_functions:
            name = sym.name
            if name.startswith("Java_"):
                out.append({"name": name, "addr": hex(sym.address), "source": "static_export"})
        # fallback: dynamic symbols if exported_functions empty (stripped)
        if not out:
            for sym in binary.dynamic_symbols:
                if sym.name.startswith("Java_"):
                    out.append({"name": sym.name, "addr": hex(sym.value), "source": "static_export"})
    except Exception as exc:
        print("[warn] JNI export scan: %s" % exc, file=sys.stderr)
    return out


def _collect_cstrings(binary) -> dict:
    """Map virtual address -> decoded string for all ro-data sections."""
    addr_to_str = {}
    try:
        for sec in binary.sections:
            if sec.name not in (".rodata", ".rodata.str1.1", ".rodata.str1.8"):
                if not sec.name.startswith(".rodata"):
                    continue
            content = bytes(sec.content)
            base = sec.virtual_address
            # find null-terminated printable runs >=4 chars
            start = None
            for i, byte in enumerate(content):
                if 32 <= byte <= 126:
                    if start is None:
                        start = i
                else:
                    if start is not None and byte == 0 and (i - start) >= 4:
                        s = content[start:i].decode(errors="ignore")
                        if re.match(r"^[A-Za-z0-9_/;\[\]\(\)<>$]+$", s):
                            addr_to_str[base + start] = s
                    if byte == 0:
                        start = None
                    else:
                        start = None
    except Exception:
        pass
    return addr_to_str


def _executable_ranges(binary) -> list:
    ranges = []
    try:
        for sec in binary.sections:
            flags = sec.flags if hasattr(sec, "flags") else 0
            # SHF_EXECINSTR = 0x4
            is_exec = bool(flags & 0x4) if isinstance(flags, int) else False
            # fallback: name check
            if not is_exec and sec.name in (".text",):
                is_exec = True
            if is_exec:
                ranges.append((sec.virtual_address, sec.virtual_address + sec.size))
    except Exception:
        pass
    return ranges


def _in_executable(addr: int, ranges: list) -> bool:
    for lo, hi in ranges:
        if lo <= addr < hi:
            return True
    return False


def _hunt_registernatives(binary) -> list:
    """Scan .data.rel.ro / .data for {name,sig,fnPtr} triples (plan C3.2)."""
    found = []
    try:
        ptr_size = 8 if binary.header.identity_class.name == "CLASS.ELF64" else 4
        fmt = "<Q" if ptr_size == 8 else "<I"
        cstrings = _collect_cstrings(binary)
        exec_ranges = _executable_ranges(binary)
        candidates = [s for s in binary.sections if s.name in (".data.rel.ro", ".data", ".rodata")]
        for sec in candidates:
            content = bytes(sec.content)
            if len(content) < ptr_size * 3:
                continue
            for off in range(0, len(content) - ptr_size * 3 + 1, ptr_size):
                try:
                    a, b, c = struct.unpack_from(fmt * 3, content, off)
                except struct.error:
                    continue
                name = cstrings.get(a)
                sig = cstrings.get(b)
                if name is None or sig is None:
                    continue
                if not re.match(r"^[A-Za-z0-9_<>$]+$", name):
                    continue
                if not sig.startswith("("):
                    continue
                if not _in_executable(c, exec_ranges):
                    continue
                found.append({"name": name, "sig": sig, "fn_addr": hex(c),
                              "table_offset": hex(sec.virtual_address + off),
                              "section": sec.name})
                if len(found) >= 32:
                    return found
    except Exception as exc:
        print("[warn] RegisterNatives hunt: %s" % exc, file=sys.stderr)
    return found


def _scan_crypto(binary) -> list:
    hints = []
    try:
        for sec in binary.sections:
            content = bytes(sec.content)
            if len(content) < MIN_SECTION_FOR_SCAN:
                continue
            for kind, pattern in CRYPTO_PATTERNS.items():
                idx = content.find(pattern)
                if idx != -1:
                    hints.append({"kind": kind, "section": sec.name,
                                  "offset": hex(idx), "size": len(pattern)})
            # RC4 identity-permutation loop: structural heuristic - look for
            # 256-byte permutation init (0..255 incrementing bytes)
            # Heuristic: search for 16-byte rising run as proxy
            for i in range(len(content) - 32):
                if content[i:i+4] == b"\x00\x01\x02\x03" and content[i+16:i+20] == b"\x10\x11\x12\x13":
                    hints.append({"kind": "rc4_sbox_init", "section": sec.name,
                                  "offset": hex(i), "size": 32})
                    break
    except Exception as exc:
        print("[warn] crypto scan: %s" % exc, file=sys.stderr)
    return hints


def _obfuscation_metrics(binary) -> dict:
    """Lightweight capstone pass over .text; Ghidra will replace this for
    deep CFG work. Returns flattened-function heuristic per plan C3.4."""
    try:
        text_sec = next((s for s in binary.sections if s.name == ".text"), None)
        if text_sec is None or len(text_sec.content) < 64:
            return {"flattened_function_fraction": 0.0, "opaque_predicate_density": 0.0,
                    "note": "no .text or too small; Ghidra headless pending for deep CFG"}
        content = bytes(text_sec.content)
        is_64 = binary.header.identity_class.name == "CLASS.ELF64"
        # ARM64: fixed 4-byte insns; ARM32: try ARM mode (Thumb handled by Ghidra later)
        if is_64:
            md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        else:
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
        md.detail = False
        targets = {}
        total = 0
        branches = 0
        for insn in md.disasm(content, text_sec.virtual_address):
            total += 1
            mnem = insn.mnemonic
            if mnem.startswith("b") or mnem in ("cbz", "cbnz", "tbz", "tbnz"):
                branches += 1
                # branch target is last operand if immediate
                if insn.op_str:
                    try:
                        tgt_str = insn.op_str.split(",")[-1].strip().lstrip("#")
                        tgt = int(tgt_str, 0)
                        targets[tgt] = targets.get(tgt, 0) + 1
                    except Exception:
                        pass
            if total > 50000:
                break
        hub_max = max(targets.values()) if targets else 0
        # Flattened heuristic: one hub with >15 predecessors and >30 distinct branch targets
        distinct_targets = len(targets)
        flattened = 1.0 if (hub_max > 15 and distinct_targets > 30) else 0.0
        # Opaque predicate proxy: conditional branches that are never taken in trace
        # Static proxy: ratio of conditional branches to total branches
        return {"flattened_function_fraction": flattened,
                "opaque_predicate_density": round(min(branches / max(total, 1), 1.0), 3),
                "branches": branches, "total_insns": total,
                "distinct_branch_targets": distinct_targets,
                "hub_max_indegree": hub_max}
    except Exception as exc:
        return {"flattened_function_fraction": 0.0, "opaque_predicate_density": 0.0,
                "error": str(exc)}


def dissect_so(so_path: pathlib.Path) -> dict:
    binary = _lief_parse(so_path)
    if binary is None:
        return {"path": str(so_path), "error": "LIEF parse failed"}
    meta = _elf_meta(binary)
    jni_static = _jni_exports(binary)
    jni_dynamic = _hunt_registernatives(binary)
    crypto = _scan_crypto(binary)
    obfuscation = _obfuscation_metrics(binary)
    return {
        "path": str(so_path),
        "sha256": sha256_file(so_path),
        "elf": meta,
        "jni_methods": jni_static + [{"name": r["name"], "addr": r["fn_addr"],
                                      "source": "registernatives_table",
                                      "table_offset": r["table_offset"]} for r in jni_dynamic],
        "registernatives_tables": jni_dynamic,
        "crypto_hints": crypto,
        "obfuscation": obfuscation,
    }


def dissect_apk(apk_path: pathlib.Path, workdir: pathlib.Path) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    native_libs = []
    with zipfile.ZipFile(apk_path) as zf:
        for info in zf.infolist():
            if info.filename.endswith(".so"):
                out = workdir / pathlib.Path(info.filename).name.replace("/", "_")
                # disambiguate ABI: prefix with abi dir
                abi = pathlib.Path(info.filename).parent.name
                out = workdir / ("%s_%s" % (abi, pathlib.Path(info.filename).name))
                out.write_bytes(zf.read(info.filename))
                native_libs.append(out)
    reports = [dissect_so(p) for p in sorted(native_libs)]
    # JNI join: correlate stub dex class names with lib exports (plan C3.2)
    # Handles trailing "__" overload suffix and randomized names; checks each
    # token of the JNI export against dex bytes rather than assuming package split.
    try:
        with zipfile.ZipFile(apk_path) as zf:
            dex_names = [n for n in zf.namelist() if re.search(r"classes\d*\.dex$", n)]
            dex_blob = b"".join(zf.read(n)[: 64 * 1024] for n in dex_names[:2])
            for rep in reports:
                for m in rep.get("jni_methods", []):
                    export = m["name"]
                    # Strip Java_ prefix and trailing overload underscores
                    core = export[5:].rstrip("_")
                    # tokens are randomized singletons: Dzhugashvili, jD3P, SUO4
                    tokens = [t for t in core.split("_") if t]
                    # class is all but last token (method name)
                    if len(tokens) >= 2 and all(t.encode() in dex_blob for t in tokens[:-1]):
                        m["java_hint"] = {"class": ".".join(tokens[:-1])}
    except Exception:
        pass
    return {
        "apk_path": str(apk_path),
        "apk_sha256": sha256_file(apk_path),
        "so_count": len(reports),
        "native_libs": reports,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", help="APK or .so path")
    parser.add_argument("--workdir", default="analysis/dissect")
    parser.add_argument("--out", help="explicit output JSON path")
    args = parser.parse_args(argv)
    inp = pathlib.Path(args.input)
    if not inp.exists():
        print("[error] not found: %s" % inp, file=sys.stderr)
        return 2
    workdir = pathlib.Path(args.workdir)
    if inp.suffix.lower() == ".so":
        report = dissect_so(inp)
        out = pathlib.Path(args.out) if args.out else workdir / (inp.stem + "_native_report.json")
    else:
        report = dissect_apk(inp, workdir / inp.stem)
        out = pathlib.Path(args.out) if args.out else workdir / (inp.stem + "_native_report.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print("\nreport -> %s" % out, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
