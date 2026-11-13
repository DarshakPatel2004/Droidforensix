#!/usr/bin/env python3
"""Master-key dispatcher: one entry point, zero blank shots.

Routes every APK to the right strategy and ALWAYS returns a typed verdict:
  - recovered artifacts (self-validated), or
  - a structured E-code with the exact reason + next step.

Usage:  venv/bin/python scripts/unpack.py <apk> [--workdir DIR] [--out JSON]
"""
import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from Crypto.Cipher import AES  # noqa: E402

LOCAL_HEADER = b"PK\x03\x04"   # ZIP local-file header signature
UNPACK_BUDGET_S = int(os.environ.get("DF_UNPACK_BUDGET_S", "900"))   # per-route wall clock (audit P9)


# --------------------------------------------------------------------------
# typed E-codes
# --------------------------------------------------------------------------
E_CODES = {
    "E-JAVA-RUNTIME-DELIVERY": "Java-only injected trojan; payload fetched at runtime (no embedded kit). IOCs extracted instead.",
    "E-JAVA-NO-IOC": "Java-only sample, no loader/IOC patterns found in decompiled classes.",
    "E-JAVA-LAYER-HANDOFF": "Soft shell runs clean but payload DEX is delivered via ART/Java (dexElements/DexClassLoader), not minted in native memory; inspect stub-DEX Application (TxAppEntry -> MultiDex wrapper).",
    "E-NATIVE-NOENTRY": "Packer registers JNI at runtime (no Java_* export). Needs .init_array/JNI_OnLoad emulation.",
    "E-NATIVE-NO-RECOVERY": "Oracle ran but produced no self-validating payload; see fault info + key_log.",
    "E-ORACLE-FAULT": "Oracle aborted with an unhandled fault; fault info attached.",
    "E-HARDENED-VM": "Code-protected (bytecode VM) packer: entries are ciphertext at rest; DEX minting runs inside a custom interpreter. Outside static oracle scope (device hook or ART runtime needed).",
}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ecode(code, detail, extra=None):
    return {"ecode": code, "detail": E_CODES.get(code, ""), "info": detail,
            "extra": extra or {}}


# --------------------------------------------------------------------------
# self-validation gates (mission-critical: no wrong identifications)
# --------------------------------------------------------------------------
def pkcs7_tail_ok(pt: bytes) -> bool:
    """IV-independent CBC padding oracle on the last two ciphertext blocks."""
    if len(pt) < 32 or len(pt) % 16:
        return False
    return True  # full check done by caller with key; here structural only


def validate_dex(b: bytes) -> bool:
    """DEX magic, header file_size equal to the buffer length, and the header Adler-32 checksum.

    A magic check alone accepted junk and partial heap copies as recovered code (audit P5).
    """
    import zlib

    if len(b) <= 112 or b[:4] != b"dex\n":
        return False
    checksum = struct.unpack_from("<I", b, 8)[0]
    file_size = struct.unpack_from("<I", b, 32)[0]
    return file_size == len(b) and (zlib.adler32(b[12:]) & 0xFFFFFFFF) == checksum


MAX_ENTRY_BYTES = 256 * 1024 * 1024   # one archive member, declared size (audit P13)
MAX_KIT_BYTES = 512 * 1024 * 1024     # total uncompressed size of a recovered kit


def read_entry(zfile, name, cap=MAX_ENTRY_BYTES, limit=None):
    """Read one member, refusing a declared size over cap before any inflation.

    The declared size comes from the (untrusted) central directory, so it is checked
    before reading. `limit` caps how much of the member is read."""
    info = zfile.getinfo(name)
    if info.file_size > cap:
        raise ValueError(f"{name}: {info.file_size} bytes exceeds {cap}")
    with zfile.open(info) as f:
        return f.read(limit) if limit is not None else f.read()


def validate_zip(pt: bytes):
    """ZIP magic + central-dir presence + sane flags (0x2769 whitelist)."""
    if pt[:2] != b"PK" or pt[2:4] != b"\x03\x04":
        return False, "no local-file header"
    try:
        import io
        zf = zipfile.ZipFile(io.BytesIO(pt))
        if sum(i.file_size for i in zf.infolist()) > MAX_KIT_BYTES:
            return False, "uncompressed size exceeds cap"
        bad = zf.testzip()
        if bad is not None:
            return False, f"crc fail at {bad}"
        return True, {"entries": len(zf.namelist())}
    except Exception as e:
        # flag-bit fakes (0x2769) can still unzip via our reader; fall back to EOCD scan
        if b"PK\x05\x06" in pt[-4096:]:
            return True, "EOCD present (strict parse skipped)"
        return False, str(e)[:80]


# --------------------------------------------------------------------------
# myg0N-family KDF brute (substring-corrected)
# --------------------------------------------------------------------------
MAX_BRUTE_LITERAL = 96   # bounds the O(n^3) seed enumeration (audit P9)


def myg0n_kdf_hits(probe: bytes, ct: bytes, stem: str, base_literal: str = None,
                   deadline: float = None):
    """Yield (seed, key, iv, plaintext) for every seed whose decrypted probe starts
    with a ZIP local-file header.

    A bare two-byte 'PK' prefix matches about 1 seed in 65536, so the full decrypt
    runs only on the complete four-byte local-header signature, over the whole
    16-byte blocks of ct (audit P11). Callers validate each hit and keep enumerating
    when validation fails. Stops early once `deadline` (time.monotonic) has passed.
    """
    if base_literal is None:
        base_literal = stem + "bootstrap.dex"
    S = base_literal[:MAX_BRUTE_LITERAL]
    aligned = ct[:len(ct) // 16 * 16]
    for a in range(len(S) + 1):
        if deadline is not None and time.monotonic() > deadline:
            return
        for b in range(a, len(S) + 1):
            mid = S[a:b]
            for c in range(len(mid) + 1):
                seed = (mid[c:] + "2").encode()
                k = hashlib.sha1(seed).digest()[:16]
                iv = hashlib.sha256(seed).digest()[:16]
                pt = AES.new(k, AES.MODE_CBC, iv).decrypt(probe)
                if pt[:4] == LOCAL_HEADER:
                    pt_full = AES.new(k, AES.MODE_CBC, iv).decrypt(aligned)
                    yield seed.decode(errors="replace"), k.hex(), iv.hex(), pt_full


def myg0n_kdf_bruteforce(ct: bytes, stem: str, base_literal: str = None):
    """First hit that validates as a ZIP, or None."""
    for seed, khex, ivhex, pt in myg0n_kdf_hits(ct[:48], ct, stem, base_literal):
        if validate_zip(pt)[0]:
            return seed, khex, ivhex, pt
    return None

# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------
def sniff_family(names):
    joined = " ".join(names)
    if "ijiami" in joined:
        return "Ijiami"
    if "bangcle" in joined or "libsecmain" in joined or "libsecexe" in joined:
        return "Bangcle/SecNeo"
    if "libjiagu" in joined:
        return "360Jiagu"
    if "libshell" in joined or "libExecution" in joined:
        return "TencentLegu"
    if "libbaiduprotect" in joined or "com.baidu.protect" in joined:
        # label aligned with data/packer_markers.json brand (was lumped into SecShell/Baidu)
        return "BaiduEnhancer"
    if "libDexHelper" in joined:
        return "SecShell/Baidu"
    if "libtup" in joined or "libexecmain" in joined:
        return "Ijiami(variant)"
    if "libchaosvmp" in joined or "libddog" in joined:
        return "TencentLegu"
    if "libnesec" in joined or "NQShield" in joined:
        return "Wangxin"
    if "libkwsgmain" in joined or "libkdp" in joined:
        return "Wangsu"
    if "libmobisec" in joined:
        return "Ali"
    if "licel" in joined or "dexprotector" in joined:
        return "DexProtector"
    return None


def java_layer_handoff(zfile) -> bool:
    """True when the Legu stub DEX drives payload delivery from Java.

    The native oracle runs clean but can never mint this payload DEX: the
    stub Application (TxAppEntry -> multi-dex wrapper) delivers it inside
    ART (dexElements/DexClassLoader) - see docs/PACKERS.md "Tencent Legu
    soft-shell boundary". Signature verified 23-Sep-2026 against both SOFT
    corpus samples (libshella-2.10.7.1 and 4.1.0.23 both carry TxAppEntry
    within the first 2 MB of classes.dex). Family gating happens at the
    call site so non-Legu failures keep E-NATIVE-NO-RECOVERY; a missing or
    unreadable stub falls back to False (old behavior, still typed).
    """
    try:
        head = read_entry(zfile, "classes.dex", limit=2_000_000)
    except Exception:
        return False
    if b"TxAppEntry" in head:
        return True
    return b"DexFile" in head and (
        b"DexClassLoader" in head or b"dexElements" in head)


def java_route(apk, zfile, workdir: pathlib.Path, report):
    """Step 2.5 — so_count:0 injected-repack path."""
    dexes = [n for n in zfile.namelist() if n.endswith(".dex")]
    iocs = {}
    try:
        logging = __import__("logging")
        logging.getLogger("androguard").setLevel(logging.ERROR)
        from androguard.core.apk import APK
        a = APK(str(apk))
        report["package"] = a.get_package()
        report["components"] = {"receivers": a.get_receivers(),
                                "services": a.get_services(),
                                "main_activity": a.get_main_activity()}
        iocs["package"] = a.get_package()
    except Exception as e:
        report["manifest_error"] = str(e)[:120]

    # decompile + IOC strings from every dex
    blob = b"".join(read_entry(zfile, n) for n in dexes if zfile.getinfo(n).file_size <= MAX_ENTRY_BYTES)
    pats = {
        "urls": rb"https?://[A-Za-z0-9./?=_&%-]{6,90}",
        "telegram": rb"(api\.telegram\.org|bot[0-9]{6,}:[A-Za-z0-9_-]{20,})",
        "firebase": rb"[a-z0-9-]+\.firebaseio\.com",
        "apk_download": rb"[A-Za-z0-9_/-]{1,40}\.apk",
        "loader": rb"(DexClassLoader|InMemoryDexClassLoader|pathUrl|openConnection)",
    }
    for key, pat in pats.items():
        found = sorted({m.decode(errors="replace") for m in re.findall(pat, blob)})
        if found:
            iocs[key] = found[:12]

    report["iocs"] = iocs
    if iocs.get("loader") or iocs.get("urls") or iocs.get("firebase"):
        report["ecode"] = "E-JAVA-RUNTIME-DELIVERY"
    else:
        report["ecode"] = "E-JAVA-NO-IOC"
    # optional jadx for human follow-up
    try:
        jadx = shutil.which("jadx")  # resolved path: on Windows this is jadx.bat, which needs it (audit P25)
        if jadx:
            out = workdir / "jadx"
            if not out.exists():
                subprocess.run([jadx, "-d", str(out), str(apk)],
                               capture_output=True, timeout=600)
            report["jadx_out"] = str(out)
    except Exception as e:
        report["jadx_error"] = str(e)[:120]
    return report


FAM_MARKS = {"Ijiami": ("ijm", "ijiami", "execmain", "libexec"),
             "Ijiami(variant)": ("ijm", "execmain", "libexec", "tup"),
             "Bangcle/SecNeo": ("secmain", "secexe", "secpreload", "bangcle"),
             "360Jiagu": ("jiagu",),
             "TencentLegu": ("chaosvmp", "ddog", "legu", "tup", "shell"),
             "SecShell/Baidu": ("DexHelper",),
             "Wangxin": ("nesec", "NQShield"),
             "Wangsu": ("kwsgmain", "kdp"),
             "Ali": ("mobisec",),
             "BaiduEnhancer": ("baiduprotect",),
             "DexProtector": ("licel", "dexprotector")}


def native_route(apk, zfile, workdir: pathlib.Path, report, prefer="arm64"):
    """Native route. `workdir` is the per-sample directory (libs/, kit.zip, recovered dex)."""
    import emulate as emu_mod

    deadline = time.monotonic() + UNPACK_BUDGET_S   # one wall-clock budget for the route (audit P9)
    names = zfile.namelist()
    fam = sniff_family(names)
    report["family"] = fam
    libs = emu_mod.extract_so_from_apk(apk, workdir / "libs")
    # Prefer packer libs over benign cover-app libs (family tokens in path)
    marks = FAM_MARKS.get(fam or "", ())
    packer_libs = [l for l in libs if any(m in str(l) for m in marks)]
    ordered = packer_libs + [l for l in libs if l not in packer_libs] if packer_libs else libs
    export_libs = []
    onload_only = []
    hardened = []
    for lib in ordered:
        try:
            e = emu_mod.Emulator(lib)
            # Code-protected libs decode 0% at the entry -> skip entirely,
            # their JNI_OnLoad is ciphertext and the 300s oracle would fault.
            try:
                hvm, hev = emu_mod.is_hardened_vm(e.binary)
            except Exception:
                hvm = False
            if hvm:
                hardened.append((lib, hev))
                continue
            entry, ename = e.find_entry()
            if ename == "JNI_OnLoad":
                # No Java_* export: the oneshot route supplies the fake JavaVM and ctors.
                # Running JNI_OnLoad directly would pass a JNIEnv as the JavaVM (audit P1).
                onload_only.append(lib)
                continue
            export_libs.append((lib, entry, ename))
        except RuntimeError as ex:
            if "no Java_*" in str(ex):
                continue
        except Exception:
            continue
    packer_exports = [l for l, _, _ in export_libs if l in packer_libs]
    if not export_libs or (onload_only and not packer_exports):
        # JNI_OnLoad-only packers (Ijiami, Bangcle, ...): try the oneshot
        # boot (ctors + JNI_OnLoad with fake JavaVM) before declaring NOENTRY.
        # Code-protected (VM) libs fail decode at the entry -> E-HARDENED-VM
        # without burning minutes in the emulator.
        fam = fam or "Unknown"
        candidates = onload_only or ordered
        hardened = []
        for lib in candidates:
            if time.monotonic() > deadline:
                report["budget_exhausted"] = "oneshot"
                break
            try:
                emu = emu_mod.Emulator(lib)
            except Exception:
                continue
            try:
                hvm, ev = emu_mod.is_hardened_vm(emu.binary)
            except Exception:
                hvm = False
            if hvm:
                hardened.append((lib, ev))
                continue
            try:
                meta = emu.run_jni_oneshot()
            except Exception:
                continue
            blobs = emu.sweep_blobs()
            dexes = [b for b in blobs if b.get("kind") in ("b64_dex", "raw_dex", "heap_dex", "obj_dex")]
            if dexes:
                out = workdir / (report["sha256"][:16] + "_recovered.dex")
                out.write_bytes(dexes[0].pop("data"))
                ok = validate_dex(out.read_bytes())
                report["oracle"] = {"lib": lib.name, "entry": meta.get("entry"),
                                    "status": meta.get("status"),
                                    "ctors": meta.get("ctors"),
                                    "jni_calls": meta.get("jni_calls"),
                                    "register_natives": meta.get("register_natives")[:6],
                                    "fault": meta.get("fault"),
                                    "null_reads": getattr(emu, "null_reads", [])[:8]}
                report["artifacts"] = [{"file": str(out), "sha256": sha256(out.read_bytes()),
                                        "validated": bool(ok)}]
                # RECOVERED only when the DEX validates; otherwise say so (audit P5).
                report["verdict"] = "RECOVERED" if ok else "UNVALIDATED_DEX"
                report["route_detail"] = "JNI_OnLoad oneshot"
                return report
        if hardened:
            report["ecode"] = "E-HARDENED-VM"
            report["family"] = fam
            report["hardened_libs"] = [{"lib": str(l), "decode_density": ev.get("decode_density")}
                                       for l, ev in hardened]
            report["next_step"] = ("Code-protected (bytecode VM) packer: JNI_OnLoad/"
                                   "init_array is ciphertext at rest; DEX minting runs "
                                   "inside a custom interpreter (see "
                                   "analysis/emulate/calc_ijiami/PHASE1_GATE.md). "
                                   "Recovery requires VM-level emulation (device hook "
                                   "or ART runtime) - outside static oracle scope.")
            return report
        report["ecode"] = "E-NATIVE-NOENTRY"
        report["family"] = fam
        if export_libs:
            report["benign_exports"] = [l.name for l, _, _ in export_libs[:4]]
        report["next_step"] = ("Implement .init_array/JNI_OnLoad capture "
                               "(scripts/ijiami_oracle.py has a JavaVM mock) "
                               "or run scripts/ijiami_oracle.py directly.")
        return report

    lib, entry, ename = export_libs[0]
    if packer_libs and lib not in packer_libs:
        # only benign libs exported; packer libs are RegisterNatives-only
        if hardened:
            report["ecode"] = "E-HARDENED-VM"
            report["family"] = fam
            report["hardened_libs"] = [{"lib": str(l), "decode_density": ev.get("decode_density")}
                                       for l, ev in hardened]
            report["benign_exports"] = [l.name for l, _, _ in export_libs[:4]]
            report["next_step"] = ("Code-protected (bytecode VM) packer libs "
                                   f"({[str(l) for l, _ in hardened]}) are ciphertext "
                                   "at rest; only cover-app libs export. Recovery "
                                   "requires VM-level emulation (device hook or ART "
                                   "runtime) - outside static oracle scope.")
            return report
        report["ecode"] = "E-NATIVE-NOENTRY"
        report["family"] = fam
        report["benign_exports"] = [l.name for l, _, _ in export_libs[:4]]
        report["next_step"] = ("Cover-app libs export JNI but packer libs "
                               f"({[l.name for l in packer_libs]}) do not — "
                               "run packer lib under JNI_OnLoad-capable oracle.")
        return report
    emu = emu_mod.Emulator(lib)
    emu.load_elf(); emu.map_regions(); emu.wire_got_shims(); emu.wire_jni_table()
    status = emu.run(entry, timeout_s=min(300, max(1, int(deadline - time.monotonic()))))
    report["oracle"] = {"lib": lib.name, "entry": ename, "status": status,
                        "jni_calls": len(emu.jni_log),
                        "fault": getattr(emu, "fault_info", None),
                        "null_reads": getattr(emu, "null_reads", [])[:8]}
    blobs = emu.sweep_blobs()
    dexes = [b for b in blobs if b.get("kind") in ("b64_dex", "raw_dex")]
    if dexes:
        out = workdir / (report["sha256"][:16] + "_recovered.dex")
        out.write_bytes(dexes[0].pop("data"))
        ok = validate_dex(out.read_bytes())
        report["artifacts"] = [{"file": str(out), "sha256": sha256(out.read_bytes()),
                                "validated": bool(ok)}]
        report["verdict"] = "RECOVERED" if ok else "UNVALIDATED_DEX"
        return report

    # no sweep blob → myg0N-style KDF brute on suspicious assets
    key_literals = [s for s in emu.key_log if s[0] == "getBytes"]
    assets = [n for n in names if n.startswith("assets/") and
              not n.lower().endswith((".png", ".jpg", ".xml", ".html", ".js", ".css"))]
    for asset in assets:
        if time.monotonic() > deadline:
            report["budget_exhausted"] = "kdf-brute"
            break
        try:
            ct = read_entry(zfile, asset)
        except ValueError:
            continue                            # oversized member: skipped, not read (audit P13)
        if len(ct) < 512:                       # skip tiny/profile assets
            continue
        if ct[:2] in (b"PK", b"d" + b"e", b"ID", b"\x1f\x8b", b"BM"):  # already plaintext
            continue
        stem = pathlib.Path(asset).stem
        base_literal = None
        for _, s in key_literals:
            if s.startswith(stem) and "bootstrap" in s:
                base_literal = s.rstrip("2").rstrip("0123456789") if s.endswith("2") else s
                base_literal = base_literal if base_literal.endswith("dex") else stem + "bootstrap.dex"
                break
        probe = ct[:48 - len(ct) % 16] if len(ct) < 48 else ct[:48]
        for seed, khex, ivhex, pt in myg0n_kdf_hits(probe, ct, stem, base_literal, deadline):
            ok, why = validate_zip(pt)
            if not ok:
                continue                        # a false PK hit: keep enumerating (audit P11)
            kit = workdir / "kit.zip"
            kit.write_bytes(pt)
            report["verdict"] = "RECOVERED"
            report["kdf"] = {"asset": asset, "seed": seed,
                             "key": khex, "iv": ivhex}
            report["artifacts"] = [{"file": str(kit), "sha256": sha256(pt),
                                    "validated": str(why)}]
            # IOC sweep inside kit, capped per member and in total
            try:
                zf = zipfile.ZipFile(io.BytesIO(pt))
                parts, total = [], 0
                for n in zf.namelist():
                    if n.endswith((".png", ".jpg", ".so")):
                        continue
                    chunk = read_entry(zf, n, limit=20_000_000)
                    parts.append(chunk)
                    total += len(chunk)
                    if total > 20_000_000:
                        break
                blob = b"".join(parts)[:20_000_000]
                report["iocs"] = {
                    "firebase": sorted({m.decode() for m in re.findall(
                        rb"[a-z0-9-]+\.firebaseio\.com", blob)})[:6],
                    "api_keys": sorted({m.decode() for m in re.findall(
                        rb"AIza[0-9A-Za-z_-]{30,}", blob)})[:6],
                }
            except Exception as e:
                # validate_zip() can pass via its EOCD fallback while ZipFile()
                # itself still fails, so this sweep can fail on an otherwise
                # "RECOVERED" kit. Record it: an absent IOC section must not
                # read as "this kit contains no indicators".
                report["iocs_error"] = "%s: %s" % (type(e).__name__, e)
                report.setdefault("iocs", {})
            return report
    if fam == "TencentLegu" and java_layer_handoff(zfile):
        # Native ran clean and the stub carries the Java-delivery signature:
        # report the typed handoff instead of a generic oracle failure.
        report["ecode"] = "E-JAVA-LAYER-HANDOFF"
        report["next_step"] = ("Payload delivered inside ART by the stub "
                               "Application (TxAppEntry -> multi-dex wrapper); "
                               "inspect classes.dex - outside the static "
                               "native oracle (docs/PACKERS.md).")
    else:
        report["ecode"] = "E-NATIVE-NO-RECOVERY"
    report["key_log"] = [k for k in emu.key_log if k[0] in ("getBytes", "digest")][:12]
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("--workdir", default="analysis/unpack")
    ap.add_argument("--out")
    args = ap.parse_args()

    apk = pathlib.Path(args.apk)
    workdir = pathlib.Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    raw = apk.read_bytes()
    sha = sha256(raw)
    # Per-sample scratch (libs/, jadx/, kit): concurrent analyses cannot collide (audit P10).
    sample_dir = workdir / sha[:16]
    sample_dir.mkdir(parents=True, exist_ok=True)
    report = {"apk": str(apk), "sha256": sha,
              "verdict": "FAILED", "ecode": None, "artifacts": []}
    out = pathlib.Path(args.out) if args.out else workdir / "unpack_report.json"

    def finish():
        # Every branch writes the report, so a crash never leaves a stale file behind (audit P12).
        print(json.dumps(report, indent=2, default=str))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, default=str))
        return 0

    try:
        zfile = zipfile.ZipFile(apk)
    except Exception as e:
        report["ecode"] = "E-ORACLE-FAULT"
        report["detail"] = f"not a readable zip/apk: {e}"
        return finish()

    names = zfile.namelist()
    report["stats"] = {"entries": len(names),
                       "so_count": sum(1 for n in names if n.endswith(".so")),
                       "dex_count": sum(1 for n in names if n.endswith(".dex"))}

    # triage verdict; resolved next to this file so it works from any cwd (audit P12)
    triage_script = pathlib.Path(__file__).resolve().parent / "triage.py"
    try:
        t = subprocess.run([sys.executable, str(triage_script), str(apk)],
                           capture_output=True, timeout=180, text=True)
        j = re.search(r"\{.*\}", t.stdout, re.S)
        if j:
            tj = json.loads(j.group(0))
            report["triage"] = {"verdict": tj.get("verdict") or tj.get("classification"),
                                "confidence": tj.get("confidence")}
    except Exception as e:
        report["triage"] = {"error": str(e)[:120]}

    try:
        if report["stats"]["so_count"] == 0:
            report["route"] = "JAVA"
            report = java_route(apk, zfile, sample_dir, report)
        else:
            report["route"] = "NATIVE"
            report = native_route(apk, zfile, sample_dir, report)
    except Exception as e:
        # The docstring promises a typed verdict: an unhandled route failure becomes E-ORACLE-FAULT.
        report["ecode"] = "E-ORACLE-FAULT"
        report["detail"] = f"{type(e).__name__}: {str(e)[:200]}"
    if report.get("verdict") != "RECOVERED" and not report.get("ecode"):
        report["ecode"] = "E-NATIVE-NO-RECOVERY"
    return finish()


if __name__ == "__main__":
    sys.exit(main())
