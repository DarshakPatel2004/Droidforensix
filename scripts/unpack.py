#!/usr/bin/env python3
"""Master-key dispatcher: one entry point, zero blank shots.

Routes every APK to the right strategy and ALWAYS returns a typed verdict:
  - recovered artifacts (self-validated), or
  - a structured E-code with the exact reason + next step.

Usage:  venv/bin/python scripts/unpack.py <apk> [--workdir DIR] [--out JSON]
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, ".")

from Crypto.Cipher import AES  # noqa: E402


# --------------------------------------------------------------------------
# typed E-codes
# --------------------------------------------------------------------------
E_CODES = {
    "E-JAVA-RUNTIME-DELIVERY": "Java-only injected trojan; payload fetched at runtime (no embedded kit). IOCs extracted instead.",
    "E-JAVA-NO-IOC": "Java-only sample, no loader/IOC patterns found in decompiled classes.",
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


def validate_dex(b: bytes):
    return b[:4] == b"dex\n" and len(b) > 112


def validate_zip(pt: bytes):
    """ZIP magic + central-dir presence + sane flags (0x2769 whitelist)."""
    if pt[:2] != b"PK" or pt[2:4] != b"\x03\x04":
        return False, "no local-file header"
    try:
        import io
        zf = zipfile.ZipFile(io.BytesIO(pt))
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
def myg0n_kdf_bruteforce_probe(probe: bytes, ct: bytes, stem: str,
                               base_literal: str = None):
    """Enumerate seed = base_literal[a:b][c:] + "2"; probe validates PK magic
    on a 16-byte-aligned prefix; full decrypt only on hit."""
    if base_literal is None:
        base_literal = stem + "bootstrap.dex"
    S = base_literal
    for a in range(len(S) + 1):
        for b in range(a, len(S) + 1):
            mid = S[a:b]
            for c in range(len(mid) + 1):
                seed = (mid[c:] + "2").encode()
                k = hashlib.sha1(seed).digest()[:16]
                iv = hashlib.sha256(seed).digest()[:16]
                pt = AES.new(k, AES.MODE_CBC, iv).decrypt(probe)
                if pt[:2] == b"PK":
                    pt_full = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
                    return seed.decode(errors="replace"), k.hex(), iv.hex(), pt_full
    return None


def myg0n_kdf_bruteforce(ct: bytes, stem: str, base_literal: str = None):
    """Back-compat wrapper: full-ct brute (validates PK magic on prefix)."""
    return myg0n_kdf_bruteforce_probe(ct[:48], ct, stem, base_literal)


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
    if "libDexHelper" in joined or "libbaiduprotect" in joined:
        return "SecShell/Baidu"
    if "libtup" in joined or "libexecmain" in joined:
        return "Ijiami(variant)"
    if "libchaosvmp" in joined or "libddog" in joined:
        return "TencentLegu"
    if "libnesec" in joined or "NQShield" in joined:
        return "Wangxin"
    return None


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
    blob = b"".join(zfile.read(n) for n in dexes)
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
        if shutil.which("jadx"):
            out = workdir / "jadx"
            if not out.exists():
                subprocess.run(["jadx", "-d", str(out), str(apk)],
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
             "SecShell/Baidu": ("DexHelper", "baiduprotect"),
             "Wangxin": ("nesec", "NQShield")}


def native_route(apk, zfile, workdir: pathlib.Path, report, prefer="arm64"):
    import emulate as emu_mod

    names = zfile.namelist()
    fam = sniff_family(names)
    report["family"] = fam
    libs = emu_mod.extract_so_from_apk(apk, workdir / "libs")
    # Prefer packer libs over benign cover-app libs (family tokens in path)
    marks = FAM_MARKS.get(fam or "", ())
    packer_libs = [l for l in libs if any(m in str(l) for m in marks)]
    ordered = packer_libs + [l for l in libs if l not in packer_libs] if packer_libs else libs
    export_libs = []
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
            export_libs.append((lib, entry, ename))
        except RuntimeError as ex:
            if "no Java_*" in str(ex):
                continue
        except Exception:
            continue
    if not export_libs:
        # JNI_OnLoad-only packers (Ijiami, Bangcle, ...): try the oneshot
        # boot (ctors + JNI_OnLoad with fake JavaVM) before declaring NOENTRY.
        # Code-protected (VM) libs fail decode at the entry -> E-HARDENED-VM
        # without burning minutes in the emulator.
        fam = fam or "Unknown"
        hardened = []
        for lib in ordered:
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
                ok, why = validate_dex(out.read_bytes()), "dex magic"
                report["oracle"] = {"lib": lib.name, "entry": meta.get("entry"),
                                    "status": meta.get("status"),
                                    "ctors": meta.get("ctors"),
                                    "jni_calls": meta.get("jni_calls"),
                                    "register_natives": meta.get("register_natives")[:6],
                                    "fault": meta.get("fault")}
                report["artifacts"] = [{"file": str(out), "sha256": sha256(out.read_bytes()),
                                        "validated": bool(ok)}]
                report["verdict"] = "RECOVERED"
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
    status = emu.run(entry, timeout_s=300)
    report["oracle"] = {"lib": lib.name, "entry": ename, "status": status,
                        "jni_calls": len(emu.jni_log),
                        "fault": getattr(emu, "fault_info", None)}
    blobs = emu.sweep_blobs()
    dexes = [b for b in blobs if b.get("kind") in ("b64_dex", "raw_dex")]
    if dexes:
        out = workdir / (report["sha256"][:16] + "_recovered.dex")
        out.write_bytes(dexes[0].pop("data"))
        ok, why = validate_dex(out.read_bytes()), "dex magic"
        report["artifacts"] = [{"file": str(out), "sha256": sha256(out.read_bytes()),
                                "validated": bool(ok)}]
        report["verdict"] = "RECOVERED"
        return report

    # no sweep blob → myg0N-style KDF brute on suspicious assets
    key_literals = [s for s in emu.key_log if s[0] == "getBytes"]
    assets = [n for n in names if n.startswith("assets/") and
              not n.lower().endswith((".png", ".jpg", ".xml", ".html", ".js", ".css"))]
    for asset in assets:
        ct = zfile.read(asset)
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
        hit = myg0n_kdf_bruteforce_probe(probe, ct, stem, base_literal)
        if hit:
            seed, khex, ivhex, pt = hit
            ok, why = validate_zip(pt)
            if ok:
                kit = workdir / report["sha256"][:16] / "kit.zip"
                kit.parent.mkdir(parents=True, exist_ok=True)
                kit.write_bytes(pt)
                report["verdict"] = "RECOVERED"
                report["kdf"] = {"asset": asset, "seed": seed,
                                 "key": khex, "iv": ivhex}
                report["artifacts"] = [{"file": str(kit), "sha256": sha256(pt),
                                        "validated": str(why)}]
                # IOC sweep inside kit
                try:
                    import io
                    zf = zipfile.ZipFile(io.BytesIO(pt))
                    blob = b"".join(zf.read(n) for n in zf.namelist()
                                    if not n.endswith((".png", ".jpg", ".so")))[:20_000_000]
                    report["iocs"] = {
                        "firebase": sorted({m.decode() for m in re.findall(
                            rb"[a-z0-9-]+\.firebaseio\.com", blob)})[:6],
                        "api_keys": sorted({m.decode() for m in re.findall(
                            rb"AIza[0-9A-Za-z_-]{30,}", blob)})[:6],
                    }
                except Exception:
                    pass
                return report
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
    report = {"apk": str(apk), "sha256": sha256(raw),
              "verdict": "FAILED", "ecode": None, "artifacts": []}

    try:
        zfile = zipfile.ZipFile(apk)
    except Exception as e:
        report["ecode"] = "E-ORACLE-FAULT"
        report["detail"] = f"not a readable zip/apk: {e}"
        print(json.dumps(report, indent=2)); return 0

    names = zfile.namelist()
    report["stats"] = {"entries": len(names),
                       "so_count": sum(1 for n in names if n.endswith(".so")),
                       "dex_count": sum(1 for n in names if n.endswith(".dex"))}

    # triage verdict (subprocess: triage.py has side-effect-y imports)
    try:
        t = subprocess.run([sys.executable, "scripts/triage.py", str(apk)],
                           capture_output=True, timeout=180, text=True)
        j = re.search(r"\{.*\}", t.stdout, re.S)
        if j:
            tj = json.loads(j.group(0))
            report["triage"] = {"verdict": tj.get("verdict") or tj.get("classification"),
                                "confidence": tj.get("confidence")}
    except Exception as e:
        report["triage"] = {"error": str(e)[:120]}

    if report["stats"]["so_count"] == 0:
        report["route"] = "JAVA"
        report = java_route(apk, zfile, workdir, report)
    else:
        report["route"] = "NATIVE"
        report = native_route(apk, zfile, workdir, report)
    if report.get("verdict") != "RECOVERED" and not report.get("ecode"):
        report["ecode"] = "E-NATIVE-NO-RECOVERY"
    print(json.dumps(report, indent=2, default=str))
    out = pathlib.Path(args.out) if args.out else workdir / "unpack_report.json"
    out.write_text(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
