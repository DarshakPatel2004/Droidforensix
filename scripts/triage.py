#!/usr/bin/env python3
"""C1 Structural Triage Engine - M0 prototype (plan section C1).

Classifies APK protection state via structure/statistics, independent of
packer brand naming. Emits triage_report.json per plan section 7.

Usage:
  python3 scripts/triage.py <apk> [--out PATH]
  python3 scripts/triage.py --locklist data/triage_locklist_m0.csv \
      [--workdir analysis/triage_m0] [--summary PATH]
"""

import argparse
import csv
import hashlib
import io
import json
import math
import pathlib
import re
import sys
import time
import zipfile

from elftools.elf.elffile import ELFFile

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX as DalvikVMFormat
    from loguru import logger as _androguard_logger
    _androguard_logger.remove()
except ImportError:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat

REPO = pathlib.Path(__file__).resolve().parent.parent
MARKERS_PATH = REPO / "data" / "packer_markers.json"
ALLOWLIST_PATH = REPO / "data" / "engine_allowlist.json"

DEX_RE = re.compile(r"(?:^|/)classes\d*\.dex$")
SO_RE = re.compile(r"\.so$", re.IGNORECASE)

ENTROPY_WINDOW = 4096
ENTROPY_SAMPLE_CAP = 16 * 1024 * 1024
BIG_ASSET_MIN = 100 * 1024
PAYLOAD_MIN = 1024 * 1024
TEXT_BIG_MIN = 256 * 1024
STUB_DEX_MAX = 300 * 1024

WEIGHTS = {"H1": 0.30, "H2": 0.15, "H3": 0.20, "H4": 0.15, "H6": 0.20}
# Calibration (M0 locklist run 2026-08-26): max clean-side score = 0.30,
# min known-packed score = 0.45 -> midpoint rounded to 0.40.
PACKED_THRESHOLD = 0.40
INDETERMINATE_THRESHOLD = 0.35

FILE_IO_SYMBOLS = {
    "open", "fopen", "fopen64", "read", "pread", "pread64",
    "mmap", "mmap64", "write", "openat", "__open_2", "open64",
}


def load_json(path):
    with open(path) as fh:
        return json.load(fh)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = float(len(data))
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def h1_dex_ratio(zf, allowlist):
    infos = zf.infolist()
    dex_total = sum(i.file_size for i in infos if DEX_RE.search(i.filename))
    total = max(sum(i.file_size for i in infos), 1)
    so_total = sum(i.file_size for i in infos if SO_RE.search(i.filename))
    big_assets = [
        i for i in infos
        if i.filename.startswith("assets/") and i.file_size >= BIG_ASSET_MIN
    ]
    ratio = dex_total / total
    native_share = so_total / total
    # Stub-sized dexes coexist with smaller encrypted blobs (observed 774 KB
    # payload in GhostBat-class sample) - relax the payload floor for them.
    payload_floor = PAYLOAD_MIN if dex_total >= STUB_DEX_MAX else 256 * 1024
    hit = ratio < 0.05 and any(i.file_size >= payload_floor for i in big_assets)
    overrides = []
    if hit:
        for info in big_assets:
            lowered = info.filename.lower()
            if any(p in lowered for p in allowlist["asset_patterns"]):
                overrides.append("asset_pattern:" + info.filename)
                hit = False
                break
        if hit and native_share > allowlist["native_share_exempt"]:
            overrides.append("native_share:%.2f" % native_share)
            hit = False
    return {
        "id": "H1",
        "value": round(ratio, 6),
        "threshold": 0.05,
        "hit": hit,
        "dex_bytes": dex_total,
        "total_uncompressed": total,
        "native_lib_share": round(native_share, 4),
        "big_asset_count": len(big_assets),
        "allowlist_overrides_applied": overrides,
    }


def _entropy_windows(fh, size):
    """Yield entropy of non-overlapping 4KiB windows; cap huge files by
    sampling head/middle/tail (plan H2 sliding window approximated at
    1/window cost - flagged-count stays comparable for thresholding)."""
    points = [0]
    if size > ENTROPY_SAMPLE_CAP:
        points = [0, max(size // 2 - ENTROPY_WINDOW * 512, 0),
                  max(size - ENTROPY_WINDOW * 1024, 0)]
    entropies = []
    for pos in points:
        fh.seek(pos)
        remaining = min(ENTROPY_WINDOW * 1024, size - pos)
        for _ in range(remaining // ENTROPY_WINDOW):
            window = fh.read(ENTROPY_WINDOW)
            if len(window) == ENTROPY_WINDOW:
                entropies.append(shannon_entropy(window))
    return entropies


def h2_asset_entropy(zf):
    candidates = [
        i for i in zf.infolist()
        if i.filename.startswith("assets/") and i.file_size >= BIG_ASSET_MIN
    ]
    entropies = []
    flagged = 0
    sampled = False
    for info in candidates[:20]:
        if info.file_size > ENTROPY_SAMPLE_CAP:
            sampled = True
        with zf.open(info) as fh:
            entropies.extend(_entropy_windows(fh, info.file_size))
    flagged = sum(1 for e in entropies if e > 7.5)
    mean = round(sum(entropies) / len(entropies), 4) if entropies else 0.0
    return {
        "id": "H2",
        "mean": mean,
        "threshold": 7.5,
        "hit": bool(entropies) and mean > 7.5,
        "windows_flagged": flagged,
        "total_windows": len(entropies),
        "sampled_capped": sampled,
        "candidates": [i.filename for i in candidates[:20]],
    }


def _dex_class_descriptor(app_class):
    """Normalize 'a.b.C' / 'La/b/C;' / 'a/b/C' to dalvik L-form bytes."""
    cleaned = app_class.lstrip(".").strip()
    if cleaned.startswith("L") and cleaned.endswith(";"):
        return cleaned.encode()
    return ("L" + cleaned.replace(".", "/") + ";").encode()


def _app_class_loads_native(dex_bytes, app_class):
    """True/False when decidable via androguard instruction scan;
    None when the dex cannot be parsed or class not found."""
    try:
        dvm = DalvikVMFormat(dex_bytes)
        target = _dex_class_descriptor(app_class).decode()
        for cls in dvm.get_classes():
            if cls.get_name() != target:
                continue
            for method in cls.get_methods():
                if method.get_code() is None:
                    continue
                for inst in method.get_instructions():
                    if "loadLibrary" in inst.get_output():
                        return True
            return False
        return None
    except Exception as exc:
        print("[warn] H3 dex parse failed: %s" % exc, file=sys.stderr)
        return None


def h3_native_app_class(zf, apk_path):
    try:
        apk = APK(str(apk_path))
        app_class = apk.get_attribute_value("application", "name") or ""
    except Exception as exc:
        print("[warn] H3 manifest parse failed: %s" % exc, file=sys.stderr)
        app_class = ""
    if not app_class:
        return {"id": "H3", "hit": False, "app_class": "",
                "reason": "no_application_class"}
    dex_names = sorted(n for n in zf.namelist() if DEX_RE.search(n))
    if not dex_names:
        return {"id": "H3", "hit": False, "app_class": app_class,
                "reason": "no_dex"}
    primary = dex_names[0]
    dex_bytes = zf.read(primary)
    loads_native = _app_class_loads_native(dex_bytes, app_class)
    if loads_native is None:
        loads_native = len(dex_bytes) <= STUB_DEX_MAX and b"loadLibrary" in dex_bytes
        reason = "fallback_string_rule"
    else:
        reason = "instruction_scan"
    return {"id": "H3", "hit": bool(loads_native), "app_class": app_class,
            "primary_dex": primary, "dex_bytes": len(dex_bytes), "reason": reason}


def _elf_facts(zf, name):
    try:
        with zf.open(name) as fh:
            elf = ELFFile(io.BytesIO(fh.read()))
            exports = 0
            und_symbols = set()
            text_size = 0
            stripped = True
            for section in elf.iter_sections():
                if section.header["sh_type"] == "SHT_SYMTAB":
                    stripped = False
                if section.header["sh_type"] not in ("SHT_DYNSYM", "SHT_SYMTAB"):
                    continue
                if section.header["sh_size"] == 0:
                    continue
                for sym in section.iter_symbols():
                    sym_name = sym.name
                    if sym["st_info"]["type"] != "STT_FUNC":
                        continue
                    if sym_name.startswith("Java_"):
                        exports += 1
                    if sym["st_shndx"] == "SHN_UNDEF":
                        und_symbols.add(sym_name.split("@")[0])
                if section.name == ".text":
                    text_size = section.header["sh_size"]
            return {"exports_java": exports, "stripped": stripped,
                    "text_size": text_size, "und": und_symbols}
    except Exception as exc:
        print("[warn] ELF parse failed for %s: %s" % (name, exc), file=sys.stderr)
        return None


def _all_lib_facts(zf):
    facts = {}
    for name in zf.namelist():
        if SO_RE.search(name):
            parsed = _elf_facts(zf, name)
            if parsed is not None:
                facts[name] = parsed
    return facts


def h4_jni_shape(facts):
    if not facts:
        return {"id": "H4", "hit": False, "libs_parsed": 0}
    worst = min(facts.values(),
                key=lambda f: (f["exports_java"], -f["text_size"]))
    hit = (worst["exports_java"] <= 2 and worst["stripped"]
           and worst["text_size"] >= TEXT_BIG_MIN)
    return {"id": "H4", "hit": hit,
            "java_exports_min": worst["exports_java"],
            "stripped": worst["stripped"],
            "max_text_bytes": worst["text_size"],
            "libs_parsed": len(facts)}


def h5_packer_markers(zf, markers):
    lowered_names = [n.lower() for n in zf.namelist()]
    dex_blob = b""
    for name in zf.namelist():
        if DEX_RE.search(name):
            dex_blob += zf.read(name)[: STUB_DEX_MAX * 4]
    lowered_dex = dex_blob.lower()
    matched = []
    for brand in markers["brands"]:
        hits = []
        for marker in brand["markers"]:
            needle = marker.lower().encode()
            if marker.lower() in " ".join(lowered_names) or needle in lowered_dex:
                hits.append(marker)
        if hits:
            matched.append({"brand": brand["name"], "markers": hits})
    return {"id": "H5", "matched": matched}


def h6_import_profile(facts, has_payload):
    all_und = set()
    for parsed in facts.values():
        all_und |= parsed["und"]
    file_io = sorted(all_und & FILE_IO_SYMBOLS)
    if not facts:
        profile = "unknown"
    elif file_io:
        profile = "file_io"
    else:
        profile = "pure_compute"
    hit = profile == "pure_compute" and has_payload
    return {"id": "H6", "profile": profile, "hit": hit,
            "file_io_symbols": file_io}


def build_verdict(heuristics):
    brands = heuristics["H5"]["matched"]
    if brands:
        return "packed_known(%s)" % brands[0]["brand"], 0.95
    score = sum(WEIGHTS[hid] for hid, res in heuristics.items()
                if res.get("hit"))
    if heuristics["H1"]["hit"] and score >= PACKED_THRESHOLD:
        return "packed_custom", round(score, 3)
    if heuristics["H4"]["hit"] and not heuristics["H1"]["hit"]:
        return "obfuscated_native", round(score, 3)
    if score >= INDETERMINATE_THRESHOLD:
        return "indeterminate", round(score, 3)
    return "clean_static", round(1.0 - score, 3)


def _payload_candidates(zf):
    candidates = [
        {"path": i.filename, "size": i.file_size}
        for i in zf.infolist()
        if i.filename.startswith("assets/") and i.file_size >= PAYLOAD_MIN
    ]
    return sorted(candidates, key=lambda c: c["size"], reverse=True)[:10]


def triage_apk(apk_path, markers, allowlist):
    started = time.monotonic()
    with zipfile.ZipFile(apk_path) as zf:
        facts = _all_lib_facts(zf)
        h1 = h1_dex_ratio(zf, allowlist)
        h2 = h2_asset_entropy(zf)
        h3 = h3_native_app_class(zf, apk_path)
        h4 = h4_jni_shape(facts)
        h5 = h5_packer_markers(zf, markers)
        has_payload = bool(_payload_candidates(zf))
        h6 = h6_import_profile(facts, has_payload)
        payload_candidates = _payload_candidates(zf)
    heuristics = {"H1": h1, "H2": h2, "H3": h3,
                  "H4": h4, "H5": h5, "H6": h6}
    verdict, confidence = build_verdict(heuristics)
    return {
        "apk_sha256": sha256_file(apk_path),
        "apk_path": str(apk_path),
        "verdict": verdict,
        "confidence": confidence,
        "duration_seconds": round(time.monotonic() - started, 3),
        "heuristics": {
            hid: {k: (sorted(v) if isinstance(v, set) else v)
                  for k, v in res.items()}
            for hid, res in heuristics.items()
        },
        "payload_candidates": payload_candidates,
        "allowlist_overrides_applied": h1["allowlist_overrides_applied"],
    }


def run_single(args):
    apk_path = pathlib.Path(args.apk)
    if not apk_path.exists():
        print("[error] not found: %s" % apk_path, file=sys.stderr)
        return 2
    report = triage_apk(apk_path, load_json(MARKERS_PATH),
                        load_json(ALLOWLIST_PATH))
    rendered = json.dumps(report, indent=2)
    if args.out:
        pathlib.Path(args.out).write_text(rendered)
        print("report -> %s" % args.out)
    print(rendered)
    return 0


def expected_flag(bucket, expected=""):
    return bucket == "packed_custom_positive" or expected.startswith("expect_")


def run_locklist(args):
    locklist = pathlib.Path(args.locklist)
    workdir = pathlib.Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    markers = load_json(MARKERS_PATH)
    allowlist = load_json(ALLOWLIST_PATH)
    rows = list(csv.DictReader(open(locklist)))
    summary_rows = []
    for row in rows:
        path = pathlib.Path(row["path"])
        if not path.exists():
            print("[missing] %s" % path, file=sys.stderr)
            continue
        try:
            report = triage_apk(path, markers, allowlist)
        except Exception as exc:
            print("[error] %s: %s" % (path.name, exc), file=sys.stderr)
            continue
        sample_dir = workdir / report["apk_sha256"][:16]
        sample_dir.mkdir(parents=True, exist_ok=True)
        (sample_dir / "triage_report.json").write_text(
            json.dumps(report, indent=2))
        flagged = report["verdict"].startswith(("packed_", "obfuscated"))
        summary_rows.append({
            "bucket": row["bucket"],
            "expected": row["expected"],
            "sha16": report["apk_sha256"][:16],
            "verdict": report["verdict"],
            "confidence": report["confidence"],
            "flagged": flagged,
            "matches_expected": str(flagged == expected_flag(
                row["bucket"], row["expected"])),
            "duration_seconds": report["duration_seconds"],
        })
        print("[%s] %-14s conf=%.2f %6.1fs  %s" % (
            "FLAG" if flagged else "pass", report["verdict"],
            report["confidence"], report["duration_seconds"], path.name))
    summary_path = pathlib.Path(args.summary) if args.summary \
        else workdir / "summary.csv"
    with open(summary_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader()
        writer.writerows(summary_rows)
    clean = [r for r in summary_rows
             if r["bucket"] in ("known_clean", "engine_big_asset_clean")]
    packed = [r for r in summary_rows
              if expected_flag(r["bucket"], r["expected"])]
    fp = sum(1 for r in clean if r["flagged"])
    fn = sum(1 for r in packed if not r["flagged"])
    print("\n=== SUMMARY ===")
    print("samples: %d | FP on clean: %d/%d (%.1f%%) | FN on packed: %d/%d"
          % (len(summary_rows), fp, len(clean),
             100.0 * fp / max(len(clean), 1), fn, len(packed)))
    print("AC5 threshold: FP < 5% | AC1 target sample is in the list")
    print("summary -> %s" % summary_path)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("apk", nargs="?", help="APK path for single mode")
    parser.add_argument("--out", help="write JSON report to PATH")
    parser.add_argument("--locklist", help="batch mode over locklist CSV")
    parser.add_argument("--workdir", default="analysis/triage_m0")
    parser.add_argument("--summary", help="summary CSV path (batch mode)")
    args = parser.parse_args(argv)
    if args.locklist:
        return run_locklist(args)
    if args.apk:
        return run_single(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
