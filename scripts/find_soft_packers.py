#!/usr/bin/env python3
"""Find soft-packed APKs in a corpus.

Soft = packer/injected libs whose code is decodable at rest (is_hardened_vm
coverage >= 0.1), i.e. an oracle run has a real chance of recovering DEX.
Hard = code-protected bytecode-VM libs (JNI_OnLoad is ciphertext; the
E-HARDENED-VM branch, see analysis/emulate/calc_ijiami/PHASE1_GATE.md).

Note on "entropy < 5.0": file entropy does NOT separate soft from hard.
Measured on Calculator.apk: benign analysable libs read 5.7-6.6, hardened VM
libs read 6.2-7.4 (ciphertext is high-entropy), and the low-entropy files
(3.9-4.9) are tiny bridge/stub libs with no payload. So entropy is reported
as a diagnostic only; the soft/hard split uses decoded-byte coverage.

Usage: python scripts/find_soft_packers.py <corpus_dir> [--out soft_packers_found.json]
"""
import argparse
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import emulate
from unpack import sniff_family, FAM_MARKS  # noqa: E402

FAMILIES = ("Ijiami", "TencentLegu", "Bangcle/SecNeo", "360Jiagu",
            "SecShell/Baidu", "Wangxin", "Ijiami(variant)")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _classify_lib(blob: bytes, abi: str, name: str) -> dict:
    """Classify one extracted ELF by decoded-byte coverage at JNI_OnLoad.

    State: "calc" (symbol present, decodes -> soft or hardened), "nosym"
    (no JNI_OnLoad/Java_* export: RegisterNatives-only, unmeasurable) or
    "error" (not a parseable ELF).
    """
    binary = None
    try:
        binary = emulate.lief.parse(blob)
    except Exception as exc:
        return {"name": name, "abi": abi, "state": "error", "error": str(exc)[:80]}
    try:
        hardened, ev = emulate.is_hardened_vm(binary)
    except Exception as exc:
        return {"name": name, "abi": abi, "state": "error", "error": str(exc)[:80]}
    if ev:  # JNI_OnLoad present -> hardened = code-protected (density<0.1)
        return {"name": name, "abi": abi, "state": "calc",
                "hardened": bool(hardened),
                "decode_density": float(ev.get("decode_density") or 0.0),
                "file_entropy": round(_entropy(blob), 3),
                "size": len(blob)}
    exports = [getattr(s, "name", "") for s in (binary.exported_functions or [])]
    if any(n.startswith("Java_") for n in exports):
        return {"name": name, "abi": abi, "state": "calc",
                "hardened": False,
                "decode_density": float("nan"),
                "file_entropy": round(_entropy(blob), 3),
                "size": len(blob)}
    return {"name": name, "abi": abi, "state": "nosym",
            "file_entropy": round(_entropy(blob), 3),
            "size": len(blob)}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    ent = 0.0
    for count in counts:
        if count:
            p = count / len(data)
            ent -= p * math.log2(p)
    return ent


def find_soft_packers(corpus_path: pathlib.Path, families=FAMILIES) -> dict:
    samples = []
    for apk_path in sorted(corpus_path.glob("**/*.apk")):
        raw = apk_path.read_bytes()
        sha = sha256_bytes(raw)
        try:
            import zipfile
            with zipfile.ZipFile(apk_path) as zf:
                names = zf.namelist()
                fam = sniff_family(names)
                if fam in families:
                    marks = FAM_MARKS.get(fam, ())
                    abi = {"arm64-v8a": "arm64", "armeabi-v7a": "arm32",
                           "armeabi": "arm32", "x86_64": "x86_64",
                           "x86": "x86"}
                    so_entries = {}
                    for n in names:
                        if not n.endswith(".so"):
                            continue
                        parts = pathlib.Path(n).parts
                        a = next((v for k, v in abi.items() if k in parts), "unknown")
                        base = pathlib.Path(n).name
                        if base not in so_entries:      # one ELF per basename best ABI
                            so_entries[base] = (a, n)
                    libs = []
                    for base, (a, n) in so_entries.items():
                        blob = zf.read(n)
                        lib = _classify_lib(blob, a, base)
                        # verdict uses the packer libs only (FAM_MARKS path
                        # tokens); cover-app libs (ijkplayer, BN, ...) always
                        # decode and would fake a SOFT signal otherwise
                        lib["packer"] = any(m in base for m in marks)
                        libs.append(lib)
                    packer = [l for l in libs if l["packer"]]
                    calc = [l for l in packer if l.get("state") == "calc"]
                    hard = [l for l in calc if l.get("hardened")]
                    soft = [l for l in calc if not l.get("hardened")]
                    samples.append({
                        "path": str(apk_path), "sha256": sha, "family": fam,
                        "verdict": "SOFT" if soft and not hard else
                                   ("HARD" if hard and not soft else
                                    ("MIXED" if soft and hard else "NONE")),
                        "libs": libs,
                    })
        except Exception as exc:
            samples.append({"path": str(apk_path), "sha256": sha,
                            "family": None, "error": str(exc)[:100]})
            continue
    grouped = {}
    for s in samples:
        for f in families:
            if s.get("family") == f:
                grouped.setdefault(f, []).append(s)
    return {"families": grouped, "total": len(samples)}


def top_soft(results: dict, n=5) -> dict:
    """Top soft APKs per family by decodable packer payload bytes."""
    picked = {}
    for fam, samples in results["families"].items():
        soft = [s for s in samples if s.get("verdict") == "SOFT"]
        soft.sort(key=lambda s: sum(l.get("size", 0) for l in s.get("libs", [])
                                    if l.get("packer") and l.get("hardened") is False),
                  reverse=True)
        picked[fam] = soft[:n]
    return picked


def run_oracle(top: dict, out_dir: pathlib.Path, per_family=3):
    """Invoke scripts/unpack.py (the DEX-recovery oracle) on top-soft APKs.

    Returns list of (apk, report) for hits whose verdict == RECOVERED.
    """
    import json as _json
    import subprocess
    out_dir.mkdir(parents=True, exist_ok=True)
    scripts = pathlib.Path(__file__).resolve().parent
    seen = set()
    roster = []
    for fam in top:
        for s in top[fam][:per_family]:
            if s["sha256"] in seen:
                continue
            seen.add(s["sha256"])
            roster.append(s)
    reports = []
    for s in roster:
        safe = pathlib.Path(s["path"]).name.replace("/", "_")[:60]
        work = out_dir / s["family"].replace("/", "_")
        work.mkdir(parents=True, exist_ok=True)
        rp = work / (safe + ".json")
        try:
            subprocess.run(
                [sys.executable, "-W", "ignore", "-X", "utf8",
                 str(scripts / "unpack.py"), s["path"],
                 "--workdir", str(work), "--out", str(rp)],
                timeout=600, cwd=str(scripts.parent))
            report = _json.loads(rp.read_text()) if rp.exists() else {}
        except Exception as exc:
            report = {"apk": s["path"], "oracle_error": str(exc)[:120]}
        report["family"] = s["family"]
        reports.append(report)
        print(f"  [{report.get('ecode', '?')}] {s['family']:<16} "
              f"{pathlib.Path(s['path']).name[:44]}")
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", default="data/corpus", nargs="?")
    parser.add_argument("--out", default="soft_packers_found.json")
    parser.add_argument("--run-oracle", dest="run_oracle", action="store_true",
                        help="run unpack.py oracle on top-3 soft APKs per family")
    args = parser.parse_args()
    root = pathlib.Path(args.corpus)
    if not root.exists():
        sys.exit(f"corpus dir not found: {root}")
    results = find_soft_packers(root)
    for fam, samples in results["families"].items():
        n_soft = len([s for s in samples if s.get("verdict") == "SOFT"])
        print(f"{fam}: {n_soft}/{len(samples)} soft")
        for s in top_soft(results)[fam]:
            pk = [l for l in s["libs"] if l.get("packer")]
            libs = ", ".join(f"{l['name']}({l.get('abi')}) "
                             f"[{l.get('state')}] d={l.get('decode_density', 0.0):.2f}"
                             if l.get("state") == "calc"
                             else f"{l['name']}({l.get('abi')}) [{l.get('state')}]"
                             for l in pk[:4])
            print("   ", pathlib.Path(s["path"]).name, "->", libs)
    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nwrote {args.out} ({results['total']} APKs)")

    top = top_soft(results)
    json.dump({"top_soft": top}, open(
        str(pathlib.Path(args.out).with_name(
            pathlib.Path(args.out).stem + "_top.json")), "w"), indent=2)

    if args.run_oracle:
        print("\n-- oracle on top-3 soft per family --")
        reports = run_oracle(top, pathlib.Path(args.out).resolve().parent / "oracle_out")
        ok = [r for r in reports if r.get("verdict") == "RECOVERED"]
        print(f"\nRECOVERED: {len(ok)}/{len(reports)}")
        for r in ok:
            print("  *", r.get("apk"), "->", [a.get("file") for a in r.get("artifacts", [])])


if __name__ == "__main__":
    main()