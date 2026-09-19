#!/usr/bin/env python3
"""DroidForensix standalone unpacking tool.

Stage-2 DEX recovery for packed Android APKs through a fully static chain:

    M1   structural packer triage          -> scripts/triage.py
    M3   JNI emulation oracle              -> scripts/unpack.py + scripts/emulate.py
    M2   KDF/IV brute-force fallback on high-entropy assets (myg0N-style)
    M3b  PRNG installer-string replay      -> stage3_replay.py (myg0N-family, --stage3)

No device, no emulator, no KVM: Unicorn runs the packer's own native decoder,
so the sample effectively unpacks itself. Every run ends with a typed verdict
(either self-validated recovered artifacts, or an E-code naming the exact
failure and the next step).

Usage:
    python rto_analysis/unpacking_tool.py --input RTO.apk --output recovered/ --stage3

Exit codes:
    0   recovered (verdict RECOVERED), or no native packer present (clean/Java-only)
    1   typed E-code failure (see <output>/summary.json)
    2   usage error
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

# NO_PACKER note: E-JAVA-* mean "no native packer", not a tool failure.
NO_PACKER_ECODES = {"E-JAVA-NO-IOC", "E-JAVA-RUNTIME-DELIVERY"}

REPO_ROOT = Path(__file__).resolve().parents[1]
UNPACK_PY = REPO_ROOT / "scripts" / "unpack.py"
POOL_PATH = REPO_ROOT / "cjk_pool.txt"
SEEDS_JSON = Path(__file__).resolve().parent / "phase2" / "installer_deobfuscated_strings.json"

# myg0N-family marker; its presence inside a recovered kit gates the stage-3
# string replay, whose seed fixture only exists for this one packer family.
MYG0N_INSTALLER = "installer.dex"


def run_stage2(apk: Path, output: Path, timeout: int) -> dict:
    """Drive the existing scripts/unpack.py dispatcher and return its report.

    Captures both the report file and stdout so a mid-run crash still yields
    a typed E-code instead of a bare process failure.
    """
    report_path = output / "stage2_report.json"
    cmd = [sys.executable, str(UNPACK_PY), str(apk),
           "--workdir", str(output / "work"), "--out", str(report_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              cwd=str(REPO_ROOT))
    except subprocess.TimeoutExpired as exc:
        return {"verdict": "FAILED", "ecode": "E-ORACLE-FAULT",
                "info": f"stage-2 pipeline timed out after {timeout}s",
                "stderr_tail": str(exc)[:400]}
    if report_path.exists():
        try:
            return json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - malformed report file
            return {"verdict": "FAILED", "ecode": "E-ORACLE-FAULT",
                    "info": f"unreadable report file: {exc}"}
    m = re.search(r"\{.*\}", proc.stdout, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {"verdict": "FAILED", "ecode": "E-ORACLE-FAULT",
            "info": "stage-2 dispatcher produced no report",
            "stderr_tail": proc.stderr[-400:] if proc.stderr else ""}


def _unique_path(directory: Path, name: str) -> Path:
    dest = directory / name
    if not dest.exists():
        return dest
    stem, suffix = name.rsplit(".", 1) if "." in name else (name, "")
    for i in range(1, 100):
        candidate = directory / f"{stem}_{i}.{suffix}" if suffix else directory / f"{stem}_{i}"
        if not candidate.exists():
            return candidate
    raise OSError(f"cannot find free output name under {directory}")


def collect_outputs(report: dict, output: Path) -> list:
    """Copy each self-validated artifact into <output>/artifacts/ and write
    the recovered key material when the KDF stage produced it."""
    artifacts_dir = output / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    copies = []
    for entry in report.get("artifacts", []):
        src = Path(entry["file"])
        if not src.exists():
            continue
        dest = _unique_path(artifacts_dir, src.name)
        shutil.copy2(src, dest)
        copies.append({"file": str(dest), "basename": src.name,
                       "sha256": entry.get("sha256")})
    kdf = report.get("kdf")
    if kdf:
        keys = dict(kdf)
        keys.pop("pt", None)
        (artifacts_dir / "recovery_keys.json").write_text(
            json.dumps(keys, indent=2), encoding="utf-8")
    return copies


def is_myg0n_kit(kit_path: Path) -> bool:
    try:
        with zipfile.ZipFile(kit_path) as zf:
            return MYG0N_INSTALLER in zf.namelist()
    except Exception:
        return False


def run_stage3(out_dir: Path) -> dict:
    """Replay myg0N-family installer strings against the committed fixture
    and materialize them next to the recovered kit."""
    sys.path.insert(0, str(REPO_ROOT))
    import stage3_replay

    pool = stage3_replay.load_pool()
    data = json.loads(SEEDS_JSON.read_text(encoding="utf-8"))
    seeds = {int(k): v for k, v in data.items() if v is not None}
    strings = {}
    for seed, _ in sorted(seeds.items()):
        try:
            strings[str(seed)] = stage3_replay.decode_string(seed, pool)
        except IndexError:
            strings[str(seed)] = None
    (out_dir / "strings.json").write_text(
        json.dumps(strings, indent=2), encoding="utf-8")
    (out_dir / "strings.tsv").write_text(
        "seed\tvalue\n" + "\n".join(
            f"{seed}\t{value}" for seed, value in strings.items()),
        encoding="utf-8")
    matches, mismatches, _ = stage3_replay.run_replay(pool, seeds)
    return {"applicable": True, "pool_len": len(pool), "seeds": len(seeds),
            "matches": matches, "mismatches": mismatches,
            "strings_json": str(out_dir / "strings.json"),
            "strings_tsv": str(out_dir / "strings.tsv")}


def print_summary(report: dict, copies: list, stage3: dict | None, elapsed: float) -> None:
    print(f"verdict     : {report.get('verdict')}")
    if report.get("ecode"):
        print(f"ecode       : {report['ecode']}"
              + (f" -- {report['info']}" if report.get("info") else ""))
    route = report.get("route")
    print(f"route       : {route}  (native libs: {report.get('stats', {}).get('so_count')})")
    triage = report.get("triage") or {}
    if triage.get("verdict"):
        print(f"triage      : {triage['verdict']} @ conf {triage.get('confidence')}")
    for item in copies:
        print(f"artifact    : {item['file']}")
    kdf = report.get("kdf")
    if kdf:
        print(f"kdf         : seed={kdf.get('seed')} key={kdf.get('key')} iv={kdf.get('iv')}")
    iocs = report.get("iocs") or {}
    if iocs.get("firebase"):
        print(f"ioc firebase: {', '.join(iocs['firebase'])}")
    if iocs.get("api_keys"):
        print(f"ioc api_key : {', '.join(iocs['api_keys'])}")
    if stage3:
        print(f"stage3      : matches={stage3['matches']} mismatches={stage3['mismatches']} "
              f"over {stage3['seeds']} seeds")
    print(f"elapsed     : {elapsed:.1f}s")


def bundle_artifacts(output: Path, zip_stem: str) -> Path:
    """Zip only deliverable outputs (artifacts, reports, strings), not raw work/."""
    zip_path = output.parent / f"{zip_stem}.zip"
    members = [output / name for name in ("summary.json", "stage2_report.json",
                                          "strings.json", "strings.tsv")
               if (output / name).exists()]
    artifacts_dir = output / "artifacts"
    if artifacts_dir.exists():
        members += sorted(p for p in artifacts_dir.rglob("*") if p.is_file())
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for member in members:
            zf.write(member, member.relative_to(output.parent))
    return zip_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", required=True, type=Path, help="packed APK to unpack")
    parser.add_argument("--output", type=Path, default=Path("recovered"),
                        help="output directory (default: ./recovered)")
    parser.add_argument("--stage3", action="store_true",
                        help="replay myg0N-family PRNG installer strings after recovery")
    parser.add_argument("--bundle", nargs="?", const="ARTIFACTS", default=None,
                        metavar="STEM",
                        help="write STEM.zip of deliverable outputs next to --output")
    parser.add_argument("--timeout", type=int, default=480,
                        help="stage-2 pipeline timeout in seconds (default: 480)")
    args = parser.parse_args(argv)

    apk = args.input.resolve()
    output = args.output.resolve()
    if not apk.exists():
        parser.error(f"input APK not found: {apk}")
    try:
        with zipfile.ZipFile(apk):
            pass
    except Exception:
        parser.error(f"input is not a readable APK/zip: {apk}")

    output.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    report = run_stage2(apk, output, args.timeout)
    copies = collect_outputs(report, output)
    elapsed = time.monotonic() - t0

    stage3 = None
    if report.get("verdict") == "RECOVERED" and args.stage3:
        kit = next((Path(c["file"]) for c in copies if c.get("basename") == "kit.zip"), None)
        if kit and is_myg0n_kit(kit):
            stage3 = run_stage3(output)
        else:
            print("stage3       : skipped (recovered kit is not myg0N-family)", flush=True)

    summary = {
        "apk": str(apk),
        "sha256": report.get("sha256"),
        "verdict": report.get("verdict"),
        "ecode": report.get("ecode"),
        "info": report.get("info"),
        "route": report.get("route"),
        "triage": report.get("triage"),
        "family": report.get("family"),
        "stats": report.get("stats"),
        "artifacts": copies,
        "kdf": report.get("kdf"),
        "iocs": report.get("iocs"),
        "stage3": stage3,
        "elapsed_s": round(elapsed, 2),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print_summary(report, copies, stage3, elapsed)
    if args.bundle:
        print(f"bundle      : {bundle_artifacts(output, args.bundle)}", flush=True)

    if report.get("verdict") == "RECOVERED":
        return 0
    if report.get("ecode") in NO_PACKER_ECODES:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())