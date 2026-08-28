"""MAFIA v2.1 Phase 0-3 runner for pendrive heavyweight APKs.

Pure static analysis per docs/MAFIA_v2.1.md:
  Phase 0: identity hashes
  Phase 1: ZIP container forensics + manifest scoring + signing cert
  Phase 2: native lib triage (entropy, JNI) + encrypted asset scan
  Phase 3: nested-payload extraction (dropper APKs in assets/)

Produces reports/mafia_handoffs/<name>.json + a consolidated handoff MD.
"""

import hashlib
import json
import math
import re
import struct
import subprocess
import zipfile
from collections import Counter
from pathlib import Path

PROJECT = Path("/home/kali/DroidForensix")
ROOT = PROJECT / "PENDRIVE DATA" / "PENDRIVE DATA"
INVENTORY = PROJECT / "reports" / "pendrive_inventory.csv"
OUTDIR = PROJECT / "reports" / "mafia_handoffs"

TIMEOUTS = [
    "Customer Support..apk", "Tubi-0415.apk", "dream11_1.apk",
    "kinemaster-mod-apk-7.5.14.34120.gp-kinemaster.gold_.apk", "157500.apk",
    "Vedu1.0.14.apk", "blinkit-app-driver-release-11.8.2.apk",
    "youtube-revanced-v20.13.41-all.apk", "AmazonFlexAndroidApp.apk",
]

MANIFEST_SCORES = {
    "REQUEST_INSTALL_PACKAGES": 10, "QUERY_ALL_PACKAGES": 5,
    "READ_SMS": 15, "RECEIVE_SMS": 0,   # pair scored once below
    "RECEIVE_BOOT_COMPLETED": 10, "WAKE_LOCK": 5,
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def phase_0_identity(apk: Path) -> dict:
    return {
        "filename": apk.name,
        "size_mb": round(apk.stat().st_size / 1e6, 1),
        "sha256": sha256_of(apk),
    }


def phase_1_container(apk: Path) -> dict:
    data = apk.read_bytes()
    eocd = data.rfind(b"\x50\x4b\x05\x06")
    if eocd == -1:
        raise ValueError("not a ZIP")
    cd_count = struct.unpack("<H", data[eocd + 10:eocd + 12])[0]
    entries, off = [], data.find(b"\x50\x4b\x01\x02")
    forged = []
    while len(entries) < cd_count and data[off:off + 4] == b"\x50\x4b\x01\x02":
        flags = struct.unpack("<H", data[off + 8:off + 10])[0]
        name_len = struct.unpack("<H", data[off + 28:off + 30])[0]
        extra_len = struct.unpack("<H", data[off + 30:off + 32])[0]
        comment_len = struct.unpack("<H", data[off + 32:off + 34])[0]
        name = data[off + 46:off + 46 + name_len].decode("utf-8", "replace")
        if flags & 0x01:
            forged.append(name)
        entries.append(name)
        off += 46 + name_len + extra_len + comment_len

    big_assets, dex_size = [], None
    try:
        with zipfile.ZipFile(apk) as zf:
            names = set(zf.namelist())
            for cand in ("classes.dex", "classes2.dex", "classes3.dex"):
                if cand in names:
                    dex_size = max(dex_size or 0,
                                   zf.getinfo(cand).file_size)
            for info in zf.infolist():
                if info.file_size > 10_000_000:
                    big_assets.append({"name": info.filename,
                                       "mb": round(info.file_size / 1e6, 1)})
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"zip read failed: {e}") from e

    return {
        "entry_count": len(entries),
        "dropper_pattern": len(entries) <= 10,
        "forged_encryption_flags": forged,
        "classes_dex_bytes": dex_size,
        "assets_over_10mb": big_assets,
    }


def phase_1_manifest(apk: Path) -> dict:
    r = subprocess.run(["aapt", "dump", "badging", str(apk)],
                       capture_output=True, text=True, timeout=120)
    # aapt may partially succeed then die on manipulated resources
    # (resource-confusion anti-tool trick) - keep parsing whatever it emitted.
    malformed = r.returncode != 0 or "error:" in r.stderr.lower() \
        or re.search(r"error getting", r.stdout, re.I)
    out = r.stdout
    m = re.search(r"package: name='([^']+)'", out)
    if not m:
        raise RuntimeError(f"aapt produced no package line; "
                           f"stderr={r.stderr[:150]}")
    package, version = m.group(1), ""
    perms, label = [], ""
    for line in out.splitlines():
        if line.startswith("uses-permission:") and "'android.permission." in line:
            perms.append(line.split("'")[1].replace("android.permission.", ""))
        elif line.startswith("application-label:") and not label:
            label = line.split(":", 1)[1].strip("'")
    vm = re.search(r"versionName='([^']+)'", out)
    version = vm.group(1) if vm else ""

    pset = set(perms)
    score = sum(v for k, v in MANIFEST_SCORES.items() if k in pset and v)
    if {"READ_SMS", "RECEIVE_SMS"} <= pset or {"SEND_SMS", "RECEIVE_SMS"} <= pset:
        score += 15
    risky = sorted(pset & set(MANIFEST_SCORES))
    hidden = "android.intent.category.INFO" in r.stdout and \
             "android.intent.category.LAUNCHER" not in r.stdout
    if hidden:
        score += 5

    return {
        "package": package, "label": label, "version": version,
        "perm_count": len(perms), "scored_perms": risky,
        "hidden_no_launcher": hidden,
        "manifest_malformed": bool(malformed),
        "manifest_risk_score": score + (10 if malformed else 0),
    }


def phase_1_cert(apk: Path) -> dict:
    r = subprocess.run(["keytool", "-printcert", "-jarfile", str(apk)],
                       capture_output=True, text=True, timeout=60)
    out = r.stdout
    owner = next((l.split(":", 1)[1].strip() for l in out.splitlines()
                  if l.startswith("Owner:")), "")
    testkey = bool(re.search(r"(testkey|AOSP|Android Debug)", owner, re.I))
    self_signed = "Issuer:" in out and owner and \
                  owner.split(",")[0] in next(
                      (l for l in out.splitlines() if l.startswith("Issuer:")), "")
    return {"cert_owner": owner[:100], "aosp_testkey": testkey,
            "self_signed": self_signed}


def _entropy(data: bytes) -> float:
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def phase_2_native_and_assets(apk: Path) -> dict:
    native, encrypted_assets = [], []
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.endswith(".so") and info.file_size > 50_000:
                with zf.open(info) as f:
                    blob = f.read(1 << 21)
                elf_ok = blob[:4] == b"\x7fELF"
                jni = sorted(set(re.findall(rb"Java_[A-Za-z0-9_]{4,80}",
                                            blob))) [:5]
                native.append({
                    "lib": name, "arch": name.split("/")[-2]
                    if "/" in name else "?",
                    "elf": elf_ok, "entropy": round(_entropy(blob), 2),
                    "jni_exports": [j.decode() for j in jni],
                })
            elif info.file_size > 500_000:
                with zf.open(info) as f:
                    head = f.read(1 << 20)
                ent = _entropy(head)
                magic = head[:4].hex()
                known = ("50534b04", "7f454c46", "4d5a9000", "03544e41")
                if ent > 7.5 and magic not in known:
                    encrypted_assets.append({
                        "asset": name, "mb": round(info.file_size / 1e6, 1),
                        "entropy": round(ent, 2), "magic": magic})
    return {"native_libs": native, "high_entropy_assets": encrypted_assets}


def phase_3_nested_payloads(apk: Path) -> dict:
    nested = []
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            if re.fullmatch(r"assets/[\w./-]*\.apk", info.filename):
                with zf.open(info) as f:
                    head = f.read(8)
                nested.append({"payload": info.filename,
                               "mb": round(info.file_size / 1e6, 2),
                               "zip_magic_valid": head[:2] == b"PK"})
    return {"nested_apks": nested}


def run_sample(apk: Path) -> dict:
    handoff = {"mafia_version": "2.1", "phases_completed": "0-3"}
    handoff["phase_0"] = phase_0_identity(apk)
    try:
        handoff["phase_1_container"] = phase_1_container(apk)
        handoff["phase_1_manifest"] = phase_1_manifest(apk)
        handoff["phase_1_cert"] = phase_1_cert(apk)
        handoff["phase_2"] = phase_2_native_and_assets(apk)
        handoff["phase_3"] = phase_3_nested_payloads(apk)
    except Exception as e:
        handoff["error"] = f"{type(e).__name__}: {e}"
    # composite triage verdict from doc criteria
    score = handoff.get("phase_1_manifest", {}).get("manifest_risk_score", 0)
    flags = []
    c = handoff.get("phase_1_container", {})
    if c.get("forged_encryption_flags"):
        flags.append("ZIP encryption-bit forgery")
        score += 10
    if c.get("dropper_pattern"):
        flags.append("dropper entry-count pattern")
    if handoff.get("phase_3", {}).get("nested_apks"):
        flags.append("nested APK payloads")
        score += 15
    if any(a["entropy"] > 7.5 for a in handoff.get("phase_2", {}).get("high_entropy_assets", [])):
        flags.append("encrypted asset(s)")
        score += 10
    if handoff.get("phase_1_cert", {}).get("aosp_testkey"):
        flags.append("AOSP test key")
        score += 10
    handoff["triage"] = {
        "composite_score": score,
        "verdict": "MALWARE-SUSPECT" if score >= 50 else
                   "SUSPICIOUS" if score >= 25 else "LOW-SIGNAL",
        "flags": flags,
    }
    return handoff


def main():
    OUTDIR.mkdir(exist_ok=True, parents=True)
    seen, results = set(), []
    for row in __import__("csv").DictReader(open(INVENTORY)):
        if row["filename"] not in TIMEOUTS or row["sha256"] in seen:
            continue
        seen.add(row["sha256"])
        apk = ROOT / row["rel_path"]
        print(f"[MAFIA] {apk.name}", flush=True)
        h = run_sample(apk)
        out = OUTDIR / f"{apk.stem[:60]}.handoff.json"
        json.dump(h, open(out, "w"), indent=1)
        t = h["triage"]
        print(f"    -> {t['verdict']} ({t['composite_score']}) {t['flags']}",
              flush=True)
        results.append(h)
    json.dump(results, open(PROJECT / "reports" / "mafia_phase03_results.json", "w"),
              indent=1)
    print(f"\n{len(results)} handoffs -> {OUTDIR}")


if __name__ == "__main__":
    main()
