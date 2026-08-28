"""
build_ground_truth.py — Build unified ground truth for all 380 samples.

Sources:
  - ground_truth_drebin.json       → 149 samples (ready, family-labeled)
  - evaluation/ground_truth_modern.json → 63 samples (mostly ready)
  - evaluation/ground_truth_benign.json → 100+ benign (AndroZoo goodware)
  - evaluation/ground_truth.json   → 302 Drebin samples (family-labeled)
  - AndroZoo latest.csv.gz         → VT detection counts (no API calls)
  - MalwareBazaar API              → Family tags for abusech samples
  - VirusTotal API                 → Remaining unknowns (26 AndroZoo + gaps)

Output:
  ground_truth_all.csv — unified CSV with sha256,source,family,is_malware,confidence
"""

import csv
import gzip
import hashlib
import json
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pyzipper
import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = PROJECT_ROOT
MALWARE_DIR = ROOT / "samples" / "malware"
ANDROZOO_CSV_GZ = ROOT / "samples" / "androzoo_latest.csv.gz"
OUTPUT_CSV = ROOT / "ground_truth_all.csv"
SAMPLE_META = ROOT / "sample_metadata.csv"

GROUND_TRUTH_FILES = [
    ("drebin", ROOT / "ground_truth_drebin.json"),
    ("modern", ROOT / "evaluation" / "ground_truth_modern.json"),
    ("benign", ROOT / "evaluation" / "ground_truth_benign.json"),
    ("gt_json", ROOT / "evaluation" / "ground_truth.json"),
    ("pendrive", ROOT / "evaluation" / "ground_truth_pendrive.json"),
]

# ---------------------------------------------------------------------------
# API config
# ---------------------------------------------------------------------------
VT_KEY = os.environ.get("VT_KEY", "")
MB_API_KEY = (
    os.environ.get("MALWAREBAZAAR_API_KEY")
    or os.environ.get("ABUSECH_API_KEY")
    or ""
)
MB_API = "https://mb-api.abuse.ch/api/v1/"
VT_BASE = "https://www.virustotal.com/api/v3"

RATE_LIMIT_SEC = 16.0  # VT free tier: 4 lookups/min ≈ 15s between, add buffer
MB_RATE_LIMIT_SEC = 6.0


# ---------------------------------------------------------------------------
# 1. Load existing ground truth
# ---------------------------------------------------------------------------
def load_ground_truth_files() -> Dict[str, Dict[str, Any]]:
    """Merge all existing ground truth files into {sha256: record}."""
    gt: Dict[str, Dict[str, Any]] = {}

    for name, path in GROUND_TRUTH_FILES:
        if not path.exists():
            print(f"[SKIP] {name}: {path} not found")
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[ERROR] {name}: {e}")
            continue

        if isinstance(raw, list):
            for entry in raw:
                sha = (entry.get("sha256") or "").lower().strip()
                if not sha:
                    continue
                gt[sha] = {
                    "sha256": sha,
                    "family": entry.get("family") or "",
                    "is_malware": entry.get("ground_truth") == "malware",
                    "source": entry.get("source") or name,
                    "confidence": "high",
                    "gt_reason": f"existing:{name}",
                }
        elif isinstance(raw, dict):
            for sha, entry in raw.items():
                sha = sha.lower().strip()
                is_mal = entry.get("is_malware", entry.get("label") == "malware")
                family = entry.get("family") or ""
                gt[sha] = {
                    "sha256": sha,
                    "family": family,
                    "is_malware": is_mal,
                    "source": entry.get("source") or name,
                    "confidence": entry.get("confidence", "high"),
                    "gt_reason": f"existing:{name}",
                }

    print(f"[GT] Loaded {len(gt)} entries from existing ground truth files")
    return gt


# ---------------------------------------------------------------------------
# 2. Parse AndroZoo latest.csv.gz for VT detection counts
# ---------------------------------------------------------------------------
def parse_androzoo_csv() -> Dict[str, int]:
    """
    Stream AndroZoo latest.csv.gz and extract sha256 -> vt_detection.
    Format: sha256,md5,sha1,dex_date,apk_size,pkg_name,vercode,vt_detection,...
    """
    if not ANDROZOO_CSV_GZ.exists():
        print("[SKIP] AndroZoo CSV not found")
        return {}

    vt_map: Dict[str, int] = {}
    count = 0
    print(f"[ANDROZOO] Scanning {ANDROZOO_CSV_GZ} for VT detections...")
    with gzip.open(ANDROZOO_CSV_GZ, "rt", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 8:
                continue
            sha256 = row[0].strip().lower()
            if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
                continue  # skip header or malformed
            try:
                vt_det = int(row[7])
            except (ValueError, IndexError):
                vt_det = 0
            vt_map[sha256] = vt_det
            count += 1
            if count % 500000 == 0:
                print(f"  ... {count} hashes parsed")

    print(f"[ANDROZOO] Parsed {len(vt_map)} hashes with VT detection counts")
    return vt_map


# ---------------------------------------------------------------------------
# 3. Extract and hash the 21 ZIP banking trojans
# ---------------------------------------------------------------------------
def extract_random23_apks() -> Dict[str, Path]:
    """Extract APKs from the 23 encrypted ZIP files using 'infected' password."""
    zips = sorted(MALWARE_DIR.glob("*.zip"))
    extract_dir = MALWARE_DIR / "random23_extracted"
    extract_dir.mkdir(exist_ok=True)

    result: Dict[str, Path] = {}
    for zp in zips:
        try:
            safe_name = "".join(c if ord(c) < 128 else "?" for c in zp.name)
        except Exception:
            safe_name = "unknown.zip"
        print(f"  [ZIP] {safe_name}")

        # Collect APK names inside the ZIP
        apk_entries: List[Tuple[str, int]] = []  # (name, size)
        try:
            with pyzipper.AESZipFile(zp, "r") as zf:
                for info in zf.infolist():
                    if info.filename.endswith(".apk"):
                        apk_entries.append((info.filename, info.file_size))
        except Exception:
            try:
                with zipfile.ZipFile(zp, "r") as zf:
                    for info in zf.infolist():
                        if info.filename.endswith(".apk"):
                            apk_entries.append((info.filename, info.file_size))
            except Exception as e:
                print(f"  [SKIP] {safe_name}: can't read ZIP ({e})")
                continue

        if not apk_entries:
            print(f"  [SKIP] {safe_name}: no APK inside")
            continue

        for apk_name, _ in apk_entries:
            # Determine SHA256 from name if possible
            apk_stem = Path(apk_name).stem.lower()
            is_sha = len(apk_stem) == 64 and all(c in "0123456789abcdef" for c in apk_stem)

            # If we already have this hash from disk, skip extraction
            if is_sha and apk_stem in result:
                continue
            if is_sha and apk_stem in {a.stem.lower() for a in MALWARE_DIR.rglob("*.apk") if not a.parent.name.startswith("random23")}:
                print(f"    Already exists on disk as {apk_stem[:16]}...apk — skipping")
                if is_sha:
                    existing = next(MALWARE_DIR.rglob(f"{apk_stem}.apk"), None)
                    if existing:
                        result[apk_stem] = existing
                continue

            # Extract
            dest_path = extract_dir / f"{apk_stem}.apk"
            try:
                with pyzipper.AESZipFile(zp, "r") as zf:
                    zf.setpassword(b"infected")
                    data = zf.read(apk_name)
            except Exception:
                try:
                    with zipfile.ZipFile(zp, "r") as zf:
                        zf.setpassword(b"infected")
                        data = zf.read(apk_name)
                except Exception as e:
                    print(f"    [ERR] {apk_name}: {e}")
                    continue

            # Verify SHA256
            actual_sha = hashlib.sha256(data).hexdigest()
            if is_sha and actual_sha != apk_stem:
                print(f"    [WARN] Hash mismatch: expected {apk_stem}, got {actual_sha}")

            write_sha = actual_sha if not is_sha or actual_sha == apk_stem else apk_stem
            dest_path = extract_dir / f"{write_sha}.apk"
            dest_path.write_bytes(data)
            result[write_sha] = dest_path
            print(f"    -> {write_sha[:16]}...apk ({len(data)//1024} KB)")

    print(f"[RANDOM23] Extracted {len(result)} APKs from ZIPs")
    return result


# ---------------------------------------------------------------------------
# 4. Query MalwareBazaar API for hash info
# ---------------------------------------------------------------------------
def mb_query_hash(sha256: str) -> Optional[Dict[str, Any]]:
    """Get MalwareBazaar info for a hash. Returns tags, signature, etc."""
    if not MB_API_KEY:
        return None
    try:
        resp = requests.post(
            MB_API,
            data={"query": "get_info", "sha256_hash": sha256},
            headers={"Auth-Key": MB_API_KEY},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                return data["data"][0]
    except Exception as e:
        print(f"  [MB ERR] {sha256}: {e}")
    return None


def batch_malwarebazaar(hashes: List[str]) -> Dict[str, Dict[str, Any]]:
    """Query MalwareBazaar for a list of hashes. Returns {sha256: info}."""
    if not MB_API_KEY:
        print("[MB] No API key, skipping")
        return {}

    results: Dict[str, Dict[str, Any]] = {}
    total = len(hashes)
    for i, sha in enumerate(hashes):
        print(f"  [MB] {i+1}/{total}: {sha[:16]}...", end=" ")
        info = mb_query_hash(sha)
        if info:
            signature = info.get("signature", "") or ""
            tags = info.get("tags", [])
            results[sha] = {
                "family": signature,
                "tags": tags,
                "vt_detections": info.get("vt_score", 0),
            }
            print(f"sig={signature or 'none'}, tags={len(tags)}")
        else:
            print("not found")
        time.sleep(MB_RATE_LIMIT_SEC)

    print(f"[MB] Got data for {len(results)}/{total} hashes")
    return results


# ---------------------------------------------------------------------------
# 5. Query VirusTotal API for file hash
# ---------------------------------------------------------------------------
def vt_query_file(sha256: str) -> Optional[Dict[str, Any]]:
    """Query VirusTotal for a file hash. Returns analysis stats + names."""
    if not VT_KEY:
        return None
    max_retries = 3
    data = None
    for attempt in range(max_retries):
        try:
            resp = requests.get(
                f"{VT_BASE}/files/{sha256}",
                headers={"x-apikey": VT_KEY},
                timeout=30,
            )
            if resp.status_code == 404:
                return {"not_found": True}
            if resp.status_code == 401:
                print("unauthorized")
                return None
            if resp.status_code == 429:
                wait = 60 * (attempt + 1)
                print(f"rate_limited, retry in {wait}s", end=" ")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            data = resp.json()
            break
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                wait = 30 * (attempt + 1)
                print(f"err ({e}), retry in {wait}s", end=" ")
                time.sleep(wait)
            else:
                print(f"failed: {e}")
                return None

    if data is None:
        return None

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    # Extract family from threat labels
    results = attrs.get("last_analysis_results", {})
    family_votes: Dict[str, int] = {}
    for engine, res in results.items():
        label = (res.get("result") or "").strip()
        if label and label not in ("clean", "unrated"):
            parts = label.replace("Android.", "").replace(":", ".").split(".")
            for part in parts:
                if part and part not in ("Trojan", "Android", "Malware", "Riskware", "PUA", "Generic"):
                    family_votes[part] = family_votes.get(part, 0) + 1

    top_family = ""
    if family_votes:
        top_family = max(family_votes, key=family_votes.get)

    names = attrs.get("names", []) or attrs.get("submissions", {}).get("names", [])

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
        "family": top_family,
        "family_votes": family_votes,
        "names": names[:5],
        "meaningful_name": attrs.get("meaningful_name", ""),
    }


CACHE_PATH = ROOT / "evaluation" / "vt_cache.json"


def load_vt_cache() -> Dict[str, Dict[str, Any]]:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_vt_cache(cache: Dict[str, Dict[str, Any]]):
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def batch_virustotal(hashes: List[str]) -> Dict[str, Dict[str, Any]]:
    """Batch query VT for multiple hashes with cache. Returns {sha256: result}."""
    if not VT_KEY:
        print("[VT] No API key, skipping")
        return {}

    cache = load_vt_cache()
    results: Dict[str, Dict[str, Any]] = {}
    remaining = [h for h in hashes if h not in cache]
    print(f"[VT] Cached: {len(cache)}, Remaining: {len(remaining)}")

    for i, sha in enumerate(remaining):
        print(f"  [VT] {i+1}/{len(remaining)} ({sha[:16]}...)", end=" ", flush=True)
        info = vt_query_file(sha)
        if info:
            results[sha] = info
            cache[sha] = info
            mal = info.get("malicious", 0)
            fam = info.get("family", "") or ""
            print(f"mal={mal}, family={fam}")
        else:
            print("failed")
            results[sha] = {"not_found": True}
            cache[sha] = {"not_found": True}

        # Save cache every 10 queries
        if (i + 1) % 10 == 0:
            save_vt_cache(cache)
            print(f"         [cached {i+1}/{len(remaining)}]")

        time.sleep(RATE_LIMIT_SEC)

    # Final save
    save_vt_cache(cache)
    # Also include cached results that weren't re-queried
    for h in hashes:
        if h in cache and h not in results:
            results[h] = cache[h]

    print(f"[VT] Got data for {len(results)}/{len(hashes)} hashes")
    return results


# ---------------------------------------------------------------------------
# 6. Merge all sources into final CSV
# ---------------------------------------------------------------------------
def determine_family_and_label(
    sha256: str,
    source: str,
    existing_gt: Dict[str, Dict],
    mb_data: Dict[str, Dict],
    vt_data: Dict[str, Dict],
    androzoo_vt: Dict[str, int],
) -> Tuple[str, bool, str, str]:
    """
    Determine family, is_malware, confidence, gt_reason for a sample.
    Priority: existing GT > MalwareBazaar signature > VT consensus > AndroZoo VT count
    """

    # Priority 1: Existing ground truth
    if sha256 in existing_gt:
        e = existing_gt[sha256]
        return e["family"], e["is_malware"], e["confidence"], e["gt_reason"]

    # Priority 2: MalwareBazaar signature
    if sha256 in mb_data and mb_data[sha256].get("family"):
        fam = mb_data[sha256]["family"]
        return fam, True, "high", "malwarebazaar_signature"

    # Priority 3: VirusTotal consensus (10+ vendors)
    if sha256 in vt_data and vt_data[sha256].get("malicious", 0) >= 10:
        fam = vt_data[sha256].get("family", "") or "unknown"
        return fam, True, "high", f"vt_consensus_{vt_data[sha256]['malicious']}"

    # Priority 4: VirusTotal any detection
    if sha256 in vt_data and vt_data[sha256].get("malicious", 0) > 0:
        mal = vt_data[sha256]["malicious"]
        fam = vt_data[sha256].get("family", "") or "unknown"
        conf = "medium" if mal >= 3 else "low"
        return fam, True, conf, f"vt_detected_{mal}"

    # Priority 5: AndroZoo VT detection count > 0
    if sha256 in androzoo_vt and androzoo_vt[sha256] > 10:
        return "unknown", True, "high", f"androzoo_vt_{androzoo_vt[sha256]}"
    if sha256 in androzoo_vt and androzoo_vt[sha256] > 0:
        return "unknown", True, "medium", f"androzoo_vt_{androzoo_vt[sha256]}"

    # Priority 6: Known malware source with no VT = likely malware but unknown family
    if source in ("abusech", "MalwareBazaar", "androzoo_drebin", "modern_eval", "pendrive"):
        return "unknown", True, "low", f"source:{source}_no_vt_confirmation"

    # Priority 7: Known benign source
    if source == "F-Droid":
        return "", False, "high", "fdroid_known_benign"

    return "unknown", False, "low", "no_data"


def build_ground_truth():
    print("=" * 60)
    print("DroidForensix Ground Truth Builder")
    print("=" * 60)

    # Step 1: Load existing ground truth
    print("\n--- Step 1: Load existing ground truth ---")
    existing_gt = load_ground_truth_files()
    print(f"  Total: {len(existing_gt)} entries")

    # Step 2: Parse AndroZoo CSV
    print("\n--- Step 2: Parse AndroZoo CSV for VT detections ---")
    androzoo_vt = parse_androzoo_csv()
    print(f"  Total: {len(androzoo_vt)} hashes")

    # Step 3: Discover all samples on disk
    print("\n--- Step 3: Discover samples on disk ---")
    all_apks: Dict[str, Dict[str, Any]] = {}

    # 3a: abusech
    abusech_dir = MALWARE_DIR / "abusech"
    if abusech_dir.exists():
        for apk in abusech_dir.glob("*.apk"):
            sha = apk.stem.lower()
            if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha):
                all_apks[sha] = {"path": str(apk), "source": "abusech"}
            else:
                # Some have family_sha256 format
                parts = apk.stem.split("_", 1)
                if len(parts) == 2 and len(parts[1]) == 64:
                    sha = parts[1].lower()
                    all_apks[sha] = {"path": str(apk), "source": "abusech", "hint_family": parts[0]}
        print(f"  abusech: {len([a for a in all_apks.values() if a['source'] == 'abusech'])} APKs")

    # 3b: androzoo
    androzoo_dir = MALWARE_DIR / "androzoo"
    if androzoo_dir.exists():
        for apk in androzoo_dir.glob("*.apk"):
            sha = apk.stem.lower()
            if len(sha) == 64:
                all_apks[sha] = {"path": str(apk), "source": "AndroZoo"}
        print(f"  androzoo: {len([a for a in all_apks.values() if a['source'] == 'AndroZoo'])} APKs")

    # 3c: androzoo_drebin
    drebin_dir = MALWARE_DIR / "androzoo_drebin"
    if drebin_dir.exists():
        for apk in drebin_dir.glob("*.apk"):
            parts = apk.stem.split("_", 1)
            sha = ""
            hint = ""
            if len(parts) == 2 and len(parts[1]) == 64:
                sha = parts[1].lower()
                hint = parts[0]
            elif len(apk.stem) == 64:
                sha = apk.stem.lower()
            if sha:
                all_apks[sha] = {"path": str(apk), "source": "androzoo_drebin", "hint_family": hint}
        print(f"  androzoo_drebin: {len([a for a in all_apks.values() if a['source'] == 'androzoo_drebin'])} APKs")

    # 3d: modern_eval
    modern_dir = MALWARE_DIR / "modern_eval"
    if modern_dir.exists():
        for apk in modern_dir.glob("*.apk"):
            sha = apk.stem.lower()
            if len(sha) == 64:
                all_apks[sha] = {"path": str(apk), "source": "modern_eval"}
        print(f"  modern_eval: {len([a for a in all_apks.values() if a['source'] == 'modern_eval'])} APKs")

    # 3e: Extract random 23 ZIPs
    print("\n  --- Extracting Random 23 ZIPs ---")
    extracted = extract_random23_apks()
    new_count = 0
    for sha, path in extracted.items():
        if sha not in all_apks:
            all_apks[sha] = {"path": str(path), "source": "random23_zip"}
            new_count += 1
    print(f"  random23: {new_count} new samples")

    print(f"\n  Total unique APKs discovered: {len(all_apks)}")

    # Step 4: Separate hashes that need API lookups
    print("\n--- Step 4: Identify coverage gaps ---")
    hashes_needing_mb = []
    hashes_needing_vt = []
    hashes_covered = 0

    for sha, info in all_apks.items():
        if sha in existing_gt:
            hashes_covered += 1
        else:
            # Try MB first, fall through to VT regardless
            if info["source"] in ("abusech", "MalwareBazaar"):
                hashes_needing_mb.append(sha)
            hashes_needing_vt.append(sha)

    print(f"  Covered by existing GT: {hashes_covered}")
    print(f"  Need MalwareBazaar query: {len(hashes_needing_mb)}")
    print(f"  Need VirusTotal query: {len(hashes_needing_vt)}")

    # Step 5: Query MalwareBazaar
    if hashes_needing_mb:
        print("\n--- Step 5: Query MalwareBazaar ---")
        mb_data = batch_malwarebazaar(hashes_needing_mb[:20])  # rate-limit: only do 20 first
        # If you have time, increase this limit or run again
        print(f"  Consider re-running with more hashes if needed")
    else:
        mb_data = {}

    # Step 6: Query VirusTotal
    if hashes_needing_vt:
        print(f"\n--- Step 6: Query VirusTotal ({len(hashes_needing_vt)} hashes) ---")
        vt_data = batch_virustotal(hashes_needing_vt)
    else:
        vt_data = {}

    # Step 7: Merge all into final CSV
    print("\n--- Step 7: Generate ground_truth_all.csv ---")
    rows = []
    for sha, info in sorted(all_apks.items()):
        source = info.get("source", "unknown")
        family, is_malware, confidence, gt_reason = determine_family_and_label(
            sha, source, existing_gt, mb_data, vt_data, androzoo_vt,
        )

        # Override with filename hint if available and no better data
        if not family and info.get("hint_family"):
            family = info["hint_family"]

        vt_det = androzoo_vt.get(sha, 0)
        # Also check VT results
        if sha in vt_data:
            vt_det = max(vt_det, vt_data[sha].get("malicious", 0))

        rows.append({
            "sha256": sha,
            "source": source,
            "family": family or "unknown",
            "is_malware": "yes" if is_malware else "no",
            "confidence": confidence,
            "vt_detections": vt_det,
            "gt_reason": gt_reason,
            "apk_path": info.get("path", ""),
        })

    # Write CSV
    fieldnames = ["sha256", "source", "family", "is_malware", "confidence", "vt_detections", "gt_reason", "apk_path"]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Summary
    labeled = sum(1 for r in rows if r["confidence"] in ("high", "medium"))
    malware = sum(1 for r in rows if r["is_malware"] == "yes")
    benign = sum(1 for r in rows if r["is_malware"] == "no")
    with_family = sum(1 for r in rows if r["family"] != "unknown")

    print(f"\n{'='*60}")
    print(f"GROUND TRUTH COMPLETE")
    print(f"{'='*60}")
    print(f"  Total samples:     {len(rows)}")
    print(f"  Labeled (high/med): {labeled}")
    print(f"  Malware:           {malware}")
    print(f"  Benign:            {benign}")
    print(f"  With family name:  {with_family}")
    print(f"  Output:            {OUTPUT_CSV}")
    print()
    print("Confidence breakdown:")
    for level in ["high", "medium", "low"]:
        count = sum(1 for r in rows if r["confidence"] == level)
        print(f"  {level}: {count}")
    print()
    print("Source breakdown:")
    for src in sorted(set(r["source"] for r in rows)):
        count = sum(1 for r in rows if r["source"] == src)
        mal = sum(1 for r in rows if r["source"] == src and r["is_malware"] == "yes")
        print(f"  {src}: {count} ({mal} malware)")

    return rows


if __name__ == "__main__":
    build_ground_truth()