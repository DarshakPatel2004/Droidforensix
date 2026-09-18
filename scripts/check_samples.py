"""
Validate the DroidForensix sample collection.

Checks:
- Metadata record count and type/source distribution
- Every metadata record has a corresponding APK file
- APK files on disk are all referenced in metadata
- SHA-256 hashes match
- No empty files
- Every file is a valid ZIP/APK

Usage (Windows):
    .\venv\Scripts\Activate.ps1
    python scripts/check_samples.py
"""

import csv
import hashlib
import zipfile
from collections import Counter
from pathlib import Path


def main():
    meta_path = Path("sample_metadata.csv")
    samples_dir = Path("samples")

    if not meta_path.exists():
        print(f"[!] Metadata file not found: {meta_path}")
        return 1

    with open(meta_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    apk_files = list(samples_dir.rglob("*.apk"))
    meta_names = {r["sample_name"] for r in rows}

    missing = []
    hash_mismatch = []
    empty = []
    bad_apk = []

    for r in rows:
        candidates = list(samples_dir.rglob(r["sample_name"]))
        if not candidates:
            missing.append(r)
            continue
        p = candidates[0]
        size = p.stat().st_size
        if size == 0:
            empty.append((r, p))
            continue
        actual_sha = hashlib.sha256(p.read_bytes()).hexdigest()
        if actual_sha.lower() != r["sha256"].lower():
            hash_mismatch.append((r, p, actual_sha))
        try:
            with zipfile.ZipFile(p, "r") as z:
                _ = z.namelist()[:1]
        except Exception as e:
            bad_apk.append((r, p, e))

    orphans = [p for p in apk_files if p.name not in meta_names]

    print("=" * 60)
    print("DroidForensix Sample Health Check")
    print("=" * 60)
    print(f"Metadata records: {len(rows)}")
    print(f"  Malware:      {sum(1 for r in rows if r['type'] == 'malware')}")
    print(f"  Legitimate:   {sum(1 for r in rows if r['type'] == 'legitimate')}")
    print(f"  Pending:      {sum(1 for r in rows if r['status'] == 'pending')}")
    print(f"  Analyzed:     {sum(1 for r in rows if r['status'] == 'analyzed')}")
    print(f"APK files on disk: {len(apk_files)}")
    print("-" * 60)
    print(f"Missing files:     {len(missing)}")
    print(f"Hash mismatches:   {len(hash_mismatch)}")
    print(f"Empty files:       {len(empty)}")
    print(f"Invalid ZIP/APK:   {len(bad_apk)}")
    print(f"Orphan APK files:  {len(orphans)}")
    print("-" * 60)

    if missing:
        print("\nMissing records:")
        for r in missing[:10]:
            print(f"  {r['sample_name']} ({r['source']})")
    if hash_mismatch:
        print("\nHash mismatches:")
        for r, p, actual in hash_mismatch[:10]:
            print(f"  {p.name}")
            print(f"    metadata: {r['sha256']}")
            print(f"    actual:   {actual}")
    if empty:
        print("\nEmpty files:")
        for r, p in empty[:10]:
            print(f"  {p}")
    if bad_apk:
        print("\nInvalid APKs:")
        for r, p, e in bad_apk[:10]:
            print(f"  {p}: {e}")
    if orphans:
        print("\nOrphan files:")
        for p in orphans[:10]:
            print(f"  {p} ({p.stat().st_size} bytes)")

    print("\nBy source:")
    for src, n in Counter(r["source"] for r in rows).most_common():
        print(f"  {src}: {n}")

    print("\nTop families:")
    for fam, n in Counter(r["family"] for r in rows).most_common(10):
        print(f"  {fam}: {n}")

    total_issues = len(missing) + len(hash_mismatch) + len(empty) + len(bad_apk) + len(orphans)
    print("=" * 60)
    if total_issues == 0:
        print("✅ Sample collection is clean.")
        return 0
    else:
        print(f"⚠️ Found {total_issues} issue(s).")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
