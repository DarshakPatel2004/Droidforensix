"""
Download Drebin malware samples from AndroZoo using sha256_family.csv.

Usage (Windows):
    .\venv\Scripts\Activate.ps1
    python scripts/download_drebin_androzoo.py <hash_csv> [count]

Example:
    python scripts/download_drebin_androzoo.py data/drebin_sha256_family.csv 50
"""

import csv
import hashlib
import os
import sys
import time
from pathlib import Path

import requests

ANDROZOO_API = "https://androzoo.uni.lu/api/download"
SAMPLES_DIR = Path(__file__).parent.parent / "samples"
META_PATH = Path(__file__).parent.parent / "sample_metadata.csv"
REQUEST_TIMEOUT = 120
RATE_LIMIT = 1  # seconds between downloads


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize_filename(name: str) -> str:
    """Make a string safe to use in a filename."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return safe.strip("._") or "unknown"


def load_metadata():
    if not META_PATH.exists():
        return []
    with open(META_PATH, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_metadata(records):
    fieldnames = [
        "sample_name", "sha256", "md5", "family", "source",
        "type", "tags", "file_size_bytes", "status", "vt_detections",
        "collection_date",
    ]
    with open(META_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({k: r.get(k, "") for k in fieldnames})


def download_apk(sha256_hash: str, dest: Path) -> bool:
    api_key = os.environ.get("ANDROZOO_API_KEY")
    if not api_key:
        raise RuntimeError("ANDROZOO_API_KEY not set")
    try:
        params = {"apikey": api_key, "sha256": sha256_hash}
        with requests.get(ANDROZOO_API, params=params, timeout=REQUEST_TIMEOUT, stream=True) as resp:
            if resp.status_code == 404:
                print(f"  [!] {sha256_hash} not found on AndroZoo")
                return False
            resp.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        return True
    except Exception as e:
        print(f"  [!] Download error for {sha256_hash}: {e}")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python download_drebin_androzoo.py <hash_csv> [count]")
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 50

    if not csv_path.exists():
        print(f"[!] CSV not found: {csv_path}")
        sys.exit(1)

    api_key = os.environ.get("ANDROZOO_API_KEY")
    if not api_key:
        print("[!] ANDROZOO_API_KEY environment variable not set")
        sys.exit(1)

    # Parse CSV
    hashes = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sha = row.get("sha256", "").strip().lower()
            family = row.get("family", "unknown").strip()
            if sha:
                hashes.append((sha, family))

    print(f"[*] Loaded {len(hashes)} hashes from {csv_path}")
    print(f"[*] Will download up to {count} samples")

    records = load_metadata()
    existing = {r["sha256"].lower() for r in records}

    malware_dir = SAMPLES_DIR / "malware" / "androzoo_drebin"
    malware_dir.mkdir(parents=True, exist_ok=True)

    fetched = 0
    failed = 0
    skipped = 0

    for sha256_hash, family in hashes:
        if fetched >= count:
            break
        if sha256_hash in existing:
            skipped += 1
            continue

        safe_family = sanitize_filename(family)
        dest = malware_dir / f"{safe_family}_{sha256_hash}.apk"
        print(f"[*] Downloading {fetched+1}/{count}: {sha256_hash} ({family})")

        if download_apk(sha256_hash, dest):
            actual_sha = sha256_file(str(dest))
            if actual_sha != sha256_hash:
                print(f"  [!] Hash mismatch, deleting")
                dest.unlink(missing_ok=True)
                failed += 1
                continue

            records.append({
                "sample_name": dest.name,
                "sha256": actual_sha,
                "md5": "",
                "family": family,
                "source": "AndroZoo-Drebin",
                "type": "malware",
                "tags": f"family={family}",
                "file_size_bytes": dest.stat().st_size,
                "status": "pending",
                "vt_detections": "",
                "collection_date": time.strftime("%Y-%m-%d"),
            })
            save_metadata(records)
            fetched += 1
            print(f"  [+] Saved {dest.name} ({dest.stat().st_size} bytes)")
        else:
            failed += 1

        time.sleep(RATE_LIMIT)

    print(f"\n[+] Done. Fetched: {fetched}, Failed: {failed}, Skipped: {skipped}")
    print(f"[+] Total malware samples in metadata: {len([r for r in records if r.get('type') == 'malware'])}")


if __name__ == "__main__":
    main()
