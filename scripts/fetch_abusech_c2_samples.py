"""
Fetch Android malware samples from abuse.ch (MalwareBazaar + ThreatFox) that have
known C2 indicators (IPs or domains).

Requires an abuse.ch API key in one of these environment variables:
    ABUSECH_API_KEY, MALWAREBAZAAR_API_KEY, MB_API_KEY

Usage:
    set ABUSECH_API_KEY=your_key
    python scripts/fetch_abusech_c2_samples.py --limit 20

Output:
    samples/malware/abusech/*.apk
    sample_metadata.csv (updated)
"""

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import pyzipper
import requests
from dotenv import load_dotenv


# Load environment variables from project .env (API keys, etc.)
load_dotenv(Path(__file__).parent.parent / ".env")


PROJECT_ROOT = Path(__file__).parent.parent
SAMPLES_DIR = PROJECT_ROOT / "samples"
META_PATH = PROJECT_ROOT / "sample_metadata.csv"
MB_API = "https://mb-api.abuse.ch/api/v1/"
TF_API = "https://threatfox-api.abuse.ch/api/v1/"
UH_API = "https://urlhaus-api.abuse.ch/v1/"
REQUEST_TIMEOUT = 120
RATE_LIMIT = 6  # seconds between abuse.ch requests
HEADERS = {"User-Agent": "DroidForensix/1.0 (Research)"}


def get_api_key() -> str:
    for env_var in ("ABUSECH_API_KEY", "MALWAREBAZAAR_API_KEY", "MB_API_KEY"):
        key = os.environ.get(env_var)
        if key:
            return key.strip().strip('"').strip("'")
    raise RuntimeError(
        "No abuse.ch API key found. Set ABUSECH_API_KEY, MALWAREBAZAAR_API_KEY, or MB_API_KEY."
    )


def api_headers() -> dict:
    return {**HEADERS, "Auth-Key": get_api_key()}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_metadata() -> list:
    if not META_PATH.exists():
        return []
    with open(META_PATH, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_metadata(records: list):
    fieldnames = [
        "sample_name", "sha256", "md5", "family", "source",
        "type", "tags", "file_size_bytes", "status", "vt_detections",
        "collection_date", "c2_indicators",
    ]
    with open(META_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({k: r.get(k, "") for k in fieldnames})


def already_have(sha256_hash: str, records: list) -> bool:
    return any(r.get("sha256", "").lower() == sha256_hash.lower() for r in records)


def mb_api_post(data: dict) -> dict:
    """POST to MalwareBazaar API."""
    try:
        resp = requests.post(MB_API, data=data, headers=api_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[!] MalwareBazaar API error: {e}")
        return {}


def tf_api_post(data: dict) -> dict:
    """POST to ThreatFox API."""
    try:
        resp = requests.post(TF_API, json=data, headers=api_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[!] ThreatFox API error: {e}")
        return {}


def mb_query_samples_by_tag(tag: str, limit: int = 100) -> list:
    """Get samples from MalwareBazaar by a specific tag."""
    print(f"[*] Querying MalwareBazaar tag='{tag}' (limit={limit})...")
    result = mb_api_post({"query": "get_taginfo", "tag": tag, "limit": limit})
    if result.get("query_status") != "ok":
        print(f"[!] MalwareBazaar tag query failed: {result.get('query_status')}")
        return []
    return result.get("data", [])


def mb_query_android_samples(tag: str = "apk", limit: int = 100) -> list:
    """Get recent Android APK samples from MalwareBazaar."""
    samples = mb_query_samples_by_tag(tag, limit=limit)
    # Fallback / enrichment: also grab recent samples
    time.sleep(RATE_LIMIT)
    result2 = mb_api_post({"query": "get_recent", "selector": "time", "limit": limit})
    if result2.get("query_status") == "ok":
        for s in result2.get("data", []):
            tags = [t.lower() for t in s.get("tags", [])]
            if "apk" in tags or "android" in tags or s.get("file_type", "").lower() == "apk":
                if s.get("sha256_hash") not in {x.get("sha256_hash") for x in samples}:
                    samples.append(s)
    return samples


def tf_query_android_iocs(days: int = 7, limit: int = 500) -> list:
    """
    Query ThreatFox for recent IOCs associated with Android malware.
    `days` must be 1-7 (ThreatFox API limit).
    Returns list of dicts with ioc, ioc_type, malware, and associated samples.
    """
    days = max(1, min(7, days))
    print(f"[*] Querying ThreatFox for recent Android IOCs (last {days} days)...")
    result = tf_api_post({
        "query": "get_iocs",
        "days": days,
        "limit": limit,
    })
    if result.get("query_status") != "ok":
        print(f"[!] ThreatFox query failed: {result.get('query_status')}")
        return []

    iocs = []
    for ioc in result.get("data", []):
        malware_print = (ioc.get("malware_printable") or "").lower()
        malware_alias = (ioc.get("malware_alias") or "").lower()
        ioc_value = ioc.get("ioc", "")
        ioc_type = ioc.get("ioc_type", "")
        threat_type = ioc.get("threat_type", "")
        # Focus on Android-related malware with network C2 indicators
        is_android = any(k in malware_print or malware_alias for k in [
            "android", "apk", "spyware", "banker", "trojan", "rat", "stealer",
        ])
        is_network_c2 = (
            ioc_type in ("domain", "ip:port", "url", "ip_range")
            and threat_type in ("botnet_cc", "c2", "payload_delivery")
        )
        if is_android and is_network_c2 and ioc_value and "%" not in ioc_value:
            iocs.append({
                "ioc": ioc_value,
                "ioc_type": ioc_type,
                "malware": ioc.get("malware_printable", "unknown"),
                "first_seen": ioc.get("first_seen", ""),
                "associated_samples": [],  # populated via search_ioc
            })
    print(f"[*] Found {len(iocs)} Android network IOCs on ThreatFox")
    return iocs


def tf_lookup_ioc_associated_samples(ioc: str, max_samples: int = 5) -> list:
    """Use ThreatFox search_ioc to find malware samples associated with a C2 IOC."""
    result = tf_api_post({"query": "search_ioc", "search_term": ioc})
    if result.get("query_status") != "ok":
        return []
    data = result.get("data", [])
    if not data:
        return []
    item = data[0] if isinstance(data, list) else data
    samples = item.get("associated_malware_samples", []) or item.get("malware_samples", []) or []
    return samples[:max_samples]


def mb_download(sha256_hash: str, dest_path: Path) -> bool:
    """Download a sample from MalwareBazaar by SHA-256 (AES passworded ZIP)."""
    data = {"query": "get_file", "sha256_hash": sha256_hash}
    zip_path = dest_path.with_suffix(".zip")
    try:
        resp = requests.post(MB_API, data=data, headers=api_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        with open(zip_path, "wb") as f:
            f.write(resp.content)

        # MalwareBazaar uses AES-encrypted ZIPs; pyzipper handles these.
        extracted = False
        try:
            with pyzipper.AESZipFile(zip_path, "r") as z:
                z.extractall(path=str(dest_path.parent), pwd=b"infected")
            extracted = True
        except Exception:
            # Fallback to standard zipfile for non-AES archives
            try:
                with zipfile.ZipFile(zip_path, "r") as z:
                    z.extractall(path=dest_path.parent, pwd=b"infected")
                extracted = True
            except Exception as e2:
                print(f"[!] Extraction failed for {sha256_hash}: {e2}")

        zip_path.unlink(missing_ok=True)
        if not extracted:
            return False

        # Rename generic extracted file if needed
        for item in dest_path.parent.iterdir():
            if item.is_file() and item != dest_path:
                with open(item, "rb") as f:
                    magic = f.read(4)
                if magic == b"PK\x03\x04":
                    item.rename(dest_path)
                    break
        return dest_path.exists()
    except Exception as e:
        print(f"[!] Download failed for {sha256_hash}: {e}")
        return False
    finally:
        zip_path.unlink(missing_ok=True)


def sanitize_filename(name: str) -> str:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return safe.strip("._") or "unknown"


def fetch_mb_android_with_c2(limit: int = 20) -> int:
    """Download Android samples from MalwareBazaar and record any C2 tags."""
    records = load_metadata()
    existing = {r["sha256"].lower() for r in records if r.get("type") == "malware"}
    fetched = 0

    samples = mb_query_android_samples(tag="apk", limit=max(limit * 3, 100))
    print(f"[*] MalwareBazaar candidates: {len(samples)}")

    dest_dir = SAMPLES_DIR / "malware" / "abusech"
    dest_dir.mkdir(parents=True, exist_ok=True)

    for sample in samples:
        if fetched >= limit:
            break
        sha256_hash = sample.get("sha256_hash", "").lower()
        if not sha256_hash or sha256_hash in existing:
            continue

        family = sample.get("signature") or sample.get("imphash") or "unknown"
        tags = [t for t in sample.get("tags", [])]
        file_name = sample.get("file_name", f"{sha256_hash}.apk")
        if not file_name.endswith(".apk"):
            file_name += ".apk"
        safe_family = sanitize_filename(str(family))
        dest = dest_dir / f"{safe_family}_{sha256_hash}.apk"

        print(f"[*] Downloading MB {fetched+1}/{limit}: {sha256_hash} ({family})")
        if mb_download(sha256_hash, dest):
            actual_sha = sha256_file(dest)
            if actual_sha.lower() != sha256_hash:
                print(f"[!] Hash mismatch for {sha256_hash}; deleting")
                dest.unlink(missing_ok=True)
                continue

            records.append({
                "sample_name": dest.name,
                "sha256": actual_sha,
                "md5": sample.get("md5_hash", ""),
                "family": family,
                "source": "MalwareBazaar",
                "type": "malware",
                "tags": ";".join(tags),
                "file_size_bytes": dest.stat().st_size,
                "status": "pending",
                "vt_detections": sample.get("vendor_count", ""),
                "collection_date": time.strftime("%Y-%m-%d"),
                "c2_indicators": "",
            })
            save_metadata(records)
            fetched += 1
            print(f"[+] Saved {dest.name}")
        else:
            print(f"[!] Failed {sha256_hash}")
        time.sleep(RATE_LIMIT)

    print(f"[+] Downloaded {fetched} Android samples from MalwareBazaar")
    return fetched


def fetch_tf_c2_samples(limit: int = 20) -> int:
    """
    Use ThreatFox IOCs to find Android malware samples associated with live
    C2 IPs/domains, then download them from MalwareBazaar.
    """
    records = load_metadata()
    existing = {r["sha256"].lower() for r in records if r.get("type") == "malware"}
    fetched = 0

    iocs = tf_query_android_iocs(days=7, limit=500)
    if not iocs:
        print("[!] No ThreatFox IOCs found")
        return 0

    dest_dir = SAMPLES_DIR / "malware" / "abusech"
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Look up associated samples for each C2 IOC (rate-limited).
    # Limit lookups to avoid excessive API calls.
    sha_to_iocs = {}
    sha_to_family = {}
    max_lookups = min(len(iocs), 50)
    print(f"[*] Looking up associated samples for {max_lookups} IOCs...")
    for idx, ioc in enumerate(iocs[:max_lookups], 1):
        assoc_samples = tf_lookup_ioc_associated_samples(ioc["ioc"], max_samples=5)
        for assoc in assoc_samples:
            sha = (assoc.get("sha256_hash") or assoc.get("sha256") or "").lower()
            if sha and len(sha) == 64:
                sha_to_iocs.setdefault(sha, set()).add(f"{ioc['ioc_type']}:{ioc['ioc']}")
                sha_to_family[sha] = ioc.get("malware", "unknown")
        if idx % 10 == 0:
            print(f"    {idx}/{max_lookups} IOCs looked up, {len(sha_to_iocs)} unique samples found")
        time.sleep(0.5)

    print(f"[*] {len(sha_to_iocs)} unique samples associated with ThreatFox C2 IOCs")

    for sha256_hash, c2_set in sorted(sha_to_iocs.items(), key=lambda x: len(x[1]), reverse=True):
        if fetched >= limit:
            break
        if sha256_hash in existing:
            continue

        family = sha_to_family.get(sha256_hash, "unknown")
        safe_family = sanitize_filename(family)
        dest = dest_dir / f"{safe_family}_{sha256_hash}.apk"

        print(f"[*] Downloading TF-associated {fetched+1}/{limit}: {sha256_hash} ({family})")
        if mb_download(sha256_hash, dest):
            actual_sha = sha256_file(dest)
            if actual_sha.lower() != sha256_hash:
                print(f"[!] Hash mismatch; deleting")
                dest.unlink(missing_ok=True)
                continue

            records.append({
                "sample_name": dest.name,
                "sha256": actual_sha,
                "md5": "",
                "family": family,
                "source": "ThreatFox",
                "type": "malware",
                "tags": f"c2;ioc_count={len(c2_set)}",
                "file_size_bytes": dest.stat().st_size,
                "status": "pending",
                "vt_detections": "",
                "collection_date": time.strftime("%Y-%m-%d"),
                "c2_indicators": ";".join(sorted(c2_set))[:2000],
            })
            save_metadata(records)
            fetched += 1
            print(f"[+] Saved {dest.name} with {len(c2_set)} C2 IOCs")
        else:
            print(f"[!] Failed {sha256_hash}")
        time.sleep(RATE_LIMIT)

    print(f"[+] Downloaded {fetched} ThreatFox-associated C2 samples")
    return fetched


ANDROID_C2_FAMILIES = [
    "anubis", "cerberus", "alien", "escobar", "ermac", "hydra",
    "teabot", "flubot", "medusa", "spynote", "rat", "bankbot",
    "anubisbankbot", "eventbot", "gustuff", "mysterybot", "exobot",
]


def fetch_mb_family_samples(families: list[str], limit_per_family: int = 10) -> int:
    """
    Download samples for specific Android malware families known to use C2.
    Queries MalwareBazaar by family tag.
    """
    records = load_metadata()
    existing = {r["sha256"].lower() for r in records if r.get("type") == "malware"}
    fetched = 0
    dest_dir = SAMPLES_DIR / "malware" / "abusech"
    dest_dir.mkdir(parents=True, exist_ok=True)

    for family in families:
        print(f"\n[*] Searching MalwareBazaar for family '{family}'...")
        samples = mb_query_samples_by_tag(family, limit=limit_per_family * 3)
        # Filter to APKs only
        apk_samples = []
        for s in samples:
            tags = [t.lower() for t in s.get("tags", [])]
            if "apk" in tags or "android" in tags or s.get("file_type", "").lower() == "apk":
                apk_samples.append(s)
        print(f"[*] Found {len(apk_samples)} APK candidates for '{family}'")

        family_fetched = 0
        for sample in apk_samples:
            if family_fetched >= limit_per_family:
                break
            sha256_hash = sample.get("sha256_hash", "").lower()
            if not sha256_hash or sha256_hash in existing:
                continue

            tags = [t for t in sample.get("tags", [])]
            file_name = sample.get("file_name", f"{sha256_hash}.apk")
            if not file_name.endswith(".apk"):
                file_name += ".apk"
            safe_family = sanitize_filename(family)
            dest = dest_dir / f"{safe_family}_{sha256_hash}.apk"

            print(f"[*] Downloading {family} {family_fetched+1}/{limit_per_family}: {sha256_hash}")
            if mb_download(sha256_hash, dest):
                actual_sha = sha256_file(dest)
                if actual_sha.lower() != sha256_hash:
                    print(f"[!] Hash mismatch for {sha256_hash}; deleting")
                    dest.unlink(missing_ok=True)
                    continue

                records.append({
                    "sample_name": dest.name,
                    "sha256": actual_sha,
                    "md5": sample.get("md5_hash", ""),
                    "family": family,
                    "source": "MalwareBazaar",
                    "type": "malware",
                    "tags": ";".join(tags),
                    "file_size_bytes": dest.stat().st_size,
                    "status": "pending",
                    "vt_detections": sample.get("vendor_count", ""),
                    "collection_date": time.strftime("%Y-%m-%d"),
                    "c2_indicators": "",
                })
                save_metadata(records)
                existing.add(actual_sha.lower())
                fetched += 1
                family_fetched += 1
                print(f"[+] Saved {dest.name}")
            else:
                print(f"[!] Failed {sha256_hash}")
            time.sleep(RATE_LIMIT)

    print(f"\n[+] Downloaded {fetched} family-specific samples")
    return fetched


def main():
    parser = argparse.ArgumentParser(description="Download Android malware from abuse.ch with C2 data")
    parser.add_argument("--limit", type=int, default=20, help="Max samples to download")
    parser.add_argument("--source", choices=["malwarebazaar", "threatfox", "both"], default="both",
                        help="Which abuse.ch source to use")
    parser.add_argument("--family", type=str, default=None,
                        help="Specific MalwareBazaar family tag to fetch (e.g. anubis, cerberus)")
    parser.add_argument("--families", action="store_true",
                        help=f"Fetch known C2-rich Android families: {', '.join(ANDROID_C2_FAMILIES)}")
    parser.add_argument("--limit-per-family", type=int, default=5,
                        help="Max samples per family when using --families")
    args = parser.parse_args()

    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("abuse.ch Android C2 Sample Downloader")
    print("=" * 60)

    total = 0
    if args.family:
        total += fetch_mb_family_samples([args.family], limit_per_family=args.limit)
    elif args.families:
        total += fetch_mb_family_samples(ANDROID_C2_FAMILIES, limit_per_family=args.limit_per_family)
    else:
        if args.source in ("malwarebazaar", "both"):
            total += fetch_mb_android_with_c2(limit=args.limit)
        if args.source in ("threatfox", "both"):
            total += fetch_tf_c2_samples(limit=args.limit)

    print("=" * 60)
    print(f"Total downloaded: {total}")
    print(f"Metadata: {META_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    main()
