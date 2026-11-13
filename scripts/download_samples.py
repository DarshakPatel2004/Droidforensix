"""
Sample Downloader for DroidForensix

Fetches Android APK samples from multiple sources:
- AndroZoo for malware samples (requires API key)
- MalwareBazaar (abuse.ch) for malware samples
- Koodous for malware samples (requires API key)
- F-Droid for legitimate baseline APKs

Generates sample_metadata.csv with SHA-256, family tags, and source info.
"""

import csv
import os
import re
import sys
import time
import zipfile
from pathlib import Path

from download_common import safe_error, sanitize_filename, sha256_file
from sample_archive import ZIP_PASSWORD, place_sample

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SAMPLES_DIR = Path(__file__).parent.parent / "samples"
META_PATH = Path(__file__).parent.parent / "sample_metadata.csv"
DREBIN_FAMILY_CSV = Path(__file__).parent.parent / "data" / "drebin_sha256_family.csv"
MALWAREBazaar_API = "https://mb-api.abuse.ch/api/v1/"
KOODOUS_API = "https://developer.koodous.com/apks/"
ANDROZOO_API = "https://androzoo.uni.lu/api/download"
ANDROZOO_CSV = "https://androzoo.uni.lu/api/lists"
FDROID_REPO = "https://f-droid.org/repo/"

REQUEST_TIMEOUT = 120
RATE_LIMIT_SLEEP = 6  # seconds between MB requests
KOODOUS_RATE_LIMIT = 1  # seconds between Koodous requests
ANDROZOO_RATE_LIMIT = 0  # seconds between AndroZoo downloads

HEADERS = {
    "User-Agent": "DroidForensix/1.0 (Research Project)",
}


def get_koodous_headers() -> dict:
    key = os.environ.get("KOODOUS_API_KEY")
    if not key:
        raise RuntimeError("KOODOUS_API_KEY environment variable not set")
    return {**HEADERS, "Authorization": f"Token {key}"}


def get_androzoo_api_key() -> str:
    key = os.environ.get("ANDROZOO_API_KEY")
    if not key:
        raise RuntimeError("ANDROZOO_API_KEY environment variable not set")
    return key


def get_malwarebazaar_headers() -> dict:
    """Return HEADERS with MalwareBazaar Auth-Key if available."""
    for env_var in ("MALWAREBAZAAR_API_KEY", "MB_API_KEY", "ABUSECH_API_KEY"):
        key = os.environ.get(env_var)
        if key:
            return {**HEADERS, "Auth-Key": key}
    return HEADERS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_family_map(csv_path: Path = DREBIN_FAMILY_CSV) -> dict:
    """Load sha256 -> family mapping from the Drebin family CSV."""
    family_map = {}
    if not csv_path.exists():
        return family_map
    try:
        with open(csv_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                sha = row.get("sha256", "").strip().lower()
                family = row.get("family", "unknown").strip()
                if sha:
                    family_map[sha] = family
    except Exception as e:
        print(f"[!] Could not load family CSV {csv_path}: {e}")
    return family_map


def ensure_dirs():
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    (SAMPLES_DIR / "malware").mkdir(exist_ok=True)
    (SAMPLES_DIR / "legitimate").mkdir(exist_ok=True)


def load_existing_metadata() -> list:
    if not META_PATH.exists():
        return []
    with open(META_PATH, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_metadata(records: list):
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


def already_have(sha256_hash: str, records: list) -> bool:
    return any(r.get("sha256", "").lower() == sha256_hash.lower() for r in records)


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------

def mb_query_recent(tag: str = "apk", limit: int = 50) -> list:
    """Query MalwareBazaar for recent samples with a given tag."""
    data = {"query": "get_recent", "selector": "time", "limit": limit}
    try:
        resp = requests.post(MALWAREBazaar_API, data=data, headers=get_malwarebazaar_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        result = resp.json()
        if result.get("query_status") != "ok":
            print(f"[!] MalwareBazaar query failed: {result.get('query_status')}")
            return []
        samples = result.get("data", [])
        # Filter to APKs
        apk_samples = []
        for s in samples:
            tags = [t.lower() for t in s.get("tags", [])]
            file_type = s.get("file_type", "").lower()
            if "apk" in tags or "android" in tags or file_type == "apk":
                apk_samples.append(s)
        return apk_samples
    except Exception as e:
        print(f"[!] MalwareBazaar query error: {e}")
        return []


def mb_query_tag(tag: str = "apk", limit: int = 50) -> list:
    """Query MalwareBazaar for samples by tag."""
    data = {"query": "get_taginfo", "tag": tag, "limit": limit}
    try:
        resp = requests.post(MALWAREBazaar_API, data=data, headers=get_malwarebazaar_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        result = resp.json()
        if result.get("query_status") != "ok":
            print(f"[!] MalwareBazaar tag query failed: {result.get('query_status')}")
            return []
        return result.get("data", [])
    except Exception as e:
        print(f"[!] MalwareBazaar tag query error: {e}")
        return []


def _extract_mb_zip(archive: Path, staging: Path) -> None:
    with zipfile.ZipFile(archive, "r") as z:
        z.extractall(path=staging, pwd=ZIP_PASSWORD)


def mb_download(sha256_hash: str, dest_path: Path) -> bool:
    """Download a sample from MalwareBazaar by SHA-256 into dest_path (only that file is written)."""
    data = {"query": "get_file", "sha256_hash": sha256_hash}
    zip_path = dest_path.with_suffix(".zip")
    try:
        resp = requests.post(MALWAREBazaar_API, data=data, headers=get_malwarebazaar_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        # Response is a ZIP containing the sample with password "infected"
        zip_path.write_bytes(resp.content)
        return place_sample(zip_path, dest_path, sha256_hash, _extract_mb_zip)
    except Exception as e:
        print(f"[!] Download failed for {sha256_hash}: {e}")
        return False
    finally:
        zip_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Koodous
# ---------------------------------------------------------------------------

def koodous_query_list(limit: int = 50, offset: int = 0) -> list:
    """Query Koodous for recent APK samples."""
    try:
        url = f"{KOODOUS_API}?limit={limit}&offset={offset}"
        resp = requests.get(url, headers=get_koodous_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", [])
    except Exception as e:
        print(f"[!] Koodous query error: {e}")
        return []


def koodous_search(query: str, limit: int = 50) -> list:
    """Search Koodous APKs by tag/family."""
    try:
        url = f"{KOODOUS_API}?search={query}&limit={limit}"
        resp = requests.get(url, headers=get_koodous_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", [])
    except Exception as e:
        print(f"[!] Koodous search error: {e}")
        return []


def koodous_download(sha256_hash: str, dest_path: Path) -> bool:
    """Download an APK from Koodous by SHA-256."""
    try:
        url = f"{KOODOUS_API}{sha256_hash}/download"
        resp = requests.get(url, headers=get_koodous_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        with open(dest_path, "wb") as f:
            f.write(resp.content)
        return True
    except Exception as e:
        print(f"[!] Koodous download error for {sha256_hash}: {e}")
        return False


# ---------------------------------------------------------------------------
# AndroZoo
# ---------------------------------------------------------------------------

def download_androzoo_csv(dest_path: Path) -> bool:
    """Download the AndroZoo latest.csv.gz metadata file."""
    try:
        url = "https://androzoo.uni.lu/static/lists/latest.csv.gz"
        print("[*] Downloading AndroZoo metadata CSV (this may take a while)...")
        print(f"    URL: {url}")
        with requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT * 10, stream=True) as resp:
            resp.raise_for_status()
            with open(dest_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        print(f"[+] Metadata CSV saved: {dest_path} ({dest_path.stat().st_size} bytes)")
        return True
    except Exception as e:
        print(f"[!] AndroZoo CSV download error: {e}")
        return False


def filter_androzoo_hashes(csv_path: Path, min_vt: int = 2, max_size: int = 50_000_000,
                            max_count: int = 100) -> list:
    """Filter AndroZoo CSV for malware hashes (vt_detection >= min_vt)."""
    import gzip
    hashes = []
    print(f"[*] Filtering AndroZoo CSV for vt_detection >= {min_vt}, size <= {max_size} bytes...")
    try:
        with gzip.open(csv_path, "rt", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    vt = int(row.get("vt_detection", "0") or 0)
                    size = int(row.get("apk_size", "0") or 0)
                    if vt >= min_vt and 0 < size <= max_size:
                        sha256 = row.get("sha256", "").strip().lower()
                        if sha256:
                            hashes.append({
                                "sha256": sha256,
                                "md5": row.get("md5", "").strip(),
                                "package_name": row.get("pkg_name", "").strip(),
                                "file_size_bytes": size,
                                "vt_detections": vt,
                                "markets": row.get("markets", "").strip(),
                            })
                            if len(hashes) >= max_count * 2:
                                break
                except (ValueError, KeyError):
                    continue
    except Exception as e:
        print(f"[!] Error filtering AndroZoo CSV: {e}")
    print(f"[*] Found {len(hashes)} candidate malware hashes")
    return hashes


def androzoo_download(sha256_hash: str, dest_path: Path) -> bool:
    """Download an APK from AndroZoo by SHA-256 (streamed with size)."""
    try:
        params = {"apikey": get_androzoo_api_key(), "sha256": sha256_hash}
        print(f"    GET AndroZoo {sha256_hash[:12]}...", flush=True)
        with requests.get(ANDROZOO_API, params=params, headers=HEADERS,
                          timeout=REQUEST_TIMEOUT * 2, stream=True) as resp:
            if resp.status_code == 404:
                print(f"[!] AndroZoo: {sha256_hash} not found (404)", flush=True)
                return False
            resp.raise_for_status()
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            print(f"    Downloading {sha256_hash[:12]} {total//1024//1024 if total else '?'}MB...", flush=True)
            with open(dest_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total and downloaded % (1024*1024) < 8192:
                            print(f"      ... {downloaded//1024//1024}MB / {total//1024//1024}MB", flush=True)
                        elif not total and downloaded % (5*1024*1024) < 8192:
                            print(f"      ... {downloaded//1024//1024}MB", flush=True)
            print(f"    Saved {downloaded} bytes {sha256_hash[:12]} {downloaded/1024/1024:.1f}MB", flush=True)
        return True
    except Exception as e:
        print(f"[!] AndroZoo download error for {sha256_hash}: {safe_error(e, os.environ.get('ANDROZOO_API_KEY', ''))}", flush=True)
        return False


# ---------------------------------------------------------------------------
# F-Droid (Legitimate)
# ---------------------------------------------------------------------------

def fdroid_get_index() -> dict:
    """Fetch F-Droid app index."""
    try:
        url = "https://f-droid.org/api/v1/apps"
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[!] F-Droid index fetch error: {e}")
        return {}


def fdroid_download_apk(package_name: str, dest_path: Path) -> bool:
    """Download latest APK for an F-Droid package (streamed, unbuffered logs)."""
    try:
        # Get package info to find download URL
        url = f"https://f-droid.org/api/v1/packages/{package_name}"
        print(f"    GET {url} ...", flush=True)
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        versions = data.get("packages", [])
        if not versions:
            print(f"[!] No versions found for {package_name}", flush=True)
            return False
        # Sort by version code descending
        versions.sort(key=lambda v: v.get("versionCode", 0), reverse=True)
        latest = versions[0]
        version_code = latest.get("versionCode")
        if not version_code:
            print(f"[!] No versionCode for {package_name}", flush=True)
            return False
        apk_name = f"{package_name}_{version_code}.apk"
        download_url = f"{FDROID_REPO}{apk_name}"
        print(f"    Downloading {download_url} ...", flush=True)
        with requests.get(download_url, headers=HEADERS, timeout=REQUEST_TIMEOUT, stream=True) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length", 0))
            downloaded = 0
            with open(dest_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total and downloaded % (1024 * 1024) < 8192:
                            print(f"      ... {downloaded//1024//1024}MB / {total//1024//1024}MB", flush=True)
            print(f"    Saved {downloaded} bytes to {dest_path.name}", flush=True)
        return True
    except Exception as e:
        print(f"[!] F-Droid download error for {package_name}: {e}", flush=True)
        return False


def fetch_androzoo(target_count: int = 50, csv_path: Path = None,
                   min_vt: int = 2, max_size: int = 50_000_000) -> int:
    """Fetch malware APKs from AndroZoo using the latest CSV metadata."""
    records = load_existing_metadata()
    fetched = 0

    print(f"[*] Fetching {target_count} malware APKs from AndroZoo...")

    # Ensure CSV is available
    if csv_path is None:
        csv_path = SAMPLES_DIR / "androzoo_latest.csv.gz"
    csv_path = Path(csv_path)

    if not csv_path.exists():
        if not download_androzoo_csv(csv_path):
            print("[!] Failed to download AndroZoo metadata CSV")
            return 0

    candidates = filter_androzoo_hashes(csv_path, min_vt=min_vt, max_size=max_size,
                                        max_count=target_count)
    if not candidates:
        print("[!] No AndroZoo candidates found matching criteria")
        return 0

    family_map = load_family_map()
    print(f"[*] Loaded {len(family_map)} Drebin family mappings")

    dest_dir = SAMPLES_DIR / "malware" / "androzoo"
    dest_dir.mkdir(parents=True, exist_ok=True)

    for candidate in candidates:
        if fetched >= target_count:
            break
        sha256_hash = candidate["sha256"].lower()
        if not sha256_hash or already_have(sha256_hash, records):
            continue

        family = family_map.get(sha256_hash, "unknown")
        safe_family = sanitize_filename(family)
        dest = dest_dir / f"{safe_family}_{sha256_hash}.apk"
        print(f"[*] Downloading AndroZoo {fetched+1}/{target_count}: {sha256_hash} ({family})")
        if androzoo_download(sha256_hash, dest):
            actual_sha = sha256_file(str(dest))
            if actual_sha.lower() != sha256_hash:
                print(f"[!] Hash mismatch! Expected {sha256_hash}, got {actual_sha}")
                dest.unlink(missing_ok=True)
                continue

            record = {
                "sample_name": dest.name,
                "sha256": actual_sha,
                "md5": candidate.get("md5", ""),
                "family": family,
                "source": "AndroZoo",
                "type": "malware",
                "tags": f"family={family};vt_detection={candidate.get('vt_detections', '')};markets={candidate.get('markets', '')}",
                "file_size_bytes": dest.stat().st_size,
                "status": "pending",
                "vt_detections": candidate.get("vt_detections", ""),
                "collection_date": time.strftime("%Y-%m-%d"),
            }
            records.append(record)
            save_metadata(records)
            fetched += 1
            print(f"[+] Saved: {dest.name} ({dest.stat().st_size} bytes)")
        else:
            print(f"[!] Failed to download {sha256_hash}")

        time.sleep(ANDROZOO_RATE_LIMIT)

    print(f"[+] AndroZoo fetch complete. Total AndroZoo samples: {fetched}")
    return fetched


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def fetch_malware(target_count: int = 50) -> int:
    """Fetch malware APKs from MalwareBazaar."""
    records = load_existing_metadata()
    existing_hashes = {r["sha256"].lower() for r in records if r.get("type") == "malware"}
    fetched = 0

    print(f"[*] Querying MalwareBazaar for Android APK malware (target: {target_count})...")

    # Try multiple query strategies
    queries = [
        ("tag", {"tag": "apk", "limit": 100}),
        ("tag", {"tag": "android", "limit": 100}),
        ("recent", {"limit": 100}),
    ]

    all_samples = []
    for qtype, params in queries:
        if qtype == "tag":
            samples = mb_query_tag(**params)
        else:
            samples = mb_query_recent(**params)
        for s in samples:
            h = s.get("sha256_hash", "").lower()
            if h and h not in existing_hashes and h not in {x.get("sha256_hash", "").lower() for x in all_samples}:
                all_samples.append(s)
        if len(all_samples) >= target_count * 2:
            break
        time.sleep(RATE_LIMIT_SLEEP)

    print(f"[*] Found {len(all_samples)} candidate malware samples")

    for sample in all_samples:
        if fetched >= target_count:
            break
        sha256_hash = sample.get("sha256_hash", "").lower()
        if not sha256_hash:
            continue
        if already_have(sha256_hash, records):
            continue

        # Name by hash only: the submitter-chosen file_name can collide with or escape other samples (R2).
        if not re.fullmatch(r"[0-9a-f]{64}", sha256_hash):
            continue
        dest = SAMPLES_DIR / "malware" / f"{sha256_hash}.apk"

        print(f"[*] Downloading malware {fetched+1}/{target_count}: {sha256_hash}")
        if mb_download(sha256_hash, dest):
            # Verify hash
            actual_sha = sha256_file(str(dest))
            if actual_sha.lower() != sha256_hash:
                print(f"[!] Hash mismatch! Expected {sha256_hash}, got {actual_sha}")
                dest.unlink(missing_ok=True)
                continue

            record = {
                "sample_name": dest.name,
                "sha256": actual_sha,
                "md5": sample.get("md5_hash", ""),
                "family": sample.get("signature", "unknown"),
                "source": "MalwareBazaar",
                "type": "malware",
                "tags": ";".join(sample.get("tags", [])),
                "file_size_bytes": dest.stat().st_size,
                "status": "pending",
                "vt_detections": sample.get("vendor_count", ""),
                "collection_date": time.strftime("%Y-%m-%d"),
            }
            records.append(record)
            save_metadata(records)
            fetched += 1
            print(f"[+] Saved: {dest.name} ({dest.stat().st_size} bytes)")
        else:
            print(f"[!] Failed to download {sha256_hash}")

        time.sleep(RATE_LIMIT_SLEEP)

    print(f"[+] Malware fetch complete. Total malware samples: {len([r for r in records if r.get('type') == 'malware'])}")
    return fetched


def fetch_koodous(target_count: int = 30, search: str = None) -> int:
    """Fetch malware APKs from Koodous."""
    records = load_existing_metadata()
    fetched = 0

    print(f"[*] Querying Koodous for Android APK malware (target: {target_count})...")

    if search:
        samples = koodous_search(search, limit=target_count * 2)
    else:
        samples = []
        offset = 0
        while len(samples) < target_count * 2:
            batch = koodous_query_list(limit=50, offset=offset)
            if not batch:
                break
            samples.extend(batch)
            offset += 50
            time.sleep(KOODOUS_RATE_LIMIT)

    print(f"[*] Found {len(samples)} candidate samples on Koodous")

    for sample in samples:
        if fetched >= target_count:
            break
        sha256_hash = sample.get("sha256", "").lower()
        if not sha256_hash:
            continue
        if already_have(sha256_hash, records):
            continue

        file_name = sample.get("app", sample.get("filename", f"{sha256_hash}.apk"))
        if not file_name.endswith(".apk"):
            file_name += ".apk"
        # Sanitize filename
        file_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in file_name)
        dest = SAMPLES_DIR / "malware" / "koodous" / file_name
        dest.parent.mkdir(parents=True, exist_ok=True)

        print(f"[*] Downloading Koodous {fetched+1}/{target_count}: {sha256_hash}")
        if koodous_download(sha256_hash, dest):
            actual_sha = sha256_file(str(dest))
            if actual_sha.lower() != sha256_hash:
                print(f"[!] Hash mismatch! Expected {sha256_hash}, got {actual_sha}")
                dest.unlink(missing_ok=True)
                continue

            # Determine family/tags from Koodous data
            tags = []
            if sample.get("is_apk"):
                tags.append("apk")
            family = sample.get("app", "unknown")

            record = {
                "sample_name": dest.name,
                "sha256": actual_sha,
                "md5": sample.get("md5", ""),
                "family": family,
                "source": "Koodous",
                "type": "malware",
                "tags": ";".join(tags),
                "file_size_bytes": dest.stat().st_size,
                "status": "pending",
                "vt_detections": sample.get("positives", ""),
                "collection_date": time.strftime("%Y-%m-%d"),
            }
            records.append(record)
            save_metadata(records)
            fetched += 1
            print(f"[+] Saved: {dest.name} ({dest.stat().st_size} bytes)")
        else:
            print(f"[!] Failed to download {sha256_hash}")

        time.sleep(KOODOUS_RATE_LIMIT)

    print(f"[+] Koodous fetch complete. Total Koodous samples: {fetched}")
    return fetched


def fetch_legitimate(target_count: int = 10) -> int:
    """Fetch legitimate APKs from F-Droid."""
    records = load_existing_metadata()
    fetched = 0

    # Popular, well-known F-Droid packages — 100 for full-speed Phase 2 (valid per index.xml)
    packages = [
        "com.github.ashutoshgngwr.tenbitclockwidget",
        "dev.lonami.klooni",
        "eu.quelltext.counting",
        "com.roufsyed.onekey",
        "com.lolo.io.onelist",
        "org.og8.a1tox",
        "ir.hsn6.tpb",
        "com.dasp.worldcup2026",
        "org.secuso.privacyfriendly2048",
        "org.andstatus.game2048",
        "org.mattvchandler.a2050",
        "nl.eventinfra.wifisetup",
        "info.metadude.android.congress.schedule",
        "io.github.nvlad1.function3danimator",
        "org.andresoviedo.dddmodel2",
        "net.yukh.xui",
        "io.github.rotundtapir.fivehundred",
        "com.tokyoxpa3.androidproxy",
        "de.rainerhock.eightbitwonders",
        "inc.flide.vi8",
        "org99managers.futsal_edition",
        "se.tube42.p9.android",
        "business.braid.polycule",
        "at.h4x.awhip",
        "com.github.sourzo.a_rithist",
        "a2dp.Vol",
        "io.github.dkter.aaaaa",
        "io.github.divverent.aaaaxy",
        "de.HS_Aalen.don",
        "itkach.aard2",
        "ch.bailu.aat",
        "com.greenaddress.abcore",
        "org.asafonov.accelerace",
        "com.pedronveloso.a11ybutton",
        "org.billthefarmer.accordion",
        "ru.ikkui.achie",
        "com.acho.chat.app",
        "com.foxdebug.acode",
        "com.metalshard.projectwave",
        "anupam.acrylic",
        "de.rampro.activitydiary",
        "de.szalkowski.activitylauncher",
        "com.activitymanager",
        "com.activitytrace",
        "net.activitywatch.android",
        "pc.javier.actualizadoropendns",
        "com.acutis.firewall",
        "ch.abertschi.adfree",
        "bluepie.ad_silence",
        "com.rascarlo.adaptive.brightness.tile",
        "org.adaway",
        "io.github.yoshi1123.adbio",
        "com.android.adbkeyboard",
        "com.oF2pks.adbungfu",
        "com.addictologs",
        "com.addismaptransit.app",
        "host.stjin.anonaddy",
        "com.adguard.android.contentblocker",
        "org.github.nynosy.adiresy_mobile",
        "com.davidshewitt.admincontrol",
        "com.trianguloy.adnihilation",
        "com.adresilo.android",
        "mattecarra.accapp",
        "com.codedead.advancedpassgen",
        "com.codedead.advancedportchecker",
        "co.epitre.aelf_lectures",
        "com.games.boardgames.aeonsend",
        "alt.nainapps.aer",
        "com.shapeshed.aerial",
        "net.gitsaibot.af",
        "org.afhdownloader",
        "com.freerdp.afreerdp",
        "ru.ifproject.android.afr",
        "com.mufradat.africaquiz",
        "com.anysoftkeyboard.languagepack.afrikaans_oss",
        "dev.ukanth.ufirewall",
        "org.strawberryforum.argentum",
        "com.agepony.app",
        "com.tughi.aggregator",
        "com.newoether.agora",
        "com.ahorcado",
        "com.foss.aihub",
        "com.lun.chin.aicamera",
        "com.aipos.aipospm",
        "de.seemoo.at_tracking_detection",
        "space.ring0.airheadwaves",
        "com.andsi.airlyrics",
        "me.tagavari.airmessage",
        "io.github.jqssun.airplay",
        "com.aisleron",
        "com.beradeep.aiyo",
        "com.aka.alarm",
        "in.digistorm.aksharam",
        "org.secuso.aktivpause",
        "org.akvo.rsr.up",
        "com.github.meypod.al_azan",
        "com.hassaneltantawy.alazkar",
        "com.github.meypod.al_quran",
        "com.angrydoughnuts.android.alarmclock",
        "co.adityarajput.alarmetrics",
    ]

    print(f"[*] Fetching {target_count} legitimate APKs from F-Droid...", flush=True)

    for pkg in packages:
        if fetched >= target_count:
            break
        dest = SAMPLES_DIR / "legitimate" / f"{pkg}.apk"
        if dest.exists():
            actual_sha = sha256_file(str(dest))
            if already_have(actual_sha, records):
                print(f"[*] Already have {pkg}", flush=True)
                fetched += 1
                continue

        print(f"[*] Downloading legitimate {fetched+1}/{target_count}: {pkg}", flush=True)
        if fdroid_download_apk(pkg, dest):
            actual_sha = sha256_file(str(dest))
            if already_have(actual_sha, records):
                print(f"[*] Already have {pkg} (duplicate)")
                dest.unlink(missing_ok=True)
                continue
            record = {
                "sample_name": dest.name,
                "sha256": actual_sha,
                "md5": "",
                "family": pkg,
                "source": "F-Droid",
                "type": "legitimate",
                "tags": "",
                "file_size_bytes": dest.stat().st_size,
                "status": "pending",
                "vt_detections": "0",
                "collection_date": time.strftime("%Y-%m-%d"),
            }
            records.append(record)
            save_metadata(records)
            fetched += 1
            print(f"[+] Saved: {dest.name} ({dest.stat().st_size} bytes)", flush=True)
        else:
            print(f"[!] Failed to download {pkg}", flush=True)

        time.sleep(2)

    print(f"[+] Legitimate fetch complete. Total legitimate samples: {len([r for r in records if r.get('type') == 'legitimate'])}", flush=True)
    return fetched


def main():
    ensure_dirs()
    print("=" * 60)
    print("DroidForensix Sample Downloader")
    print("=" * 60)

    args = sys.argv[1:]
    malware_target = 50
    legit_target = 68  # 32 already done → 100 total for Phase 2, 68 more within rate limits
    koodous_target = 30
    koodous_search = None
    androzoo_target = 50
    androzoo_min_vt = 2
    androzoo_csv = None

    if "--koodous-search" in args:
        idx = args.index("--koodous-search")
        if idx + 1 < len(args):
            koodous_search = args[idx + 1]

    if "--androzoo-count" in args:
        idx = args.index("--androzoo-count")
        if idx + 1 < len(args):
            try:
                androzoo_target = int(args[idx + 1])
            except ValueError:
                pass

    if "--androzoo-csv" in args:
        idx = args.index("--androzoo-csv")
        if idx + 1 < len(args):
            androzoo_csv = Path(args[idx + 1])

    if "--androzoo" in args:
        fetch_androzoo(androzoo_target, csv_path=androzoo_csv, min_vt=androzoo_min_vt)
    elif "--androzoo-only" in args:
        fetch_androzoo(androzoo_target, csv_path=androzoo_csv, min_vt=androzoo_min_vt)
    elif "--koodous" in args:
        fetch_koodous(koodous_target, search=koodous_search)
    elif "--koodous-only" in args:
        fetch_koodous(koodous_target, search=koodous_search)
    elif "--malware-only" in args:
        fetch_malware(malware_target)
    elif "--legit-only" in args:
        fetch_legitimate(legit_target)
    elif "--small" in args:
        fetch_malware(5)
        fetch_legitimate(2)
    else:
        # Default: AndroZoo + F-Droid
        fetch_androzoo(androzoo_target, csv_path=androzoo_csv, min_vt=androzoo_min_vt)
        fetch_legitimate(legit_target)

    records = load_existing_metadata()
    print("=" * 60)
    print(f"Total samples in metadata: {len(records)}")
    print(f"  Malware: {len([r for r in records if r.get('type') == 'malware'])}")
    print(f"  Legitimate: {len([r for r in records if r.get('type') == 'legitimate'])}")
    print(f"Metadata saved to: {META_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    main()
