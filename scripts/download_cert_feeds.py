"""
Download known-bad certificate feeds for DroidForensix.

Sources:
- Abuse.ch SSL Blacklist (https://sslbl.abuse.ch/blacklist/sslblacklist.csv)
- MalwareBazaar SSL fingerprints
- Custom local additions
"""

import argparse
import csv
import hashlib
import json
import logging
import time
import urllib.request
from datetime import datetime
from io import StringIO
from pathlib import Path

logger = logging.getLogger(__name__)

CERT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "known_bad_certificates.json"

SOURCES = {
    "sslbl": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
}

RATE_LIMIT_SECONDS = 2


def load_existing_data(path: Path) -> dict:
    if not path.exists():
        return {
            "schema_version": "1.0",
            "description": "Known-bad Android code signing certificates",
            "sources": [],
            "last_updated": datetime.now().strftime("%Y-%m-%d"),
            "certificates": [],
            "suspicious_issuers": [],
        }
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_data(data: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def download_sslbl(output: Path):
    """Download Abuse.ch SSL Blacklist, extract SHA-256 fingerprints."""
    url = SOURCES["sslbl"]
    logger.info("Downloading SSL Blacklist from %s", url)

    existing = load_existing_data(output)
    existing_fps = {c["sha256_fingerprint"] for c in existing.get("certificates", [])}
    existing_sources = set(existing.get("sources", []))
    existing_sources.add("sslbl.abuse.ch")

    new_count = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DroidForensix/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        reader = csv.reader(StringIO(content))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 2:
                continue
            raw_fp = row[1].strip()
            fp = ":".join(raw_fp[i:i+2] for i in range(0, len(raw_fp), 2)).upper() if ":" not in raw_fp else raw_fp.upper()
            if len(fp) != 95:
                continue
            if fp not in existing_fps:
                existing["certificates"].append({
                    "sha256_fingerprint": fp,
                    "family": "sslbl_listed",
                    "source": "sslbl.abuse.ch",
                    "notes": f"Listed on Abuse.ch SSL Blacklist. Reason: {row[2] if len(row) > 2 else 'unknown'}",
                })
                existing_fps.add(fp)
                new_count += 1
        time.sleep(RATE_LIMIT_SECONDS)
    except Exception as e:
        logger.error("SSLBL download failed: %s", e)

    existing["sources"] = sorted(existing_sources)
    existing["last_updated"] = datetime.now().strftime("%Y-%m-%d")
    save_data(existing, output)
    logger.info("SSLBL: %d new fingerprints added (total: %d)", new_count, len(existing["certificates"]))


def download_all(output: Path):
    for source_name in SOURCES:
        if source_name == "sslbl":
            download_sslbl(output)


def main():
    parser = argparse.ArgumentParser(description="Download known-bad certificate feeds")
    parser.add_argument("--source", choices=list(SOURCES) + ["all"], default="all",
                        help="Feed source to download (default: all)")
    parser.add_argument("--output", type=Path, default=CERT_DB_PATH,
                        help=f"Output JSON file (default: {CERT_DB_PATH})")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.source == "all":
        download_all(args.output)
    else:
        download_fn = {
            "sslbl": download_sslbl,
        }[args.source]
        download_fn(args.output)

    print(f"[+] Certificate database updated: {args.output}")


if __name__ == "__main__":
    main()
