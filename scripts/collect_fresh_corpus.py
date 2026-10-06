"""Collect a small, provenance-recorded fresh APK corpus for holdout evaluation.

The collector downloads bytes only. It never installs or executes APKs. Binaries
are written below data/, which is ignored by git; the manifest is the durable
artifact.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "fresh_corpus"
MANIFEST = ROOT / "evaluation" / "FRESH_CORPUS_MANIFEST.csv"
FDROID_INDEX = "https://f-droid.org/repo/index-v1.json"
ANDROZOO_METADATA = ROOT / "samples" / "androzoo_latest.csv.gz"
ANDROZOO_DOWNLOAD = "https://androzoo.uni.lu/api/download"
EXCLUSION_FILES = (
    ROOT / "evaluation" / "classifier_data" / "features.csv",
    ROOT / "ground_truth_all_corrected.csv",
    ROOT / "sample_metadata.csv",
    MANIFEST,
)
PACKAGE_EXCLUSION_FILE = ROOT / "data" / "engine_apps_manifest.csv"
MANIFEST_FIELDS = (
    "sha256",
    "path",
    "label",
    "role",
    "source",
    "source_url",
    "license",
    "collected_at",
    "notes",
)
MIN_DATE = "2024-01-01"
MIN_ADDED_MS = 1735689600000
COLLECTED_AT = date.today().isoformat()


def load_exclusions(extra_manifest: Path | None = None) -> tuple[set[str], set[str]]:
    hashes: set[str] = set()
    exclusion_files = list(EXCLUSION_FILES)
    if extra_manifest and extra_manifest not in exclusion_files:
        exclusion_files.append(extra_manifest)
    for path in exclusion_files:
        if not path.exists():
            continue
        with path.open(newline="", encoding="utf-8-sig") as handle:
            hashes.update(
                row.get("sha256", "").strip().lower()
                for row in csv.DictReader(handle)
                if row.get("sha256", "").strip()
            )
    packages: set[str] = set()
    if PACKAGE_EXCLUSION_FILE.exists():
        with PACKAGE_EXCLUSION_FILE.open(newline="", encoding="utf-8-sig") as handle:
            packages.update(
                row.get("package", "").strip()
                for row in csv.DictReader(handle)
                if row.get("package", "").strip()
            )
    return hashes, packages


def safe_error(exc: Exception, secret: str = "") -> str:
    """Remove API credentials from third-party request errors."""
    message = str(exc)
    if secret:
        message = message.replace(secret, "<redacted>")
    return message


def download(url: str, destination: Path, expected_sha256: str, max_bytes: int) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    downloaded = 0
    with requests.get(url, stream=True, timeout=180) as response:
        response.raise_for_status()
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                downloaded += len(chunk)
                if downloaded > max_bytes:
                    raise ValueError(f"download exceeded {max_bytes} bytes: {url}")
                digest.update(chunk)
                handle.write(chunk)
    if digest.hexdigest() != expected_sha256:
        destination.unlink(missing_ok=True)
        raise ValueError(f"SHA-256 mismatch for {url}")
    return downloaded


def fdroid_candidates(
    index: dict[str, Any], excluded_hashes: set[str], excluded_packages: set[str], max_bytes: int
) -> list[dict[str, Any]]:
    apps = {app["packageName"]: app for app in index.get("apps", [])}
    candidates: list[dict[str, Any]] = []
    for package, versions in index.get("packages", {}).items():
        app = apps.get(package, {})
        if package in excluded_packages or not app.get("license"):
            continue
        for version in sorted(versions, key=lambda item: item.get("versionCode", 0), reverse=True):
            sha = (version.get("hash") or "").lower()
            size = int(version.get("size") or 0)
            added = int(version.get("added") or 0)
            if (
                version.get("hashType") != "sha256"
                or len(sha) != 64
                or sha in excluded_hashes
                or not 0 < size <= max_bytes
                or added < MIN_ADDED_MS
            ):
                continue
            candidates.append(
                {
                    "sha256": sha,
                    "package": package,
                    "apk_name": version["apkName"],
                    "size": size,
                    "license": app["license"],
                    "source_url": f"https://f-droid.org/repo/{version['apkName']}",
                    "notes": (
                        f"sourceCode={app.get('sourceCode', '')}; "
                        f"version={version.get('versionName', '')}"
                    ),
                }
            )
            break
    candidates.sort(key=lambda item: (item["package"], item["sha256"]))
    return candidates


def collect_fdroid(
    count: int, max_bytes: int, excluded_hashes: set[str], excluded_packages: set[str]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    response = requests.get(FDROID_INDEX, timeout=120)
    response.raise_for_status()
    candidates = fdroid_candidates(response.json(), excluded_hashes, excluded_packages, max_bytes)
    rows: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []
    for candidate in candidates:
        if len(rows) >= count:
            break
        relative = Path("data") / "fresh_corpus" / "benign" / "fdroid" / candidate["apk_name"]
        destination = ROOT / relative
        try:
            download(candidate["source_url"], destination, candidate["sha256"], max_bytes)
            rows.append(
                {
                    "sha256": candidate["sha256"],
                    "path": relative.as_posix(),
                    "label": "benign",
                    "role": "holdout",
                    "source": "F-Droid",
                    "source_url": candidate["source_url"],
                    "license": candidate["license"],
                    "collected_at": COLLECTED_AT,
                    "notes": candidate["notes"],
                }
            )
        except Exception as exc:
            failures.append(
                {
                    "source": "F-Droid",
                    "sha256": candidate["sha256"],
                    "error": str(exc),
                }
            )
    return rows, failures


def androzoo_candidates(
    excluded_hashes: set[str], max_bytes: int, wanted: int
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    with gzip.open(
        ANDROZOO_METADATA,
        "rt",
        encoding="utf-8",
        errors="replace",
        newline="",
    ) as handle:
        for row in csv.DictReader(handle):
            sha = (row.get("sha256") or "").strip().lower()
            try:
                size = int(row.get("apk_size") or 0)
                detections = int(row.get("vt_detection") or 0)
            except ValueError:
                continue
            dex_date = (row.get("dex_date") or "")[:10]
            if (
                len(sha) != 64
                or sha in excluded_hashes
                or detections < 2
                or not 0 < size <= max_bytes
                or dex_date < MIN_DATE
            ):
                continue
            candidates.append(
                {
                    "sha256": sha,
                    "package": (row.get("pkg_name") or "").strip(),
                    "size": str(size),
                    "detections": str(detections),
                    "markets": (row.get("markets") or "").strip(),
                    "dex_date": dex_date,
                }
            )
            if len(candidates) >= wanted * 5:
                break
    return candidates


def collect_androzoo(
    count: int, max_bytes: int, excluded_hashes: set[str]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    if count <= 0:
        return [], []
    api_key = os.environ.get("ANDROZOO_API_KEY", "")
    if not api_key:
        raise RuntimeError("ANDROZOO_API_KEY is required for malware collection")
    candidates = androzoo_candidates(excluded_hashes, max_bytes, count)
    rows: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []
    for candidate in candidates:
        if len(rows) >= count:
            break
        sha = candidate["sha256"]
        relative = Path("data") / "fresh_corpus" / "malware" / "androzoo" / f"{sha}.apk"
        destination = ROOT / relative
        try:
            response = requests.get(
                ANDROZOO_DOWNLOAD,
                params={"apikey": api_key, "sha256": sha},
                stream=True,
                timeout=180,
            )
            if response.status_code == 404:
                response.close()
                continue
            response.raise_for_status()
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            downloaded = 0
            with destination.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        raise ValueError(f"download exceeded {max_bytes} bytes")
                    digest.update(chunk)
                    handle.write(chunk)
            response.close()
            if digest.hexdigest() != sha:
                destination.unlink(missing_ok=True)
                raise ValueError("SHA-256 mismatch")
            rows.append(
                {
                    "sha256": sha,
                    "path": relative.as_posix(),
                    "label": "malware",
                    "role": "holdout",
                    "source": "AndroZoo",
                    "source_url": f"{ANDROZOO_DOWNLOAD}?sha256={sha}",
                    "license": "AndroZoo research access; redistribution not authorized",
                    "collected_at": COLLECTED_AT,
                    "notes": (
                        f"package={candidate['package']}; markets={candidate['markets']}; "
                        f"vt_detections={candidate['detections']}; dex_date={candidate['dex_date']}"
                    ),
                }
            )
        except Exception as exc:
            destination.unlink(missing_ok=True)
            failures.append(
                {
                    "source": "AndroZoo",
                    "sha256": sha,
                    "error": safe_error(exc, api_key),
                }
            )
    return rows, failures


def read_manifest(manifest: Path) -> list[dict[str, str]]:
    if not manifest.exists():
        return []
    with manifest.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_manifest(rows: list[dict[str, str]], manifest: Path) -> None:
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign-count", type=int, default=10)
    parser.add_argument("--malware-count", type=int, default=10)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--max-size-mb", type=int, default=25)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    excluded_hashes, excluded_packages = load_exclusions(args.manifest)
    max_bytes = args.max_size_mb * 1024 * 1024
    if args.dry_run:
        fdroid = fdroid_candidates(
            requests.get(FDROID_INDEX, timeout=120).json(),
            excluded_hashes,
            excluded_packages,
            max_bytes,
        )
        print(
            json.dumps(
                {
                    "fdroid_candidates": len(fdroid),
                    "excluded_hashes": len(excluded_hashes),
                },
                indent=2,
            )
        )
        return

    existing_rows = read_manifest(args.manifest)
    existing_hashes = {row.get("sha256", "").strip().lower() for row in existing_rows}
    benign_rows, benign_failures = collect_fdroid(
        args.benign_count, max_bytes, excluded_hashes, excluded_packages
    )
    malware_rows, malware_failures = collect_androzoo(
        args.malware_count, max_bytes, excluded_hashes
    )
    new_rows = [
        row
        for row in benign_rows + malware_rows
        if row["sha256"].lower() not in existing_hashes
    ]
    rows = existing_rows + new_rows
    if rows:
        write_manifest(rows, args.manifest)
    report = {
        "collected_at": COLLECTED_AT,
        "existing_rows": len(existing_rows),
        "benign_collected": len(benign_rows),
        "malware_collected": len(malware_rows),
        "new_rows": len(new_rows),
        "failures": benign_failures + malware_failures,
        "manifest": str(args.manifest),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
