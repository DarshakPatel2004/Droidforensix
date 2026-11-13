"""Fetch a random sample of F-Droid apps as new benign APKs.

Uses the public F-Droid index (index-v1.jar). Takes the newest version of each sampled app,
skips hashes already in training or LAMDA, and keeps a file only if its sha256 matches the index.

Usage: fetch_fdroid_benign.py <count> [seed]
Output: samples/new_benign/<sha256>.apk and evaluation/fdroid_benign_fetch.jsonl
"""

import csv
import hashlib
import json
import random
import sys
import zipfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://f-droid.org/repo/"
OUT_DIR = ROOT / "samples" / "new_benign"
INDEX_PATH = ROOT / "samples" / "new_benign_fdroid_tmp" / "index-v1.jar"
LOG_PATH = ROOT / "evaluation" / "fdroid_benign_fetch.jsonl"
MAX_SIZE = 60 * 1024 * 1024


def used_hashes() -> set[str]:
    used = set()
    for path in [
        ROOT / "evaluation" / "classifier_data" / "features.csv",
        ROOT / "evaluation" / "classifier_eval_2026-10-23" / "pilot_gt.csv",
        ROOT / "evaluation" / "new_benign_gt.csv",
        ROOT / "evaluation" / "new_malware_fetch.jsonl",
        ROOT / "evaluation" / "malben_eval" / "manifest.csv",
        ROOT / "evaluation" / "malben_eval" / "validation_split.csv",
        ROOT / "evaluation" / "malben_eval" / "train_extra.csv",
    ]:
        if path.suffix == ".jsonl":
            used |= {json.loads(l)["sha256"].lower() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()}
        else:
            used |= {r["sha256"].lower() for r in csv.DictReader(path.open(encoding="utf-8"))}
    selection = json.loads((ROOT / "evaluation" / "lamda_fetch" / "selection.json").read_text(encoding="utf-8"))
    used |= {x["sha256"].lower() for x in selection}
    return used


def newest_version(versions: list[dict]) -> dict | None:
    eligible = [v for v in versions if v.get("hashType") == "sha256" and v.get("size", 0) <= MAX_SIZE]
    return max(eligible, key=lambda v: v.get("versionCode", 0)) if eligible else None


def main() -> None:
    count = int(sys.argv[1])
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 42
    index = json.loads(zipfile.ZipFile(INDEX_PATH).read("index-v1.json"))
    used = used_hashes()
    packages = sorted(index["packages"])
    random.Random(seed).shuffle(packages)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    fetched = 0
    with LOG_PATH.open("a", encoding="utf-8") as log:
        for pkg in packages:
            if fetched >= count:
                break
            entry = newest_version(index["packages"][pkg])
            if entry is None:
                continue
            sha = entry["hash"].lower()
            dest = OUT_DIR / f"{sha}.apk"
            if sha in used or dest.exists():
                continue
            status = "error"
            try:
                resp = requests.get(REPO + entry["apkName"], timeout=300)
                if resp.status_code != 200:
                    status = f"http_{resp.status_code}"
                elif hashlib.sha256(resp.content).hexdigest() != sha:
                    status = "hash_mismatch"
                else:
                    dest.write_bytes(resp.content)
                    status = "ok"
                    fetched += 1
            except requests.RequestException as exc:
                status = f"error: {str(exc)[:120]}"
            log.write(json.dumps({"package": pkg, "sha256": sha, "status": status}) + "\n")
            log.flush()
    print(f"fetched {fetched} F-Droid benign APKs (target {count})")


if __name__ == "__main__":
    main()
