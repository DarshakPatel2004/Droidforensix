"""Fetch APKs from AndroZoo for LAMDA malware rows, keyed by LAMDA's sha256 hash.

Reads the selection written by evaluation/select_lamda_samples.py. Each downloaded file must
match its hash before it is kept. Output: samples/lamda/<sha256>.apk and
evaluation/lamda_fetch/fetch_log.jsonl.

Usage:
    python evaluation/fetch_lamda_apks.py evaluation/lamda_fetch/selection.json [--limit N]
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
SAMPLES_DIR = PROJECT_ROOT / "samples" / "lamda"
LOG_DIR = PROJECT_ROOT / "evaluation" / "lamda_fetch"
ANDROZOO_API = "https://androzoo.uni.lu/api/download"


def read_androzoo_key() -> str:
    """Return the AndroZoo key from the environment or .env. Never prints it."""
    key = os.environ.get("ANDROZOO_API_KEY")
    if key:
        return key
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("ANDROZOO_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError("ANDROZOO_API_KEY not found in environment or .env")


def download(sha256: str, key: str, dest: Path) -> str:
    query = urllib.parse.urlencode({"apikey": key, "sha256": sha256})
    with urllib.request.urlopen(f"{ANDROZOO_API}?{query}", timeout=300) as resp, open(dest, "wb") as out:
        digest = hashlib.sha256()
        while chunk := resp.read(1 << 20):
            out.write(chunk)
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("selection", type=Path)
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args()
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    key = read_androzoo_key()
    log_path = LOG_DIR / "fetch_log.jsonl"
    done = set()
    if log_path.exists():
        done = {json.loads(line)["sha256"] for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()}

    selection = json.loads(args.selection.read_text(encoding="utf-8"))
    candidates = [(row["family"], row["sha256"]) for row in selection]

    fetched = 0
    with open(log_path, "a", encoding="utf-8") as log:
        for family, sha in candidates:
            if fetched >= args.limit:
                break
            if sha in done:
                continue
            dest = SAMPLES_DIR / f"{sha}.apk"
            record = {"sha256": sha, "family": family}
            try:
                digest = download(sha, key, dest)
                if digest != sha:
                    dest.unlink()
                    record.update({"status": "hash_mismatch"})
                else:
                    record.update({"status": "ok"})
                    fetched += 1
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
                record.update({"status": "error", "error": f"{type(exc).__name__}: {exc}"[:200]})
            log.write(json.dumps(record) + "\n")
            log.flush()
            print(f"{record['status']} {family} {sha[:12]}", flush=True)
    print(f"fetched {fetched}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
