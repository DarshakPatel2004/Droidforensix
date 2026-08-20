"""
check_ground_truth.py — Check ground truth of all APK samples on disk.

For every APK in samples/:
  1. Resolve its sha256 (metadata -> filename -> computed).
  2. Consolidate the existing ground truth label from ground_truth_all.csv,
     sample_metadata.csv, and error_apks.csv.
  3. Re-verify samples that lack a strong label (benign_eval with no VT data,
     low-confidence malware, unknown families) via MalwareBazaar then
     VirusTotal, using a persistent cache so re-runs are cheap.
  4. Write a segregated report (by ground-truth class then source) plus a
     summary CSV to the repo root.

Usage:
    python scripts/check_ground_truth.py          # consolidate + recheck gaps
    python scripts/check_ground_truth.py --skip-recheck   # local only
    python scripts/check_ground_truth.py --recheck-all    # recheck every sample
"""

import argparse
import csv
import hashlib
import json
import re
import sys
import time
from collections import Counter, OrderedDict
from pathlib import Path

import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

ROOT = PROJECT_ROOT
SAMPLES_DIR = ROOT / "samples"
GT_CSV = ROOT / "ground_truth_all.csv"
META_CSV = ROOT / "sample_metadata.csv"
ERROR_CSV = ROOT / "error_apks.csv"

OUTPUT_ALL = ROOT / "ground_truth_check_all.csv"
OUTPUT_SUMMARY = ROOT / "ground_truth_check_summary.csv"
CACHE_PATH = ROOT / "evaluation" / "gt_recheck_cache.json"

VT_KEY = __import__("os").environ.get("VT_KEY", "")
MB_API_KEY = (
    __import__("os").environ.get("MALWAREBAZAAR_API_KEY")
    or __import__("os").environ.get("ABUSECH_API_KEY")
    or ""
)
MB_API = "https://mb-api.abuse.ch/api/v1/"
VT_BASE = "https://www.virustotal.com/api/v3"

VT_RATE_LIMIT_SEC = 16.0
MB_RATE_LIMIT_SEC = 6.0

SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")


# ---------------------------------------------------------------------------
# Input loading
# ---------------------------------------------------------------------------
def load_gt_rows() -> dict:
    """{sha256.lower(): row} from ground_truth_all.csv."""
    if not GT_CSV.exists():
        return {}
    with open(GT_CSV, newline="", encoding="utf-8") as f:
        return {r["sha256"].lower(): r for r in csv.DictReader(f)}


def load_meta_rows() -> dict:
    """{sample_name: row} from sample_metadata.csv."""
    if not META_CSV.exists():
        return {}
    with open(META_CSV, newline="", encoding="utf-8") as f:
        return {r["sample_name"]: r for r in csv.DictReader(f)}


def load_error_rows() -> dict:
    """{sample_name: error_type} from error_apks.csv."""
    if not ERROR_CSV.exists():
        return {}
    with open(ERROR_CSV, newline="", encoding="utf-8") as f:
        return {r["sample_name"]: r["error_type"] for r in csv.DictReader(f)}


# ---------------------------------------------------------------------------
# Sample discovery
# ---------------------------------------------------------------------------
def resolve_sha256(path: Path, meta_row: dict) -> str:
    """Return the sample's sha256: metadata, then filename, then computed."""
    if meta_row and meta_row.get("sha256"):
        return meta_row["sha256"].lower()
    stem = path.stem
    if SHA_RE.fullmatch(stem):
        return stem.lower()
    if stem.startswith("unknown_") and SHA_RE.fullmatch(stem[8:]):
        return stem[8:].lower()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def discover_samples(meta_by_name: dict) -> list:
    """Return sorted list of {path, sha256, meta, source} for every APK."""
    samples = []
    for p in sorted(SAMPLES_DIR.rglob("*.apk")):
        meta = meta_by_name.get(p.name, {})
        sha = resolve_sha256(p, meta)
        samples.append(
            {
                "path": p,
                "name": p.name,
                "sha256": sha,
                "meta": meta,
                "source": meta.get("source") or p.parent.name,
            }
        )
    return samples


# ---------------------------------------------------------------------------
# External re-verification
# ---------------------------------------------------------------------------
def load_cache() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_cache(cache: dict):
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def mb_query(sha256: str) -> dict:
    """Query MalwareBazaar. Returns family/tags/vt_score or {} if absent."""
    if not MB_API_KEY:
        return {}
    try:
        resp = requests.post(
            MB_API,
            data={"query": "get_info", "hash": sha256},
            headers={"Auth-Key": MB_API_KEY},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                info = data["data"][0]
                return {
                    "engine": "malwarebazaar",
                    "family": info.get("signature") or "",
                    "vt_detections": info.get("vt_score", 0),
                    "tags": info.get("tags", []),
                }
    except Exception as e:
        print(f"  [MB ERR] {sha256[:16]}: {e}")
    return {}


def vt_query(sha256: str) -> dict:
    """Query VirusTotal. Returns malicious count + top family or {} if absent."""
    if not VT_KEY:
        return {}
    try:
        resp = requests.get(
            f"{VT_BASE}/files/{sha256}",
            headers={"x-apikey": VT_KEY},
            timeout=30,
        )
        if resp.status_code == 404:
            return {"engine": "virustotal", "not_found": True}
        if resp.status_code == 429:
            print(f"  [VT] rate-limited on {sha256[:16]}, waiting 60s")
            time.sleep(60)
            return {}
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)

        family_votes: Counter = Counter()
        results = attrs.get("last_analysis_results", {})
        for res in results.values():
            label = (res.get("result") or "").strip()
            if label and label not in ("clean", "unrated"):
                parts = label.replace("Android.", "").replace(":", ".").split(".")
                for part in parts:
                    if part and part not in (
                        "Trojan",
                        "Android",
                        "Malware",
                        "Riskware",
                        "PUA",
                        "Generic",
                    ):
                        family_votes[part] += 1
        top_family = family_votes.most_common(1)[0][0] if family_votes else ""
        return {
            "engine": "virustotal",
            "family": top_family,
            "vt_detections": malicious,
            "not_found": False,
        }
    except Exception as e:
        print(f"  [VT ERR] {sha256[:16]}: {e}")
    return {}


def recheck_sample(sha256: str, cache: dict) -> dict:
    """Recheck one sha256, using cache first. Returns the result dict."""
    if sha256 in cache:
        return cache[sha256]
    result = mb_query(sha256)
    if result:
        cache[sha256] = result
        save_cache(cache)
        return result
    time.sleep(MB_RATE_LIMIT_SEC)
    result = vt_query(sha256)
    if result:
        cache[sha256] = result
        save_cache(cache)
        return result
    cache[sha256] = {"engine": "none", "not_found": True}
    save_cache(cache)
    return cache[sha256]


# ---------------------------------------------------------------------------
# Label merge
# ---------------------------------------------------------------------------
def build_report(samples: list, gt_by_sha: dict, error_by_name: dict) -> list:
    """Merge existing ground truth into per-sample records."""
    report = []
    for s in samples:
        gt = gt_by_sha.get(s["sha256"])
        meta = s["meta"]
        error = error_by_name.get(s["name"], "")

        is_malware = "unknown"
        family = ""
        confidence = ""
        vt_detections = ""
        gt_reason = ""

        if gt:
            is_malware = gt.get("is_malware", "unknown")
            family = gt.get("family", "")
            confidence = gt.get("confidence", "")
            vt_detections = gt.get("vt_detections", "")
            gt_reason = gt.get("gt_reason", "existing_ground_truth")
        elif s["source"] == "benign_eval":
            is_malware = "no"
            confidence = "medium"
            gt_reason = "benign_source"
            vt_detections = meta.get("vt_detections", "")
        else:
            gt_reason = "no_ground_truth"

        # Determine segregation class
        if is_malware == "yes":
            cls = f"malware_{confidence or 'unknown'}"
        elif is_malware == "no":
            cls = "benign"
        else:
            cls = "unknown"

        report.append(
            {
                "class": cls,
                "sha256": s["sha256"],
                "sample_name": s["name"],
                "source": s["source"],
                "is_malware": is_malware,
                "family": family,
                "confidence": confidence,
                "vt_detections": vt_detections,
                "gt_reason": gt_reason,
                "analysis_status": meta.get("status", "") if meta else "",
                "error": error,
                "file_path": str(s["path"]),
                # filled in by recheck step
                "recheck_engine": "",
                "recheck_family": "",
                "recheck_vt_detections": "",
                "recheck_note": "",
            }
        )
    return report


def apply_recheck(report: list, cache: dict, recheck_all: bool):
    """Attach external re-verification results to the report."""
    needs = {
        id(r)
        for r in report
        if (
            recheck_all
            or r["class"] == "benign"
            or r["confidence"] == "low"
            or r["family"] in ("unknown", "")
            or r["gt_reason"] in ("no_ground_truth",)
        )
    }
    todo = [r for r in report if id(r) in needs]
    total = len(todo)
    done = 0
    for row in todo:
        done += 1
        sha = row["sha256"]
        print(f"  [{done}/{total}] {row['source']} {sha[:12]}...", flush=True)
        res = recheck_sample(sha, cache)
        row["recheck_engine"] = res.get("engine", "")
        row["recheck_family"] = res.get("family", "")
        row["recheck_vt_detections"] = res.get("vt_detections", "")
        if res.get("not_found"):
            row["recheck_note"] = "not_found_in_threat_intel"
        elif res.get("engine"):
            row["recheck_note"] = "confirmed_external"


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def write_outputs(report: list):
    fieldnames = [
        "class",
        "sha256",
        "sample_name",
        "source",
        "is_malware",
        "family",
        "confidence",
        "vt_detections",
        "gt_reason",
        "recheck_engine",
        "recheck_family",
        "recheck_vt_detections",
        "recheck_note",
        "analysis_status",
        "error",
        "file_path",
    ]

    # Segregate: sort by class, then source, then sha256
    sorted_rows = sorted(report, key=lambda r: (r["class"], r["source"], r["sha256"]))

    with open(OUTPUT_ALL, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sorted_rows)

    # Summary: counts by class, and class x source
    class_counts = Counter(r["class"] for r in report)
    class_source = Counter((r["class"], r["source"]) for r in report)
    with open(OUTPUT_SUMMARY, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["class", "source", "count"])
        for (cls, src), n in sorted(class_source.items()):
            w.writerow([cls, src, n])
        w.writerow(["TOTAL", "ALL", len(report)])
        w.writerow([])
        w.writerow(["class", "", "count"])
        for cls, n in sorted(class_counts.items()):
            w.writerow([cls, "", n])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-recheck", action="store_true", help="consolidate existing labels only"
    )
    parser.add_argument(
        "--recheck-all", action="store_true", help="recheck every sample externally"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("DroidForensix Ground Truth Check")
    print("=" * 60)

    gt_by_sha = load_gt_rows()
    meta_by_name = load_meta_rows()
    error_by_name = load_error_rows()

    print(f"Existing GT rows: {len(gt_by_sha)}")
    print(f"Metadata rows:    {len(meta_by_name)}")
    print(f"Error rows:       {len(error_by_name)}")

    samples = discover_samples(meta_by_name)
    print(f"APKs on disk:     {len(samples)}")

    report = build_report(samples, gt_by_sha, error_by_name)
    print("\nSegregation (existing labels):")
    for cls, n in Counter(r["class"] for r in report).most_common():
        print(f"  {cls}: {n}")

    if not args.skip_recheck:
        cache = load_cache()
        print(f"\nRe-verification (cache: {len(cache)} entries) ...")
        apply_recheck(report, cache, args.recheck_all)
        print(f"  cache now: {len(cache)} entries")

    write_outputs(report)
    print(f"\nWrote {OUTPUT_ALL}")
    print(f"Wrote {OUTPUT_SUMMARY}")

    print("\nRecheck summary:")
    for note, n in Counter(
        r["recheck_note"] or "not_rechecked" for r in report
    ).most_common():
        print(f"  {note}: {n}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())