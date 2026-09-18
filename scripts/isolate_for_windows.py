#!/usr/bin/env python3
"""Isolate samples that failed on this host into a Windows-ready recheck CSV.

Reads the batch metadata CSV (status column updated by run_batch_analysis.py)
and writes kali result/windows_recheck.csv in the same format, with only
samples that did NOT reach "analyzed". The error is recorded in the tags
column so a Windows run can tell why each sample was handed over.

Usage: python3 scripts/isolate_for_windows.py [--batch /tmp/opencode/error_batch.csv] [--out "kali result/windows_recheck.csv"]
"""
import argparse
import csv
import sys
from pathlib import Path

ERROR_LABELS = {
    "Pipeline process exited with code -9": "oom_killed",
    "Pipeline finished but produced no result": "runner_queue_race",
    "timeout after": "timeout_on_kali",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", default="/tmp/opencode/error_batch.csv")
    parser.add_argument("--out", default="kali result/windows_recheck.csv")
    args = parser.parse_args()

    batch_path = Path(args.batch)
    if not batch_path.exists():
        print(f"batch CSV not found: {batch_path}")
        sys.exit(1)

    with open(batch_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    failed = [r for r in rows if r.get("status") != "analyzed" and r.get("status") != "pending"]
    failed.sort(key=lambda r: r["sample_name"])

    fields = ["sample_name", "sha256", "md5", "family", "source", "type",
              "tags", "file_size_bytes", "status", "vt_detections", "collection_date"]
    out = []
    for r in failed:
        status = r.get("status", "")
        tag = next(
            (label for marker, label in ERROR_LABELS.items() if marker in status),
            "other_error",
        )
        out.append({
            "sample_name": r["sample_name"],
            "sha256": r["sha256"],
            "md5": "",
            "family": "",
            "source": r.get("source", ""),
            "type": r.get("type", ""),
            "tags": tag,
            "file_size_bytes": r.get("file_size_bytes", ""),
            "status": "pending",
            "vt_detections": "",
            "collection_date": "",
        })

    out_path = Path(args.out)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(out)

    print(f"wrote {len(out)} failed samples -> {out_path}")
    for row in out:
        size_mb = int(row["file_size_bytes"] or 0) / (1024 * 1024)
        print(f"  [{row['tags']:<18}] {row['sample_name']} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()