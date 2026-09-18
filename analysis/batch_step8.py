#!/usr/bin/env python3
"""
Batch run step8 obfuscation analysis on all 359 samples.
Outputs to analysis/obfuscation_cache.json (consolidated).
"""
import json
import os
import sys
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.step8_obfuscation_analysis import analyze_obfuscation

GROUND_TRUTH = Path("D:/DroidForensix/ground_truth_all.csv")
OUTPUT = Path("D:/DroidForensix/analysis/obfuscation_cache.json")
WORK_DIR = Path("D:/DroidForensix/analysis/obfuscation_work")
MAX_WORKERS = 4
TIMEOUT_PER_SAMPLE = 180


def load_ground_truth():
    gt = {}
    with open(GROUND_TRUTH) as f:
        for row in csv.DictReader(f):
            gt[row["sha256"].lower()] = {
                "apk_path": row.get("apk_path", ""),
                "family": row["family"],
            }
    return gt


def run_step8(sha256, apk_path, work_dir):
    """Run step8 on a single sample with timeout."""
    sample_dir = work_dir / sha256
    sample_dir.mkdir(parents=True, exist_ok=True)

    output_file = sample_dir / "step8_obfuscation.json"
    if output_file.exists():
        try:
            with open(output_file) as f:
                return json.load(f)
        except Exception:
            pass

    if not apk_path or not os.path.exists(apk_path):
        return {"error": f"APK not found: {apk_path}", "obfuscation_score": 0.0}

    try:
        result = analyze_obfuscation(
            apk_path=apk_path,
            work_dir=str(work_dir),
            sample_id=sha256,
        )
        return result
    except Exception as e:
        return {"error": str(e), "obfuscation_score": 0.0}


def main():
    gt = load_ground_truth()
    print(f"Loaded {len(gt)} samples from ground truth")

    # Check existing cache
    existing = {}
    if OUTPUT.exists():
        with open(OUTPUT) as f:
            existing = json.load(f)
    print(f"Existing cache: {len(existing)} samples")

    # Find samples that need processing
    to_process = []
    for sha256, info in gt.items():
        if sha256 in existing and "obfuscation_score" in existing[sha256]:
            continue
        apk_path = info.get("apk_path", "")
        if apk_path and os.path.exists(apk_path):
            to_process.append((sha256, apk_path))

    print(f"Samples to process: {len(to_process)}")
    if not to_process:
        print("Nothing to do!")
        return

    WORK_DIR.mkdir(parents=True, exist_ok=True)

    # Run in parallel
    results = {}
    completed = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(run_step8, sha256, apk_path, WORK_DIR): sha256
            for sha256, apk_path in to_process
        }

        for future in as_completed(futures):
            sha256 = futures[future]
            completed += 1
            try:
                result = future.result(timeout=TIMEOUT_PER_SAMPLE + 30)
                results[sha256] = result
                score = result.get("obfuscation_score", 0)
                level = result.get("obfuscation_level", "?")
                elapsed = time.time() - start_time
                rate = completed / elapsed * 60 if elapsed > 0 else 0
                print(
                    f"  [{completed}/{len(to_process)}] {sha256[:12]} "
                    f"score={score:.1f} level={level} "
                    f"({rate:.0f}/min, {elapsed:.0f}s elapsed)"
                )
            except Exception as e:
                results[sha256] = {"error": str(e), "obfuscation_score": 0}
                print(f"  [{completed}/{len(to_process)}] {sha256[:12]} ERROR: {e}")

            # Save intermediate results every 20 samples
            if completed % 20 == 0:
                merged = {**existing, **results}
                with open(OUTPUT, "w") as f:
                    json.dump(merged, f, indent=1)

    # Final save
    merged = {**existing, **results}
    with open(OUTPUT, "w") as f:
        json.dump(merged, f, indent=1)

    elapsed = time.time() - start_time
    print(f"\nDone! Processed {completed} samples in {elapsed:.0f}s")
    print(f"Total cache: {len(merged)} samples")
    print(f"Output: {OUTPUT}")


if __name__ == "__main__":
    main()
