"""Run the full pipeline and family identification over the selected LAMDA APKs.

Ground-truth lookup is disabled for family identification. For each APK the record keeps the
family prediction and the classifier feature vector. The pipeline work folder for that APK is
deleted once its record is written, to save disk. The APKs in samples/lamda are kept.

Usage:
    python evaluation/run_lamda_pipeline.py <shard> <shards>
Writes evaluation/lamda_fetch/run_log_<shard>.jsonl. Re-running skips APKs already recorded.
"""

import json
import shutil
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SELECTION = PROJECT_ROOT / "evaluation" / "lamda_fetch" / "selection.json"
SAMPLES_DIR = PROJECT_ROOT / "samples" / "lamda"
RUN_DIR = PROJECT_ROOT / "evaluation" / "lamda_fetch"
WORK_DIR = PROJECT_ROOT / "evaluation" / "lamda_run" / "work"


def main() -> int:
    shard, shards = int(sys.argv[1]), int(sys.argv[2])
    sys.path.insert(0, str(PROJECT_ROOT))
    from backend import family_id
    family_id.GROUND_TRUTH_FILES = []  # no label leakage into identification
    family_id._ground_truth_map.cache_clear()
    from analysis.classify_fast import extract_feature_vector
    from analysis.pipeline import run_pipeline

    selection = json.loads(SELECTION.read_text(encoding="utf-8"))
    mine = [row for i, row in enumerate(selection) if i % shards == shard]
    out_path = RUN_DIR / f"run_log_{shard}.jsonl"
    done = set()
    if out_path.exists():
        done = {json.loads(line)["sha256"] for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()}

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as out:
        for row in mine:
            sha = row["sha256"]
            if sha in done:
                continue
            apk = SAMPLES_DIR / f"{sha}.apk"
            start = time.time()
            record = {"sha256": sha, "family": row["family"], "group": row["group"]}
            try:
                result = run_pipeline(str(apk), work_dir=str(WORK_DIR / f"w{shard}"), pipeline_timeout=1200)
                fam = result.get("family_identification") or {}
                record.update({"status": "ok", "prediction": fam.get("family", "unknown"),
                               "confidence": fam.get("confidence", 0.0),
                               "method": fam.get("method", "none"),
                               "candidates": (fam.get("candidates") or [])[:5],
                               "features": extract_feature_vector(result)})
            except Exception as exc:  # recorded, never dropped
                record.update({"status": "error", "error": f"{type(exc).__name__}: {exc}"[:300]})
            record["seconds"] = round(time.time() - start, 1)
            out.write(json.dumps(record, default=str) + "\n")
            out.flush()
            shutil.rmtree(WORK_DIR / f"w{shard}" / sha, ignore_errors=True)
            print(record["status"], row["group"], row["family"], flush=True)
    print(f"shard {shard} done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
