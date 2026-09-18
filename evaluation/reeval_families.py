"""Re-evaluate family identification using cached pipeline results.

Loads each malware sample's cached pipeline result (analysis/work/<sha>),
re-runs ONLY family identification (signature_v3 + knowledge-base matcher +
LLM with candidate guidance), and writes predictions in the format
evaluation/metrics_recompute.py expects.

Run:
    python evaluation/reeval_families.py --output-dir evaluation/metrics_v2

Then:
    python evaluation/metrics_recompute.py \
        --gt ground_truth_all_corrected.csv \
        --predictions evaluation/metrics_v2/predictions.json \
        --output-dir evaluation/metrics_v2
"""

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv

load_dotenv(PROJECT_ROOT / ".env")

WORK_DIR = PROJECT_ROOT / "analysis" / "work"
GT_CHECK = PROJECT_ROOT / "ground_truth_check_all.csv"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("reeval")


def _init_worker():
    """Per-worker init: disable ground-truth leakage."""
    from backend import family_id
    family_id.GROUND_TRUTH_FILES = []
    family_id._ground_truth_map.cache_clear()


def _worker(sha: str) -> dict:
    from backend import family_id
    from backend.config import settings
    settings.WORK_DIR = WORK_DIR
    result_path = WORK_DIR / sha / "pipeline_result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result.pop("family_identification", None)
    outcome = family_id.identify_family(sha, result, use_llm=True, use_cache=False)
    return {
        "sha256": sha,
        "prediction": outcome.get("family", "unknown"),
        "confidence": outcome.get("confidence", 0.0),
        "method": outcome.get("method", "none"),
        "reasoning": outcome.get("reasoning", ""),
        "candidates": outcome.get("candidates", [])[:5],
        "status": "success",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "evaluation" / "metrics_v2")
    parser.add_argument("--parallel", "-p", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    import csv
    rows = list(csv.DictReader(GT_CHECK.open(newline="", encoding="utf-8")))
    malware = [
        r for r in rows
        if r["class"].startswith("malware") and (WORK_DIR / r["sha256"].lower() / "pipeline_result.json").exists()
    ]
    if args.limit:
        malware = malware[: args.limit]
    shas = [r["sha256"].lower() for r in malware]
    print(f"Re-evaluating {len(shas)} samples -> {args.output_dir}", flush=True)

    results = []
    if args.parallel > 1:
        with ProcessPoolExecutor(max_workers=args.parallel, initializer=_init_worker) as ex:
            futures = {ex.submit(_worker, sha): sha for sha in shas}
            for i, future in enumerate(as_completed(futures), 1):
                res = future.result()
                results.append(res)
                print(f"  [{i}/{len(shas)}] {res['sha256'][:12]}: {res['method']} -> {res['prediction']} ({res['confidence']})", flush=True)
    else:
        _init_worker()
        for i, sha in enumerate(shas, 1):
            res = _worker(sha)
            results.append(res)
            print(f"  [{i}/{len(shas)}] {res['sha256'][:12]}: {res['method']} -> {res['prediction']} ({res['confidence']})", flush=True)

    (args.output_dir / "predictions.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"Wrote {len(results)} predictions -> {args.output_dir / 'predictions.json'}")


if __name__ == "__main__":
    main()