"""Extract the 15-feature deployment vector for the validation and extra-training splits.

Same path as analysis/classify_fast.py (pipeline steps 1-6 + extract_feature_vector), so the
vectors match what the holdout run scored. Resumable: rows already in the output are skipped.

Usage: python evaluation/malben_eval/extract_split_features.py [--workers 4]
Output: evaluation/malben_eval/split_features.csv (sha256,group,label,status,error,vector...)
"""

import argparse
import csv
import shutil
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

HERE = Path(__file__).resolve().parent
INPUTS = [HERE / "validation_split.csv", HERE / "train_extra.csv"]
OUT = HERE / "split_features.csv"
PIPELINE_TIMEOUT = 600


def _extract(sha256: str, apk_rel: str) -> dict:
    from analysis.classify_fast import FEATURES, extract_feature_vector
    from analysis.pipeline import run_pipeline

    work = tempfile.mkdtemp(prefix="split_feat_")
    try:
        result = run_pipeline(str(ROOT / apk_rel), work, event_emitter=None,
                              pipeline_timeout=PIPELINE_TIMEOUT, stop_after=6)
        vec = extract_feature_vector(result)
        return {"sha256": sha256, "status": "ok", "error": "", "vector": vec, "n": len(FEATURES)}
    except Exception as exc:  # recorded per sample, never silently dropped
        return {"sha256": sha256, "status": "error", "error": repr(exc)[:300], "vector": [], "n": 0}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _load_rows() -> list:
    rows = []
    for path in INPUTS:
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows.append({"sha256": r["sha256"], "path": r["path"], "label": r["label"], "group": r["group"]})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    from analysis.classify_fast import FEATURES

    rows = _load_rows()
    done = {}
    if OUT.exists():
        with open(OUT, encoding="utf-8") as f:
            done = {r["sha256"]: r for r in csv.DictReader(f)}
    pending = [r for r in rows if r["sha256"] not in done or done[r["sha256"]]["status"] != "ok"]
    missing = [r["path"] for r in pending if not (ROOT / r["path"]).exists()]
    print(f"{len(rows)} rows, {len(done)} already in output, {len(pending)} to run, {len(missing)} APK files missing", flush=True)
    if missing:
        raise SystemExit("missing APKs: " + ", ".join(missing[:5]))

    header = ["sha256", "group", "label", "status", "error"] + FEATURES
    results = dict(done)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_extract, r["sha256"], r["path"]): r for r in pending}
        for i, fut in enumerate(as_completed(futures), 1):
            meta = futures[fut]
            res = fut.result()
            results[meta["sha256"]] = {
                "sha256": meta["sha256"], "group": meta["group"], "label": meta["label"],
                "status": res["status"], "error": res["error"],
                **{f: v for f, v in zip(FEATURES, res["vector"])},
            }
            if i % 10 == 0 or i == len(pending):
                _write(results, header)
                print(f"{i}/{len(pending)} done", flush=True)
    _write(results, header)
    errors = sum(1 for r in results.values() if r["status"] != "ok")
    print(f"finished: {len(results)} rows, {errors} errors", flush=True)


def _write(results: dict, header: list) -> None:
    tmp = OUT.with_suffix(".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=header, extrasaction="ignore")
        w.writeheader()
        for r in results.values():
            w.writerow(r)
    tmp.replace(OUT)


if __name__ == "__main__":
    main()
