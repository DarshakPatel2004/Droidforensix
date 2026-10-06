"""Evaluate the current binary model on a frozen fresh-corpus manifest."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.classify_fast import classify_malware_fast

DEFAULT_MANIFEST = ROOT / "evaluation" / "FRESH_CORPUS_MANIFEST.csv"
DEFAULT_PREDICTIONS = ROOT / "evaluation" / "validation_359" / "fresh_binary_predictions.json"
DEFAULT_REPORT = ROOT / "evaluation" / "validation_359" / "fresh_binary_report.json"


def manifest_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate(manifest: Path, predictions_path: Path, report_path: Path, timeout: int) -> dict:
    with manifest.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    results: list[dict] = []
    for index, row in enumerate(rows, start=1):
        apk_path = ROOT / row["path"]
        try:
            predicted_malware, confidence = classify_malware_fast(
                str(apk_path),
                pipeline_timeout=timeout,
                work_dir=str(ROOT / "evaluation" / "validation_359" / "fresh_work"),
            )
            result = {
                "sha256": row["sha256"],
                "label": row["label"],
                "source": row["source"],
                "predicted_malware": bool(predicted_malware),
                "confidence": float(confidence),
                "correct": bool(predicted_malware) == (row["label"] == "malware"),
                "status": "success",
            }
        except Exception as exc:
            result = {
                "sha256": row["sha256"],
                "label": row["label"],
                "source": row["source"],
                "predicted_malware": None,
                "confidence": None,
                "correct": False,
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }
        results.append(result)
        print(f"[{index}/{len(rows)}] {row['label']} {result['status']}", flush=True)

    evaluated = [row for row in results if row["status"] == "success"]
    by_label = defaultdict(lambda: {"total": 0, "correct": 0, "errors": 0})
    by_source = defaultdict(lambda: {"total": 0, "correct": 0, "errors": 0})
    for row in results:
        label_stats = by_label[row["label"]]
        source_stats = by_source[row["source"]]
        label_stats["total"] += 1
        source_stats["total"] += 1
        if row["status"] == "success":
            label_stats["correct"] += int(row["correct"])
            source_stats["correct"] += int(row["correct"])
        else:
            label_stats["errors"] += 1
            source_stats["errors"] += 1

    report = {
        "manifest": str(manifest),
        "manifest_sha256": manifest_sha256(manifest),
        "model": "evaluation/classifier_data/malben_rf.pkl (15 features)",
        "pipeline": "classify_malware_fast, steps 1-6, no LLM",
        "total": len(results),
        "evaluated": len(evaluated),
        "errors": len(results) - len(evaluated),
        "accuracy": round(sum(row["correct"] for row in evaluated) / len(evaluated), 4)
        if evaluated
        else 0.0,
        "by_label": {
            key: {
                **stats,
                "accuracy": round(stats["correct"] / (stats["total"] - stats["errors"]), 4)
                if stats["total"] - stats["errors"]
                else 0.0,
            }
            for key, stats in sorted(by_label.items())
        },
        "by_source": {
            key: {
                **stats,
                "accuracy": round(stats["correct"] / (stats["total"] - stats["errors"]), 4)
                if stats["total"] - stats["errors"]
                else 0.0,
            }
            for key, stats in sorted(by_source.items())
        },
        "prediction_counts": dict(Counter(
            "malware" if row["predicted_malware"] else "benign"
            for row in evaluated
        )),
    }
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    predictions_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    report = evaluate(args.manifest, args.predictions, args.report, args.timeout)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
