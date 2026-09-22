"""Misclassification root-cause analysis for BOTH classifiers.

Binary misses come from the explainer output (evaluation/binary_explanations.json).
Family misses are computed by joining the repo-retained predictions
(evaluation/metrics_v2/predictions.json) against the corrected ground truth,
then bucketing each miss:

  * label_unresolvable  - GT family is a catch-all AV category (AndroidOS/*,
                          GenericKD, 'suspicious', ...) that no engine can match;
                          only lowers the accuracy floor, not a model fault.
  * abstention          - GT is specific, prediction is a low-confidence generic
                          or 'unknown': the pipeline declined to commit.
  * wrong_family        - GT specific, prediction is a DIFFERENT specific family
                          (the real correctness ceiling).
  * under_matched       - GT specific, prediction stayed on a generic/catch-all
                          label instead of the specific family.

Usage:
    python evaluation/misclassification_analysis.py \
        --output-dir evaluation/metrics_misclassification
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_validation_359 import is_correct

from analysis.labels import is_catch_all

DEFAULT_GT = ROOT / "ground_truth_all_corrected.csv"
DEFAULT_PREDICTIONS = ROOT / "evaluation" / "metrics_v2" / "predictions.json"
DEFAULT_EXPLANATIONS = ROOT / "evaluation" / "binary_explanations.json"


def family_root_causes(gt_rows: list[dict], predictions: list[dict]) -> dict:
    gt_index = {r["sha256"].strip().lower(): r for r in gt_rows}
    buckets: dict[str, list[dict]] = defaultdict(list)
    for pred in predictions:
        gt = gt_index.get(pred.get("sha256", "").strip().lower())
        if gt is None:
            continue
        pred_fam = (pred.get("prediction") or "unknown").strip()
        gt_fam = gt["family"].strip()
        if is_correct(pred_fam, gt_fam):
            continue
        if is_catch_all(gt_fam):
            bucket = "label_unresolvable"
        elif is_catch_all(pred_fam):
            bucket = "under_matched"
        elif "unknown" in pred_fam.lower() or "suspicious" in pred_fam.lower():
            bucket = "abstention"
        else:
            bucket = "wrong_family"
        buckets[bucket].append(
            {
                "sha256": pred["sha256"],
                "source": gt["source"].strip(),
                "ground_truth": gt_fam,
                "prediction": pred_fam,
            }
        )

    summary = {}
    for bucket, rows in sorted(buckets.items()):
        by_source = Counter(r["source"] for r in rows)
        rep = sorted(rows, key=lambda r: (r["source"], r["sha256"]))[:3]
        summary[bucket] = {
            "count": len(rows),
            "by_source": dict(by_source.most_common()),
            "examples": rep,
        }
    return summary


def binary_root_causes(explanations: list[dict]) -> dict:
    fns = [e for e in explanations if not e["correct"] and e["gt_malware"]]
    fps = [e for e in explanations if not e["correct"] and not e["gt_malware"]]
    out = {}
    for label, misses in (("false_negative", fns), ("false_positive", fps)):
        by_source = Counter(m["source"] for m in misses)
        common_signal = Counter()
        for m in misses:
            for s in m["top_signals"][:3]:
                common_signal[(s["feature"], s["lean"])] += 1
        out[label] = {
            "count": len(misses),
            "by_source": dict(by_source.most_common()),
            "dominating_top_signals": [
                {"signal": f"{feat}->{lean}", "count": n}
                for (feat, lean), n in common_signal.most_common(5)
            ],
            "examples": sorted(misses, key=lambda m: abs(m["confidence"] - 0.5))[:4],
        }
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gt", type=Path, default=DEFAULT_GT)
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    parser.add_argument("--explanations", type=Path, default=DEFAULT_EXPLANATIONS)
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "evaluation" / "metrics_misclassification"
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    gt_rows = list(csv.DictReader(args.gt.open(newline="", encoding="utf-8")))
    predictions = json.loads(args.predictions.read_text(encoding="utf-8"))
    explanations = json.loads(args.explanations.read_text(encoding="utf-8"))

    family = family_root_causes(gt_rows, predictions)
    binary = binary_root_causes(explanations)

    report = {
        "family_misses": family,
        "binary_misses": binary,
    }
    (args.output_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    def top_sources(source_counts: dict, limit: int = 3) -> dict:
        ordered = sorted(source_counts.items(), key=lambda pair: -pair[1])
        return {source: count for source, count in ordered[:limit]}

    print("=" * 78)
    print("FAMILY misses (baseline predictions vs corrected GT)")
    for bucket, info in family.items():
        top = top_sources(info["by_source"])
        print(f"  {bucket:<18} n={info['count']:>4}  sources={top}")
        for ex in info["examples"]:
            print(
                f"    {ex['sha256'][:12]} {ex['source']:<16} gt={ex['ground_truth']:<24} "
                f"pred={ex['prediction']}"
            )
    print("-" * 78)
    print("BINARY misses (RandomForest on cached features)")
    for label, info in binary.items():
        top = top_sources(info["by_source"])
        dominating = ", ".join(s["signal"] for s in info["dominating_top_signals"][:4])
        print(f"  {label:<20} n={info['count']:>4}  sources={top}")
        print(f"    dominating top signals: {dominating}")
        for ex in info["examples"]:
            print(
                f"    {ex['sha256'][:12]} {ex['source']:<16} proba={ex['confidence']:.3f} "
                f"c2={ex['feature_values'].get('num_c2')} perms={ex['feature_values'].get('num_dangerous_perms')}"
            )
    print(f"Report written to: {args.output_dir}")


if __name__ == "__main__":
    main()
