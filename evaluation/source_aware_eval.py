"""Source-aware evaluation: how much of the per-source accuracy gap is GT label
quality versus the pipeline?

Motivation (docs/accuracy-improvement-plan.md, thesis feedback): reviewers see
"abusech 35% family accuracy" and read it as a broken model. But abusech labels
are dominated by catch-all AV categories (AndroidOS/GenericKD) with no family
identity to match. This script separates the two:

  * measured label reliability per source, derived ONLY from the ground-truth
    CSV itself (no hand-set constants, no VT API calls):
      - specific_share           - non-catch-all family labels / total
      - external_confirmation    - labels backed by external consensus
                                    (gt_reason starts with vt_consensus /
                                    manual_analysis)
      - high_confidence_share    - GT confidence == high
  * family accuracy per source (from a predictions.json run)
  * source-reliability-weighted accuracy (bar chart vs raw)

Frame: the weighted number measures "accuracy on labels we have external reason
to trust", NOT a free accuracy inflation.

Usage:
    python evaluation/source_aware_eval.py \
        --predictions evaluation/metrics_v2/predictions.json \
        --features evaluation/classifier_data/features.csv \
        --output-dir evaluation/metrics_source_aware
"""

import argparse
import csv
import json
import sys
import warnings
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVALUATION_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(EVALUATION_DIR))

from run_validation_359 import is_correct

from analysis.labels import is_catch_all

DEFAULT_PREDICTIONS = PROJECT_ROOT / "evaluation" / "metrics_v2" / "predictions.json"
DEFAULT_GT = PROJECT_ROOT / "ground_truth_all_corrected.csv"
DEFAULT_FEATURES = PROJECT_ROOT / "evaluation" / "classifier_data" / "features.csv"
MODEL_PATH = PROJECT_ROOT / "evaluation" / "classifier_data" / "malben_rf.pkl"

# Weights for blending measured reliability indicators into a single number.
# All inputs are measured ratios in [0,1], so the blend is a ratio too.
RELIABILITY_WEIGHTS = {
    "specific_share": 0.4,
    "external_confirmation": 0.4,
    "high_confidence_share": 0.2,
}


def _csv_rows(path: Path) -> list[dict]:
    return list(csv.DictReader(path.open(newline="", encoding="utf-8")))


def measured_reliability(rows: list[dict]) -> dict:
    total = len(rows) or 1
    specific = sum(
        1
        for r in rows
        if not is_catch_all((r.get("family") or r.get("ground_truth") or "").strip())
    )
    external = sum(
        1
        for r in rows
        if (r.get("gt_reason") or "").startswith(("vt_consensus", "manual_analysis", "mb_"))
    )
    high = sum(1 for r in rows if r.get("confidence") == "high")
    shares = {
        "specific_share": specific / total,
        "external_confirmation": external / total,
        "high_confidence_share": high / total,
    }
    reliability = sum(shares[k] * RELIABILITY_WEIGHTS[k] for k in RELIABILITY_WEIGHTS)
    return {**shares, "label_reliability": round(reliability, 4)}


def family_by_source(gt_rows: list[dict], predictions: dict) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for pred in predictions.values():
        gt = next((r for r in gt_rows if r["sha256"].strip().lower() == pred["sha256"]), None)
        if gt is None:
            continue
        pred_family = (pred.get("prediction") or "unknown").strip()
        gt_family = gt["family"].strip()
        groups[gt["source"].strip()].append(
            {
                "sha256": pred["sha256"],
                "ground_truth": gt_family,
                "prediction": pred_family,
                "confidence": gt.get("confidence", "").strip(),
                "gt_reason": gt.get("gt_reason", "").strip(),
                "correct": is_correct(pred_family, gt_family),
            }
        )
    out = []
    for source, members in sorted(groups.items(), key=lambda item: -len(item[1])):
        acc = sum(m["correct"] for m in members) / len(members)
        rel = measured_reliability(members)
        out.append(
            {
                "source": source,
                "total": len(members),
                "family_accuracy": round(acc, 4),
                **rel,
            }
        )
    return out


def weighted_accuracy(per_source: list[dict], accuracy_key: str) -> float:
    """Accuracy over rows re-weighted by the share of trustworthy labels."""
    num = sum(s["total"] * s[accuracy_key] * s["label_reliability"] for s in per_source)
    den = sum(s["total"] * s["label_reliability"] for s in per_source)
    return round(num / den, 4) if den else 0.0


def binary_predictions(features_df: list[dict]) -> list[dict]:
    """Run the deployment RandomForest over the cached 20-feature rows."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        bundle = _load_bundle()
    model, feats = bundle
    rows = []
    for row in features_df:
        vec = [float(row[f]) for f in feats]
        proba = model.predict_proba([vec])[0]
        pred_mal = bool(proba[1] >= 0.5)
        rows.append(
            {
                "sha256": row["sha256"].strip().lower(),
                "source": row["source"].strip(),
                "is_malware": row["is_malware"] == "1",
                "predicted_malware": pred_mal,
                "confidence": round(float(proba[1]), 4),
                "correct": pred_mal == (row["is_malware"] == "1"),
                "family": row.get("family", "").strip(),
            }
        )
    return rows


def _load_bundle():
    import pickle

    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["features"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gt", type=Path, default=DEFAULT_GT)
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument(
        "--output-dir", type=Path, default=PROJECT_ROOT / "evaluation" / "metrics_source_aware"
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    gt_rows = _csv_rows(args.gt)
    predictions = {p["sha256"]: p for p in json.loads(args.predictions.read_text(encoding="utf-8"))}
    family_sources = family_by_source(gt_rows, predictions)
    fam_weighted = weighted_accuracy(family_sources, "family_accuracy")

    binary_rows = binary_predictions(_csv_rows(args.features))
    bin_groups: dict[str, list[dict]] = defaultdict(list)
    for row in binary_rows:
        bin_groups[row["source"]].append(row)
    binary_sources = []
    for source, members in sorted(bin_groups.items(), key=lambda item: -len(item[1])):
        acc = sum(m["correct"] for m in members) / len(members)
        rel = measured_reliability(members)
        binary_sources.append(
            {
                "source": source,
                "total": len(members),
                "in_sample_accuracy": round(acc, 4),
                **rel,
            }
        )
    bin_weighted = weighted_accuracy(binary_sources, "in_sample_accuracy")

    metrics = {
        "generated_at": __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat(),
        "family": {
            "by_source": family_sources,
            "raw_accuracy": round(
                sum(s["total"] * s["family_accuracy"] for s in family_sources)
                / sum(s["total"] for s in family_sources),
                4,
            ),
            "reliability_weighted_accuracy": fam_weighted,
            "frame": "weighted accuracy = shares of labels externally confirmed; "
            "it measures GT label quality, not a model accuracy ceiling.",
        },
        "binary": {
            "by_source": binary_sources,
            "in_sample_raw_accuracy": round(
                sum(s["total"] * s["in_sample_accuracy"] for s in binary_sources)
                / sum(s["total"] for s in binary_sources),
                4,
            ),
            "reliability_weighted_in_sample_accuracy": bin_weighted,
            "deployment_grade": "held-out 200 (real_world_accuracy_report.json): 0.970 "
            "overall, 0 FN, 6% FP; 5-fold CV (seed 0): 0.892",
        },
    }
    (args.output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("=" * 78)
    print("FAMILY - per source: raw accuracy vs measured label reliability")
    print(f"{'Source':<16} {'N':>4} {'Acc':>6} {'Rel':>6} {'Spec%':>6} {'Ext%':>6} {'High%':>6}")
    for s in family_sources:
        print(
            f"{s['source']:<16} {s['total']:>4} {s['family_accuracy']:>6.3f} "
            f"{s['label_reliability']:>6.3f} {s['specific_share']*100:>5.1f} "
            f"{s['external_confirmation']*100:>5.1f} {s['high_confidence_share']*100:>5.1f}"
        )
    print(f"Raw family accuracy          : {metrics['family']['raw_accuracy']:.4f}")
    print(f"Reliability-weighted accuracy: {fam_weighted:.4f}")
    print("-" * 78)
    print("BINARY - per source (RandomForest on cached features, no re-pipeline)")
    print(f"{'Source':<16} {'N':>4} {'Acc':>6} {'Rel':>6}")
    for s in binary_sources:
        print(
            f"{s['source']:<16} {s['total']:>4} {s['in_sample_accuracy']:>6.3f} {s['label_reliability']:>6.3f}"
        )
    print(
        f"Raw binary accuracy (in-sample 509 cache)   : {float(metrics['binary']['in_sample_raw_accuracy']):.4f}"
    )
    print(f"Reliability-weighted (in-sample)            : {bin_weighted:.4f}")
    print(f"Deployment-grade: held-out 0.970 / CV 0.892  " f"(real_world_accuracy_report.json)")
    print(f"Outputs written to: {args.output_dir}")


if __name__ == "__main__":
    main()
