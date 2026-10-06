"""Head-to-head evaluation: production family engine vs multi-signal fusion.

Additive evaluator for ``analysis/family_confidence_scorer.py``. Loads the
retained production predictions (evaluation/metrics_v2/predictions.json), the
corrected ground truth, and the gap-feature cache, then scores every sample the
fusion scorer can handle and reports:

  * baseline accuracy on the same subset (fair, apples-to-apples)
  * fusion accuracy at the abstention bar (default 0.75)
  * an abstention trade-off sweep (bar 0.55..0.85)
  * per-source and per-family breakdowns
  * which GT families have no static profile (scorer's structural blind spot)

No ground truth is used to build score pools - see the scorer module.

Usage:
    python evaluation/family_ensemble_eval.py \
        --predictions evaluation/metrics_v2/predictions.json \
        --output-dir evaluation/metrics_family_ensemble

For a split-safe evaluator run, pass ``--split dev`` (or ``holdout`` only at
an explicitly declared milestone), a split-specific ground-truth file, and a
split-specific cache when one is available. The default remains the historical
full-corpus comparison.
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVALUATION_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(EVALUATION_DIR))

from run_validation_359 import filter_by_split, is_correct

from analysis.family_confidence_scorer import (
    FamilyConfidenceScorer,
    SampleSignals,
)
from analysis.labels import is_catch_all

DEFAULT_PREDICTIONS = PROJECT_ROOT / "evaluation" / "metrics_v2" / "predictions.json"
DEFAULT_GT = PROJECT_ROOT / "ground_truth_all_corrected.csv"
GAP_CACHE = PROJECT_ROOT / "analysis" / "gap_features_cache.json"
SPLIT_FILE = PROJECT_ROOT / "evaluation" / "holdout_split_v1.csv"


def load_gt(path: Path) -> dict:
    rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))
    by_sha = {row["sha256"].strip().lower(): row for row in rows}
    for sha in list(by_sha):
        if not sha:
            by_sha.pop(sha, None)
    return by_sha


def restrict_to_split(values: dict, split_name: str) -> dict:
    """Restrict a SHA-indexed artifact to a frozen split membership."""
    if split_name == "all":
        return values
    rows = filter_by_split(list(values.values()), split_name)
    return {row["sha256"].strip().lower(): row for row in rows}


def _has_scorer_input(entry: dict[str, Any] | None) -> bool:
    return bool(
        entry
        and not entry.get("parse_error")
        and (entry.get("strings") or entry.get("domains"))
    )


def evaluate(
    predictions: dict,
    gt: dict,
    cache: dict,
    bars,
    include_missing_as_unknown: bool = False,
) -> dict:
    scorer = FamilyConfidenceScorer()
    families_without_profile = {
        fam
        for fam in {g["family"] for g in gt.values()}
        if fam
        and fam.lower() != "unknown"
        and not is_catch_all(fam)
        and fam not in set(scorer.families)
    }

    rows = []
    candidate_shas = sorted(gt) if include_missing_as_unknown else cache.keys()
    cache_available_rows = 0
    missing_baseline_rows = 0
    for sha in candidate_shas:
        entry = cache.get(sha)
        pred = predictions.get(sha)
        sample_gt = gt.get(sha)
        if not sample_gt or (not pred and not include_missing_as_unknown):
            continue
        if not pred:
            missing_baseline_rows += 1
        gt_family = sample_gt["family"].strip()
        if is_catch_all(gt_family):
            continue
        baseline_pred = ((pred or {}).get("prediction") or "unknown").strip()
        cache_available = _has_scorer_input(entry)
        if cache_available:
            sample = SampleSignals.from_cache(entry)
            fused = scorer.score(sample, bar=0.0)
            cache_available_rows += 1
        elif include_missing_as_unknown:
            fused = {"family": "unknown", "confidence": 0.0, "signals": {}}
        else:
            continue
        rows.append(
            {
                "sha256": sha,
                "source": sample_gt["source"].strip(),
                "ground_truth": gt_family,
                "baseline": baseline_pred,
                "baseline_conf": float((pred or {}).get("confidence") or 0.0),
                "method": (pred or {}).get("method") or "missing",
                "fused": fused["family"],
                "fused_conf": fused["confidence"],
                "fused_signals": fused["signals"],
                "cache_available": cache_available,
                "baseline_correct": is_correct(baseline_pred, gt_family),
                "fused_correct": is_correct(fused["family"], gt_family),
            }
        )

    total = len(rows) or 1
    baseline_acc = sum(r["baseline_correct"] for r in rows) / total
    # Pure ranking quality: fused argmax with no abstention. Isolates whether
    # fusion picks the right family, independent of bar calibration.
    ranking_acc = sum(r["fused_correct"] for r in rows) / total
    out = {
        "evaluated": len(rows),
        "cache_available_rows": cache_available_rows,
        "missing_as_unknown_rows": len(rows) - cache_available_rows,
        "missing_baseline_rows": missing_baseline_rows,
        "baseline_accuracy": round(baseline_acc, 4),
        "fusion_ranking_accuracy": round(ranking_acc, 4),
        "families_without_static_profile": sorted(families_without_profile),
        "sweep": {},
    }
    for bar in bars:
        fused_preds = [r["fused"] if r["fused_conf"] >= bar else "unknown" for r in rows]
        correct = sum(is_correct(p, r["ground_truth"]) for p, r in zip(fused_preds, rows))
        abstained = sum(1 for p in fused_preds if p == "unknown")
        answered = total - abstained
        per_source_at_bar = defaultdict(lambda: {"total": 0, "correct": 0, "answered": 0})
        newly_answered_wrong = defaultdict(int)
        for prediction, row in zip(fused_preds, rows):
            source_stats = per_source_at_bar[row["source"]]
            source_stats["total"] += 1
            source_stats["correct"] += int(is_correct(prediction, row["ground_truth"]))
            if prediction != "unknown":
                source_stats["answered"] += 1
                if not is_correct(prediction, row["ground_truth"]):
                    newly_answered_wrong[prediction] += 1
        out["sweep"][str(bar)] = {
            "accuracy": round(correct / total, 4),
            "correct": correct,
            "abstained_to_unknown": abstained,
            "answered": answered,
            "precision_among_answered": round(correct / answered, 4) if answered else 0.0,
            "per_source": [
                {
                    "source": source,
                    **stats,
                    "accuracy": round(stats["correct"] / stats["total"], 4),
                    "precision_among_answered": round(
                        stats["correct"] / stats["answered"], 4
                    ) if stats["answered"] else 0.0,
                }
                for source, stats in sorted(per_source_at_bar.items())
            ],
            "newly_answered_wrong": dict(sorted(newly_answered_wrong.items())),
        }

    per_source = defaultdict(lambda: {"total": 0, "base_correct": 0, "fused_correct": 0})
    for r in rows:
        s = per_source[r["source"]]
        s["total"] += 1
        s["base_correct"] += int(r["baseline_correct"])
        s["fused_correct"] += int(r["fused_correct"])
    out["per_source"] = [
        {
            "source": src,
            **stats,
            "baseline_accuracy": round(stats["base_correct"] / stats["total"], 4),
            "fused_accuracy": round(stats["fused_correct"] / stats["total"], 4),
        }
        for src, stats in sorted(per_source.items())
    ]

    per_family = defaultdict(lambda: {"total": 0, "base_correct": 0, "fused_correct": 0})
    for r in rows:
        f = per_family[r["ground_truth"]]
        f["total"] += 1
        f["base_correct"] += int(r["baseline_correct"])
        f["fused_correct"] += int(r["fused_correct"])
    out["per_family"] = [
        {
            "family": fam,
            **stats,
            "baseline_accuracy": round(stats["base_correct"] / stats["total"], 4),
            "fused_accuracy": round(stats["fused_correct"] / stats["total"], 4),
        }
        for fam, stats in sorted(per_family.items())
    ]
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    parser.add_argument("--gt", type=Path, default=DEFAULT_GT)
    parser.add_argument(
        "--cache",
        type=Path,
        default=GAP_CACHE,
        help="Gap-feature cache JSON (use a dev-only cache for split-safe runs)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=PROJECT_ROOT / "evaluation" / "metrics_family_ensemble"
    )
    parser.add_argument(
        "--bars",
        type=str,
        default="0.55,0.60,0.65,0.70,0.75,0.80,0.85",
        help="comma list of abstention bars to sweep",
    )
    parser.add_argument(
        "--split",
        choices=("all", "dev", "holdout"),
        default="all",
        help="Restrict evaluation to the frozen split membership",
    )
    parser.add_argument(
        "--include-missing-as-unknown",
        action="store_true",
        help="Count scorable rows without scorer input as unknown instead of dropping them",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    predictions = {
        p["sha256"].lower(): p for p in json.loads(args.predictions.read_text(encoding="utf-8"))
    }
    gt = load_gt(args.gt)
    cache = json.loads(args.cache.read_text(encoding="utf-8"))
    if args.split != "all":
        gt = restrict_to_split(gt, args.split)
        allowed_shas = set(gt)
        predictions = {sha: row for sha, row in predictions.items() if sha in allowed_shas}
        cache = {sha: row for sha, row in cache.items() if sha in allowed_shas}
    bars = [float(b) for b in args.bars.split(",")]

    metrics = evaluate(
        predictions,
        gt,
        cache,
        bars,
        include_missing_as_unknown=args.include_missing_as_unknown,
    )
    metrics["split"] = args.split
    metrics["split_file"] = (
        str(SPLIT_FILE.relative_to(PROJECT_ROOT)) if args.split != "all" else None
    )
    (args.output_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )

    print("=" * 72)
    print(f"Split: {metrics['split']}")
    print(
        f"Samples scored (specific-family): {metrics['evaluated']} "
        f"(cache={metrics['cache_available_rows']}, "
        f"missing-as-unknown={metrics['missing_as_unknown_rows']}, "
        f"missing-baseline={metrics['missing_baseline_rows']})"
    )
    print(f"Baseline (production engine) accuracy        : {metrics['baseline_accuracy']:.4f}")
    print(
        f"Fusion ranking accuracy (argmax, no bar)     : {metrics['fusion_ranking_accuracy']:.4f}"
    )
    print("-" * 72)
    header = (
        f"{'bar':>5} {'accuracy':>9} {'correct':>8} {'abstained':>10} "
        f"{'answered':>9} {'prec@ans':>9}"
    )
    print(header)
    for bar, stats in metrics["sweep"].items():
        print(
            f"{float(bar):>5.2f} {stats['accuracy']:>9.4f} "
            f"{stats['correct']:>8} {stats['abstained_to_unknown']:>10} "
            f"{stats['answered']:>9} {stats['precision_among_answered']:>9.4f}"
        )
    print("-" * 72)
    print(f"{'Source':<18} {'N':>4} {'Baseline':>9} {'Fused':>7}")
    for s in metrics["per_source"]:
        print(
            f"{s['source']:<18} {s['total']:>4} "
            f"{s['baseline_accuracy']:>9.4f} {s['fused_accuracy']:>7.4f}"
        )
    print("-" * 72)
    print(
        "Families with NO static profile (scorer cannot reach):",
        ", ".join(metrics["families_without_static_profile"]) or "(none)",
    )
    print(f"Outputs written to: {args.output_dir}")


if __name__ == "__main__":
    main()
