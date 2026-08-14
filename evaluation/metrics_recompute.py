"""Recompute validation metrics from ground_truth_all.csv + a run's predictions.json.

This is the single source of truth for thesis numbers. It joins the ground
truth CSV with a validation run's predictions and emits:

  * evaluation/metrics/metrics.json                 (machine-readable, everything)
  * evaluation/metrics/per_source_accuracy.csv
  * evaluation/metrics/per_family_breakdown.csv

Matching semantics are identical to evaluation/run_validation_359.py
(``is_correct`` + ``ALIASES``) so numbers cannot drift between the two scripts.

Usage:
    python evaluation/metrics_recompute.py \
        --gt ground_truth_all.csv \
        --predictions evaluation/validation_359_full/predictions.json \
        --output-dir evaluation/metrics --verbose
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVALUATION_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Matching semantics ΓÇö imported from evaluation/run_validation_359.py so the
# two scripts cannot drift apart. The local copies are a last-resort fallback
# (warned on) and must be kept identical if ever edited.
# ---------------------------------------------------------------------------
_FALLBACK_ALIASES = {
    "KungFu": "DroidKungFu",
    "Andr/NGate-G": "NGate",
    "Andr/Banker-HDY": "BankBot",
}

try:
    sys.path.insert(0, str(EVALUATION_DIR))
    from run_validation_359 import ALIASES, is_correct  # single source of truth
except Exception as exc:  # pragma: no cover - fallback keeps this script standalone
    ALIASES = _FALLBACK_ALIASES
    print(
        f"[!] Could not import is_correct/ALIASES from run_validation_359 "
        f"({exc}); using local fallback copies.",
        file=sys.stderr,
    )

    def is_correct(prediction: str, ground_truth: str) -> bool:
        """Exact (case-insensitive) family match, honoring vendor aliases."""
        if prediction.strip().casefold() == ground_truth.strip().casefold():
            return True
        return ALIASES.get(ground_truth.strip(), "").casefold() == prediction.strip().casefold()


# ---------------------------------------------------------------------------
# Catch-all / category labels: no family-level identity exists to match.
#
# These label a malware *category* (or a parse artifact), so exact-match
# family accuracy is meaningless for them. They are enumerated from the 87
# distinct ground-truth labels in ground_truth_all.csv and grouped by reason:
#   - AV category labels: AndroidOS, Agent, Banker, Gen, Adware, Backdoor,
#     Linux, Detected, Dropper, Trojan-Banker, Trojan-Dropper, Exploit,
#     Hacktool, Application, General, Android/Packed, Evo-gen [Trj], HEUR
#   - Kaspersky generic: GenericKD
#   - VT "Trojan (<hash>)" style and bare numeric/letter parse artifacts
#   - unknown: no family label at all
# ---------------------------------------------------------------------------
CATCH_ALL_LABELS = frozenset({
    "unknown", "androidos", "generic", "gen", "agent", "banker", "adware",
    "backdoor", "linux", "detected", "dropper", "trojan-banker",
    "trojan-dropper", "exploit", "hacktool", "application", "general",
    "android/packed", "evo-gen [trj]", "heur", "generickd", "a",
    "33107585", "40094400",
})
# VT-style "Trojan ( <hash> )" labels are catch-alls too ΓÇö matched structurally.
_ARTIFACT_PREFIXES = ("trojan (", "trojan-", "pua.", "riskware.", "adware.")


def is_catch_all(family: str) -> bool:
    lowered = family.strip().lower()
    if lowered in CATCH_ALL_LABELS:
        return True
    return lowered.startswith(_ARTIFACT_PREFIXES)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_ground_truth(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_predictions(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list of predictions")
    return data


def join_gt_and_predictions(gt_rows: list[dict], predictions: list[dict]) -> list[dict]:
    """Join predictions to ground truth by sha256, keeping GT source/family."""
    gt_hashes = [row["sha256"].strip().lower() for row in gt_rows]
    if len(gt_hashes) != len(set(gt_hashes)):
        dupes = {h for h in set(gt_hashes) if gt_hashes.count(h) > 1}
        print(
            f"[!] Duplicate sha256 in ground truth (last row wins): {sorted(dupes)}",
            file=sys.stderr,
        )
    by_hash = {row["sha256"].strip().lower(): row for row in gt_rows}
    joined = []
    seen: set[str] = set()
    for pred in predictions:
        sha = pred["sha256"].strip().lower()
        if sha in seen:
            print(f"[!] Duplicate prediction for {sha} ΓÇö counted once", file=sys.stderr)
            continue
        seen.add(sha)
        gt = by_hash.get(sha)
        if gt is None:
            continue  # prediction for a sample not in this ground-truth file
        joined.append({
            "sha256": sha,
            "source": (pred.get("source") or gt["source"]).strip(),
            "ground_truth": gt["family"].strip(),
            "prediction": (pred.get("prediction") or "unknown").strip(),
            "confidence": float(pred.get("confidence") or 0.0),
            "method": pred.get("method") or "none",
            "status": pred.get("status") or "success",
            "gt_confidence": gt["confidence"].strip(),
            "gt_reason": gt.get("gt_reason", "").strip(),
            "vt_detections": gt.get("vt_detections", "").strip(),
        })
    return joined


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def classification_metrics(rows: list[dict]) -> dict:
    """Overall accuracy + macro precision/recall (same math as run_validation_359)."""
    labels = sorted(
        {row["ground_truth"] for row in rows} | {row["prediction"] for row in rows}
    )
    per_family = []
    for label in labels:
        true_positive = sum(
            row["ground_truth"] == label and row["prediction"] == label for row in rows
        )
        false_positive = sum(
            row["ground_truth"] != label and row["prediction"] == label for row in rows
        )
        false_negative = sum(
            row["ground_truth"] == label and row["prediction"] != label for row in rows
        )
        per_family.append({
            "family": label,
            "support": true_positive + false_negative,
            "precision": round(true_positive / (true_positive + false_positive), 4)
            if true_positive + false_positive else 0.0,
            "recall": round(true_positive / (true_positive + false_negative), 4)
            if true_positive + false_negative else 0.0,
        })
    correct = sum(is_correct(row["prediction"], row["ground_truth"]) for row in rows)
    return {
        "evaluated": sum(row["status"] == "success" for row in rows),
        "errors": sum(row["status"] != "success" for row in rows),
        "correct": correct,
        "accuracy": round(correct / len(rows), 4) if rows else 0.0,
        "precision_macro": round(sum(p["precision"] for p in per_family) / len(per_family), 4)
        if per_family else 0.0,
        "recall_macro": round(sum(p["recall"] for p in per_family) / len(per_family), 4)
        if per_family else 0.0,
    }


def _accuracy(members: list[dict]) -> float:
    if not members:
        return 0.0
    return round(
        sum(is_correct(r["prediction"], r["ground_truth"]) for r in members) / len(members), 4
    )


def per_source_metrics(rows: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["source"]].append(row)
    out = []
    for source, members in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        specific = [m for m in members if not is_catch_all(m["ground_truth"])]
        catch_all = [m for m in members if is_catch_all(m["ground_truth"])]
        out.append({
            "source": source,
            "total": len(members),
            "catch_all_count": len(catch_all),
            "catch_all_pct": round(100 * len(catch_all) / len(members), 1),
            "specific_count": len(specific),
            "specific_pct": round(100 * len(specific) / len(members), 1),
            "accuracy_overall": _accuracy(members),
            "accuracy_specific": _accuracy(specific),
            "accuracy_catch_all": _accuracy(catch_all),
            "overall_correct": sum(
                is_correct(r["prediction"], r["ground_truth"]) for r in members
            ),
            "specific_correct": sum(
                is_correct(r["prediction"], r["ground_truth"]) for r in specific
            ),
        })
    return out


def per_family_metrics(rows: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["ground_truth"]].append(row)
    out = []
    for family, members in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        sources = sorted({m["source"] for m in members})
        confidences = Counter(m["gt_confidence"] for m in members)
        conf_str = "; ".join(
            f"{conf}:{confidences[conf]}"
            for conf in ("high", "medium", "low") if conf in confidences
        )
        correct = sum(is_correct(r["prediction"], r["ground_truth"]) for r in members)
        out.append({
            "family": family,
            "gt_count": len(members),
            "correct": correct,
            "accuracy": round(correct / len(members), 4),
            "sources": ";".join(sources),
            "confidence": conf_str,
            "catch_all": is_catch_all(family),
        })
    return out


def build_metrics(rows: list[dict], gt_path: Path, predictions_path: Path) -> dict:
    specific_rows = [r for r in rows if not is_catch_all(r["ground_truth"])]
    high_conf_specific = [
        r for r in rows
        if r["gt_confidence"] == "high" and not is_catch_all(r["ground_truth"])
    ]
    unknown_rows = [r for r in rows if r["ground_truth"] == "unknown"]

    overall = classification_metrics(rows)
    return {
        "ground_truth": str(gt_path),
        "predictions": str(predictions_path),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(rows),
        "catch_all_label_count": len(CATCH_ALL_LABELS),
        "overall": overall,
        "subset_metrics": {
            "specific_families": {
                "total": len(specific_rows),
                "correct": sum(is_correct(r["prediction"], r["ground_truth"]) for r in specific_rows),
                "accuracy": _accuracy(specific_rows),
            },
            "high_confidence_specific": {
                "total": len(high_conf_specific),
                "correct": sum(is_correct(r["prediction"], r["ground_truth"]) for r in high_conf_specific),
                "accuracy": _accuracy(high_conf_specific),
            },
            "unknown_refusal": {
                "total": len(unknown_rows),
                "correct": sum(
                    is_correct(r["prediction"], r["ground_truth"]) for r in unknown_rows
                ),
                "refused_correctly": sum(
                    is_correct(r["prediction"], r["ground_truth"]) for r in unknown_rows
                ),  # alias for readability in metrics.json
                "accuracy": _accuracy(unknown_rows),
            },
        },
        "per_source_accuracy": per_source_metrics(rows),
        "per_family_breakdown": per_family_metrics(rows),
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def write_csv(path: Path, header: list[str], rows: list[list]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def write_outputs(metrics: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )

    write_csv(
        output_dir / "per_source_accuracy.csv",
        ["Source", "Total", "Catch-all %", "Specific %",
         "Pipeline Accuracy Overall", "Pipeline Accuracy on Specific"],
        [
            [s["source"], s["total"], s["catch_all_pct"], s["specific_pct"],
             s["accuracy_overall"], s["accuracy_specific"]]
            for s in metrics["per_source_accuracy"]
        ],
    )

    write_csv(
        output_dir / "per_family_breakdown.csv",
        ["Family", "GT Count", "Correct", "Accuracy", "Source(s)", "Confidence", "Catch-all"],
        [
            [f["family"], f["gt_count"], f["correct"], f["accuracy"],
             f["sources"], f["confidence"], f["catch_all"]]
            for f in metrics["per_family_breakdown"]
        ],
    )


def print_summary(metrics: dict, verbose: bool = False) -> None:
    ov = metrics["overall"]
    sub = metrics["subset_metrics"]
    print("=" * 66)
    print(f"Total samples evaluated : {ov['evaluated']} (errors: {ov['errors']})")
    print(f"Overall family accuracy : {ov['correct']}/{metrics['total_samples']} = {ov['accuracy']:.3f}")
    print(f"Precision (macro)       : {ov['precision_macro']}")
    print(f"Recall (macro)          : {ov['recall_macro']}")
    print("-" * 66)
    for name, data in sub.items():
        label = {
            "specific_families": "Specific families (non-catch-all)",
            "high_confidence_specific": "High-confidence specific labels",
            "unknown_refusal": "Unknown refusal (GT=unknown)",
        }[name]
        print(f"{label:34s}: {data['correct']:3d}/{data['total']:<3d} = {data['accuracy']:.3f}")
    print("-" * 66)
    print(f"{'Source':<18} {'Total':>5} {'Catch%':>6} {'Spec%':>6} {'AccAll':>7} {'AccSpec':>7}")
    for s in metrics["per_source_accuracy"]:
        print(f"{s['source']:<18} {s['total']:>5} {s['catch_all_pct']:>6.1f} "
              f"{s['specific_pct']:>6.1f} {s['accuracy_overall']:>7.3f} {s['accuracy_specific']:>7.3f}")
    if verbose:
        print("-" * 66)
        print("Per-family (GT count >= 3, sorted by accuracy):")
        for f in sorted(
            [f for f in metrics["per_family_breakdown"] if f["gt_count"] >= 3],
            key=lambda f: (-f["accuracy"], -f["gt_count"]),
        ):
            tag = "CATCH-ALL" if f["catch_all"] else "specific "
            print(f"  [{tag}] {f['family']:<16} n={f['gt_count']:>2} "
                  f"correct={f['correct']:>2} acc={f['accuracy']:.3f}")
    print("=" * 66)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gt", type=Path,
                        default=PROJECT_ROOT / "ground_truth_all.csv")
    parser.add_argument("--predictions", type=Path,
                        default=EVALUATION_DIR / "validation_359_full" / "predictions.json")
    parser.add_argument("--output-dir", type=Path,
                        default=EVALUATION_DIR / "metrics")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    gt_rows = load_ground_truth(args.gt)
    predictions = load_predictions(args.predictions)
    rows = join_gt_and_predictions(gt_rows, predictions)

    if len(rows) != len(gt_rows):
        covered = {r["sha256"] for r in rows}
        missing = [r["sha256"] for r in gt_rows if r["sha256"].strip().lower() not in covered]
        detail = f" (e.g. {missing[:5]})" if len(missing) <= 10 else ""
        print(
            f"[!] Joined {len(rows)}/{len(gt_rows)} ground-truth rows ΓÇö "
            f"predictions.json does not cover the full dataset; "
            f"{len(missing)} sample(s) missing{detail}.",
            file=sys.stderr,
        )

    metrics = build_metrics(rows, args.gt, args.predictions)
    write_outputs(metrics, args.output_dir)
    print_summary(metrics, verbose=args.verbose)
    print(f"\nOutputs written to: {args.output_dir}")


if __name__ == "__main__":
    main()
