"""Auto-categorize misclassified abuse.ch-specific samples into failure modes.

Joins ground_truth_all.csv + a validation run's predictions.json with the
per-sample pipeline artifacts (evaluation/<run>/<sha>/pipeline_result.json)
to fill the Phase 2 failure-mode table WITHOUT manual JADX walking.

Categories (primary failure mode):
  * empty_extraction        - classes==0 AND strings==0: extraction produced
                              no code (Phase 1 territory: crypter/nested/corrupt).
                              Wins over abstention: the root cause is the
                              missing code, not a verdict choice.
  * abstention_no_signal    - predicted "unknown" with little extractable
                              signal (correct refusal; thesis: static ceiling).
  * abstention_despite_signal - predicted "unknown" despite rich features
                              (classes/strings/c2 present): a signature gap on
                              features that exist.
  * false_positive          - predicted a wrong family at confidence >= 0.7:
                              a real signature bug worth fixing.
  * low_confidence_miss     - predicted a wrong family below 0.7.
  * missing_artifact        - no pipeline_result.json found for the sample.

Usage:
    python evaluation/categorize_failures.py \
        --gt ground_truth_all.csv \
        --predictions evaluation/validation_359_full/predictions.json \
        --artifacts evaluation/validation_359_full \
        --output evaluation/failure_modes_abusech.csv
"""

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVALUATION_DIR = Path(__file__).resolve().parent

# Match semantics shared with run_validation_359.py / metrics_recompute.py
sys.path.insert(0, str(EVALUATION_DIR))
# metrics_recompute already resolves is_correct/ALIASES with a fallback, so
# importing from it avoids a hard dependency on run_validation_359 internals.
from metrics_recompute import is_catch_all, is_correct  # noqa: E402


def load_ground_truth(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_predictions(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list of predictions")
    return data


def load_artifact_features(run_dir: Path, sha: str) -> dict:
    """Pull the features needed to categorize failure modes from pipeline_result.json."""
    feat = {
        "classes": None,
        "strings": None,
        "crypter_stub": None,
        "extraction_status": None,
        "c2_count": None,
        "c2_values": "",
        "obf_score": None,
        "perms": "",
        "candidates": "",
        "needs_manual_review": "",
        "has_artifact": False,
    }
    for d in run_dir.glob(f"{sha}*"):
        result_path = d / "pipeline_result.json"
        if not result_path.exists():
            continue
        try:
            r = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        ext = r.get("extraction", {}) or {}
        feat["classes"] = ext.get("decompiled_classes")
        feat["strings"] = ext.get("total_strings_extracted")
        feat["crypter_stub"] = ext.get("crypter_stub")
        feat["extraction_status"] = ext.get("extraction_status")
        c2 = r.get("c2_infrastructure", []) or []
        feat["c2_count"] = len(c2)
        feat["c2_values"] = "; ".join(
            str(c.get("value")) for c in c2 if c.get("value")
        )[:200]
        feat["obf_score"] = (r.get("obfuscation_analysis") or {}).get("obfuscation_score")
        manifest = r.get("manifest", {}) or {}
        perms = manifest.get("uses_permissions", []) or []
        feat["perms"] = "; ".join(perms)[:300]
        fi = r.get("family_identification", {}) or {}
        cands = fi.get("candidates", []) or []
        feat["candidates"] = "; ".join(
            f"{c.get('family')}@{c.get('confidence')}" for c in cands[:4]
        )
        feat["needs_manual_review"] = r.get("needs_manual_review", "")
        feat["has_artifact"] = True
        break
    return feat


def categorize(pred: dict, gt_family: str, feat: dict) -> tuple[str, str]:
    """Return (category, evidence)."""
    prediction = (pred.get("prediction") or "unknown").strip()
    confidence = float(pred.get("confidence") or 0.0)
    classes = feat.get("classes")
    strings = feat.get("strings")

    # No pipeline artifact -> we have no feature evidence at all.
    if not feat.get("has_artifact"):
        return "missing_artifact", f"no pipeline_result.json; predicted {prediction} @ {confidence}"

    # Empty extraction wins: with zero code extracted the root cause is the
    # missing code (Phase 1 territory), not the verdict that followed.
    if classes == 0 and strings == 0:
        status = feat.get("extraction_status") or "n/a"
        return "empty_extraction", f"classes=0 strings=0 (status={status}); predicted {prediction} @ {confidence}"

    if prediction.strip().casefold() == "unknown":
        # Sub-classify abstentions: genuinely thin signal (correct refusal) vs
        # rich features the signature engine still failed to map (gap).
        has_signal = classes >= 100 or strings >= 100 or (feat.get("c2_count") or 0) >= 1
        if not has_signal:
            return "abstention_no_signal", f"predicted unknown @ {confidence}; cls={classes} str={strings}"
        return "abstention_despite_signal", (
            f"predicted unknown @ {confidence}; cls={classes} str={strings} c2={feat.get('c2_count')}"
        )
    if not is_correct(prediction, gt_family):
        if confidence >= 0.7:
            return "false_positive", f"predicted {prediction} @ {confidence}"
        return "low_confidence_miss", f"predicted {prediction} @ {confidence}"
    return "unknown", "unexpected: matched family in wrong set"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gt", default=str(PROJECT_ROOT / "ground_truth_all.csv"))
    parser.add_argument(
        "--predictions",
        default=str(EVALUATION_DIR / "validation_359_full" / "predictions.json"),
    )
    parser.add_argument(
        "--artifacts",
        default=str(EVALUATION_DIR / "validation_359_full"),
    )
    parser.add_argument("--output", default=str(EVALUATION_DIR / "failure_modes_abusech.csv"))
    parser.add_argument("--source", default="abusech", help="GT source filter")
    args = parser.parse_args()

    gt_rows = load_ground_truth(Path(args.gt))
    preds = load_predictions(Path(args.predictions))
    run_dir = Path(args.artifacts)

    gt_by_hash = {r["sha256"].strip().lower(): r for r in gt_rows}
    pred_by_hash = {p["sha256"].strip().lower(): p for p in preds}

    # Collect all samples from the source, then split specific vs catch-all.
    source_rows = [r for r in gt_rows if r["source"].strip().lower() == args.source.lower()]
    specific = [r for r in source_rows if not is_catch_all(r["family"])]

    rows_out = []
    for gt in specific:
        sha = gt["sha256"].strip().lower()
        pred = pred_by_hash.get(sha, {})
        prediction = (pred.get("prediction") or "MISSING").strip()
        gt_family = gt["family"].strip()
        feat = load_artifact_features(run_dir, sha)
        category, evidence = categorize(pred, gt_family, feat)
        correct = is_correct(pred.get("prediction", "") or "", gt_family)
        rows_out.append({
            "sha256": sha,
            "gt_family": gt_family,
            "gt_confidence": gt.get("confidence", "").strip(),
            "gt_reason": gt.get("gt_reason", "").strip(),
            "prediction": prediction,
            "confidence": pred.get("confidence", ""),
            "method": pred.get("method", ""),
            "correct": "yes" if correct else "no",
            "category": category,
            "evidence": evidence,
            "classes": feat["classes"],
            "strings": feat["strings"],
            "crypter_stub": feat["crypter_stub"],
            "extraction_status": feat["extraction_status"],
            "c2_count": feat["c2_count"],
            "c2_values": feat["c2_values"],
            "obf_score": feat["obf_score"],
            "perms": feat["perms"],
            "candidates": feat["candidates"],
            "needs_manual_review": feat["needs_manual_review"],
        })

    if not rows_out:
        print(f"No specific samples found for source={args.source}; nothing written.")
        sys.exit(1)

    rows_out.sort(key=lambda r: (r["correct"], r["category"], r["gt_family"]))
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
        writer.writeheader()
        writer.writerows(rows_out)

    # Summary
    n = len(rows_out)
    n_correct = sum(1 for r in rows_out if r["correct"] == "yes")
    wrong = [r for r in rows_out if r["correct"] == "no"]
    cat_counts = Counter(r["category"] for r in wrong)
    print(f"source={args.source}: {n} specific samples | {n_correct} correct | {len(wrong)} wrong")
    print(f"specific accuracy: {n_correct}/{n} = {n_correct / n:.1%}")
    print("\nFailure-mode breakdown of the wrong ones:")
    for cat, count in cat_counts.most_common():
        print(f"  {cat:22s} {count}")
    print(f"\nTable written to: {out_path}")


if __name__ == "__main__":
    main()
