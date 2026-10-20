"""Explainable binary predictions - why is this APK labelled malicious/benign?

Wraps the deployed RandomForest (evaluation/classifier_data/malben_rf.pkl) with a
per-sample explanation layer:

  * the predicted class + calibrated ``P(malware)``
  * the top-K contributing features (value, model importance, and the median
    value across the malware and benign training populations from
    evaluation/classifier_data/features.csv)
  * an interpretation line per feature
  * false-positive / false-negative risk flags tied to the model's structural
    blind spots (zero-C2 malware for FN, high-permission benign for FP)

Usage:
    python analysis/binary_explainer.py --sha <sha256>      # one sample
    python analysis/binary_explainer.py --all               # all cached features
    python analysis/binary_explainer.py --top-misses 10     # most-confident errors
"""

import argparse
import csv
import json
import pickle
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "evaluation" / "classifier_data" / "malben_rf.pkl"
FEATURES_CSV = ROOT / "evaluation" / "classifier_data" / "features.csv"

TOP_K = 5


# Structural blind-spot rules (mirror docs/accuracy-improvement-plan.md: GT shows
# 107 malware with zero plaintext C2 - encrypted/packed droppers the model cannot
# distinguish from a quiet benign app on C2 alone).
def _num(features: dict, key: str) -> float:
    return float(features.get(key, 0) or 0)


FN_RISK_RULES = (
    (
        "zero_c2",
        lambda f: _num(f, "num_c2") == 0,
        "no plaintext C2 extracted - packed/encrypted droppers are statically silent",
    ),
)
FP_RISK_RULES = (
    (
        "perm_heavy",
        lambda f: _num(f, "num_dangerous_perms") >= 3,
        "high dangerous-permission count overlaps malware profiles",
    ),
    (
        "no_c2_but_perms",
        lambda f: _num(f, "num_c2") == 0 and _num(f, "num_dangerous_perms") >= 3,
        "permission-heavy with no C2 - the classic benign SDK profile",
    ),
)


def _load_bundle():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with open(MODEL_PATH, "rb") as f:
            bundle = pickle.load(f)
    return bundle["model"], bundle["features"]


def _load_population_stats(rows: list[dict], feats: list[str]) -> dict[str, dict]:
    """Median per feature for the malware and benign populations."""
    from statistics import median

    malware = [r for r in rows if r["is_malware"] == "1"]
    benign = [r for r in rows if r["is_malware"] == "0"]
    out = {}
    for feat in feats:
        mal_vals = [float(r[feat]) for r in malware]
        ben_vals = [float(r[feat]) for r in benign]
        out[feat] = {
            "malware_median": median(mal_vals) if mal_vals else 0.0,
            "benign_median": median(ben_vals) if ben_vals else 0.0,
        }
    return out


def explain_row(features: dict, importances: dict, population: dict) -> dict:
    model, feats = _load_bundle()
    vec = [float(features[f]) for f in feats]
    proba = model.predict_proba([vec])[0]
    p_mal = float(proba[1])
    is_mal = bool(p_mal >= 0.5)

    ranked = sorted(feats, key=lambda f: -importances[f])[:TOP_K]
    top_signals = []
    for feat in ranked:
        value = float(features[feat])
        stats = population.get(feat, {})
        mal_med = stats.get("malware_median", 0.0)
        ben_med = stats.get("benign_median", 0.0)
        lean = "malware-like" if value >= mal_med else "benign-like"
        top_signals.append(
            {
                "feature": feat,
                "value": round(value, 3),
                "importance": round(importances[feat], 4),
                "malware_median": round(mal_med, 3),
                "benign_median": round(ben_med, 3),
                "lean": lean,
                "interpretation": (
                    f"{feat}={value:g} vs malware-median {mal_med:g} / benign-median {ben_med:g} "
                    f"-> {lean}"
                ),
            }
        )

    fn_risks = [
        {"rule": name, "reason": reason} for name, cond, reason in FN_RISK_RULES if cond(features)
    ]
    fp_risks = [
        {"rule": name, "reason": reason} for name, cond, reason in FP_RISK_RULES if cond(features)
    ]

    return {
        "classification": "malicious" if is_mal else "benign",
        "confidence": round(p_mal, 4),
        "feature_values": {f: round(float(features[f]), 4) for f in feats},
        "top_signals": top_signals,
        "false_positive_risk": "high" if is_mal and p_mal < 0.80 else "low",
        "false_negative_risk": "high" if not is_mal and fn_risks else "low",
        "risk_flags": {
            "fn": fn_risks,
            "fp": fp_risks,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", type=str, help="sha256 to explain")
    parser.add_argument("--all", action="store_true", help="explain every cached sample")
    parser.add_argument(
        "--top-misses", type=int, default=0, help="show the N highest-confidence wrong predictions"
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "evaluation" / "binary_explanations.json"
    )
    args = parser.parse_args()

    bundle = _load_bundle()
    model, feats = bundle
    importances = {f: float(i) for f, i in zip(feats, model.feature_importances_, strict=True)}

    rows = list(csv.DictReader(FEATURES_CSV.open(newline="", encoding="utf-8")))
    population = _load_population_stats(rows, list(feats))

    explanations = []
    misses = []
    for row in rows:
        expl = explain_row(row, importances, population)
        expl["sha256"] = row["sha256"]
        expl["source"] = row["source"]
        expl["gt_family"] = row.get("family", "")
        expl["gt_malware"] = row["is_malware"] == "1"
        expl["correct"] = expl["gt_malware"] == (expl["classification"] == "malicious")
        explanations.append(expl)
        if not expl["correct"]:
            misses.append(expl)

    if args.sha:
        target = args.sha.lower()
        matches = [e for e in explanations if e["sha256"].lower() == target]
        if not matches:
            sys.exit(f"No cached features for sha {target}")
        print(json.dumps(matches[0], indent=2))
        return

    if args.top_misses:
        misses.sort(key=lambda e: abs(e["confidence"] - 0.5), reverse=True)
        for miss in misses[: args.top_misses]:
            verdict = "FP" if miss["classification"] == "malicious" else "FN"
            print(
                f"[{verdict}] {miss['sha256'][:12]} {miss['source']:<16} "
                f"gt={miss['gt_malware']} proba={miss['confidence']:.3f} "
                f"c2={miss['feature_values'].get('num_c2')}"
            )
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(explanations, indent=1), encoding="utf-8")
    correct = sum(1 for e in explanations if e["correct"])
    fns = sum(1 for e in explanations if not e["correct"] and e["gt_malware"])
    fps = sum(1 for e in explanations if not e["correct"] and not e["gt_malware"])
    print(f"Explained {len(explanations)} samples -> {args.output}")
    print(
        f"In-sample accuracy (509-row cache = explainability set, NOT a "
        f"generalization claim): {correct}/{len(explanations)} = "
        f"{correct/len(explanations):.4f} (FP {fps}, FN {fns})"
    )
    print(
        "Deployment-grade numbers live in evaluation/real_world_accuracy_report.json "
        "(200 held-out: 97.0%; 5-fold CV ~89-91%)."
    )


if __name__ == "__main__":
    main()
