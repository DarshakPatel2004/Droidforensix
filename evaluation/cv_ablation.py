"""Leave-one-feature-out ablation for the binary RandomForest, cross-validated.

Refits a clone of the deployment model per fold (5-fold StratifiedCV, seed 0) so
the deltas reflect generalization, not in-sample training error. THE numbers in
evaluation/METHODOLOGY.md §3 come from here.

Usage:
    python evaluation/cv_ablation.py [--output evaluation/metrics_binary_ablation.json]
"""

import argparse
import json
import pickle
import warnings
from pathlib import Path

import numpy as np
from sklearn.base import clone
from sklearn.model_selection import StratifiedKFold

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "evaluation" / "classifier_data" / "malben_rf.pkl"
FEATURES_CSV = ROOT / "evaluation" / "classifier_data" / "features.csv"
DEFAULT_OUTPUT = ROOT / "evaluation" / "metrics_binary_ablation.json"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with open(MODEL_PATH, "rb") as f:
            bundle = pickle.load(f)
    model, feats = bundle["model"], list(bundle["features"])

    import csv

    with open(FEATURES_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    X = np.array([[float(r[f]) for f in feats] for r in rows])
    y = np.array([1 if r["is_malware"] == "1" else 0 for r in rows])

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)

    def cv_acc(subset: list[int]) -> float:
        accs = []
        for tr, te in cv.split(X, y):
            m = clone(model)
            m.random_state = 0
            m.fit(X[tr][:, subset], y[tr])
            accs.append(float((m.predict(X[te][:, subset]) == y[te]).mean()))
        return float(np.mean(accs))

    all_idx = list(range(len(feats)))
    baseline = cv_acc(all_idx)

    single_feats = [
        "decompiled_classes",
        "total_strings",
        "num_dangerous_perms",
        "file_size_kb",
        "num_permissions",
        "native_libs_found",
        "num_c2",
        "num_c2_real",
        "num_c2_fb_ip",
        "num_encodings",
        "num_payloads",
        "num_chains",
        "c2_alignment",
    ]
    results = {"baseline": round(baseline, 4), "remove_one": {}, "not_in_model": []}
    print(f"CV baseline (all {len(feats)} features): {baseline:.4f}")
    print(f"{'removed feature':<24} {'CV acc':>9} {'delta':>9}")
    for feat in single_feats:
        if feat not in feats:
            # S2-dropped feature: leave-one-out would silently remove nothing.
            results["not_in_model"].append(feat)
            print(f"  - {feat:<22} {'n/a':>9}  (not in model: S2 drop)")
            continue
        subset = [i for i in all_idx if feats[i] != feat]
        acc = cv_acc(subset)
        results["remove_one"][feat] = {
            "cv_accuracy": round(acc, 4),
            "delta": round(acc - baseline, 4),
        }
        print(f"  - {feat:<22} {acc:>9.4f} {acc - baseline:>+9.4f}")

    c2_feats = ("num_c2", "num_c2_real", "num_c2_fb_ip")
    present_c2 = [f for f in c2_feats if f in feats]
    if present_c2:
        subset_no_c2 = [i for i in all_idx if feats[i] not in present_c2]
        acc = cv_acc(subset_no_c2)
        results["remove_all_c2"] = {
            "cv_accuracy": round(acc, 4),
            "delta": round(acc - baseline, 4),
        }
        print(f"  - ALL c2 features         {acc:>9.4f} {acc - baseline:>+9.4f}")
    else:
        results["remove_all_c2"] = {"note": "C2 count features not in model (S2 drop)"}
        print("  - ALL c2 count feats      n/a  (not in model: S2 drop)")

    results["protocol"] = (
        "StratifiedKFold(5, shuffle, seed 0), refit clone per "
        "fold, in-sample accuracy deliberately excluded "
        "(see METHODOLOGY.md §3)"
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote: {args.output}")


if __name__ == "__main__":
    main()
