"""Retrain the 15-feature RandomForest with the 100 extra APKs, and score the validation split.

Training: evaluation/classifier_data/features.csv (original set) + train_extra rows of split_features.csv.
Validation: validation rows of split_features.csv (never trained on, never used for the holdout).
The deployed evaluation/classifier_data/malben_rf.pkl is NOT modified; the new bundle is written
to evaluation/malben_eval/malben_rf_retrained.pkl. The 200-sample holdout is not touched here.

Usage: python evaluation/malben_eval/retrain_with_extra.py
"""

import csv
import json
import pickle
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analysis.classify_fast import FEATURES  # noqa: E402

HERE = Path(__file__).resolve().parent
ORIGINAL_CSV = ROOT / "evaluation" / "classifier_data" / "features.csv"
DEPLOYED_PKL = ROOT / "evaluation" / "classifier_data" / "malben_rf.pkl"
SPLIT_CSV = HERE / "split_features.csv"
OUT_PKL = HERE / "malben_rf_retrained.pkl"
OUT_JSON = HERE / "retrain_result.json"


def load_original() -> tuple[list, list, set]:
    X, y, shas = [], [], set()
    for row in csv.DictReader(open(ORIGINAL_CSV, encoding="utf-8")):
        X.append([float(row[f]) for f in FEATURES])
        y.append(int(row["is_malware"]))
        shas.add(row["sha256"].lower())
    return X, y, shas


def load_split(group: str) -> tuple[list, list, list]:
    X, y, shas = [], [], []
    for row in csv.DictReader(open(SPLIT_CSV, encoding="utf-8")):
        if row["group"] != group:
            continue
        assert row["status"] == "ok", f"extraction error for {row['sha256']}"
        X.append([float(row[f]) for f in FEATURES])
        y.append({"benign": 0, "malware": 1}[row["label"]])
        shas.append(row["sha256"].lower())
    return X, y, shas


def sweep(y: np.ndarray, p: np.ndarray) -> list[dict]:
    rows = []
    for t in np.round(np.arange(0.30, 0.91, 0.05), 2):
        pred = p >= t
        rows.append({
            "threshold": float(t),
            "malware_detected": round(float(np.mean(pred[y == 1])), 4),
            "benign_flagged": round(float(np.mean(pred[y == 0])), 4),
            "accuracy": round(float(np.mean(pred == y)), 4),
        })
    return rows


def main() -> None:
    X0, y0, shas0 = load_original()
    Xe, ye, she = load_split("train_extra")
    Xv, yv, shv = load_split("validation")

    # Self-check: the splits must not overlap each other or the original training set.
    assert not (set(she) & shas0), "train_extra overlaps original training data"
    assert not (set(shv) & (shas0 | set(she))), "validation overlaps training data"

    X = np.array(X0 + Xe, dtype=float)
    y = np.array(y0 + ye)
    Xv = np.array(Xv, dtype=float)
    yv = np.array(yv)

    old = pickle.load(open(DEPLOYED_PKL, "rb"))
    old_p = old["model"].predict_proba(Xv)[:, 1]

    new = RandomForestClassifier(
        n_estimators=300, class_weight="balanced", min_samples_leaf=2,
        max_features="sqrt", random_state=42, n_jobs=-1,
    )
    new.fit(X, y)
    new_p = new.predict_proba(Xv)[:, 1]

    pickle.dump({"model": new, "features": FEATURES}, open(OUT_PKL, "wb"))

    result = {
        "train_original": len(y0), "train_extra": len(ye), "train_total": len(y),
        "validation_rows": len(yv),
        "validation_benign": int(np.sum(yv == 0)), "validation_malware": int(np.sum(yv == 1)),
        "deployed_auc": round(float(roc_auc_score(yv, old_p)), 4),
        "retrained_auc": round(float(roc_auc_score(yv, new_p)), 4),
        "deployed_at_0_5": {"malware_detected": round(float(np.mean(old_p[yv == 1] >= 0.5)), 4),
                            "benign_flagged": round(float(np.mean(old_p[yv == 0] >= 0.5)), 4)},
        "retrained_sweep": sweep(yv, new_p),
        "deployed_sweep": sweep(yv, old_p),
    }
    OUT_JSON.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
