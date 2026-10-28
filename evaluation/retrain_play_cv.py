"""Retrain the binary classifier with clean Play-store apps in training, measured by cross-validation.

Training data is the shipped training CSV plus the Play-store benign apps in the training folds.
Each Play-store app is scored only by a model that did not train on it. The malware test set is
the unseen holdout malware (not in the training CSV), which is scored by every fold's model.

Usage:
    python evaluation/retrain_play_cv.py <features.json> <holdout_features.json> <output_dir>
"""

import csv
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAIN_CSV = PROJECT_ROOT / "evaluation" / "classifier_data" / "features.csv"


def load_csv_rows(features: list[str]):
    X, y = [], []
    for row in csv.DictReader(open(TRAIN_CSV, encoding="utf-8")):
        X.append([float(row[f]) for f in features])
        y.append(int(row["is_malware"]))
    return X, y


def main() -> int:
    play_file, holdout_file, out_dir = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)
    play = json.loads(play_file.read_text(encoding="utf-8"))
    features = play["features"]
    play_rows = [r for r in play["rows"] if r["label"] == 0]
    holdout_rows = json.loads(holdout_file.read_text(encoding="utf-8"))["rows"]

    base_X, base_y = load_csv_rows(features)
    play_X = [r["vector"] for r in play_rows]
    holdout_X = [r["vector"] for r in holdout_rows]

    play_fp = []  # per Play app: out-of-fold flagged?
    holdout_scores = []
    folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=7)
    dummy_y = np.zeros(len(play_X))
    for train_idx, test_idx in folds.split(play_X, dummy_y):
        X = base_X + [play_X[i] for i in train_idx]
        y = base_y + [0] * len(train_idx)
        model = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=7, n_jobs=-1)
        model.fit(X, y)
        play_probs = model.predict_proba([play_X[i] for i in test_idx])[:, 1]
        play_fp += [bool(p >= 0.5) for p in play_probs]
        holdout_scores.append(model.predict_proba(holdout_X)[:, 1])

    holdout_mean = np.mean(holdout_scores, axis=0)
    summary = {
        "play_apps_scored_out_of_fold": len(play_fp),
        "play_false_positives": sum(play_fp),
        "false_positive_rate": round(sum(play_fp) / len(play_fp), 4),
        "holdout_malware": len(holdout_X),
        "holdout_detected_at_0_5": int(np.sum(holdout_mean >= 0.5)),
        "holdout_detection_rate_at_0_5": round(float(np.mean(holdout_mean >= 0.5)), 4),
        "holdout_detection_rate_at_0_7": round(float(np.mean(holdout_mean >= 0.7)), 4),
        "holdout_mean_p_malware": round(float(np.mean(holdout_mean)), 4),
    }
    (out_dir / "retrain_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
