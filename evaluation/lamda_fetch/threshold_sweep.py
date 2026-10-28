"""Pick a decision threshold from out-of-fold benign scores only, then report holdout detection.

The threshold is chosen on Play-store apps scored out of fold (no malware holdout used),
so the LAMDA holdout is never used to set it. Same 5-fold setup as retrain_play_cv.py.

Usage: threshold_sweep.py <features.json> <holdout_features.json> <fp_limit>
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evaluation"))
from retrain_play_cv import load_csv_rows  # noqa: E402


def main() -> None:
    play = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    holdout = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    fp_limit = float(sys.argv[3])
    features = play["features"]
    play_rows = [r for r in play["rows"] if r["label"] == 0]
    play_X = [r["vector"] for r in play_rows]
    holdout_X = [r["vector"] for r in holdout["rows"]]
    base_X, base_y = load_csv_rows(features)

    oof = np.zeros(len(play_X))
    holdout_scores = []
    folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=7)
    for train_idx, test_idx in folds.split(play_X, np.zeros(len(play_X))):
        X = base_X + [play_X[i] for i in train_idx]
        y = base_y + [0] * len(train_idx)
        model = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=7, n_jobs=-1)
        model.fit(X, y)
        oof[test_idx] = model.predict_proba([play_X[i] for i in test_idx])[:, 1]
        holdout_scores.append(model.predict_proba(holdout_X)[:, 1])
    holdout_mean = np.mean(holdout_scores, axis=0)

    # Lowest threshold whose out-of-fold benign flag rate stays within the limit.
    candidates = np.round(np.arange(0.05, 1.001, 0.01), 2)
    chosen = None
    for t in candidates:
        if np.mean(oof >= t) <= fp_limit:
            chosen = float(t)
            break
    if chosen is None:
        raise SystemExit("no threshold meets the false-positive limit")

    summary = {
        "fp_limit": fp_limit,
        "threshold_chosen_on_benign_only": chosen,
        "play_oof_fp_rate": round(float(np.mean(oof >= chosen)), 4),
        "holdout_malware": len(holdout_X),
        "holdout_detection_rate": round(float(np.mean(holdout_mean >= chosen)), 4),
        "holdout_detection_rate_at_0_5": round(float(np.mean(holdout_mean >= 0.5)), 4),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
