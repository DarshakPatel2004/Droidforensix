"""Compare model classes on the existing 15 features.

Selection uses 5-fold CV over training CSV + Play-store benign only (AUC).
The LAMDA holdout is scored once, at the end, with the threshold chosen on
out-of-fold benign scores for a 5% false-positive limit.

Usage: model_compare.py <play_features.json> <lamda_features.json>
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evaluation"))
from retrain_play_cv import load_csv_rows  # noqa: E402

FP_LIMIT = 0.05
MODELS = {
    "rf": lambda: RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=7, n_jobs=-1),
    "gbm": lambda: GradientBoostingClassifier(random_state=7),
    "logreg": lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
}


def main() -> None:
    play = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    lamda = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    features = play["features"]
    base_X, base_y = load_csv_rows(features)
    play_rows = [r for r in play["rows"] if r["label"] == 0]
    pool_X = np.array(base_X + [r["vector"] for r in play_rows], dtype=float)
    pool_y = np.array(base_y + [0] * len(play_rows))
    lamda_X = np.array([r["vector"] for r in lamda["rows"]], dtype=float)
    n_base = len(base_X)

    results = {}
    for name, make in MODELS.items():
        oof = np.zeros(len(pool_y))
        lamda_scores = []
        folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=7)
        for tr, te in folds.split(pool_X, pool_y):
            model = make().fit(pool_X[tr], pool_y[tr])
            oof[te] = model.predict_proba(pool_X[te])[:, 1]
            lamda_scores.append(model.predict_proba(lamda_X)[:, 1])
        lamda_mean = np.mean(lamda_scores, axis=0)

        cv_auc = roc_auc_score(pool_y, oof)
        benign_oof = oof[pool_y == 0]
        candidates = np.round(np.arange(0.05, 1.001, 0.01), 2)
        chosen = next((float(t) for t in candidates if np.mean(benign_oof >= t) <= FP_LIMIT), None)
        results[name] = {
            "cv_auc": round(float(cv_auc), 4),
            "threshold_from_benign_oof": chosen,
            "lamda_detection_at_threshold": round(float(np.mean(lamda_mean >= chosen)), 4) if chosen else None,
        }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
