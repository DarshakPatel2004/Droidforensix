"""Compare feature arms on the 222 training rows (CV) and the LAMDA holdout (one final scoring).

Threshold: lowest value whose out-of-fold benign flag rate is within FP_LIMIT, from training data only.
LAMDA scores are averaged over the 5 fold models, as in lamda_fetch/threshold_sweep.py.
"""

import json
import os
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold

HERE = Path(__file__).resolve().parent
LAMDA = HERE.parent / "lamda_fetch"
FP_LIMIT = float(os.environ.get("FP_LIMIT", "0.16"))
TRAIN_CV_ROWS = 222


def vectorize(rows: list[dict], extra: dict, keys: list[str]) -> np.ndarray:
    out = []
    for r in rows:
        e = extra[r["sha256"].lower()]
        out.append([float(e.get(k, 0) or 0) for k in keys])
    return np.array(out, dtype=float)


def run_arm(X_tr: np.ndarray, y: np.ndarray, X_lamda: np.ndarray) -> dict:
    oof = np.zeros(len(y))
    lamda_scores = []
    for tr, te in StratifiedKFold(n_splits=5, shuffle=True, random_state=7).split(X_tr, y):
        m = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=7, n_jobs=-1)
        m.fit(X_tr[tr], y[tr])
        oof[te] = m.predict_proba(X_tr[te])[:, 1]
        lamda_scores.append(m.predict_proba(X_lamda)[:, 1])
    benign = oof[y == 0]
    threshold = next(float(t) for t in np.round(np.arange(0.05, 1.001, 0.01), 2)
                     if np.mean(benign >= t) <= FP_LIMIT)
    lamda_mean = np.mean(lamda_scores, axis=0)
    return {
        "cv_auc": round(float(roc_auc_score(y, oof)), 4),
        "threshold_16pct_fp": threshold,
        "cv_malware_detected": round(float(np.mean(oof[y == 1] >= threshold)), 4),
        "lamda_detection": round(float(np.mean(lamda_mean >= threshold)), 4),
    }


def main() -> None:
    base = json.loads((HERE / "features.json").read_text(encoding="utf-8"))
    rows = base["rows"]
    y = np.array([r["label"] for r in rows])
    old_tr = np.array([r["vector"] for r in rows], dtype=float)

    lamda = json.loads((LAMDA / "binary_features.json").read_text(encoding="utf-8"))
    lamda_rows = lamda["rows"]
    old_lamda = np.array([r["vector"] for r in lamda_rows], dtype=float)

    train_extra = json.loads((HERE / "train_extra.json").read_text(encoding="utf-8"))
    lamda_extra = json.loads((LAMDA / "lamda_extra.json").read_text(encoding="utf-8"))
    keys = sorted({k for e in train_extra.values() for k in e if not k.endswith("_error")})

    new_tr = vectorize(rows, train_extra, keys)
    new_lamda = vectorize(lamda_rows, lamda_extra, keys)

    results = {
        "rows": len(rows),
        "extra_feature_count": len(keys),
        "old_15": run_arm(old_tr, y, old_lamda),
        "old_15_plus_extra": run_arm(np.hstack([old_tr, new_tr]), y, np.hstack([old_lamda, new_lamda])),
        "extra_only": run_arm(new_tr, y, new_lamda),
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
