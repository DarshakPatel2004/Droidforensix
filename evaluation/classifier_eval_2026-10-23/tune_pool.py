"""Tune the random forest on the expanded pool with CV only. LAMDA is scored once, on the winner.

Selection metric: out-of-fold malware detection at a 10% benign-flag ceiling (threshold from
out-of-fold benign scores). Usage: tune_pool.py
"""

import itertools
import json
import os
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

HERE = Path(__file__).resolve().parent
LAMDA = HERE.parent / "lamda_fetch"
CEILING = 0.10


def build():
    train_rows = json.loads((HERE / "features.json").read_text(encoding="utf-8"))["rows"]
    train_extra = json.loads((HERE / "train_extra.json").read_text(encoding="utf-8"))
    new_extra = json.loads((HERE.parent / "new_pool_extra.json").read_text(encoding="utf-8"))
    lamda_rows = json.loads((LAMDA / "binary_features.json").read_text(encoding="utf-8"))["rows"]
    lamda_extra = json.loads((LAMDA / "lamda_extra.json").read_text(encoding="utf-8"))
    malware = {p[:-4] for p in os.listdir(HERE.parent.parent / "samples" / "new_malware") if p.endswith(".apk")}
    keys = sorted({k for e in train_extra.values() for k in e if not k.endswith("_error")})

    def vec(extra, sha):
        return [float(extra[sha].get(k, 0) or 0) for k in keys]

    X, y = [], []
    for r in train_rows:
        X.append(vec(train_extra, r["sha256"].lower()))
        y.append(r["label"])
    for sha in new_extra:
        X.append(vec(new_extra, sha))
        y.append(1 if sha in malware else 0)
    XL = [vec(lamda_extra, r["sha256"].lower()) for r in lamda_rows]
    return np.array(X, dtype=float), np.array(y), np.array(XL, dtype=float)


def threshold_for(benign: np.ndarray, ceiling: float) -> float:
    return next(float(t) for t in np.round(np.arange(0.05, 1.001, 0.01), 2) if np.mean(benign >= t) <= ceiling)


def fit_scores(make, X, y, XL):
    oof = np.zeros(len(y))
    lamda = []
    for tr, te in StratifiedKFold(n_splits=5, shuffle=True, random_state=7).split(X, y):
        m = make().fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
        lamda.append(m.predict_proba(XL)[:, 1])
    return oof, np.mean(lamda, axis=0)


def main() -> None:
    X, y, XL = build()
    grid = list(itertools.product([300, 600], [None, 12, 24], [1, 3, 5], ["sqrt", 0.3]))
    rows = []
    for n, depth, leaf, mf in grid:
        make = lambda n=n, depth=depth, leaf=leaf, mf=mf: RandomForestClassifier(  # noqa: E731
            n_estimators=n, max_depth=depth, min_samples_leaf=leaf, max_features=mf,
            class_weight="balanced", random_state=7, n_jobs=-1)
        oof, _ = fit_scores(make, X, y, XL)
        t = threshold_for(oof[y == 0], CEILING)
        rows.append({"n": n, "depth": depth, "leaf": leaf, "max_features": mf,
                     "threshold": t, "oof_malware_det": round(float(np.mean(oof[y == 1] >= t)), 4),
                     "oof_benign_acc": round(float(np.mean(oof[y == 0] < t)), 4)})
    rows.sort(key=lambda r: -r["oof_malware_det"])
    best = rows[0]
    print(json.dumps({"best_by_pool_cv": best, "top5": rows[:5], "configs": len(rows)}, indent=2))

    make = lambda: RandomForestClassifier(  # noqa: E731
        n_estimators=best["n"], max_depth=best["depth"], min_samples_leaf=best["leaf"],
        max_features=best["max_features"], class_weight="balanced", random_state=7, n_jobs=-1)
    oof, lamda = fit_scores(make, X, y, XL)
    t = best["threshold"]
    print(json.dumps({"final_config": best, "lamda_detection_once": round(float(np.mean(lamda >= t)), 4)}, indent=2))


if __name__ == "__main__":
    main()
