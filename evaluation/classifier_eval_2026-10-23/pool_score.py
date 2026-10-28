"""Score the expanded pool with the new-features-only model.

Pool: 222 training rows + 481 new APKs (200 malware, 281 benign: 100 Play-era from training is
already in the 222; the 281 are 81 unused local benign + 200 F-Droid). 5-fold CV gives
out-of-fold scores; thresholds come from out-of-fold benign scores only. LAMDA is scored once
with fold-averaged models, as in threshold_sweep.py.

Usage: pool_score.py
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
CEILINGS = [0.05, 0.10, 0.16]


def threshold_for(benign_scores: np.ndarray, ceiling: float) -> float:
    return next(float(t) for t in np.round(np.arange(0.05, 1.001, 0.01), 2)
                if np.mean(benign_scores >= t) <= ceiling)


def main() -> None:
    train_rows = json.loads((HERE / "features.json").read_text(encoding="utf-8"))["rows"]
    train_extra = json.loads((HERE / "train_extra.json").read_text(encoding="utf-8"))
    new_extra = json.loads((HERE.parent / "new_pool_extra.json").read_text(encoding="utf-8"))
    lamda_rows = json.loads((LAMDA / "binary_features.json").read_text(encoding="utf-8"))["rows"]
    lamda_extra = json.loads((LAMDA / "lamda_extra.json").read_text(encoding="utf-8"))
    # Labels for the new APKs come from which folder they were fetched into.
    malware_shas = {p[:-4] for p in os.listdir(HERE.parent.parent / "samples" / "new_malware") if p.endswith(".apk")}
    benign_source = {}
    for sha in new_extra:
        benign_source[sha] = "malware" if sha in malware_shas else "benign"

    keys = sorted({k for e in train_extra.values() for k in e if not k.endswith("_error")})

    def vec(extra: dict, sha: str) -> list[float]:
        e = extra[sha]
        return [float(e.get(k, 0) or 0) for k in keys]

    X, y, source = [], [], []
    for r in train_rows:
        sha = r["sha256"].lower()
        X.append(vec(train_extra, sha))
        y.append(r["label"])
        source.append("train_play" if r["label"] == 0 else "train_malware")
    for sha in new_extra:
        X.append(vec(new_extra, sha))
        is_mal = benign_source[sha] == "malware"
        y.append(1 if is_mal else 0)
        source.append("new_malware" if is_mal else "new_benign")
    X = np.array(X, dtype=float)
    y = np.array(y)
    source = np.array(source)

    XL = np.array([vec(lamda_extra, r["sha256"].lower()) for r in lamda_rows], dtype=float)

    oof = np.zeros(len(y))
    lamda_scores = []
    for tr, te in StratifiedKFold(n_splits=5, shuffle=True, random_state=7).split(X, y):
        m = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=7, n_jobs=-1)
        m.fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
        lamda_scores.append(m.predict_proba(XL)[:, 1])
    lamda_mean = np.mean(lamda_scores, axis=0)

    benign_mask = y == 0
    results = {
        "pool_rows": int(len(y)),
        "benign": int(benign_mask.sum()),
        "malware": int((~benign_mask).sum()),
        "cv_auc": round(float(roc_auc_score(y, oof)), 4),
        "by_source_benign_fp_at_0_5": {
            s: round(float(np.mean(oof[source == s] >= 0.5)), 4)
            for s in ["train_play", "new_benign"]
        },
        "ceilings": {},
    }
    for c in CEILINGS:
        t = threshold_for(oof[benign_mask], c)
        ben_fp = float(np.mean(oof[benign_mask] >= t))
        cv_det = float(np.mean(oof[~benign_mask] >= t))
        lamda_det = float(np.mean(lamda_mean >= t))
        results["ceilings"][f"{int(c * 100)}pct"] = {
            "threshold": t,
            "benign_fp_oof": round(ben_fp, 4),
            "benign_accuracy_oof": round(1 - ben_fp, 4),
            "pool_malware_detected_oof": round(cv_det, 4),
            "lamda_detection": round(lamda_det, 4),
            "balanced_accuracy_lamda_and_pool_benign": round(((1 - ben_fp) + lamda_det) / 2, 4),
        }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
