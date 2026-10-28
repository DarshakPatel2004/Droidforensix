"""Does more training data help? Train on growing fractions of the pool, score LAMDA.

Pool = shipped training CSV + Play benign (as in retrain_play_cv.py). Detection is reported
at the frozen 16% threshold (0.34) and at 0.5, averaged over 3 seeds per fraction.
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evaluation"))
from retrain_play_cv import load_csv_rows  # noqa: E402

HERE = Path(__file__).resolve().parent
play = json.loads((HERE.parent / "classifier_eval_2026-10-23" / "features.json").read_text(encoding="utf-8"))
lamda = json.loads((HERE / "binary_features.json").read_text(encoding="utf-8"))
base_X, base_y = load_csv_rows(play["features"])
play_X = [r["vector"] for r in play["rows"] if r["label"] == 0]
X = np.array(base_X + play_X, dtype=float)
y = np.array(base_y + [0] * len(play_X))
L = np.array([r["vector"] for r in lamda["rows"]], dtype=float)

out = {}
for frac in [0.25, 0.5, 0.75, 1.0]:
    at34, at50 = [], []
    for seed in [1, 2, 3]:
        if frac < 1.0:
            idx, _ = train_test_split(np.arange(len(y)), train_size=frac, stratify=y, random_state=seed)
        else:
            idx = np.arange(len(y))
        m = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=-1)
        m.fit(X[idx], y[idx])
        p = m.predict_proba(L)[:, 1]
        at34.append(np.mean(p >= 0.34))
        at50.append(np.mean(p >= 0.5))
    out[str(frac)] = {
        "train_rows": int(round(frac * len(y))),
        "lamda_detection_at_0_34": round(float(np.mean(at34)), 4),
        "lamda_detection_at_0_5": round(float(np.mean(at50)), 4),
    }
print(json.dumps(out, indent=2))
