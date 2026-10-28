"""Compare the current extra-feature set with the same set plus certificate and extended API features.

Pool CV selects nothing here: both arms use the default forest and the same 10% ceiling rule.
LAMDA is scored once per arm with fold-averaged models.
"""

import json
import os
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

HERE = Path(__file__).resolve().parent
LAMDA = HERE.parent / "lamda_fetch"
CEILING = 0.10


def load():
    train_rows = json.loads((HERE / "features.json").read_text(encoding="utf-8"))["rows"]
    train_extra = json.loads((HERE / "train_extra.json").read_text(encoding="utf-8"))
    new_extra = json.loads((HERE.parent / "new_pool_extra.json").read_text(encoding="utf-8"))
    lamda_rows = json.loads((LAMDA / "binary_features.json").read_text(encoding="utf-8"))["rows"]
    lamda_extra = json.loads((LAMDA / "lamda_extra.json").read_text(encoding="utf-8"))
    cert = json.loads((HERE.parent / "all_cert_api.json").read_text(encoding="utf-8"))
    malware = {p[:-4] for p in os.listdir(HERE.parent.parent / "samples" / "new_malware") if p.endswith(".apk")}

    base = {**train_extra, **new_extra, **lamda_extra}
    pool_shas = [r["sha256"].lower() for r in train_rows] + list(new_extra.keys())
    y = np.array([r["label"] for r in train_rows] + [1 if s in malware else 0 for s in new_extra])
    lamda_shas = [r["sha256"].lower() for r in lamda_rows]

    keys = sorted({k for e in train_extra.values() for k in e if not k.endswith("_error")})
    cert_keys = sorted({k for e in cert.values() for k in e if not k.endswith("_error")})

    def matrix(shas, extra_keys, source):
        return np.array([[float(source[s].get(k, 0) or 0) for k in extra_keys] for s in shas], dtype=float)

    arms = {
        "current": (matrix(pool_shas, keys, base), matrix(lamda_shas, keys, base)),
        "current_plus_cert_api": (
            np.hstack([matrix(pool_shas, keys, base), matrix(pool_shas, cert_keys, cert)]),
            np.hstack([matrix(lamda_shas, keys, base), matrix(lamda_shas, cert_keys, cert)]),
        ),
    }
    return arms, y


def run(X, y, XL):
    oof = np.zeros(len(y))
    lamda = []
    for tr, te in StratifiedKFold(n_splits=5, shuffle=True, random_state=7).split(X, y):
        m = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=7, n_jobs=-1)
        m.fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
        lamda.append(m.predict_proba(XL)[:, 1])
    benign = oof[y == 0]
    t = next(float(v) for v in np.round(np.arange(0.05, 1.001, 0.01), 2) if np.mean(benign >= v) <= CEILING)
    ben_acc = float(np.mean(benign < t))
    mal_oof = float(np.mean(oof[y == 1] >= t))
    lam_det = float(np.mean(np.mean(lamda, axis=0) >= t))
    return {"threshold": t, "pool_benign_acc_oof": round(ben_acc, 4),
            "pool_malware_det_oof": round(mal_oof, 4), "lamda_detection": round(lam_det, 4),
            "balanced_lamda_and_pool_benign": round((lam_det + ben_acc) / 2, 4)}


def main() -> None:
    arms, y = load()
    results = {name: run(X, y, XL) for name, (X, XL) in arms.items()}
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
