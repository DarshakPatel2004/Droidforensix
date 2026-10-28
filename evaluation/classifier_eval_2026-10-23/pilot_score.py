"""Pilot: do the new APK-derived features add signal over the 15 pipeline features?

Same 222 rows for both arms; 5-fold CV (AUC, and detection at a 5% benign-FP threshold
chosen from out-of-fold benign scores). LAMDA is not used here.

Usage: pilot_score.py
"""

import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold

HERE = Path(__file__).resolve().parent

DANGEROUS = (
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "READ_CALL_LOG", "CALL_PHONE",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "READ_PHONE_STATE",
    "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW",
    "BIND_DEVICE_ADMIN", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "RECEIVE_BOOT_COMPLETED", "PACKAGE_USAGE_STATS", "QUERY_ALL_PACKAGES",
)


def new_features(entry: dict) -> list[float]:
    if entry.get("parse_error"):
        # Unparseable APKs (mostly encrypted classes.dex) keep their row: the failure is a signal.
        return [0.0] * 8 + [1.0]
    perms = [p.split(".")[-1] for p in entry.get("permissions", []) or []]
    return [
        float(len(perms)),
        float(sum(p in DANGEROUS for p in perms)),
        float(len(entry.get("native_libs", []) or [])),
        float(len(entry.get("domains", []) or [])),
        float(len(entry.get("ad_domains", []) or [])),
        float(entry.get("class_count", 0) or 0),
        float(len(entry.get("opcodes", []) or [])),
        float(len(entry.get("strings", []) or [])),
        0.0,
    ]


def cv_metrics(X: np.ndarray, y: np.ndarray) -> dict:
    oof = np.zeros(len(y))
    for tr, te in StratifiedKFold(n_splits=5, shuffle=True, random_state=7).split(X, y):
        model = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=7, n_jobs=-1)
        model.fit(X[tr], y[tr])
        oof[te] = model.predict_proba(X[te])[:, 1]
    benign = oof[y == 0]
    threshold = next(
        float(t) for t in np.round(np.arange(0.05, 1.001, 0.01), 2) if np.mean(benign >= t) <= 0.05
    )
    return {
        "cv_auc": round(float(roc_auc_score(y, oof)), 4),
        "threshold_from_benign_oof": threshold,
        "malware_detected_at_threshold": round(float(np.mean(oof[y == 1] >= threshold)), 4),
    }


def main() -> None:
    base = json.loads((HERE / "features.json").read_text(encoding="utf-8"))
    cache = json.loads((HERE / "pilot_features.json").read_text(encoding="utf-8"))
    rows = base["rows"]
    y = np.array([r["label"] for r in rows])
    old = np.array([r["vector"] for r in rows], dtype=float)
    new = []
    for r in rows:
        entry = cache.get(r["sha256"].lower())
        if entry is None:
            raise SystemExit(f"missing pilot features: {r['sha256']}")
        new.append(new_features(entry))
    new = np.array(new, dtype=float)

    print(json.dumps({
        "rows": len(rows),
        "benign": int(np.sum(y == 0)),
        "malware": int(np.sum(y == 1)),
        "old_15": cv_metrics(old, y),
        "old_15_plus_new": cv_metrics(np.hstack([old, new]), y),
        "new_only": cv_metrics(new, y),
    }, indent=2))


if __name__ == "__main__":
    main()
