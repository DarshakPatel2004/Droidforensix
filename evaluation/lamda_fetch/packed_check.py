"""Are the LAMDA misses packed? Marker check (zip entries and DEX strings) against per-APK detection.

Per-APK scores use the frozen current configuration (fold-averaged, threshold 0.34 = 10% ceiling).
"""

import json
import sys
import zipfile
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation" / "classifier_eval_2026-10-23"))
import score_v2 as s2  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.model_selection import StratifiedKFold  # noqa: E402

HERE = Path(__file__).resolve().parent
markers = [m for b in json.loads((ROOT / "data" / "packer_markers.json").read_text(encoding="utf-8"))["brands"]
           for m in b["markers"]]
apk_map = json.loads((HERE / "lamda_apk_map.json").read_text(encoding="utf-8"))
gap = {**json.loads((HERE / "kb_features.json").read_text(encoding="utf-8")),
       **json.loads((HERE / "eval_features.json").read_text(encoding="utf-8"))}


def has_marker(sha: str) -> tuple[bool, list[str]]:
    hits = []
    with zipfile.ZipFile(apk_map[sha]) as zf:
        names = zf.namelist()
    hits += [m for m in markers if any(m in n for n in names)]
    strings = "\n".join(gap[sha].get("strings", []) or [])
    hits += [m for m in markers if m in strings and m not in hits]
    return bool(hits), hits


def main() -> None:
    arms, y = s2.load()
    X, _ = arms["current"]
    lamda_rows = json.loads((HERE / "binary_features.json").read_text(encoding="utf-8"))["rows"]
    XL = np.array([[float(json.loads((HERE / "lamda_extra.json").read_text(encoding="utf-8"))[r["sha256"].lower()].get(k, 0) or 0)
                    for k in sorted({k for e in json.loads((HERE.parent / "classifier_eval_2026-10-23" / "train_extra.json").read_text(encoding="utf-8")).values() for k in e if not k.endswith("_error")})]
                   for r in lamda_rows], dtype=float)
    lamda = []
    for tr, te in StratifiedKFold(n_splits=5, shuffle=True, random_state=7).split(X, y):
        m = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=7, n_jobs=-1).fit(X[tr], y[tr])
        lamda.append(m.predict_proba(XL)[:, 1])
    scores = np.mean(lamda, axis=0)
    rows = []
    for r, p in zip(lamda_rows, scores):
        sha = r["sha256"].lower()
        packed, hits = has_marker(sha)
        rows.append({"sha256": sha, "p": round(float(p), 4), "detected": bool(p >= 0.34),
                     "packed_marker": packed, "markers": hits})
    det = [r for r in rows if r["detected"]]
    miss = [r for r in rows if not r["detected"]]
    summary = {
        "detected": len(det), "missed": len(miss),
        "packed_among_detected": sum(r["packed_marker"] for r in det),
        "packed_among_missed": sum(r["packed_marker"] for r in miss),
        "missed_markers": {m: sum(m in r["markers"] for r in miss) for m in markers if any(m in r["markers"] for r in miss)},
    }
    print(json.dumps(summary, indent=2))
    (HERE / "packed_check.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
