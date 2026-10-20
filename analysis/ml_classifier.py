"""
ML family classifier for accuracy Phase 2 - supplements signature/KB/LLM.

Trains LightGBM on gap_features_cache.json (296 samples, 81 families) +
ground_truth_all_corrected.csv:is_malware labels for mal/ben, but here for
family. Features already extracted (no new pipeline cost):
- TF-IDF on strings (300 dims, ngram 1-2) from gap_features_cache strings
- One-hot permissions (~150) + class_count + native_libs flag

Wired to backend/family_id.py:identify_family() between KB and LLM:
  if ML prob >0.6 → use ML, else fallback to LLM.

See docs/accuracy-improvement-plan.md Phase 2, docs/FULL_KNOWLEDGE_TRANSFER.md §4.

Usage:
  python analysis/ml_classifier.py --train   # 5-fold CV, save family_ml.pkl
  python analysis/ml_classifier.py --predict <sha>  # quick test
"""

import argparse
import csv
import json
import pickle
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
CACHE_PATH = ROOT / "analysis" / "gap_features_cache.json"
GT_PATH = ROOT / "ground_truth_all_corrected.csv"
MODEL_PATH = ROOT / "analysis" / "family_ml.pkl"
VECTORIZER_PATH = ROOT / "analysis" / "family_ml_vectorizer.pkl"

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import MultiLabelBinarizer
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from sklearn.metrics import accuracy_score  # noqa: F401  availability probe
    import lightgbm as lgb
    import numpy as np  # noqa: F401  availability probe
    from scipy.sparse import hstack, csr_matrix
    HAS_DEPS = True
except ImportError as e:
    HAS_DEPS = False
    print(f"Missing dep: {e} - pip install scikit-learn lightgbm")


def load_training_data() -> Tuple[List[str], List[str], List[Dict]]:
    """Load gap cache + GT, return (X_strings_blob, y_family, meta)."""
    cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    gt_by_sha = {r["sha256"].lower(): r for r in csv.DictReader(GT_PATH.open(encoding="utf-8"))}
    X_blob = []
    y = []
    meta = []
    for sha, entry in cache.items():
        if entry.get("parse_error"):
            continue
        gt = gt_by_sha.get(sha.lower())
        if not gt or gt["is_malware"] != "yes" or not gt["family"] or gt["family"].lower() == "unknown":
            continue
        fam = gt["family"]
        # Filter to families with n>=2 for train stability, but keep all for predict
        strings = entry.get("strings", []) or []
        blob = " ".join(s.lower() for s in strings if isinstance(s, str) and 4 <= len(s) <= 120)[:10000]
        if not blob.strip():
            blob = " ".join(entry.get("permissions", []) or [])
        X_blob.append(blob)
        y.append(fam)
        meta.append({"sha": sha, "family": fam, "perms": entry.get("permissions", []), "class_count": entry.get("class_count", 0)})
    return X_blob, y, meta


def train() -> Dict:
    if not HAS_DEPS:
        raise RuntimeError("Missing sklearn/lightgbm")
    X_blob, y, meta = load_training_data()
    print(f"Training on {len(y)} samples, {len(set(y))} families")
    from collections import Counter
    cnt = Counter(y)
    print("Top families:", cnt.most_common(5))
    # Filter families with <2 samples for CV stability - keep but stratified will handle
    # Use TF-IDF 300 + perms + class_count
    tfidf = TfidfVectorizer(max_features=300, ngram_range=(1, 2), min_df=2, max_df=0.9)
    X_str = tfidf.fit_transform(X_blob)
    # Permissions one-hot
    perms_list = [m["perms"] for m in meta]
    # Normalize perms to short name
    perms_short = [[p.split(".")[-1] for p in ps] for ps in perms_list]
    mlb = MultiLabelBinarizer()
    X_perm = mlb.fit_transform(perms_short)
    X_perm = csr_matrix(X_perm)
    # Class count + native flag as numeric
    import numpy as np
    X_num = np.array([[m["class_count"] or 0, 1 if m["perms"] else 0] for m in meta], dtype=float)
    # Simple scaling
    X_num = (X_num - X_num.mean(axis=0)) / (X_num.std(axis=0) + 1e-9)
    X_num = csr_matrix(X_num)
    X = hstack([X_str, X_perm, X_num]).tocsr()
    print(f"Feature dims: TF-IDF {X_str.shape[1]} + perms {X_perm.shape[1]} + num 2 = {X.shape[1]}")

    # LightGBM with class balance
    clf = lgb.LGBMClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.05,
        class_weight="balanced",
        verbose=-1,
        n_jobs=-1,
        random_state=42,
    )
    # 5-fold CV - stratified, need at least 5 per class, so use 3-fold for small
    n_splits = 3 if min(cnt.values()) < 5 else 5
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scores = cross_val_score(clf, X, y, cv=skf, scoring="accuracy")
    print(f"{n_splits}-fold CV accuracy: {scores.mean():.3f} +/- {scores.std():.3f} per fold {scores}")

    # Fit on all
    clf.fit(X, y)
    # Save
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump({"tfidf": tfidf, "mlb": mlb, "cnt": cnt}, f)
    print(f"Saved {MODEL_PATH} + {VECTORIZER_PATH}")
    # Also save feature importances
    return {"cv_mean": float(scores.mean()), "cv_std": float(scores.std()), "n_samples": len(y), "n_features": X.shape[1]}


def load_model():
    if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
        return None, None
    with open(MODEL_PATH, "rb") as f:
        clf = pickle.load(f)
    with open(VECTORIZER_PATH, "rb") as f:
        vec = pickle.load(f)
    return clf, vec


def predict_for_result(result: Dict, sample_id: str = None) -> Tuple[str, float]:
    """Predict family for a pipeline result dict (uses gap cache if sample_id present)."""
    clf, vec = load_model()
    if clf is None:
        return "unknown", 0.0
    # Try gap cache first
    try:
        cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        entry = cache.get(sample_id.lower()) if sample_id else None
        if entry and not entry.get("parse_error"):
            strings = entry.get("strings", []) or []
            blob = " ".join(s.lower() for s in strings if isinstance(s, str) and 4 <= len(s) <= 120)[:10000]
            perms = entry.get("permissions", []) or []
            class_count = entry.get("class_count", 0)
        else:
            # Fallback to result strings
            blob = " ".join(str(v) for v in result.get("strings", {}).values() if isinstance(v, str))[:10000]
            perms = result.get("permissions", []) or result.get("manifest", {}).get("uses_permissions", []) or []
            class_count = result.get("extraction", {}).get("decompiled_classes", 0)
    except Exception:
        return "unknown", 0.0

    tfidf = vec["tfidf"]
    mlb = vec["mlb"]
    try:
        X_str = tfidf.transform([blob])
        perms_short = [p.split(".")[-1] for p in perms]
        X_perm = mlb.transform([perms_short])
        import numpy as np
        from scipy.sparse import hstack, csr_matrix
        X_num = np.array([[class_count or 0, 1 if perms else 0]], dtype=float)
        X = hstack([X_str, csr_matrix(X_perm), csr_matrix(X_num)]).tocsr()
        # Align dims - if new perms unseen, mlb may have different shape; pad
        # For simplicity, if shape mismatch, skip perm part
        if X.shape[1] != clf.n_features_in_:
            # Rebuild with only TF-IDF if mismatch (rare)
            X = X_str
            if X.shape[1] != clf.n_features_in_:
                return "unknown", 0.0
        proba = clf.predict_proba(X)[0]
        idx = int(proba.argmax())
        fam = str(clf.classes_[idx])
        conf = float(proba[idx])
        return fam, conf
    except Exception as e:
        print(f"ML predict failed: {e}")
        return "unknown", 0.0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true", help="Train and save model")
    ap.add_argument("--predict", type=str, help="SHA to predict")
    args = ap.parse_args()
    if args.train:
        res = train()
        print(json.dumps(res, indent=2))
    elif args.predict:
        fam, conf = predict_for_result({}, sample_id=args.predict)
        print(f"{args.predict} -> {fam} {conf:.3f}")
    else:
        ap.print_help()
