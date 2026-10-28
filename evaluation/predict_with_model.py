"""Predict with the shipped binary classifier from a feature file, and report detection rates.

Needs only scikit-learn and numpy, so it can run in an environment with a different
scikit-learn version than the project. Output goes to the --output path as JSON.

Usage:
    python evaluation/predict_with_model.py <features.json> <output.json>
"""

import json
import pickle
import sys
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent / "classifier_data" / "malben_rf.pkl"


def main() -> int:
    features_file, output_path = Path(sys.argv[1]), Path(sys.argv[2])
    payload = json.loads(features_file.read_text(encoding="utf-8"))
    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)
    model, model_features = bundle["model"], bundle["features"]
    if list(model_features) != payload["features"]:
        raise SystemExit("feature order mismatch between model and feature file")

    rows = payload["rows"]
    probs = model.predict_proba([row["vector"] for row in rows])[:, 1]
    tally = {0: [0, 0], 1: [0, 0]}  # label -> [flagged, total]
    results = []
    for row, p in zip(rows, probs):
        flagged = bool(p >= 0.5)
        tally[row["label"]][1] += 1
        tally[row["label"]][0] += int(flagged)
        results.append({"sha256": row["sha256"], "source": row["source"], "label": row["label"],
                        "p_malware": round(float(p), 4), "flagged": flagged})

    benign_flagged, benign_total = tally[0]
    malware_flagged, malware_total = tally[1]
    summary = {
        "sklearn_version_loaded": __import__("sklearn").__version__,
        "benign_total": benign_total,
        "benign_flagged": benign_flagged,
        "false_positive_rate": round(benign_flagged / benign_total, 4) if benign_total else None,
        "malware_total": malware_total,
        "malware_detected": malware_flagged,
        "detection_rate": round(malware_flagged / malware_total, 4) if malware_total else None,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"summary": summary, "results": results}, indent=1), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
