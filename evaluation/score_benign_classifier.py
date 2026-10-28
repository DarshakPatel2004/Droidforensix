"""Score the binary classifier on the benign Play-market run and report the false-positive rate.

Reads each APK's pipeline_result.json from the benign run's work dirs, builds the classifier
feature vector, and writes per-APK predictions plus a summary.

Usage:
    python evaluation/score_benign_classifier.py <benign_run_dir> <output_dir>
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    run_dir, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(PROJECT_ROOT))
    from analysis.classify_fast import _load_model, extract_feature_vector

    clf = _load_model()["model"]
    records = []
    for shard_file in sorted(run_dir.glob("benign_*.jsonl")):
        records += [json.loads(line) for line in shard_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    rows = []
    for rec in records:
        if rec["status"] != "success":
            continue
        result_paths = list(run_dir.glob(f"work_*/{rec['sha256']}/pipeline_result.json"))
        if not result_paths:
            rows.append({"sha256": rec["sha256"], "pkg": rec["pkg"], "error": "no pipeline_result.json"})
            continue
        result = json.loads(result_paths[0].read_text(encoding="utf-8"))
        vec = extract_feature_vector(result)
        p_malware = float(clf.predict_proba([vec])[0][1])
        rows.append({"sha256": rec["sha256"], "pkg": rec["pkg"], "p_malware": round(p_malware, 4),
                     "flagged": p_malware >= 0.5})

    scored = [r for r in rows if "p_malware" in r]
    flagged = [r for r in scored if r["flagged"]]
    summary = {
        "benign_apks": len(records),
        "scored": len(scored),
        "errors": len(rows) - len(scored),
        "flagged_malware": len(flagged),
        "false_positive_rate": round(len(flagged) / len(scored), 4) if scored else None,
        "benign_accuracy": round(1 - len(flagged) / len(scored), 4) if scored else None,
    }
    (out_dir / "benign_predictions.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    (out_dir / "benign_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
