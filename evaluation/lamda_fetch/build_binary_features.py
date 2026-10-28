"""Build predictor input for the LAMDA holdout from the pipeline run logs.

The run logs already hold the classifier's 15-value feature vector per APK, so no
pipeline_result.json is needed. Every LAMDA APK is malware (label 1).
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analysis.classify_fast import FEATURES  # noqa: E402

HERE = Path(__file__).resolve().parent

if __name__ == "__main__":
    rows = []
    for name in ["run_log_0.jsonl", "run_log_1.jsonl"]:
        for line in (HERE / name).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec["status"] != "ok":
                raise SystemExit(f"non-ok run record: {rec['sha256']} {rec['status']}")
            rows.append({"sha256": rec["sha256"], "source": rec["group"], "label": 1,
                         "vector": rec["features"]})
    if len(rows) != 102 or any(len(r["vector"]) != len(FEATURES) for r in rows):
        raise SystemExit(f"expected 102 rows of {len(FEATURES)} features, got {len(rows)}")
    payload = {"features": FEATURES, "rows": rows}
    (HERE / "binary_features.json").write_text(json.dumps(payload), encoding="utf-8")
    print(f"wrote {len(rows)} rows")
