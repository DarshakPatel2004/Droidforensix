"""Extract classifier feature vectors from finished pipeline runs.

Each run directory holds <name>_<n>.jsonl records (status, sha256, label) and work_<n>/<sha256>/
pipeline_result.json. The output is one JSON list the predictor can read without the project.

Usage:
    python evaluation/extract_classifier_features.py <out.json> <run_dir>:<label> [<run_dir>:<label> ...]
    label is 1 for malware, 0 for benign.
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    out_path = Path(sys.argv[1])
    sys.path.insert(0, str(PROJECT_ROOT))
    from analysis.classify_fast import FEATURES, extract_feature_vector

    rows = []
    for spec in sys.argv[2:]:
        run_dir, label = Path(spec.rsplit(":", 1)[0]), int(spec.rsplit(":", 1)[1])
        for record_file in sorted(run_dir.glob("*_*.jsonl")):
            for line in record_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("status") != "success":
                    continue
                matches = list(run_dir.glob(f"work_*/{record['sha256']}/pipeline_result.json"))
                if not matches:
                    continue
                result = json.loads(matches[0].read_text(encoding="utf-8"))
                rows.append({"sha256": record["sha256"], "source": str(run_dir), "label": label,
                             "vector": extract_feature_vector(result)})
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"features": FEATURES, "rows": rows}), encoding="utf-8")
    print(f"wrote {len(rows)} rows to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
