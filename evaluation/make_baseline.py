"""Merge sharded family-identification runs and score them against the ground truth.

Writes, into --output-dir:
  * predictions.json   (records in the format metrics_recompute.py reads)
  * manifest.json      (commit, ground-truth hash, counts, and the metric command)
  * metrics/           (metrics_recompute.py output)

Usage:
    python evaluation/make_baseline.py \
        --shards-dir <dir with predictions_*.jsonl> \
        --gt ground_truth_all_corrected.csv \
        --output-dir evaluation/baseline_<date>
"""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVALUATION_DIR = Path(__file__).resolve().parent


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_commit() -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, capture_output=True, text=True)
    return result.stdout.strip() or "unknown"


def load_records(shards_dir: Path) -> list[dict]:
    records: dict[str, dict] = {}
    for shard in sorted(shards_dir.glob("predictions_*.jsonl")):
        for line in shard.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                records[record["sha256"]] = record  # a re-run replaces an earlier record
    return list(records.values())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shards-dir", type=Path, required=True)
    parser.add_argument("--gt", type=Path, default=PROJECT_ROOT / "ground_truth_all_corrected.csv")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    records = load_records(args.shards_dir)
    predictions_path = args.output_dir / "predictions.json"
    predictions_path.write_text(json.dumps(records, indent=1, default=str), encoding="utf-8")

    success = [r for r in records if r.get("status") == "success"]
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "ground_truth": str(args.gt.name),
        "ground_truth_sha256": _sha256(args.gt),
        "records": len(records),
        "successful": len(success),
        "errors": len(records) - len(success),
        "methods": {m: sum(1 for r in success if r.get("method") == m)
                    for m in sorted({r.get("method", "none") for r in success})},
        "metric_command": f"python evaluation/metrics_recompute.py --gt {args.gt.name} "
                          f"--predictions {predictions_path} --output-dir {args.output_dir / 'metrics'}",
    }
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    command = [sys.executable, str(EVALUATION_DIR / "metrics_recompute.py"), "--gt", str(args.gt),
               "--predictions", str(predictions_path), "--output-dir", str(args.output_dir / "metrics")]
    return subprocess.run(command, cwd=PROJECT_ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
