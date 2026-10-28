"""Run the full pipeline over the benign Play-market APKs, one shard per process.

Results: <out_dir>/benign_<shard>.jsonl (one record per APK) and <out_dir>/work_<shard>/
(pipeline output). Re-running skips APKs already recorded.

Usage:
    python evaluation/run_benign_pipeline.py <out_dir> <shard> <shards>
"""

import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENIGN_DIR = PROJECT_ROOT / "samples" / "benign_playstore"


def main() -> int:
    out_dir, shard, shards = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(PROJECT_ROOT))
    from analysis.pipeline import run_pipeline

    picks = json.loads((BENIGN_DIR / "selection.json").read_text(encoding="utf-8"))
    mine = [p for i, p in enumerate(picks) if i % shards == shard]
    out_path = out_dir / f"benign_{shard}.jsonl"
    done = set()
    if out_path.exists():
        done = {json.loads(line)["sha256"] for line in out_path.read_text(encoding="utf-8").splitlines()}

    with open(out_path, "a", encoding="utf-8") as out:
        for pick in mine:
            sha = pick["sha256"].lower()
            if sha in done:
                continue
            apk = BENIGN_DIR / f"{sha}.apk"
            start = time.time()
            record = {"sha256": sha, "is_malware": 0, "pkg": pick["pkg"]}
            try:
                result = run_pipeline(str(apk), work_dir=str(out_dir / f"work_{shard}"), pipeline_timeout=1200)
                record.update({"status": "success",
                               "severity": (result.get("llm_assessment") or {}).get("severity")})
            except Exception as exc:  # recorded, never dropped
                record.update({"status": "error", "error": f"{type(exc).__name__}: {exc}"[:300]})
            record["seconds"] = round(time.time() - start, 1)
            out.write(json.dumps(record, default=str) + "\n")
            out.flush()
    print(f"shard {shard} done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
