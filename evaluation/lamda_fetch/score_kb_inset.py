"""In-KB recall for the family matcher: kb_gt samples scored against the kb_only KB.

Caveat: kb_only was mined from these same samples, so this is optimistic.
"""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import backend.family_id as fid  # noqa: E402

HERE = Path(__file__).resolve().parent
fid._KB_PATH = HERE / "kb_knowledge_base.json"
fid._KB_CACHE_PATH = HERE / "kb_features.json"
fid._KB_LOADED = None
fid._KB_CACHE_LOADED = None

rows = list(csv.DictReader(open(HERE / "kb_gt.csv", encoding="utf-8")))
hits = correct = 0
for r in rows:
    h = fid._match_family_knowledge({}, sample_id=r["sha256"])
    if h:
        hits += 1
        correct += h["family"].lower() == r["family_corrected"].lower()
print(json.dumps({"kb_n": len(rows), "predicted": hits, "correct": correct,
                  "recall": round(correct / len(rows), 4)}, indent=2))
