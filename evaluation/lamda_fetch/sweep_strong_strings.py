"""Sweep _KB_STRONG_STRING_HITS: open-set false attributions vs in-KB recall."""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import backend.family_id as fid  # noqa: E402

HERE = Path(__file__).resolve().parent
selection = json.loads((HERE / "selection.json").read_text(encoding="utf-8"))
eval_shas = [x["sha256"] for x in selection if x["group"] == "eval"]
kb_rows = list(csv.DictReader(open(HERE / "kb_gt.csv", encoding="utf-8")))
samples = [("33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2", "SpyNote"),
           ("a08f4f1816977d996dce4ab91732d918a13e9c02bed6080ac2b372c370b9da80", None)]

for n in [int(x) for x in sys.argv[1:]] or [5, 8, 10, 15, 20]:
    fid._KB_STRONG_STRING_HITS = n
    fid._KB_PATH = HERE / "eval_kb_placeholder.json"  # overwritten below
    results = {}
    for label, kb_path, cache in [("open", ROOT / "analysis" / "family_knowledge_base.json", HERE / "eval_features.json"),
                                  ("inset", HERE / "kb_knowledge_base.json", HERE / "kb_features.json")]:
        fid._KB_PATH, fid._KB_CACHE_PATH = kb_path, cache
        fid._KB_LOADED = None
        fid._KB_CACHE_LOADED = None
        if label == "open":
            fp = sum(1 for s in eval_shas if fid._match_family_knowledge({}, sample_id=s))
            results["open_false"] = fp
        else:
            ok = sum(1 for r in kb_rows
                     if (lambda h: h and h["family"].lower() == r["family_corrected"].lower())(
                         fid._match_family_knowledge({}, sample_id=r["sha256"])))
            results["inset_recall"] = f"{ok}/{len(kb_rows)}"
    fid._KB_PATH = ROOT / "analysis" / "family_knowledge_base.json"
    fid._KB_CACHE_PATH = HERE / "eval_features.json"
    fid._KB_LOADED = None
    fid._KB_CACHE_LOADED = None
    for sid, _ in samples:
        r = json.load(open(ROOT / "analysis" / "work" / sid / "pipeline_result.json", encoding="utf-8"))
        h = fid._match_family_knowledge(r, sample_id=sid)
        results[sid[:8]] = h["family"] if h else None
    print(json.dumps({"min_string_hits": n, **results}), flush=True)
