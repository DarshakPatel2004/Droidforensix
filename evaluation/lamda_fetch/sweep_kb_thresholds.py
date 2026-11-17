"""Sweep KB matcher thresholds on the open-set eval group.

Every eval family is absent from the knowledge base, so the correct count of
family attributions is zero. Each attribution here is a false positive.
Usage: sweep_kb_thresholds.py [shipped|kb_only]
"""

import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import backend.family_id as fid  # noqa: E402

HERE = Path(__file__).resolve().parent
KBS = {
    "shipped": ROOT / "analysis" / "family_knowledge_base.json",
    "kb_only": HERE / "kb_knowledge_base.json",
}


def load(name: str) -> None:
    fid._KB_PATH = KBS[name]
    fid._KB_CACHE_PATH = HERE / "eval_features.json"
    fid._KB_LOADED = None
    fid._KB_CACHE_LOADED = None


def open_set_false_attributions(eval_shas: list) -> int:
    return sum(1 for sha in eval_shas if fid._match_family_knowledge({}, sample_id=sha))


def main() -> None:
    name = sys.argv[1] if len(sys.argv) > 1 else "shipped"
    load(name)
    selection = json.loads((HERE / "selection.json").read_text(encoding="utf-8"))
    eval_shas = [x["sha256"] for x in selection if x["group"] == "eval"]
    defaults = {"score": fid._KB_MIN_SCORE, "tokens": fid._KB_MIN_TOKENS, "anchor": fid._KB_ANCHOR_FP}
    print("defaults", defaults, "eval_n", len(eval_shas))
    results = []
    for score, tokens, anchor in itertools.product(
        [0.35, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0], [2, 3, 4], [0.05, 0.02, 0.01]
    ):
        fid._KB_MIN_SCORE, fid._KB_MIN_TOKENS, fid._KB_ANCHOR_FP = score, tokens, anchor
        fp = open_set_false_attributions(eval_shas)
        results.append({"score": score, "tokens": tokens, "anchor": anchor, "false_attributions": fp})
        print(f"score={score} tokens={tokens} anchor={anchor} false_attributions={fp}", flush=True)
    (HERE / f"kb_threshold_sweep_{name}.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
