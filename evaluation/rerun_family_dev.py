"""Re-run CURRENT family attribution over the saved dev results and score it against the 18-Oct baseline.

Uses the per-sample pipeline_result.json files of the dev anchor (evaluation/validation_359_dev/), so no
pipeline or LLM run is needed. Layers 1 and 2 only (signatures, knowledge base): the LLM layer is off, the
cache is off and the ground-truth override is off. Dev split only; it never reads holdout rows.

    python evaluation/rerun_family_dev.py

Scoring uses analysis.labels.is_correct (aliases, lineage) and is_catch_all, the same functions the
validation harness uses. "Scoreable" rows are those whose ground truth is a real family, not a catch-all
vendor token such as AndroidOS, GenericKD or Agent.
"""
import collections
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.pop("DF_FAMILY_GROUND_TRUTH", None)
os.environ["FAMILY_USE_LLM"] = "0"
os.environ["FAMILY_USE_CACHE"] = "0"

from analysis.labels import is_catch_all, is_correct  # noqa: E402
from backend import family_id  # noqa: E402

DEV_DIR = ROOT / "evaluation" / "validation_359_dev"
OUTPUT = DEV_DIR / "family_rerun.json"  # gitignored artifact directory


def rerun():
    family_id.GROUND_TRUTH_FILES = []
    rows = json.loads((DEV_DIR / "predictions.json").read_text(encoding="utf-8"))
    out = []
    for row in rows:
        path = DEV_DIR / row["sha256"] / "pipeline_result.json"
        if not path.exists():
            out.append({**row, "new_prediction": None, "new_method": "missing_result"})
            continue
        result = json.loads(path.read_text(encoding="utf-8"))
        try:
            verdict = family_id.identify_family(row["sha256"], result, use_llm=False, use_cache=False)
            out.append({**row, "new_prediction": verdict.get("family"), "new_method": verdict.get("method")})
        except Exception as exc:  # recorded in the output, never hidden
            out.append({**row, "new_prediction": None, "new_method": f"error:{type(exc).__name__}"})
    OUTPUT.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    return out


def bucket(prediction, truth):
    if (prediction or "unknown").lower() in ("unknown", "none", ""):
        return "abstain"
    return "correct" if is_correct(prediction, truth) else "wrong-name"


def report(rows, name, get_prediction):
    scoreable = [r for r in rows if not is_catch_all(r["ground_truth"])]
    catch_all = [r for r in rows if is_catch_all(r["ground_truth"])]
    counts = collections.Counter(bucket(get_prediction(r), r["ground_truth"]) for r in scoreable)
    named = counts["correct"] + counts["wrong-name"]
    named_catch_all = sum(1 for r in catch_all if bucket(get_prediction(r), r["ground_truth"]) != "abstain")
    all_correct = sum(is_correct(get_prediction(r) or "", r["ground_truth"]) for r in rows)
    print(f"{name:22s} scoreable({len(scoreable)}): correct={counts['correct']:3d} wrong={counts['wrong-name']:3d} "
          f"abstain={counts['abstain']:3d} | precision={counts['correct'] / named:.3f} "
          f"coverage={named / len(scoreable):.3f} | catch-all rows named={named_catch_all}/{len(catch_all)} "
          f"| all rows {all_correct}/{len(rows)}={all_correct / len(rows):.3f}")


def main():
    rows = [r for r in rerun() if r["new_method"] != "missing_result"]
    print(f"evaluated {len(rows)} dev rows (LLM layer off)")
    report(rows, "18-Oct baseline (LLM)", lambda r: r["prediction"])
    report(rows, "current code", lambda r: r["new_prediction"])
    print(f"per-row output: {OUTPUT}")


if __name__ == "__main__":
    main()
