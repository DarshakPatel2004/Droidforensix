"""Score the family KB matcher on the LAMDA eval group.

Usage: score_kb.py shipped|kb_only
Both configs read the same eval feature cache, so only the KB differs.
The matcher's KB and cache paths are module constants, so they are overridden here.
"""

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


def main() -> None:
    name = sys.argv[1]
    fid._KB_PATH = KBS[name]
    fid._KB_CACHE_PATH = HERE / "eval_features.json"
    fid._KB_LOADED = None
    fid._KB_CACHE_LOADED = None

    selection = json.loads((HERE / "selection.json").read_text(encoding="utf-8"))
    evals = [x for x in selection if x["group"] == "eval"]

    rows = []
    for x in evals:
        hit = fid._match_family_knowledge({}, sample_id=x["sha256"])
        predicted = hit["family"] if hit else None
        rows.append({
            "sha256": x["sha256"],
            "truth": x["family"],
            "predicted": predicted,
            "correct": predicted is not None and predicted.lower() == x["family"].lower(),
        })

    predicted_rows = [r for r in rows if r["predicted"] is not None]
    correct = sum(r["correct"] for r in rows)
    summary = {
        "kb": name,
        "eval_n": len(rows),
        "predicted": len(predicted_rows),
        "correct": correct,
        "recall": round(correct / len(rows), 4),
        "precision": round(correct / len(predicted_rows), 4) if predicted_rows else None,
    }
    print(json.dumps(summary, indent=2))
    (HERE / f"kb_score_{name}.json").write_text(
        json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
