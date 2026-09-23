"""Create the frozen dev/holdout split for family-validation work (v1).

Why: results of the full-corpus run (evaluation/VALIDATION_359.md) have been
observed, so any engine tuning informed by per-row failures risks test-set
contamination. This split freezes a holdout subset BEFORE the accuracy push;
tuning iterates on dev only and the holdout is scored once, aggregate-only,
at declared milestones. Rules: evaluation/HOLDOUT_SPLIT.md.

Stratification: (source, is_catch_all(family)) so each source keeps its
scorable/catch-all proportion on both sides; uses the declared single source
of truth analysis/labels.py — no ad-hoc matching.

Deterministic: rows sorted by sha256, then shuffled per stratum with
random.Random(SEED). Re-running reproduces the file byte-for-byte.
"""

from __future__ import annotations

import csv
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from analysis.labels import is_catch_all  # noqa: E402  (needs sys.path above)

GROUND_TRUTH = PROJECT_ROOT / "ground_truth_all.csv"
OUTPUT = PROJECT_ROOT / "evaluation" / "holdout_split_v1.csv"

SEED = 42  # house seed (same as step17_family_clustering)
HOLDOUT_FRACTION = 0.30


def build_split() -> list[dict[str, str]]:
    with GROUND_TRUTH.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))

    strata: dict[tuple[str, bool], list[str]] = defaultdict(list)
    for row in rows:
        key = (row["source"], is_catch_all(row["family"]))
        strata[key].append(row["sha256"].lower())

    rng = random.Random(SEED)
    membership: dict[str, str] = {}
    for key in sorted(strata):
        members = sorted(strata[key])
        rng.shuffle(members)
        n_holdout = int(len(members) * HOLDOUT_FRACTION + 0.5)
        for sha in members[:n_holdout]:
            membership[sha] = "holdout"
        for sha in members[n_holdout:]:
            membership[sha] = "dev"

    assert len(membership) == len(rows), "split must cover every GT row exactly once"
    return [
        {
            "sha256": row["sha256"].lower(),
            "source": row["source"],
            "split": membership[row["sha256"].lower()],
        }
        for row in rows
    ]


def main() -> None:
    split_rows = build_split()
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sha256", "source", "split"])
        writer.writeheader()
        writer.writerows(split_rows)

    print(f"Wrote {len(split_rows)} rows -> {OUTPUT}")
    by_split: dict[str, int] = defaultdict(int)
    by_source: dict[tuple[str, str], int] = defaultdict(int)
    for row in split_rows:
        by_split[row["split"]] += 1
        by_source[(row["source"], row["split"])] += 1
    print(f"totals: {dict(by_split)}")
    for source in sorted({row['source'] for row in split_rows}):
        dev = by_source[(source, "dev")]
        hold = by_source[(source, "holdout")]
        print(f"  {source:<16} dev={dev:<4} holdout={hold}")


if __name__ == "__main__":
    main()
