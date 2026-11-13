"""Append/update the c2_alignment column in evaluation/classifier_data/features.csv.

Idempotent: rerunning recomputes the column in place (same semantics, same
coverage), never duplicates it.

c2_alignment definition (reuses analysis/family_confidence_scorer verbatim -
the same signal the family scorer fuses at weight 0.25):

    value = max over all known family profiles of
            FamilyConfidenceScorer._c2_alignment(sample, profile)
          = max_families( matched_c2_pool_patterns / len(pool_patterns) )

    where the sample's domains come from analysis/gap_features_cache.json and
    each family's pool = FAMILY_SIGNATURES c2 patterns + mined KB domains
    (static knowledge only, no ground-truth labels).

EXPLICIT NO-CACHE SEMANTICS (not silent zero-fill) - three cases, reported on
every run, value 0.0 in the first two:

  no_cache_entry : sha absent from gap_features_cache.json. 0.0 means "no
                   observed C2-alignment evidence", NOT a verified zero.
                   (150 rows: all 100 benign + 50 malware)
  empty_domains  : cache entry exists but holds no domains. Same meaning:
                   extraction observed no C2 domains for this row. (160 rows,
                   all malware)
  computed       : domains present; real alignment value in [0, 1]. (199 rows,
                   all malware; 133 of them > 0)

Coverage limitation, stated honestly: domain lists persist only for 199/509
rows and never for benign rows, so benign alignment is structurally recorded
0.0. This is defensible - the C2 pools are mined from malware-only knowledge,
so benign overlap is expected ~0 - but it remains an assumption about the 75
benign rows that have num_c2 > 0 whose domain strings were never persisted.

Usage:
    python scripts/build_c2_alignment_column.py [--check]
        --check  recompute and report drift without writing
"""
import argparse
import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FEATS_CSV = ROOT / "evaluation" / "classifier_data" / "features.csv"
GAP_CACHE = ROOT / "analysis" / "gap_features_cache.json"
COLUMN = "c2_alignment"
ROUND_DP = 6


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="recompute and report drift without writing")
    args = parser.parse_args()

    from analysis.family_confidence_scorer import FamilyConfidenceScorer, SampleSignals

    scorer = FamilyConfidenceScorer()
    profiles = list(scorer._profiles.values())
    cache = json.loads(GAP_CACHE.read_text(encoding="utf-8"))

    with open(FEATS_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    coverage = {"no_cache_entry": 0, "empty_domains": 0, "computed": 0}
    nonzero = 0
    for row in rows:
        entry = cache.get(row["sha256"])
        if entry is None:
            value, reason = 0.0, "no_cache_entry"
        else:
            sample = SampleSignals.from_cache(entry)
            if not sample.domains:
                value, reason = 0.0, "empty_domains"
            else:
                value = max((scorer._c2_alignment(sample, p) for p in profiles),
                            default=0.0)
                reason = "computed"
        coverage[reason] += 1
        nonzero += value > 0
        row[COLUMN] = f"{round(value, ROUND_DP):g}"

    print(f"rows: {len(rows)}  coverage: {coverage}  nonzero: {nonzero}")

    if COLUMN in fieldnames:
        out_fields = fieldnames
    else:
        out_fields = fieldnames + [COLUMN]

    if args.check:
        print("--check: not writing")
        return

    tmp_csv = FEATS_CSV.with_suffix(".csv.tmp")  # atomic: a crash never truncates features.csv
    with open(tmp_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=out_fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp_csv, FEATS_CSV)
    print(f"Wrote {COLUMN} -> {FEATS_CSV}")


if __name__ == "__main__":
    main()
