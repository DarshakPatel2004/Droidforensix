"""Campaign-consistency audit for ground truth (read-only gate).

Compares GT labels against campaign communities (built WITHOUT labels):
  - contradiction: a sample whose label differs from the UNANIMOUS specific
    majority of its campaign co-members (probable mislabel; review first).
  - proposal: a catch-all-labeled sample with specific co-members
    (relabel candidate with measured precision).

GT release process (permanent noise control):
  1. Run this audit: python scripts/audit_gt_consistency.py
  2. Review reports/gt_consistency.json (contradictions, then proposals).
  3. Apply confirmed relabels with source tags (family_source/confidence).
  4. Snapshot: copy the corrected CSV to ground_truth_vX.Y.csv + note the
     change; re-run evaluation/metrics_recompute.py into a new versioned dir.

Usage: python scripts/audit_gt_consistency.py [purity_json] [gt_csv] [out]
Exit code is always 0; the report is the gate (review it before recompute).
"""

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analysis.labels import canonical_family, is_catch_all

PURITY_JSON = ROOT / "evaluation_results" / "campaign_purity.json"
GT_CSV = ROOT / "ground_truth_all_corrected.csv"
OUT_PATH = ROOT / "reports" / "gt_consistency.json"


def main() -> None:
    purity_path = Path(sys.argv[1]) if len(sys.argv) > 1 else PURITY_JSON
    gt_path = Path(sys.argv[2]) if len(sys.argv) > 2 else GT_CSV
    out_path = Path(sys.argv[3]) if len(sys.argv) > 3 else OUT_PATH

    report = json.loads(purity_path.read_text(encoding="utf-8"))
    gt: dict = {}
    with open(gt_path, encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            gt[row["sha256"].lower()] = row.get("family", "unknown")

    contradictions = []
    proposals = []
    for campaign in report.get("campaigns", []):
        members = campaign.get("members", [])
        if len(members) < 2:
            continue
        labels = [(m, gt.get(m, "unknown")) for m in members]
        specific = [(m, fam) for m, fam in labels if not is_catch_all(fam)]
        catchalls = [(m, fam) for m, fam in labels if is_catch_all(fam)]
        if not specific:
            continue
        # Canonicalize through lineage so vendor splits don't read as conflict.
        canon = Counter(canonical_family(fam) for _, fam in specific)
        top, top_count = canon.most_common(1)[0]
        fraction = top_count / len(specific)
        evidence = {
            "campaign_size": len(members),
            "shared_c2_hosts": campaign.get("shared_c2_hosts", []),
            "shared_certs": campaign.get("shared_certs", []),
        }
        if fraction < 0.8:
            continue  # no supermajority: nothing reviewable
        # Supermajority: dissenting specific members contradict it.
        for member, family in specific:
            if canonical_family(family) != top:
                contradictions.append(
                    {
                        "sample": member,
                        "gt_label": family,
                        "campaign_majority": top,
                        "majority_fraction": round(fraction, 4),
                        **evidence,
                    }
                )
        # Catch-all members are relabel proposals at this precision.
        for member, family in catchalls:
            proposals.append(
                {
                    "sample": member,
                    "gt_label": family,
                    "proposed_family": top,
                    "majority_fraction": round(fraction, 4),
                    **evidence,
                }
            )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            {
                "contradictions": contradictions,
                "contradiction_count": len(contradictions),
                "proposals": proposals,
                "proposal_count": len(proposals),
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    print(
        f"contradictions={len(contradictions)} proposals={len(proposals)} -> {out_path}",
        flush=True,
    )


if __name__ == "__main__":
    main()
