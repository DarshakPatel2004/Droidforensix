"""Export review-ready campaign IOC bundles (offline, cached data only).

Usage: python scripts/export_campaign_bundles.py <campaign_purity.json> <gt_csv> <out.json>

Emits multi-sample campaigns ranked by size with GT family mix, shared
C2 hosts, and shared certs — the per-campaign review packet.
"""

import csv
import json
import sys
from collections import Counter
from pathlib import Path


def main() -> None:
    purity_path, gt_csv, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    report = json.loads(open(purity_path, encoding="utf-8").read())
    gt = {}
    with open(gt_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gt[row["sha256"].lower()] = {
                "family": row.get("family", "unknown"),
                "confidence": row.get("confidence", ""),
            }

    bundles = []
    for campaign in report.get("campaigns", []):
        if campaign.get("size", 0) < 2:
            continue
        members = campaign.get("members", [])
        if not members:
            continue
        families = Counter(
            gt.get(sha, {}).get("family", "unlabeled") for sha in members
        )
        top_family, top_count = families.most_common(1)[0]
        bundles.append(
            {
                "size": len(members),
                "members": members,
                "family_mix": dict(families.most_common()),
                "majority_family": top_family,
                "majority_fraction": round(top_count / len(members), 4),
                "shared_c2_hosts": campaign.get("shared_c2_hosts", []),
                "shared_certs": campaign.get("shared_certs", []),
            }
        )
    bundles.sort(key=lambda b: -b["size"])
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"campaigns": bundles, "total": len(bundles)}, f, indent=1)
    print(f"bundles={len(bundles)} samples={sum(b['size'] for b in bundles)} -> {out_path}")


if __name__ == "__main__":
    main()
