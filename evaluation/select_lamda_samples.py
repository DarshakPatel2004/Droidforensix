"""Select LAMDA malware for fetching: families split into a knowledge-base group and an evaluation group.

Only malware whose hash is not in the classifier's training CSV is eligible. Singleton families
are excluded. Families with at least MIN_FAMILY candidates are kept, up to PER_FAMILY samples each.
Families are split at random (seed 7) so the family knowledge base is built only from the
"kb" group and scored only on the "eval" group.

Usage:
    python evaluation/select_lamda_samples.py <meta_dir> <output.json>
"""

import csv
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAIN_CSV = PROJECT_ROOT / "evaluation" / "classifier_data" / "features.csv"
MIN_FAMILY = 3
PER_FAMILY = 3
KB_FAMILIES = 17
EVAL_FAMILIES = 17
SEED = 7


def main() -> int:
    meta_dir, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    trained = {r["sha256"].lower() for r in csv.DictReader(open(TRAIN_CSV, encoding="utf-8"))}

    by_family = defaultdict(list)
    for meta in sorted(meta_dir.glob("*_meta_*.npz")):
        z = np.load(meta, allow_pickle=True)
        year = meta.name.split("_")[0]
        for label, family, sha in zip(z["y"], z["family"], z["hash"]):
            family, sha = str(family), sha.lower()
            if int(label) != 1 or family.startswith("singleton:") or family == "benign" or sha in trained:
                continue
            by_family[family].append({"sha256": sha, "family": family, "year": year})

    eligible = {f: rows for f, rows in by_family.items() if len(rows) >= MIN_FAMILY}
    names = sorted(eligible)
    random.Random(SEED).shuffle(names)
    groups = {"kb": names[:KB_FAMILIES], "eval": names[KB_FAMILIES:KB_FAMILIES + EVAL_FAMILIES]}

    selection = []
    for group, family_names in groups.items():
        for family in family_names:
            rows = sorted(eligible[family], key=lambda r: r["sha256"])[:PER_FAMILY]
            for row in rows:
                selection.append({**row, "group": group})

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(selection, indent=1), encoding="utf-8")
    print(f"families eligible: {len(eligible)} (kb {len(groups['kb'])}, eval {len(groups['eval'])})")
    print(f"selected APKs: {len(selection)} (kb {sum(r['group'] == 'kb' for r in selection)}, "
          f"eval {sum(r['group'] == 'eval' for r in selection)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
