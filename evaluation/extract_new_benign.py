"""Gap-style features for the new benign APKs (and their extra manifest/archive features)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis.gap_signature_mining import extract_corpus  # noqa: E402

if __name__ == "__main__":
    extract_corpus(ROOT / "evaluation" / "new_benign_gt.csv", ROOT / "evaluation" / "new_benign_features.json", workers=8)
