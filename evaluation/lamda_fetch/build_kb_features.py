"""Extract gap-style features for the LAMDA kb group into a separate cache."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analysis.gap_signature_mining import extract_corpus  # noqa: E402

HERE = Path(__file__).resolve().parent

if __name__ == "__main__":
    extract_corpus(HERE / "kb_gt.csv", HERE / "kb_features.json", workers=8)
