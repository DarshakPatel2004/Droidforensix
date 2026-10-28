"""Extract the same gap-style features for the LAMDA eval group (held out from mining)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analysis.gap_signature_mining import extract_corpus  # noqa: E402

HERE = Path(__file__).resolve().parent

if __name__ == "__main__":
    extract_corpus(HERE / "eval_gt.csv", HERE / "eval_features.json", workers=8)
