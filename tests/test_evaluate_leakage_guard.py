"""E5: the leakage guard must catch overlap with every training-side source."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_malben as em  # noqa: E402


def test_overlap_with_train_extra_is_rejected(tmp_path):
    train_hash = next(iter(em._csv_hashes(em.TRAIN_EXTRA)))
    empty_map = tmp_path / "map.json"
    empty_map.write_text("{}", encoding="utf-8")
    sample = em.Sample(sha256=train_hash, path="x", label="benign", source="holdout")
    with pytest.raises(em.ManifestError):
        em.check_no_training_overlap([sample], empty_map)
