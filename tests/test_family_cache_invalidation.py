"""B1-04: family.json must not persist failed outcomes and must recompute on a stale stamp."""
import json

from backend import family_id
from backend.family_id import identify_family

PROBE = "ee" * 32
RESULT = {
    "metadata": {"sha256": PROBE},
    "certificate_analysis": {},
    "strings": {"string_literals": []},
    "c2_infrastructure": [],
}


def _sig(family):
    return lambda _res: {
        "family": family, "confidence": 0.9, "method": "signature_v3",
        "reasoning": "test", "candidates": [], "deterministic": True,
    }


def test_none_outcome_is_not_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(family_id.settings, "WORK_DIR", tmp_path)
    outcome = identify_family(PROBE, RESULT, use_llm=False, use_cache=True)
    assert outcome["method"] == "none"
    assert not (tmp_path / PROBE / "family.json").exists()


def test_stale_stamp_is_recomputed(tmp_path, monkeypatch):
    monkeypatch.setattr(family_id.settings, "WORK_DIR", tmp_path)
    cache = tmp_path / PROBE / "family.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({
        "family": "OldFam", "confidence": 0.9, "method": "signature_v3",
        "reasoning": "old", "candidates": [], "deterministic": True,
        "cache_stamp": "sig0-kb0",
    }), encoding="utf-8")
    monkeypatch.setattr(family_id, "_match_family_signatures", _sig("NewFam"))
    outcome = identify_family(PROBE, RESULT, use_llm=False, use_cache=True)
    assert outcome["family"] == "NewFam"
