"""Tests for split-safe family ensemble evaluation coverage."""

from evaluation import family_ensemble_eval


class _FakeScorer:
    families = {"Known"}

    def score(self, sample, bar=0.0):
        return {"family": "Known", "confidence": 0.8, "signals": {}}


def test_missing_cache_is_counted_as_unknown_when_requested(monkeypatch):
    monkeypatch.setattr(family_ensemble_eval, "FamilyConfidenceScorer", _FakeScorer)
    ground_truth = {
        "cached": {"sha256": "cached", "source": "fixture", "family": "Known"},
        "missing": {"sha256": "missing", "source": "fixture", "family": "Known"},
    }
    predictions = {
        "cached": {"prediction": "Known", "confidence": 0.9},
        "missing": {"prediction": "Known", "confidence": 0.9},
    }
    cache = {"cached": {"strings": ["known-token"], "domains": []}}

    limited = family_ensemble_eval.evaluate(predictions, ground_truth, cache, [0.75])
    complete = family_ensemble_eval.evaluate(
        predictions,
        ground_truth,
        cache,
        [0.75],
        include_missing_as_unknown=True,
    )

    assert limited["evaluated"] == 1
    assert complete["evaluated"] == 2
    assert complete["cache_available_rows"] == 1
    assert complete["missing_as_unknown_rows"] == 1
    assert complete["sweep"]["0.75"]["correct"] == 1
