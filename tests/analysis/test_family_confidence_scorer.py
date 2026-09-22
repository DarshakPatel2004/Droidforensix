"""Unit tests for family_confidence_scorer signals (additive evaluator only)."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from analysis.family_confidence_scorer import (
    FamilyConfidenceScorer,
    SampleSignals,
    SignalProfile,
)

PROFILE = SignalProfile(
    family="GinMaster",
    string_patterns=["ginmaster"],
    c2_patterns=["ginmaster.example.com"],
    permission_sigs={"SYSTEM_ALERT_WINDOW": 1.0},
    class_count_min=None,
    class_count_max=None,
    has_native_libs=False,
    conf_scale=1.0,
)


@pytest.fixture(scope="module")
def scorer() -> FamilyConfidenceScorer:
    return FamilyConfidenceScorer()


def signals_for(**overrides) -> SampleSignals:
    base = {
        "strings": [],
        "domains": [],
        "permissions": [],
        "class_count": 0,
        "native_libs": [],
    }
    base.update(overrides)
    return SampleSignals.from_cache(base)


class TestSignatureSignal:
    def test_full_hit_non_negative(self, scorer):
        signals = signals_for(strings=["ginmaster", "hello"])
        assert scorer._signature_signal(signals, PROFILE) > 0.0

    def test_no_hit_is_zero(self, scorer):
        signals = signals_for(strings=["unrelated"])
        assert scorer._signature_signal(signals, PROFILE) == 0.0

    def test_fractional_hit(self, scorer):
        signals = signals_for(strings=["ginmaster"])
        sig = scorer._signature_signal(signals, PROFILE)
        assert 0.0 < sig <= 1.0


class TestC2Alignment:
    def test_c2_domain_present_boosts(self, scorer):
        signals = signals_for(domains=["ginmaster.example.com"])
        assert scorer._c2_alignment(signals, PROFILE) > 0.0

    def test_no_domains_is_zero(self, scorer):
        signals = signals_for(domains=[])
        assert scorer._c2_alignment(signals, PROFILE) == 0.0


class TestProfileSignal:
    def test_kb_token_and_permission_both_contribute(self, scorer):
        signals = signals_for(strings=["ginmaster"], permissions=["SYSTEM_ALERT_WINDOW"])
        score = scorer._profile_signal(signals, PROFILE)
        assert 0.0 <= score <= 1.0
        assert score > 0.0

    def test_empty_sample_no_signal(self, scorer):
        signals = signals_for()
        score = scorer._profile_signal(signals, PROFILE)
        assert score == 0.0  # kb 0 and declared permission sig unmet

    def test_no_permission_sigs_is_neutral(self, scorer):
        no_perm_profile = SignalProfile(family="Other", permission_sigs={}, conf_scale=1.0)
        score = scorer._profile_signal(signals_for(), no_perm_profile)
        assert score > 0.0  # 0.5 neutral carries the signal


class TestScoreFamily:
    def test_confidence_bounded_and_weighted(self, scorer):
        signals = signals_for(
            strings=["ginmaster"],
            domains=["ginmaster.example.com"],
            permissions=["SYSTEM_ALERT_WINDOW"],
        )
        result = scorer.score_family(signals, PROFILE.family)
        assert 0.0 <= result["confidence"] <= 1.0
        assert set(result["signals"]) == {"signature", "c2_alignment", "profile", "metadata"}

    def test_unknown_family_scores_zero(self, scorer):
        result = scorer.score_family(signals_for(), "NotAFamily")
        assert result["confidence"] == 0.0

    def test_abstains_below_bar(self, scorer):
        result = scorer.score(signals_for(strings=["ginmaster"]), bar=0.99)
        assert result["family"] == "unknown"
