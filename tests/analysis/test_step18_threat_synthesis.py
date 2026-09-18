import pytest
from analysis.step18_threat_synthesis import (
    synthesize_threat_profile,
    score_zero_day_risk,
    THREAT_WEIGHTS,
)


class TestSynthesizeThreatProfile:
    def test_empty(self):
        result = synthesize_threat_profile({})
        assert result["zero_day_risk_score"] == 0.0
        assert result["risk_level"] == "unknown"

    def test_with_indicators(self):
        context = {
            "packing": {"packing_detected": True, "obfuscation_score": 80},
            "reflective_tracing": {"total_sensitive": 5},
            "permissions": {"total_used": 3, "usage_ratio": 0.3},
            "network": {"total_c2": 2},
            "strings": {"total_high_entropy": 10},
        }
        result = synthesize_threat_profile(context)
        assert result["zero_day_risk_score"] > 0
        assert result["risk_level"] in ("low", "medium", "high", "critical")

    def test_clean(self):
        context = {
            "packing": {"packing_detected": False, "obfuscation_score": 0},
            "reflective_tracing": {"total_sensitive": 0},
            "permissions": {"total_used": 0, "usage_ratio": 0.0},
            "network": {"total_c2": 0},
            "strings": {"total_high_entropy": 0},
        }
        result = synthesize_threat_profile(context)
        assert result["risk_level"] in ("none", "low", "unknown")

    def test_none_context(self):
        result = synthesize_threat_profile(None)
        assert result["zero_day_risk_score"] == 0.0
        assert result["risk_level"] == "unknown"


class TestScoreZeroDayRisk:
    def test_clean(self):
        context = {
            "packing": {"packing_detected": False, "obfuscation_score": 0},
            "reflective_tracing": {"total_sensitive": 0},
            "permissions": {"total_used": 0, "usage_ratio": 0.0},
            "network": {"total_c2": 0},
            "strings": {"total_high_entropy": 0},
        }
        score = score_zero_day_risk(context)
        assert score < 20

    def test_malicious(self):
        context = {
            "packing": {"packing_detected": True, "obfuscation_score": 85},
            "reflective_tracing": {"total_sensitive": 8},
            "permissions": {"total_used": 5, "usage_ratio": 0.1},
            "network": {"total_c2": 4},
            "strings": {"total_high_entropy": 25},
        }
        score = score_zero_day_risk(context)
        assert score > 50

    def test_empty(self):
        assert score_zero_day_risk({}) == 0.0


class TestConstants:
    def test_threat_weights_defined(self):
        assert len(THREAT_WEIGHTS) > 0
        total = sum(w["weight"] for w in THREAT_WEIGHTS)
        assert abs(total - 100) < 0.01
