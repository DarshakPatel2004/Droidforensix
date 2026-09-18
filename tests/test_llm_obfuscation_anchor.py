"""Tests for obfuscation-aware LLM fallback and sanity checks."""

from analysis.step7_llm_assessment import fallback_assessment, sanity_check


def test_fallback_assessment_obfuscation_anchor():
    chains = {"sample_id": "test", "total_chains": 0, "threat_chains": []}
    c2 = {"sample_id": "test", "total_c2s": 0, "c2_infrastructure": []}
    obfuscation = {
        "obfuscation_score": 65.0,
        "obfuscation_level": "medium",
        "indicators": {
            "dangerous_permissions": ["p1", "p2", "p3"],
            "suspicious_apis": ["a1"],
            "reflection": ["r1"],
            "dynamic_loading": ["d1"],
        },
    }
    result = fallback_assessment(chains, c2, obfuscation)
    assert result["severity"] == "medium"
    assert result["risk_score"] == 65
    assert "obfuscation" in result["narrative"].lower()
    assert "dangerous permissions" in result["narrative"].lower()


def test_fallback_assessment_low_obfuscation():
    chains = {"sample_id": "test", "total_chains": 0, "threat_chains": []}
    c2 = {"sample_id": "test", "total_c2s": 0, "c2_infrastructure": []}
    obfuscation = {
        "obfuscation_score": 10.0,
        "obfuscation_level": "low",
        "indicators": {"dangerous_permissions": []},
    }
    result = fallback_assessment(chains, c2, obfuscation)
    assert result["severity"] == "low"
    assert result["risk_score"] == 25


def test_sanity_check_raises_on_obfuscation():
    chains = {"sample_id": "test", "total_chains": 0, "threat_chains": []}
    c2 = {"sample_id": "test", "total_c2s": 0, "c2_infrastructure": []}
    obfuscation = {
        "obfuscation_score": 75.0,
        "obfuscation_level": "high",
        "indicators": {"dangerous_permissions": ["p1", "p2", "p3", "p4"]},
    }
    assessment = {
        "severity": "medium",
        "risk_score": 45,
        "narrative": "Initial medium verdict.",
    }
    result = sanity_check(assessment, chains, c2, obfuscation)
    # No C2 detected → sanity_check caps at medium / risk_score 50 max
    assert result["severity"] == "medium"
    assert result["risk_score"] <= 50


def test_sanity_check_low_with_obfuscation():
    chains = {"sample_id": "test", "total_chains": 0, "threat_chains": []}
    c2 = {"sample_id": "test", "total_c2s": 0, "c2_infrastructure": []}
    obfuscation = {
        "obfuscation_score": 55.0,
        "obfuscation_level": "medium",
        "indicators": {"dangerous_permissions": ["p1"]},
    }
    assessment = {
        "severity": "low",
        "risk_score": 10,
        "narrative": "Initial low verdict.",
    }
    result = sanity_check(assessment, chains, c2, obfuscation)
    # obf_score 55 + 1 dangerous perm → raised to medium / risk_score 30
    assert result["severity"] == "medium"
    assert result["risk_score"] >= 30
