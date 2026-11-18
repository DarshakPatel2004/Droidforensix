"""A LOW-severity benign verdict must not carry a risk score above the no-C2 ceiling of 50."""

from analysis.step7_llm_assessment import benign_verdict_heuristic


def test_low_severity_risk_never_exceeds_fifty():
    obf = {
        "obfuscation_score": 80,
        "indicators": {
            "dangerous_permissions": [f"p{i}" for i in range(5)],
            "suspicious_apis": [f"a{i}" for i in range(5)],
            "reflection": [f"r{i}" for i in range(3)],
            "dynamic_loading": ["d0"],
        },
    }
    out = benign_verdict_heuristic({}, {"c2_infrastructure": []}, obf)
    assert out["severity"] == "low"
    assert out["risk_score"] <= 50
