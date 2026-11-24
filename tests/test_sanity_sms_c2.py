"""SMS-fraud floor needs a corroborated C2 endpoint, not a bare domain string."""

from analysis.step7_llm_assessment import sanity_check

SMS_OBF = {"indicators": {"permission_behaviors": [{"group": "sms_fraud"}]}}


def _assessment():
    return {"severity": "low", "risk_score": 40, "narrative": ""}


def _c2(path, fallback, confidence=0.9):
    return {"c2_infrastructure": [{"domain": "x.test", "path": path,
                                   "is_fallback": fallback, "confidence": confidence}],
            "total_c2s": 1}


def test_bare_domain_c2_does_not_raise_sms_severity():
    out = sanity_check(_assessment(), {}, _c2(path="/", fallback=True), SMS_OBF)
    assert out["severity"] != "high"
    assert any("uncorroborated" in n for n in out.get("sanity_notes", []))


def test_corroborated_url_c2_raises_sms_severity():
    out = sanity_check(_assessment(), {}, _c2(path="/gate.php", fallback=False), SMS_OBF)
    assert out["severity"] == "high"
    assert out["risk_score"] >= 65


def test_truncated_telegram_prefix_does_not_raise_sms_severity():
    # "https://api.telegram.org/bot" is a cut-off prefix, not an endpoint.
    out = sanity_check(_assessment(), {}, _c2(path="/bot", fallback=False), SMS_OBF)
    assert out["severity"] != "high"
    assert any("uncorroborated" in n for n in out.get("sanity_notes", []))


def test_no_c2_leaves_severity_alone():
    c2 = {"c2_infrastructure": [], "total_c2s": 0}
    out = sanity_check(_assessment(), {}, c2, SMS_OBF)
    assert out["severity"] == "low"


def test_unverified_endpoint_does_not_raise_low_to_medium():
    out = sanity_check(_assessment(), {}, _c2(path="/", fallback=True), {})
    assert out["severity"] == "low"


def test_corroborated_endpoint_raises_low_to_medium():
    out = sanity_check(_assessment(), {}, _c2(path="/gate.php", fallback=False), {})
    assert out["severity"] in ("medium", "high")
