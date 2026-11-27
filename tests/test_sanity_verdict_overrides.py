"""Sanity rules must not overwrite a secrets-based verdict or match C2 inside other tokens (audit A1-04/05)."""

from analysis.step7_llm_assessment import sanity_check

NO_C2 = {"total_c2s": 0}
CRITICAL_SECRETS = {"hardcoded_secrets": [{"severity": "critical", "type": "private_key"}]}


def _assessment(narrative="The app stores a private key."):
    return {"severity": "low", "risk_score": 20, "narrative": narrative}


def test_critical_secret_survives_no_c2_cap():
    out = sanity_check(_assessment(), {}, NO_C2, None, CRITICAL_SECRETS)
    assert out["severity"] == "high"
    assert out["risk_score"] >= 70


def test_c2_word_inside_other_token_is_not_a_c2_claim():
    out = sanity_check(_assessment("Uses an rc2 cipher for local storage."), {}, NO_C2)
    assert out["severity"] == "low"
    assert out["risk_score"] == 20
    assert not any("speculative" in n for n in out.get("sanity_notes", []))


def test_real_c2_claim_without_indicators_is_still_reduced():
    out = sanity_check(_assessment("The app beacons to a C2 server."), {}, NO_C2)
    assert out["severity"] == "low"
    assert out["risk_score"] <= 25
    assert any("speculative" in n for n in out.get("sanity_notes", []))
