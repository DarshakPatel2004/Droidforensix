"""Report model status rules: a family is supported only by a strong signature; endpoints are never verified."""

from backend.report_model import _endpoint, _family_status


def test_knowledge_base_match_is_a_lead():
    assert _family_status({"family": "SpyNote", "method": "knowledge_base", "confidence": 0.9}) == "LEAD"


def test_strong_signature_is_supported():
    assert _family_status({"family": "FakeInst", "method": "signature_v3", "confidence": 0.95}) == "SUPPORTED_BY_SIGNATURE"


def test_weak_signature_is_a_lead():
    assert _family_status({"family": "X", "method": "signature_v3", "confidence": 0.7}) == "LEAD"


def test_no_family_is_no_attribution():
    assert _family_status({"family": "unknown"}) == "NO_ATTRIBUTION"
    assert _family_status({}) == "NO_ATTRIBUTION"


def test_endpoint_is_never_verified_and_bare_domain_not_corroborated():
    e = _endpoint({"raw_url": "telegram.org", "is_fallback": True, "path": None, "confidence": 0.7})
    assert e["status"] == "UNVERIFIED"
    assert e["corroborated"] is False
    e2 = _endpoint({"raw_url": "https://example.test/gate.php", "is_fallback": False, "path": "/gate.php", "confidence": 0.9})
    assert e2["corroborated"] is True and e2["status"] == "UNVERIFIED"


def test_truncated_prefix_is_not_corroborated_even_at_full_confidence():
    e = _endpoint({"raw_url": "https://api.telegram.org/bot", "is_fallback": False, "path": "/bot", "confidence": 1.0})
    assert e["corroborated"] is False
    assert e["status"] == "UNVERIFIED"


def test_endpoint_tier_separates_confirmed_from_lead():
    from backend.report_model import _endpoint
    confirmed = _endpoint({"domain": "gate.example", "path": "/gate.php", "confidence": 1.0,
                           "device_data_signal": True, "is_fallback": False})
    lead = _endpoint({"domain": "gate.example", "path": "/gate.php", "confidence": 1.0,
                      "device_data_signal": False, "is_fallback": False})
    none = _endpoint({"domain": "r2.adwo.com", "path": "/adfs", "confidence": 1.0,
                      "device_data_signal": True, "is_fallback": False})
    assert (confirmed["tier"], lead["tier"], none["tier"]) == ("confirmed", "lead", "none")
