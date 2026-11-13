"""Bare IP / domain indicators must survive step 2 and step 5 (audit A1-01, A1-02)."""
from analysis.step2_string_enumeration import is_noisy_string
from analysis.step5_c2_extraction import extract_c2_infrastructure


def test_bare_ip_and_ip_port_are_not_noise():
    assert not is_noisy_string("8.8.8.8")
    assert not is_noisy_string("45.77.12.9:7771")


def test_decoded_bare_domain_and_ip_become_c2_records():
    payloads = {
        "sample_id": "t",
        "payloads": [{
            "payload_id": "p1",
            "source_location": "dex",
            "artifacts": [
                {"type": "domain", "value": "panel-evil.top"},
                {"type": "ip", "value": "45.77.12.9:7771"},
            ],
        }],
    }
    result = extract_c2_infrastructure(payloads, {"categories": {}})
    raw = {r["raw_url"] for r in result["c2_infrastructure"]}
    assert {"panel-evil.top", "45.77.12.9:7771"} <= raw
