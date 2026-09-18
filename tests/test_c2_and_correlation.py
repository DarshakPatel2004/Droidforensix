import pytest
from analysis.step5_c2_extraction import (
    extract_c2_infrastructure,
    classify_ip,
    parse_url,
    calculate_c2_confidence,
    is_benign_url,
    is_ad_network,
)
from analysis.step6_correlation import build_threat_chains
from analysis.step7_llm_assessment import fallback_assessment


def test_classify_ip():
    assert classify_ip("192.168.1.1") == "private"
    assert classify_ip("10.0.0.1") == "private"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("999.999.999.999") == "invalid"


def test_parse_url():
    parsed = parse_url("https://evil-domain.com:8443/api/data?key=value")
    assert parsed is not None
    assert parsed["protocol"] == "https"
    assert parsed["domain"] == "evil-domain.com"
    assert parsed["port"] == 8443
    assert parsed["path"] == "/api/data"
    assert parsed["query_params"] == {"key": "value"}


def test_extract_c2_from_payload():
    payloads_result = {
        "sample_id": "test_sample",
        "payloads": [
            {
                "payload_id": "pld_000",
                "encoding_id": "enc_000",
                "decoded_content": "https://evil-domain.com/c2",
                "artifacts": [
                    {"type": "url", "value": "https://evil-domain.com/c2", "confidence": 0.95}
                ],
                "source_location": "Decoder.java:15",
                "confidence": 0.9,
            }
        ],
    }
    strings_result = {
        "sample_id": "test_sample",
        "categories": {
            "string_literals": [],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = extract_c2_infrastructure(payloads_result, strings_result)
    assert result["total_c2s"] == 1
    c2 = result["c2_infrastructure"][0]
    assert c2["protocol"] == "https"
    assert c2["domain"] == "evil-domain.com"
    assert c2["path"] == "/c2"


def test_build_threat_chain():
    encodings_result = {
        "sample_id": "test_sample",
        "encodings": [
            {
                "encoding_id": "enc_000",
                "type": "base64",
                "original_string": "aHR0cHM6Ly9ldmlsLWRvbWFpbi5jb20vYzI=",
                "confidence": 0.9,
                "entropy": 4.5,
                "source_location": "MainActivity.java:42",
                "decoded_preview": "https://evil-domain.com/c2",
                "validation_status": "valid",
            }
        ],
    }
    payloads_result = {
        "sample_id": "test_sample",
        "payloads": [
            {
                "payload_id": "pld_000",
                "encoding_id": "enc_000",
                "decoded_content": "https://evil-domain.com/c2",
                "artifacts": [
                    {"type": "url", "value": "https://evil-domain.com/c2", "confidence": 0.95}
                ],
                "source_location": "Decoder.java:15",
                "confidence": 0.9,
            }
        ],
    }
    c2_result = {
        "sample_id": "test_sample",
        "total_c2s": 1,
        "c2_infrastructure": [
            {
                "c2_id": "c2_000",
                "payload_id": "pld_000",
                "raw_url": "https://evil-domain.com/c2",
                "protocol": "https",
                "domain": "evil-domain.com",
                "ip": None,
                "port": 443,
                "path": "/c2",
                "query_params": {},
                "ip_classification": "n/a",
                "communication_type": "http_request",
                "is_fallback": False,
                "source_location": "NetworkTask.java:88",
                "confidence": 0.85,
            }
        ],
    }
    result = build_threat_chains(encodings_result, payloads_result, c2_result)
    assert result["total_chains"] == 1
    chain = result["threat_chains"][0]
    assert chain["severity"] in ("critical", "high", "medium", "low")
    assert len(chain["steps"]) == 5
    assert chain["steps"][0]["type"] == "encoded_string"
    assert chain["steps"][-1]["type"] == "c2_infrastructure"


def test_fallback_assessment_with_c2():
    chains_result = {"total_chains": 1}
    c2_result = {
        "total_c2s": 2,
        "c2_infrastructure": [
            {
                "c2_id": "c2_000",
                "domain": "evil-domain.com",
                "threat_category": "malware",
                "confidence": 0.9,
            },
            {
                "c2_id": "c2_001",
                "domain": "ads.example-analytics.com",
                "threat_category": "adware",
                "confidence": 0.6,
            },
        ],
    }
    assessment = fallback_assessment(chains_result, c2_result)
    assert assessment["severity"] == "high"
    assert assessment["primary_threat"] == "c2_exfiltration"


# ---------------------------------------------------------------------------
# Repair regression tests
# ---------------------------------------------------------------------------

BENIGN_URLS = [
    "http://java.sun.com/dtd/properties.dtd",
    "http://www.w3.org/2001/XMLSchema",
    "http://android.com/",
    "https://schemas.android.com/apk/res/android",
]

MALICIOUS_URLS = [
    "https://47.116.192.150:444/cBYFilXD/HNbfYsYd8Shi2GHLBHyb-gDN9Hwbd6Itpm3jtM4fQpWreFMkgGdQyEmayxRNMBKyMfb6kZsi71hMzOxV8VpPRQrcsurLqQCsGxh7PvRmdUTTbgDb/",
    "https://evil-c2.malicious-test.com/beacon",
]


def test_benign_urls_are_filtered():
    for url in BENIGN_URLS:
        assert is_benign_url(url) is True, f"Expected {url} to be filtered"


def test_malicious_urls_are_not_filtered():
    for url in MALICIOUS_URLS:
        assert is_benign_url(url) is False, f"Expected {url} to be allowed"


def test_private_ip_c2_gets_high_confidence():
    url = "https://47.116.192.150:444/cBYFilXD/endpoint"
    parsed = parse_url(url)
    assert parsed is not None
    confidence = calculate_c2_confidence(parsed, "unknown")
    assert confidence >= 0.75, f"Expected high confidence for private IP C2, got {confidence}"


def test_malicious_domain_c2_gets_high_confidence():
    url = "http://malicious.tk/beacon"
    parsed = parse_url(url)
    assert parsed is not None
    confidence = calculate_c2_confidence(parsed, "unknown")
    assert confidence >= 0.60, f"Expected confidence >= 0.60 for malicious domain, got {confidence}"


def test_direct_string_url_confidence_not_penalized():
    """Direct URLs found in strings should not receive a 0.9 confidence penalty."""
    payloads_result = {
        "sample_id": "test_direct_string",
        "payloads": [],
    }
    strings_result = {
        "sample_id": "test_direct_string",
        "categories": {
            "string_literals": [
                {
                    "value": "https://47.116.192.150:444/cBYFilXD/endpoint",
                    "source": "MainActivity.java:10",
                }
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = extract_c2_infrastructure(payloads_result, strings_result)
    assert result["total_c2s"] == 1
    assert result["c2_infrastructure"][0]["confidence"] >= 0.75


def test_low_confidence_c2_excluded_from_chains():
    encodings_result = {
        "sample_id": "test_threshold",
        "encodings": [
            {
                "encoding_id": "enc_000",
                "type": "base64",
                "original_string": "aHR0cHM6Ly9ldmlsLWRvbWFpbi5jb20vYzI=",
                "confidence": 0.9,
                "entropy": 4.5,
                "source_location": "MainActivity.java:42",
                "decoded_preview": "https://evil-domain.com/c2",
                "validation_status": "valid",
            }
        ],
    }
    payloads_result = {
        "sample_id": "test_threshold",
        "payloads": [
            {
                "payload_id": "pld_000",
                "encoding_id": "enc_000",
                "decoded_content": "https://evil-domain.com/c2",
                "artifacts": [
                    {"type": "url", "value": "https://evil-domain.com/c2", "confidence": 0.95}
                ],
                "source_location": "Decoder.java:15",
                "confidence": 0.9,
            }
        ],
    }
    c2_result = {
        "sample_id": "test_threshold",
        "total_c2s": 1,
        "c2_infrastructure": [
            {
                "c2_id": "c2_000",
                "payload_id": "pld_000",
                "raw_url": "https://evil-domain.com/c2",
                "protocol": "https",
                "domain": "evil-domain.com",
                "ip": None,
                "port": 443,
                "path": "/c2",
                "query_params": {},
                "ip_classification": "n/a",
                "communication_type": "http_request",
                "is_fallback": False,
                "source_location": "NetworkTask.java:88",
                "confidence": 0.85,
            }
        ],
    }
    result = build_threat_chains(encodings_result, payloads_result, c2_result)
    assert result["total_chains"] == 1

    # Now drop the C2 confidence below the threshold and verify it is excluded.
    c2_result["c2_infrastructure"][0]["confidence"] = 0.4
    result = build_threat_chains(encodings_result, payloads_result, c2_result)
    assert result["total_chains"] == 1  # still one chain, but without the C2 step
    assert all(
        step["type"] != "c2_infrastructure"
        for chain in result["threat_chains"]
        for step in chain["steps"]
    )


def test_ad_network_domain_recognized():
    assert is_ad_network("api.airpush.com") is True
    assert is_ad_network("airpush.com") is True
    assert is_ad_network("www.leadbolt.net") is True
    assert is_ad_network("evil-domain.com") is False


def test_ad_network_c2_has_reduced_confidence():
    parsed = parse_url("http://api.airpush.com/v2/api.php")
    assert parsed is not None
    confidence = calculate_c2_confidence(parsed, "unknown")
    # Without ad-network penalty this would be 1.0; with penalty it is 0.5.
    assert confidence < 0.6, f"Expected ad network confidence < 0.6, got {confidence}"


def test_malicious_domain_c2_has_high_confidence():
    parsed = parse_url("http://gp-imports.com/android.php")
    assert parsed is not None
    confidence = calculate_c2_confidence(parsed, "unknown")
    assert confidence >= 0.9, f"Expected malicious domain confidence >= 0.9, got {confidence}"


def test_yandex_benign_domain_filtered():
    assert is_benign_url("http://yandex.ru") is True


def test_threat_intel_ip_helpers():
    from backend.threat_intel import _is_valid_ip, _classify_ip
    
    assert _is_valid_ip("1.2.3.4") is True
    assert _is_valid_ip("256.0.0.1") is False
    assert _is_valid_ip("not-an-ip") is False
    
    assert _classify_ip("127.0.0.1") == "loopback"
    assert _classify_ip("192.168.1.1") == "private"
    assert _classify_ip("8.8.8.8") == "public"
    assert _classify_ip("invalid-ip") == "invalid"


def test_build_threat_intel_liveness_enrichment(tmp_path, monkeypatch):
    import json
    import socket
    import backend.threat_intel
    from backend.config import settings
    
    # Mock settings.WORK_DIR to use our temp path
    monkeypatch.setattr(settings, "WORK_DIR", tmp_path)
    
    # Mock DNS resolution to avoid hanging on slow/no network
    def _mock_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        if host == "localhost.localdomain":
            raise socket.gaierror("Mock: no address")
        return [((2, 1, 0, '', (host, port)))]
    monkeypatch.setattr(socket, "getaddrinfo", _mock_getaddrinfo)
    
    # Mock network-dependent enrichment functions
    monkeypatch.setattr(backend.threat_intel, "_enrich_isp", lambda ip: {"isp": "", "org": "", "as": ""})
    monkeypatch.setattr(backend.threat_intel, "_geo_lookup", lambda ip: None)
    monkeypatch.setattr(backend.threat_intel, "_censys_enrich", lambda ip: None)
    monkeypatch.setattr(backend.threat_intel, "identify_family", lambda *a, **kw: {
        "family": "unknown", "confidence": 0.0, "method": "none",
        "reasoning": "", "candidates": [],
    })
    
    # Prepare dummy pipeline result and directories
    sample_id = "test_sample_123"
    sample_dir = tmp_path / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    
    pipeline_result = {
        "sample_id": sample_id,
        "c2_infrastructure": [
            {
                "c2_id": "c2_domain",
                "domain": "localhost.localdomain",  # should fail or resolve
                "ip": None,
            },
            {
                "c2_id": "c2_public_ip",
                "domain": None,
                "ip": "8.8.8.8",
            },
            {
                "c2_id": "c2_loopback_ip",
                "domain": None,
                "ip": "127.0.0.1",
            }
        ]
    }
    
    # Save the files to disk so threat_intel can update them
    pipeline_path = sample_dir / "pipeline_result.json"
    with open(pipeline_path, "w", encoding="utf-8") as f:
        json.dump(pipeline_result, f)
        
    step5_path = sample_dir / "step5_c2s.json"
    with open(step5_path, "w", encoding="utf-8") as f:
        json.dump({"c2_infrastructure": pipeline_result["c2_infrastructure"]}, f)
        
    # Run build_threat_intel which triggers on-the-fly resolution
    data = backend.threat_intel.build_threat_intel(pipeline_result, sample_id)
    
    # Verify returning structured fields
    assert "c2s" in data, f"Keys in data: {list(data.keys())}. Data: {data}"
    c2s_out = data["c2s"]
    assert len(c2s_out) == 3
    
    # Public IP should be active
    c2_pub = next(c for c in c2s_out if c["c2_id"] == "c2_public_ip")
    assert c2_pub["status"] == "active"
    assert c2_pub["live_dns"]["resolves"] is True
    assert "8.8.8.8" in c2_pub["live_dns"]["ips"]
    
    # Loopback IP should be dead
    c2_loop = next(c for c in c2s_out if c["c2_id"] == "c2_loopback_ip")
    assert c2_loop["status"] == "dead"
    assert c2_loop["live_dns"]["resolves"] is False
    
    # Verify that ips_geolocated contains resolved public IP as fallback
    geo_ips = data.get("ips_geolocated", [])
    assert len(geo_ips) > 0
    assert any(g["ip"] == "8.8.8.8" for g in geo_ips)
    pub_geo = next(g for g in geo_ips if g["ip"] == "8.8.8.8")
    assert pub_geo["country"] == "Unknown"
    
    # Check that disk caches were updated
    with open(pipeline_path, "r", encoding="utf-8") as f:
        saved_result = json.load(f)
    saved_c2s = saved_result["c2_infrastructure"]
    saved_pub = next(c for c in saved_c2s if c["c2_id"] == "c2_public_ip")
    assert saved_pub["status"] == "active"
    assert saved_pub["live_dns"]["resolves"] is True

