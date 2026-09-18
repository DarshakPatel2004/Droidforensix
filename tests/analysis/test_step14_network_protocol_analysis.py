import pytest
from analysis.step14_network_protocol_analysis import (
    analyze_network_protocols,
    classify_endpoint,
    extract_endpoints,
)


class TestAnalyzeNetworkProtocols:
    def test_empty(self):
        result = analyze_network_protocols([])
        assert result["total_endpoints"] == 0

    def test_with_data(self):
        result = analyze_network_protocols([
            "http://94.137.2.8:8080/gate.php",
            "https://api.amplitude.com/identify",
        ])
        assert result["total_endpoints"] >= 1

    def test_only_normal_strings(self):
        result = analyze_network_protocols(["hello world", "just a string"])
        assert result["total_endpoints"] == 0


class TestClassifyEndpoint:
    def test_c2(self):
        classification = classify_endpoint("http://94.137.2.8:8080/gate.php")
        assert classification["classification"] == "c2"
        assert classification["confidence"] >= 0.6

    def test_sdk(self):
        classification = classify_endpoint("https://api.amplitude.com/identify")
        assert classification["classification"] in ("sdk", "benign", "unknown")

    def test_benign_google(self):
        classification = classify_endpoint("https://www.google.com/")
        assert classification["classification"] == "benign"

    def test_unknown(self):
        classification = classify_endpoint("https://some-cdn.example.com/assets.js")
        assert classification["classification"] in ("unknown", "benign")

    def test_ip_only(self):
        classification = classify_endpoint("192.168.1.1")
        assert classification["is_ip"] is True

    def test_empty_string(self):
        classification = classify_endpoint("")
        assert "classification" in classification


class TestExtractEndpoints:
    def test_with_urls(self):
        endpoints = extract_endpoints([
            "https://evil.com/payload",
            "http://192.168.1.1/config",
            "/api/update",
            "just a normal string",
        ])
        assert len(endpoints) >= 1

    def test_empty(self):
        assert extract_endpoints([]) == []

    def test_no_endpoints(self):
        assert extract_endpoints(["hello world", "foo bar"]) == []
