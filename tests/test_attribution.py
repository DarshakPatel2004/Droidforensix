"""Tests for attribution and threat-summary API endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.transformers import load_result
from tests.test_code_analysis import SIMPLE_CLASS_SOURCE


# Sample result used for mocking load_result
SAMPLE_RESULT = {
    "sample_id": "test_sample_001",
    "metadata": {
        "sample_name": "MalwareSample.apk",
        "package_name": "com.evil.malware",
        "version_name": "1.0",
        "sha256": "abcdef1234567890",
        "permissions": [
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA",
        ],
        "file_size_bytes": 123456,
    },
    "llm_assessment": {
        "severity": "critical",
        "risk_score": 85,
        "primary_threat": "sms_trojan",
        "confidence": 0.92,
    },
    "obfuscation_analysis": {
        "obfuscation_score": 72,
        "obfuscation_level": "high",
        "indicators": {
            "reflection": ["Lcom/evil/Main;->invoke()V"],
            "dynamic_loading": ["Lcom/evil/Main;->loadDex()V"],
            "crypto_apis": ["Lcom/evil/Main;->encrypt()V"],
            "native_loading": [],
            "suspicious_apis": ["Lcom/evil/Main;->exec()V"],
            "dangerous_permissions": ["android.permission.SEND_SMS"],
        },
    },
    "c2_infrastructure": [
        {"domain": "evil-c2.com", "ip": "203.0.113.5", "protocol": "https",
         "port": 443, "status": "active", "path": "/c2", "confidence": 0.95},
        {"domain": "backup-c2.net", "ip": "198.51.100.10", "protocol": "http",
         "port": 8080, "status": "unknown", "path": "/gate", "confidence": 0.8},
    ],
    "encodings": [],
    "payloads": [],
    "threat_chains": [],
    "heuristic": {
        "score": 82,
        "method": "ensemble",
        "reasoning": "Multiple strong signals detected",
    },
    "family_identification": {
        "family": "XHelper",
        "confidence": 0.95,
        "method": "ensemble",
        "reasoning": "Permission and C2 overlap with XHelper baseline",
        "candidates": [{"family": "XHelper", "score": 0.95}],
        "matched_permissions": [
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
        ],
        "matched_c2": ["evil-c2.com"],
    },
    "strings": {
        "string_literals": [
            {"category": "string_literal", "value": "evil-c2.com", "entropy": 3.8, "source": "dex"},
            {"category": "string_literal", "value": "SMSApp.apk", "entropy": 2.9, "source": "dex"},
            {"category": "string_literal", "value": "\x00\x01\x00\x01", "entropy": 1.0, "source": "dex"},
        ],
        "byte_arrays": [],
        "numeric_constants": [],
        "resource_strings": [],
        "native_strings": [],
    },
}

# Second sample sharing the same family + permissions, used to verify
# related-sample matching.
OTHER_SAMPLE = {
    "sample_id": "test_sample_002",
    "metadata": {
        "sample_name": "SiblingMalware.apk",
        "package_name": "com.evil.sibling",
        "sha256": "fedcba9876543210",
        "permissions": [
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.CALL_PHONE",
        ],
        "file_size_bytes": 100000,
    },
    "obfuscation_analysis": {"obfuscation_score": 10, "obfuscation_level": "low", "indicators": {}},
    "c2_infrastructure": [],
    "heuristic": {"score": 10, "method": "heuristic"},
    "family_identification": {
        "family": "XHelper",
        "confidence": 0.9,
        "method": "signature_v3",
        "reasoning": "matching signature",
        "candidates": [],
    },
    "strings": {
        "string_literals": [
            {"category": "string_literal", "value": "evil-c2.com", "entropy": 3.7, "source": "dex"},
        ],
        "byte_arrays": [],
        "numeric_constants": [],
        "resource_strings": [],
        "native_strings": [],
    },
}


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def mock_deps(monkeypatch):
    """Mock load_result to return SAMPLE_RESULT for our test sample."""
    def _mock_load(sample_id):
        if sample_id == "test_sample_001":
            return SAMPLE_RESULT
        return None
    monkeypatch.setattr("backend.main.load_result", _mock_load)
    monkeypatch.setattr("backend.transformers.load_result", _mock_load)

    def _mock_identify(sample_id, result):
        return SAMPLE_RESULT["family_identification"]
    monkeypatch.setattr("backend.main.identify_family", _mock_identify)

    # Mock transformers.load_all_results for related samples
    def _mock_all():
        return [SAMPLE_RESULT, OTHER_SAMPLE]
    monkeypatch.setattr("backend.transformers.load_all_results", _mock_all)

    # Mock community intel search (no network in tests)
    monkeypatch.setattr(
        "backend.main.get_cached_community_intel",
        lambda sample_id, package_name, family: {
            "package_name": package_name,
            "family": family,
            "queried_at": "2026-07-31T00:00:00",
            "total_posts": 2,
            "posts": [
                {
                    "source": "Reddit",
                    "title": "Anyone seen com.evil.malware?",
                    "url": "https://www.reddit.com/r/android/comments/1",
                    "snippet": "SMS fraud",
                    "author": "sleuth",
                    "score": 12,
                    "published_at": "2026-07-01T00:00:00",
                    "subreddit": "android",
                },
                {
                    "source": "Hacker News",
                    "title": "XHelper trojan analysis",
                    "url": "https://news.ycombinator.com/item?id=1",
                    "snippet": "C2 analysis",
                    "author": "researcher",
                    "score": 5,
                    "published_at": "2026-07-02T00:00:00",
                },
            ],
            "sources_failed": ["duckduckgo"],
        },
    )

    # Mock CodeAnalyzer
    class MockAnalyzer:
        def analyze_class(self, class_name):
            return {
                "class_name": class_name,
                "methods": [
                    {
                        "name": "onCreate",
                        "start_line": 7, "end_line": 14,
                        "risk_level": "LOW", "techniques": [],
                        "calls": [{"target": "getVersion", "line": 9, "action": "Calls getVersion()"}],
                        "suspicious_lines": [],
                    },
                    {
                        "name": "startEvil",
                        "start_line": 25, "end_line": 35,
                        "risk_level": "CRITICAL",
                        "techniques": ["service_dropping", "dynamic_loading"],
                        "calls": [],
                        "suspicious_lines": [
                            {"line": 27, "pattern": "service_dropping",
                             "code": "startService(i)", "description": "Service launch",
                             "risk": "CRITICAL"},
                        ],
                    },
                ],
                "string_references": {
                    "SMSApp.apk": [{"method": "startEvil", "line": 30, "usage": "payload_filename"}],
                },
                "attack_flow": [
                    {"step": 1, "method": "onCreate", "line": 7,
                     "action": "Entry point: onCreate()", "description": "onCreate()",
                     "risk_level": "LOW"},
                    {"step": 2, "method": "startEvil", "line": 25,
                     "action": "Malware execution: startEvil()",
                     "description": "startEvil() - service_dropping, dynamic_loading",
                     "risk_level": "CRITICAL"},
                ],
            }

        def get_string_references(self, string_value):
            if string_value == "SMSApp.apk":
                return {
                    "string": "SMSApp.apk",
                    "usages": [
                        {"class_name": "com.evil.Main", "method": "startEvil",
                         "line": 30, "usage": "payload_filename",
                         "context": "C0005b.m41b(..., \"SMSApp.apk\", this)"},
                    ],
                }
            return {"string": string_value, "usages": []}

    def _mock_analyzer(apk_path, work_dir, sample_id, cache=None):
        return MockAnalyzer()

    monkeypatch.setattr("backend.main.CodeAnalyzer", lambda apk_path, work_dir, sample_id, cache=None: MockAnalyzer())

    # Mock _get_sample_apk_path to return a fake path
    monkeypatch.setattr("backend.main._get_sample_apk_path", lambda sid: "C:\\fake\\path.apk")


class TestThreatSummary:

    def test_threat_summary_200(self, client):
        response = client.get("/api/sample/test_sample_001/threat-summary")
        assert response.status_code == 200
        data = response.json()
        assert data["sample_id"] == "test_sample_001"
        assert data["package_name"] == "com.evil.malware"
        assert data["threat_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert data["threat_score"] >= 0
        assert "red_flags" in data
        assert "family" in data
        assert "confidence" in data

    def test_threat_summary_red_flags(self, client):
        response = client.get("/api/sample/test_sample_001/threat-summary")
        data = response.json()
        flag_types = {f["type"] for f in data["red_flags"]}
        assert "dangerous_permissions" in flag_types
        assert "active_c2_endpoints" in flag_types
        assert "obfuscation" in flag_types
        assert "evasion_techniques" in flag_types

    def test_threat_summary_404(self, client):
        response = client.get("/api/sample/nonexistent/threat-summary")
        assert response.status_code == 404

    def test_threat_summary_values(self, client):
        response = client.get("/api/sample/test_sample_001/threat-summary")
        data = response.json()
        assert data["family"] == "XHelper"
        assert data["confidence"] == 0.95
        assert data["c2_count"] == 2

    def test_threat_summary_missing_sample(self, client):
        response = client.get("/api/sample/bad_id/threat-summary")
        assert response.status_code == 404


class TestAttribution:

    def test_attribution_200(self, client):
        response = client.get("/api/sample/test_sample_001/attribution")
        assert response.status_code == 200
        data = response.json()
        assert data["family"] == "XHelper"
        assert data["confidence"] == 0.95
        assert "confidence_breakdown" in data
        assert "supporting_signals" in data
        assert "related_samples" in data

    def test_attribution_confidence_breakdown(self, client):
        response = client.get("/api/sample/test_sample_001/attribution")
        data = response.json()
        breakdown = data["confidence_breakdown"]
        assert "permissions_match" in breakdown
        assert "c2_overlap" in breakdown
        assert "obfuscation_pattern" in breakdown
        assert "code_similarity" in breakdown
        for key, val in breakdown.items():
            assert 0.0 <= val <= 1.0, f"{key} out of range: {val}"

    def test_attribution_supporting_signals(self, client):
        response = client.get("/api/sample/test_sample_001/attribution")
        data = response.json()
        assert len(data["supporting_signals"]) > 0
        # Should mention permissions match
        signals_text = " ".join(data["supporting_signals"]).lower()
        assert any("permission" in signals_text for signals_text in data["supporting_signals"])

    def test_attribution_404(self, client):
        response = client.get("/api/sample/nonexistent/attribution")
        assert response.status_code == 404

    def test_attribution_confidence_ranges(self, client):
        response = client.get("/api/sample/test_sample_001/attribution")
        data = response.json()
        assert 0.0 <= data["confidence"] <= 1.0

    def test_attribution_related_samples(self, client):
        response = client.get("/api/sample/test_sample_001/attribution")
        data = response.json()
        related = data["related_samples"]
        assert len(related) == 1
        assert related[0]["sample_id"] == "test_sample_002"
        assert related[0]["similarity"] >= 0.5
        assert "family" in related[0]
        assert "package_name" in related[0]

    def test_attribution_code_references(self, client):
        response = client.get("/api/sample/test_sample_001/attribution")
        data = response.json()
        refs = data["code_references"]
        assert refs["total_strings"] == 3
        assert "by_category" in refs
        assert refs["by_category"].get("string_literal") == 3
        values = {s["value"] for s in refs["notable_strings"]}
        # Binary junk (control chars) is filtered out; printable strings kept
        assert "evil-c2.com" in values
        assert "SMSApp.apk" in values
        assert all("value" in s and "entropy" in s and "category" in s for s in refs["notable_strings"])


class TestCommunityIntel:

    def test_community_intel_200(self, client):
        response = client.get("/api/sample/test_sample_001/community-intel")
        assert response.status_code == 200
        data = response.json()
        assert data["package_name"] == "com.evil.malware"
        assert data["family"] == "XHelper"
        assert data["total_posts"] == 2
        assert len(data["posts"]) == 2
        sources = {p["source"] for p in data["posts"]}
        assert "Reddit" in sources
        assert "Hacker News" in sources
        for post in data["posts"]:
            assert post["title"]
            assert post["url"]

    def test_community_intel_404(self, client):
        response = client.get("/api/sample/nonexistent/community-intel")
        assert response.status_code == 404


class TestCodeAnalysis:

    def test_code_analysis_200(self, client):
        response = client.get("/api/sample/test_sample_001/code-analysis/com.evil.Main")
        assert response.status_code == 200
        data = response.json()
        assert "class_name" in data
        assert "methods" in data
        assert "attack_flow" in data

    def test_code_analysis_methods(self, client):
        response = client.get("/api/sample/test_sample_001/code-analysis/com.evil.Main")
        data = response.json()
        assert len(data["methods"]) >= 2
        methods = {m["name"]: m for m in data["methods"]}
        assert "onCreate" in methods
        assert "startEvil" in methods
        assert methods["startEvil"]["risk_level"] == "CRITICAL"

    def test_code_analysis_attack_flow(self, client):
        response = client.get("/api/sample/test_sample_001/code-analysis/com.evil.Main")
        data = response.json()
        assert len(data["attack_flow"]) >= 2
        assert data["attack_flow"][0]["method"] == "onCreate"
        assert data["attack_flow"][-1]["method"] == "startEvil"

    def test_code_analysis_404_class(self, client):
        response = client.get("/api/sample/nonexistent/code-analysis/Foo")
        assert response.status_code == 404


class TestStringReferences:

    def test_string_references_200(self, client):
        response = client.get("/api/sample/test_sample_001/string-references/SMSApp.apk")
        assert response.status_code == 200
        data = response.json()
        assert data["string"] == "SMSApp.apk"
        assert len(data["usages"]) > 0

    def test_string_references_usage_fields(self, client):
        response = client.get("/api/sample/test_sample_001/string-references/SMSApp.apk")
        data = response.json()
        usage = data["usages"][0]
        assert "class_name" in usage
        assert "method" in usage
        assert "line" in usage
        assert "usage" in usage
        assert "context" in usage
        assert usage["usage"] == "payload_filename"

    def test_string_references_empty(self, client):
        response = client.get("/api/sample/test_sample_001/string-references/nonexistent_string")
        assert response.status_code == 200
        data = response.json()
        assert data["string"] == "nonexistent_string"
        assert data["usages"] == []

    def test_string_references_404(self, client):
        response = client.get("/api/sample/nonexistent/string-references/foo")
        assert response.status_code == 404


class TestEndpointErrors:

    def test_404_on_bad_sample_id(self, client):
        for endpoint in [
            "/api/sample/bad_id/threat-summary",
            "/api/sample/bad_id/attribution",
            "/api/sample/bad_id/code-analysis/Foo",
            "/api/sample/bad_id/string-references/bar",
        ]:
            response = client.get(endpoint)
            assert response.status_code == 404, f"{endpoint} should return 404"
