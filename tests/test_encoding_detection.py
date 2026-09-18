import pytest
from analysis.step3_encoding_detection import (
    detect_encoding,
    try_base64_decode,
    try_hex_decode,
    has_meaningful_content,
    is_benign_source,
    is_suspicious_source,
    is_likely_obfuscated_payload,
)
from analysis.step4_decoding import decode_payloads, extract_artifacts


def test_base64_detection():
    # Base64 of "https://evil-domain.com/c2"
    original = "aHR0cHM6Ly9ldmlsLWRvbWFpbi5jb20vYzI="
    strings_result = {
        "sample_id": "test_sample",
        "categories": {
            "string_literals": [
                {
                    "value": original,
                    "entropy": 4.5,
                    "source": "Test.java:10",
                }
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = detect_encoding(strings_result)
    assert result["total_encodings"] >= 1
    enc = result["encodings"][0]
    assert enc["type"] == "base64"
    assert "evil-domain.com" in enc["decoded_preview"]


def test_hex_detection():
    # Hex of "hello world" in a suspicious decoder context. The string length is
    # not a multiple of 4, so it fails the Base64 check and is detected as hex.
    original = "68656c6c6f20776f726c64"
    strings_result = {
        "sample_id": "test_sample",
        "categories": {
            "string_literals": [
                {
                    "value": original,
                    "entropy": 5.5,
                    "source": "com\\malware\\decoder\\PayloadDecoder.smali:20",
                }
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = detect_encoding(strings_result)
    assert result["total_encodings"] >= 1
    enc = result["encodings"][0]
    assert enc["type"] == "hex"
    assert "hello world" in enc["decoded_preview"]


def test_xor_detection():
    # XOR of a URL with key 0xA7 (produces mostly non-printable bytes,
    # so only the correct key should exceed the printable threshold)
    original = "https://secret-server.com/api/data"
    key = 0xA7
    encoded = "".join(chr(ord(c) ^ key) for c in original)
    strings_result = {
        "sample_id": "test_sample",
        "categories": {
            "string_literals": [
                {
                    "value": encoded,
                    "entropy": 6.5,
                    "source": "Test.java:30",
                }
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = detect_encoding(strings_result)
    assert result["total_encodings"] >= 1
    enc = result["encodings"][0]
    assert enc["type"] == "xor"
    assert "secret-server.com" in enc["decoded_preview"]


def test_decoding_extracts_url():
    encodings_result = {
        "sample_id": "test_sample",
        "encodings": [
            {
                "encoding_id": "enc_000",
                "type": "base64",
                "original_string": "aHR0cHM6Ly9ldmlsLWRvbWFpbi5jb20vYzI=",
                "confidence": 0.9,
                "entropy": 4.5,
                "source_location": "Test.java:10",
                "decoded_preview": "https://evil-domain.com/c2",
                "validation_status": "valid",
            }
        ],
    }
    result = decode_payloads(encodings_result)
    assert result["total_payloads"] == 1
    payload = result["payloads"][0]
    assert any(a["type"] == "url" and "evil-domain.com" in a["value"] for a in payload["artifacts"])


def test_has_meaningful_content():
    assert has_meaningful_content("Visit https://evil.com/path") is True
    assert has_meaningful_content("Contact admin@example.com") is True
    assert has_meaningful_content("just some random text") is False


# ---------------------------------------------------------------------------
# Repair regression tests
# ---------------------------------------------------------------------------


def test_benign_support_library_strings_not_flagged():
    """Android support-library identifiers should not be treated as encodings."""
    strings_result = {
        "sample_id": "test_benign_support",
        "categories": {
            "string_literals": [
                {
                    "value": "setHomeAsUpIndicator",  # Base64-decodes to garbage
                    "entropy": 4.0,
                    "source": "android\\support\\v7\\app\\ActionBarDrawerToggleHoneycomb.smali:40",
                },
                {
                    "value": "0123456789abcdef",  # Hex constant
                    "entropy": 4.0,
                    "source": "com\\jovial\\jrpn\\BigInt.smali:453",
                },
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = detect_encoding(strings_result)
    assert result["total_encodings"] == 0


def test_benign_resource_strings_not_flagged():
    """XML resource content should not be treated as an obfuscated payload."""
    xml_content = '<?xml version="1.0" encoding="utf-8"?>\n<properties></properties>'
    strings_result = {
        "sample_id": "test_benign_resource",
        "categories": {
            "resource_strings": [
                {
                    "value": xml_content,
                    "entropy": 5.2,
                    "source": "res/raw/config.xml:1",
                }
            ],
            "string_literals": [],
            "byte_arrays": [],
            "numeric_constants": [],
            "native_strings": [],
        },
    }
    result = detect_encoding(strings_result)
    assert result["total_encodings"] == 0


def test_suspicious_context_keeps_encoding_without_meaningful_decode():
    """High-entropy strings in suspicious contexts should still be flagged."""
    strings_result = {
        "sample_id": "test_suspicious",
        "categories": {
            "string_literals": [
                {
                    "value": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",  # 'A' repeated
                    "entropy": 5.5,
                    "source": "com\\evil\\loader\\PayloadDecoder.smali:42",
                }
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = detect_encoding(strings_result)
    assert result["total_encodings"] >= 1


def test_is_likely_obfuscated_payload_logic():
    # Meaningful decoded content -> keep
    assert is_likely_obfuscated_payload(
        "dummy", "https://evil.com", "Foo.java:1", 4.0
    ) is True
    # Benign source without meaningful decode -> drop
    assert is_likely_obfuscated_payload(
        "setHomeAsUpIndicator", "garbage", "android\\support\\v7\\app\\X.smali:1", 4.0
    ) is False
    # Suspicious source alone -> keep (even without meaningful content or high entropy)
    assert is_likely_obfuscated_payload(
        "AAAA", "garbage", "com\\evil\\loader\\Decoder.smali:1", 4.0
    ) is True


def test_is_benign_source():
    assert is_benign_source("android\\support\\v7\\app\\Foo.smali:1") is True
    assert is_benign_source("androidx\\core\\Bar.java:10") is True
    assert is_benign_source("res\\raw\\config.xml:1") is True
    assert is_benign_source("com\\evil\\payload\\Loader.smali:1") is False


def test_is_suspicious_source():
    assert is_suspicious_source("com\\evil\\loader\\Decoder.smali:1") is True
    assert is_suspicious_source("com\\malware\\reflect\\Hide.smali:1") is True
    assert is_suspicious_source("android\\support\\v7\\app\\Foo.smali:1") is False
