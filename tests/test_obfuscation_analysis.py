"""Unit tests for Step 8 obfuscation analysis."""

import pytest
from analysis.step8_obfuscation_analysis import (
    shannon_entropy,
    calculate_obfuscation_score,
    dex_entropy_from_apk,
)


def test_shannon_entropy_uniform():
    # Random-looking bytes should have entropy near 8.0
    data = bytes(range(256))
    assert shannon_entropy(data) == pytest.approx(8.0, abs=0.01)


def test_shannon_entropy_constant():
    # Constant bytes should have entropy 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0


def test_calculate_obfuscation_score_empty():
    indicators = {
        "reflection": [],
        "dynamic_loading": [],
        "native_loading": [],
        "crypto_apis": [],
        "suspicious_apis": [],
        "dangerous_permissions": [],
    }
    score = calculate_obfuscation_score(indicators, [])
    assert score == 0.0


def test_calculate_obfuscation_score_capped():
    indicators = {
        "reflection": ["m"] * 100,
        "dynamic_loading": ["m"] * 100,
        "native_loading": ["m"] * 100,
        "crypto_apis": ["m"] * 100,
        "suspicious_apis": ["m"] * 100,
        "dangerous_permissions": ["p"] * 100,
    }
    dex_entropy = [{"file": "classes.dex", "entropy": 7.8, "likely_packed": True}]
    score = calculate_obfuscation_score(indicators, dex_entropy)
    assert score == 100.0


def test_dex_entropy_from_apk_not_found(tmp_path):
    fake_apk = tmp_path / "not_an_apk.zip"
    fake_apk.write_text("not a zip")
    result = dex_entropy_from_apk(fake_apk)
    assert result == []


def test_obfuscation_level_thresholds():
    from analysis.step8_obfuscation_analysis import analyze_obfuscation

    # Direct score/level mapping via a minimal manual check
    indicators_low = {
        "reflection": [],
        "dynamic_loading": [],
        "native_loading": [],
        "crypto_apis": [],
        "suspicious_apis": [],
        "dangerous_permissions": [],
    }
    assert calculate_obfuscation_score(indicators_low, []) < 40

    indicators_med = {
        "reflection": ["m"] * 10,
        "dynamic_loading": ["m"] * 4,
        "native_loading": ["m"] * 2,
        "crypto_apis": ["m"] * 6,
        "suspicious_apis": ["m"] * 5,
        "dangerous_permissions": ["p"] * 3,
    }
    score = calculate_obfuscation_score(indicators_med, [])
    assert 40 <= score < 70

    indicators_high = {
        "reflection": ["m"] * 10,
        "dynamic_loading": ["m"] * 4,
        "native_loading": ["m"] * 3,
        "crypto_apis": ["m"] * 10,
        "suspicious_apis": ["m"] * 10,
        "dangerous_permissions": ["p"] * 5,
    }
    score = calculate_obfuscation_score(indicators_high, [{"likely_packed": True}])
    assert score >= 70
