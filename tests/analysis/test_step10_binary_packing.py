import pytest
from analysis.step10_binary_packing import (
    detect_binary_packing,
    detect_dex_in_dex,
    analyze_dex_sections,
    PACKING_INDICATORS,
)


class TestDetectBinaryPacking:
    def test_empty(self):
        result = detect_binary_packing({})
        assert result["packing_detected"] is False
        assert result["obfuscation_score"] == 0.0
        assert "indicators" in result

    def test_nonexistent_apk(self):
        result = detect_binary_packing({"apk_path": "/nonexistent/file.apk"})
        assert result["packing_detected"] is False
        assert result["error"] is not None

    def test_with_dex_sections(self):
        sections = {
            ".text": {"size": 500000, "entropy": 7.9},
            ".data": {"size": 1000, "entropy": 4.5},
        }
        result = analyze_dex_sections(sections)
        assert len(result["scored_indicators"]) > 0
        assert result["obfuscation_score"] > 0

    def test_clean_sections(self):
        sections = {
            ".text": {"size": 10000, "entropy": 5.2},
        }
        result = analyze_dex_sections(sections)
        assert result["obfuscation_score"] == 0.0

    def test_packing_indicators_defined(self):
        assert len(PACKING_INDICATORS) > 0
        for pi in PACKING_INDICATORS:
            assert "name" in pi
            assert "weight" in pi
            assert 0 < pi["weight"] <= 100


class TestDetectDexInDex:
    def test_suspicious_dex_name(self):
        result = detect_dex_in_dex(["classes.dex", "classes2.dex", "r%le3.dex"])
        assert result["suspicious"] is True
        assert any("suspicious_dex_name" in i for i in result.get("indicators", []))

    def test_missing_dex(self):
        result = detect_dex_in_dex(["resources.arsc", "AndroidManifest.xml"])
        assert result["suspicious"] is True
        assert "missing_dex" in result["indicators"]

    def test_normal_dex(self):
        result = detect_dex_in_dex(["classes.dex", "classes2.dex", "classes3.dex"])
        assert result["suspicious"] is False

    def test_empty_list(self):
        result = detect_dex_in_dex([])
        assert result["suspicious"] is True
        assert "missing_dex" in result["indicators"]
