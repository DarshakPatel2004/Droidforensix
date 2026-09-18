import pytest
from analysis.step13_native_elf_analysis import (
    extract_elf_files,
    parse_elf_header,
    detect_elf_obfuscation,
    analyze_native_libraries_from_apk,
    match_symbols,
    extract_symbols_from_elf,
    shannon_entropy,
    CRYPTO_SYMBOL_PATTERNS,
    ANTI_ANALYSIS_PATTERNS,
)


class TestExtractElfFiles:
    def test_no_apk(self):
        result = extract_elf_files("nonexistent.apk")
        assert result == []


class TestDetectElfObfuscation:
    def test_detected(self):
        sections = {
            ".text": {"size": 500000, "entropy": 7.8},
            ".data.rel.ro": {"size": 20000, "entropy": 4.2},
        }
        result = detect_elf_obfuscation(sections)
        assert result["obfuscation_score"] > 0
        assert len(result["indicators"]) > 0

    def test_clean(self):
        sections = {
            ".text": {"size": 50000, "entropy": 5.2},
            ".data": {"size": 1000, "entropy": 4.0},
            ".rodata": {"size": 500, "entropy": 3.5},
            ".bss": {"size": 0, "entropy": 0.0},
            ".init": {"size": 100, "entropy": 5.0},
            ".fini": {"size": 80, "entropy": 4.8},
        }
        result = detect_elf_obfuscation(sections)
        assert result["obfuscation_score"] == 0.0

    def test_empty(self):
        result = detect_elf_obfuscation({})
        assert result["obfuscation_score"] > 0

    def test_minimal_sections(self):
        sections = {
            ".text": {"size": 50000, "entropy": 5.2},
        }
        result = detect_elf_obfuscation(sections)
        assert any("minimal_sections" in i["type"] for i in result["indicators"])


class TestParseElfHeader:
    def test_no_data(self):
        result = parse_elf_header({})
        assert result == {}

    def test_with_data(self):
        result = parse_elf_header({"arch": "ARM", "bits": 64, "endian": "little"})
        assert result["arch"] == "ARM"
        assert result["bits"] == 64


class TestAnalyzeNativeLibrariesFromApk:
    def test_no_apk(self):
        result = analyze_native_libraries_from_apk("nonexistent.apk")
        assert result["has_native_code"] is False
        assert result["total_libraries"] == 0

    def test_with_extracted_path(self, tmp_path):
        fake_apk = tmp_path / "test.apk"
        fake_apk.write_text("not a real apk")
        result = analyze_native_libraries_from_apk(str(fake_apk), str(tmp_path))
        assert result["total_libraries"] == 0
        assert result["has_native_code"] is False


class TestMatchSymbols:
    def test_crypto_match(self):
        result = match_symbols(["AES_encrypt", "MD5_Update", "normal_func"])
        assert "AES_encrypt" in result["crypto_functions"]
        assert "MD5_Update" in result["crypto_functions"]
        assert "normal_func" not in result["crypto_functions"]

    def test_anti_analysis_match(self):
        result = match_symbols(["ptrace", "frida_detection", "normal_func"])
        assert "ptrace" in result["anti_analysis"]
        assert "frida_detection" in result["anti_analysis"]

    def test_empty(self):
        result = match_symbols([])
        assert result["crypto_functions"] == []
        assert result["anti_analysis"] == []


class TestExtractSymbolsFromElf:
    def test_nonexistent(self):
        assert extract_symbols_from_elf("nonexistent.so") == []


class TestShannonEntropy:
    def test_uniform(self):
        data = bytes(range(256))
        assert shannon_entropy(data) == pytest.approx(8.0, abs=0.01)

    def test_constant(self):
        assert shannon_entropy(b"\x00" * 100) == 0.0

    def test_empty(self):
        assert shannon_entropy(b"") == 0.0


class TestConstants:
    def test_crypto_symbol_patterns(self):
        assert len(CRYPTO_SYMBOL_PATTERNS) > 0

    def test_anti_analysis_patterns(self):
        assert len(ANTI_ANALYSIS_PATTERNS) > 0
