"""Tests for step9_post_process sanity corrections."""

from typing import Any, Dict

import pytest

from analysis.step9_post_process import (
    BENIGN_PACKAGE_PATTERNS,
    MALWARE_PACKAGE_PATTERNS,
    PostProcessError,
    _chains_have_c2,
    _count_obfuscation_indicators,
    _get_dex_method_count,
    _has_real_c2,
    _has_suspicious_package,
    _package_match,
    correct_benign_false_positive,
    correct_decoding_no_c2,
    correct_metasploit_stager,
    correct_suspicious_package,
    correct_tiny_dex,
    post_process_result,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(**overrides: Any) -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        "metadata": {"package_name": "com.example.app", "file_size_bytes": 500_000},
        "obfuscation_analysis": {
            "indicators": {
                "reflection": [],
                "dynamic_loading": [],
                "suspicious_apis": [],
                "dangerous_permissions": [],
                "crypto_apis": [],
                "total_classes": 100,
                "total_methods": 500,
            }
        },
        "c2_infrastructure": [],
        "threat_chains": [],
        "manifest": {"uses_permissions": []},
        "llm_assessment": {
            "severity": "low",
            "risk_score": 25,
            "narrative": "Initial assessment",
            "confidence": 0.5,
        },
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# _package_match
# ---------------------------------------------------------------------------


class TestPackageMatch:
    def test_exact_match(self):
        assert _package_match("com.metasploit.stage", MALWARE_PACKAGE_PATTERNS) == "metasploit_stager"

    def test_substring_match(self):
        assert _package_match("com.metasploit.stage.xyz", MALWARE_PACKAGE_PATTERNS) == "metasploit_stager"

    def test_case_insensitive(self):
        assert _package_match("COM.METASPLOIT.STAGE", MALWARE_PACKAGE_PATTERNS) == "metasploit_stager"

    def test_no_match(self):
        assert _package_match("com.google.app", MALWARE_PACKAGE_PATTERNS) == ""

    def test_empty(self):
        assert _package_match("", MALWARE_PACKAGE_PATTERNS) == ""

    def test_none(self):
        assert _package_match("", MALWARE_PACKAGE_PATTERNS) == ""

    def test_benign_patterns(self):
        assert _package_match("com.jovial.jrpn", BENIGN_PACKAGE_PATTERNS) == "calculator"


# ---------------------------------------------------------------------------
# _count_obfuscation_indicators
# ---------------------------------------------------------------------------


class TestCountObfuscationIndicators:
    def test_empty(self):
        counts = _count_obfuscation_indicators({})
        assert counts == {"reflection": 0, "dynamic_loading": 0, "suspicious_apis": 0, "dangerous_permissions": 0}

    def test_with_data(self):
        obf = {
            "indicators": {
                "reflection": ["r1", "r2"],
                "dynamic_loading": ["d1"],
                "suspicious_apis": ["s1", "s2", "s3"],
                "dangerous_permissions": ["p1"],
            }
        }
        counts = _count_obfuscation_indicators(obf)
        assert counts["reflection"] == 2
        assert counts["dynamic_loading"] == 1
        assert counts["suspicious_apis"] == 3
        assert counts["dangerous_permissions"] == 1

    def test_missing_keys(self):
        obf = {"indicators": {"reflection": ["r1"]}}
        counts = _count_obfuscation_indicators(obf)
        assert counts["reflection"] == 1
        assert counts["dynamic_loading"] == 0


# ---------------------------------------------------------------------------
# _has_real_c2
# ---------------------------------------------------------------------------


class TestHasRealC2:
    def test_public_ip(self):
        assert _has_real_c2([{"ip_classification": "public"}])

    def test_real_domain(self):
        assert _has_real_c2([{"domain": "evil.example.com"}])

    def test_benign_domain(self):
        assert not _has_real_c2([{"domain": "java.sun.com"}])
        assert not _has_real_c2([{"domain": "www.w3.org"}])
        assert not _has_real_c2([{"domain": "schemas.android.com"}])

    def test_empty(self):
        assert not _has_real_c2([])

    def test_no_matching_keys(self):
        assert not _has_real_c2([{"ip_classification": "private"}])


# ---------------------------------------------------------------------------
# _chains_have_c2
# ---------------------------------------------------------------------------


class TestChainsHaveC2:
    def test_has_c2_step(self):
        chains = [{"steps": [{"type": "c2_match", "artifact": "evil.com"}]}]
        assert _chains_have_c2(chains)

    def test_no_c2_step(self):
        chains = [{"steps": [{"type": "decoding", "artifact": "base64"}]}]
        assert not _chains_have_c2(chains)

    def test_empty_chains(self):
        assert not _chains_have_c2([])

    def test_empty_steps(self):
        assert not _chains_have_c2([{"steps": []}])


# ---------------------------------------------------------------------------
# _has_suspicious_package
# ---------------------------------------------------------------------------


class TestHasSuspiciousPackage:
    def test_normal_package(self):
        assert not _has_suspicious_package("com.example.app")

    def test_random_package(self):
        assert _has_suspicious_package("a.b.c.d.e.f.g")

    def test_consonant_package(self):
        assert _has_suspicious_package("a.ghbklmnp")

    def test_empty(self):
        assert not _has_suspicious_package("")

    def test_single_segment(self):
        assert not _has_suspicious_package("mono")


# ---------------------------------------------------------------------------
# _get_dex_method_count
# ---------------------------------------------------------------------------


class TestGetDexMethodCount:
    def test_from_obfuscation(self):
        result = _make_result(obfuscation_analysis={"indicators": {"total_methods": 42}})
        assert _get_dex_method_count(result) == 42

    def test_from_metadata_fallback(self):
        result = _make_result(
            obfuscation_analysis={"indicators": {}},
            metadata={"decompiled_classes": 30},
        )
        assert _get_dex_method_count(result) == 30

    def test_zero(self):
        result = _make_result(obfuscation_analysis={"indicators": {}}, metadata={})
        assert _get_dex_method_count(result) == 0


# ---------------------------------------------------------------------------
# correct_metasploit_stager
# ---------------------------------------------------------------------------


class TestCorrectMetasploitStager:
    def test_package_match_boosts(self):
        result = _make_result(metadata={"package_name": "com.metasploit.stage", "file_size_bytes": 200_000})
        corrected = correct_metasploit_stager(result)
        assert corrected["llm_assessment"]["risk_score"] >= 85
        assert corrected["llm_assessment"]["severity"] == "high"

    def test_small_apk_with_reflection_boosts(self):
        result = _make_result(
            metadata={"package_name": "com.evil.app", "file_size_bytes": 50_000},
            obfuscation_analysis={
                "indicators": {
                    "reflection": ["r1", "r2", "r3"],
                    "dynamic_loading": ["d1"],
                    "suspicious_apis": [],
                    "dangerous_permissions": [],
                    "crypto_apis": [],
                }
            },
        )
        corrected = correct_metasploit_stager(result)
        assert corrected["llm_assessment"]["risk_score"] >= 85
        assert corrected["llm_assessment"]["severity"] == "high"

    def test_already_high_skipped(self):
        result = _make_result(
            metadata={"package_name": "com.metasploit.stage", "file_size_bytes": 200_000},
            llm_assessment={"severity": "high", "risk_score": 90, "narrative": "", "confidence": 0.9},
        )
        corrected = correct_metasploit_stager(result)
        assert corrected["llm_assessment"]["risk_score"] == 90

    def test_no_match_unchanged(self):
        result = _make_result()
        corrected = correct_metasploit_stager(result)
        assert corrected["llm_assessment"]["risk_score"] == 25

    def test_sets_post_process_notes(self):
        result = _make_result(metadata={"package_name": "com.metasploit.stage", "file_size_bytes": 200_000})
        corrected = correct_metasploit_stager(result)
        assert len(corrected.get("post_process_notes", [])) == 1
        assert "Post-process correction" in corrected["post_process_notes"][0]


# ---------------------------------------------------------------------------
# correct_benign_false_positive
# ---------------------------------------------------------------------------


class TestCorrectBenignFalsePositive:
    def test_known_benign_downgrades(self):
        result = _make_result(
            metadata={"package_name": "com.jovial.jrpn"},
            llm_assessment={"severity": "high", "risk_score": 70, "narrative": "", "confidence": 0.8},
        )
        corrected = correct_benign_false_positive(result)
        assert corrected["llm_assessment"]["risk_score"] <= 25
        assert corrected["llm_assessment"]["severity"] == "low"

    def test_known_benign_with_real_c2_unchanged(self):
        result = _make_result(
            metadata={"package_name": "com.jovial.jrpn"},
            c2_infrastructure=[{"domain": "evil.com"}],
            llm_assessment={"severity": "high", "risk_score": 70, "narrative": "", "confidence": 0.8},
        )
        corrected = correct_benign_false_positive(result)
        assert corrected["llm_assessment"]["risk_score"] == 70

    def test_not_benign_unchanged(self):
        result = _make_result(llm_assessment={"severity": "high", "risk_score": 70, "narrative": "", "confidence": 0.8})
        corrected = correct_benign_false_positive(result)
        assert corrected["llm_assessment"]["risk_score"] == 70

    def test_already_low_skipped(self):
        result = _make_result(
            metadata={"package_name": "com.jovial.jrpn"},
            llm_assessment={"severity": "low", "risk_score": 25, "narrative": "", "confidence": 0.5},
        )
        corrected = correct_benign_false_positive(result)
        assert corrected["llm_assessment"]["risk_score"] == 25


# ---------------------------------------------------------------------------
# correct_tiny_dex
# ---------------------------------------------------------------------------


class TestCorrectTinyDex:
    def test_tiny_with_perms_boosts(self):
        result = _make_result(
            obfuscation_analysis={
                "indicators": {
                    "total_methods": 12,
                    "dangerous_permissions": ["SEND_SMS"],
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
        )
        corrected = correct_tiny_dex(result)
        assert corrected["llm_assessment"]["risk_score"] == 55
        assert "tiny DEX" in corrected["post_process_notes"][0]

    def test_tiny_empty_boosts(self):
        result = _make_result(
            obfuscation_analysis={
                "indicators": {
                    "total_methods": 8,
                    "dangerous_permissions": [],
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
        )
        corrected = correct_tiny_dex(result)
        assert corrected["llm_assessment"]["risk_score"] == 55

    def test_large_app_not_boosted(self):
        result = _make_result(
            obfuscation_analysis={
                "indicators": {
                    "total_methods": 3000,
                    "dangerous_permissions": ["SEND_SMS", "READ_SMS"],
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
        )
        corrected = correct_tiny_dex(result)
        assert corrected["llm_assessment"]["risk_score"] == 25

    def test_tiny_with_code_signals_not_boosted(self):
        result = _make_result(
            obfuscation_analysis={
                "indicators": {
                    "total_methods": 10,
                    "dangerous_permissions": ["SEND_SMS"],
                    "reflection": ["r1"],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
        )
        corrected = correct_tiny_dex(result)
        assert corrected["llm_assessment"]["risk_score"] == 25

    def test_already_high_skipped(self):
        result = _make_result(
            obfuscation_analysis={
                "indicators": {
                    "total_methods": 10,
                    "dangerous_permissions": ["SEND_SMS"],
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
            llm_assessment={"severity": "medium", "risk_score": 60, "narrative": "", "confidence": 0.6},
        )
        corrected = correct_tiny_dex(result)
        assert corrected["llm_assessment"]["risk_score"] == 60

    def test_with_real_c2_not_boosted(self):
        result = _make_result(
            obfuscation_analysis={
                "indicators": {
                    "total_methods": 10,
                    "dangerous_permissions": ["SEND_SMS"],
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
            c2_infrastructure=[{"domain": "evil.com"}],
        )
        corrected = correct_tiny_dex(result)
        assert corrected["llm_assessment"]["risk_score"] == 25


# ---------------------------------------------------------------------------
# correct_decoding_no_c2
# ---------------------------------------------------------------------------


class TestCorrectDecodingNoC2:
    def test_non_trivial_encoding_boosts(self):
        result = _make_result(
            threat_chains=[
                {"decoding_chain": ["base64", "xor"], "steps": []},
            ],
            obfuscation_analysis={
                "indicators": {
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
            llm_assessment={"severity": "low", "risk_score": 45, "narrative": "", "confidence": 0.5},
        )
        corrected = correct_decoding_no_c2(result)
        assert corrected["llm_assessment"]["risk_score"] == 55

    def test_unknown_only_encoding_not_boosted(self):
        result = _make_result(
            threat_chains=[
                {"decoding_chain": ["unknown"], "steps": []},
            ],
            obfuscation_analysis={
                "indicators": {
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
            llm_assessment={"severity": "low", "risk_score": 45, "narrative": "", "confidence": 0.5},
        )
        corrected = correct_decoding_no_c2(result)
        assert corrected["llm_assessment"]["risk_score"] == 45

    def test_no_chains_not_boosted(self):
        result = _make_result(
            threat_chains=[],
            llm_assessment={"severity": "low", "risk_score": 25, "narrative": "", "confidence": 0.5},
        )
        corrected = correct_decoding_no_c2(result)
        assert corrected["llm_assessment"]["risk_score"] == 25

    def test_with_code_signals_not_boosted(self):
        result = _make_result(
            threat_chains=[
                {"decoding_chain": ["base64"], "steps": []},
            ],
            obfuscation_analysis={
                "indicators": {
                    "reflection": ["r1"],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
            llm_assessment={"severity": "low", "risk_score": 45, "narrative": "", "confidence": 0.5},
        )
        corrected = correct_decoding_no_c2(result)
        assert corrected["llm_assessment"]["risk_score"] == 45

    def test_with_c2_not_boosted(self):
        result = _make_result(
            threat_chains=[
                {"decoding_chain": ["base64"], "steps": []},
            ],
            c2_infrastructure=[{"domain": "evil.com"}],
            obfuscation_analysis={
                "indicators": {
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
            llm_assessment={"severity": "low", "risk_score": 45, "narrative": "", "confidence": 0.5},
        )
        corrected = correct_decoding_no_c2(result)
        assert corrected["llm_assessment"]["risk_score"] == 45

    def test_already_high_skipped(self):
        result = _make_result(
            threat_chains=[
                {"decoding_chain": ["base64"], "steps": []},
            ],
            obfuscation_analysis={
                "indicators": {
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
            llm_assessment={"severity": "medium", "risk_score": 60, "narrative": "", "confidence": 0.6},
        )
        corrected = correct_decoding_no_c2(result)
        assert corrected["llm_assessment"]["risk_score"] == 60


# ---------------------------------------------------------------------------
# correct_suspicious_package
# ---------------------------------------------------------------------------


class TestCorrectSuspiciousPackage:
    def test_suspicious_package_boosts(self):
        result = _make_result(metadata={"package_name": "a.b.c.d.e.f.g"})
        corrected = correct_suspicious_package(result)
        assert corrected["llm_assessment"]["risk_score"] >= 55

    def test_no_package_extracted_boosts(self):
        result = _make_result(metadata={"package_name": ""})
        corrected = correct_suspicious_package(result)
        assert corrected["llm_assessment"]["risk_score"] >= 55

    def test_normal_package_unchanged(self):
        result = _make_result(metadata={"package_name": "com.example.app"})
        corrected = correct_suspicious_package(result)
        assert corrected["llm_assessment"]["risk_score"] == 25

    def test_with_real_c2_unchanged(self):
        result = _make_result(
            metadata={"package_name": "a.b.c.d"},
            c2_infrastructure=[{"domain": "evil.com"}],
        )
        corrected = correct_suspicious_package(result)
        assert corrected["llm_assessment"]["risk_score"] == 25

    def test_already_high_skipped(self):
        result = _make_result(
            metadata={"package_name": "a.b.c.d"},
            llm_assessment={"severity": "high", "risk_score": 65, "narrative": "", "confidence": 0.7},
        )
        corrected = correct_suspicious_package(result)
        assert corrected["llm_assessment"]["risk_score"] == 65


# ---------------------------------------------------------------------------
# post_process_result
# ---------------------------------------------------------------------------


class TestPostProcessResult:
    def test_non_dict_raises(self):
        with pytest.raises(PostProcessError):
            post_process_result("not a dict")

    def test_empty_result_passes_through(self):
        result = _make_result()
        processed = post_process_result(result)
        assert isinstance(processed, dict)

    def test_metasploit_caught_before_benign_downgrade(self):
        result = _make_result(
            metadata={"package_name": "com.metasploit.stage", "file_size_bytes": 200_000},
            llm_assessment={"severity": "low", "risk_score": 25, "narrative": "", "confidence": 0.5},
        )
        processed = post_process_result(result)
        assert processed["llm_assessment"]["risk_score"] >= 85

    def test_suspicious_package_and_tiny_dex_both_fire(self):
        result = _make_result(
            metadata={"package_name": "a.b.c.d.e.f"},
            obfuscation_analysis={
                "indicators": {
                    "total_methods": 10,
                    "dangerous_permissions": ["SEND_SMS"],
                    "reflection": [],
                    "dynamic_loading": [],
                    "suspicious_apis": [],
                }
            },
            llm_assessment={"severity": "low", "risk_score": 25, "narrative": "", "confidence": 0.5},
        )
        processed = post_process_result(result)
        assert processed["llm_assessment"]["risk_score"] >= 55
        assert len(processed.get("post_process_notes", [])) >= 1
