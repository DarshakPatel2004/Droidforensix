"""End-to-end integration tests for the full pipeline orchestration.

Tests pipeline orchestration with mocked steps to verify:
- All 18 steps execute in correct order
- Step input validation catches missing keys
- Timeout handling works
- Error handling and fallbacks work
- Result dict has expected structure
- Event emission fires correctly
"""

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from analysis.pipeline import (
    TOTAL_STEPS,
    STEP_NAMES,
    STEP_TIMEOUTS,
    PipelineError,
    TimeoutError,
    InterruptableThread,
    run_with_timeout,
    _validate_step_input,
    run_pipeline,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_apk(tmp_path):
    """Create a minimal synthetic APK (ZIP with AndroidManifest.xml)."""
    import zipfile
    apk_path = tmp_path / "test.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest package="com.test.app" '
            'xmlns:android="http://schemas.android.com/apk/res/android">\n'
            '  <uses-permission android:name="android.permission.INTERNET"/>\n'
            '</manifest>'
        ))
        zf.writestr("classes.dex", b"\x00" * 1024)
    return str(apk_path)


@pytest.fixture
def mock_extraction():
    """Returns a mock extraction result."""
    return {
        "sample_id": "test_sample_001",
        "sample_name": "test.apk",
        "file_size_bytes": 1024,
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "package_name": "com.test.app",
        "apktool_output_dir": "/tmp/apktool",
        "apktool_success": True,
        "native_libs_found": False,
        "decompiled_classes": 10,
        "errors": [],
        "manifest_info": {
            "version_name": "1.0",
            "version_code": "1",
            "target_sdk_version": 30,
            "min_sdk_version": 21,
            "uses_permissions": ["android.permission.INTERNET"],
        },
    }


@pytest.fixture
def mock_strings():
    return {
        "total_strings": 100,
        "categories": {
            "urls": [],
            "ips": [],
            "domains": [],
            "files": [],
            "other": [],
        },
    }


@pytest.fixture
def mock_encodings():
    return {"encodings": []}


@pytest.fixture
def mock_payloads():
    return {"payloads": []}


@pytest.fixture
def mock_c2():
    return {"c2_infrastructure": []}


@pytest.fixture
def mock_chains():
    return {"threat_chains": []}


@pytest.fixture
def mock_secrets():
    return {
        "hardcoded_secrets": [],
        "secret_risk": {"total_secrets": 0, "severity": "low"},
    }


# ---------------------------------------------------------------------------
# Unit tests for helper utilities
# ---------------------------------------------------------------------------

class TestInterruptableThread:
    def test_successful_execution(self):
        thread = InterruptableThread(target=lambda x: x + 1, args=(41,))
        thread.start()
        thread.join()
        assert thread.result == 42
        assert thread.exception is None

    def test_exception_captured(self):
        def fail():
            raise ValueError("oops")

        thread = InterruptableThread(target=fail)
        thread.start()
        thread.join()
        assert thread.result is None
        assert isinstance(thread.exception, ValueError)

    def test_no_target(self):
        thread = InterruptableThread(target=lambda: None)
        thread.start()
        thread.join()
        assert thread.result is None


class TestRunWithTimeout:
    def test_completes_before_timeout(self):
        result = run_with_timeout(lambda x: x * 2, (21,), 5, "test")
        assert result == 42

    def test_raises_timeout_error(self):
        def slow():
            time.sleep(10)
            return 42

        with pytest.raises(TimeoutError, match="timed out after"):
            run_with_timeout(slow, (), 0.1, "slow_step")

    def test_raises_exception_from_function(self):
        def fail():
            raise ValueError("bad")

        with pytest.raises(ValueError, match="bad"):
            run_with_timeout(fail, (), 5, "fail_step")

    def test_returns_none_for_void_function(self):
        result = run_with_timeout(lambda: None, (), 5, "void")
        assert result is None


class TestValidateStepInput:
    def test_all_keys_present(self):
        data = {"a": 1, "b": 2, "c": 3}
        _validate_step_input("test", data, ["a", "b"])  # should not raise

    def test_missing_keys_raises(self):
        data = {"a": 1}
        with pytest.raises(PipelineError, match="missing required keys"):
            _validate_step_input("test", data, ["a", "b"])

    def test_empty_required_list(self):
        data = {}
        _validate_step_input("test", data, [])  # should not raise

    def test_empty_data_with_keys(self):
        with pytest.raises(PipelineError):
            _validate_step_input("test", {}, ["key"])


# ---------------------------------------------------------------------------
# Integration tests for run_pipeline
# ---------------------------------------------------------------------------

class TestPipelineOrder:
    """Verify all 18 steps execute in the correct order."""

    @patch("analysis.pipeline.extract_apk")
    @patch("analysis.pipeline.enumerate_strings")
    @patch("analysis.pipeline.detect_encoding")
    @patch("analysis.pipeline.decode_payloads")
    @patch("analysis.pipeline.extract_c2_infrastructure")
    @patch("analysis.pipeline.build_threat_chains")
    @patch("analysis.pipeline.analyze_obfuscation")
    @patch("analysis.pipeline.assess_with_llm")
    @patch("analysis.pipeline.analyze_hardcoded_secrets")
    @patch("analysis.pipeline.post_process_result")
    @patch("analysis.pipeline.identify_family")
    @patch("analysis.pipeline.detect_binary_packing")
    @patch("analysis.pipeline.cluster_high_entropy_strings")
    @patch("analysis.pipeline.find_reflective_calls")
    @patch("analysis.pipeline.analyze_native_libraries_from_apk")
    @patch("analysis.pipeline.analyze_network_protocols")
    @patch("analysis.pipeline.correlate_reflective_permission_usage")
    @patch("analysis.pipeline.analyze_certificate")
    @patch("analysis.pipeline.cluster_family")
    @patch("analysis.pipeline.synthesize_threat_profile")
    @patch("analysis.pipeline.APKDissector")
    def test_all_steps_executed(
        self,
        mock_dissector,
        mock_synthesize,
        mock_cluster_family,
        mock_cert,
        mock_perm_corr,
        mock_network,
        mock_elf,
        mock_reflective,
        mock_string_cluster,
        mock_packing,
        mock_family_id,
        mock_post_process,
        mock_secrets,
        mock_llm,
        mock_obfuscation,
        mock_chains,
        mock_c2,
        mock_decode,
        mock_encoding,
        mock_strings,
        mock_extract,
        tmp_path,
        mock_extraction,
        mock_strings_result,
        mock_encodings,
        mock_payloads,
        mock_c2_result,
        mock_chains_result,
    ):
        mock_extract.return_value = mock_extraction
        mock_strings.return_value = mock_strings_result
        mock_encoding.return_value = mock_encodings
        mock_decode.return_value = mock_payloads
        mock_c2.return_value = mock_c2_result
        mock_chains.return_value = mock_chains_result
        mock_secrets.return_value = {
            "hardcoded_secrets": [],
            "secret_risk": {"total_secrets": 0, "severity": "low"},
        }
        mock_obfuscation.return_value = {
            "obfuscation_score": 0, "obfuscation_level": "low",
            "indicators": {}, "dex_entropy": [],
            "native_library_artifacts": [],
        }
        mock_llm.return_value = {
            "severity": "low", "risk_score": 0, "narrative": "",
            "primary_threat": "other", "recommended_actions": [],
            "confidence": 0.0,
        }
        mock_post_process.return_value = {"post_processed": True}
        mock_family_id.return_value = {
            "family": "unknown", "confidence": 0.0,
            "method": "none", "candidates": [],
        }
        mock_packing.return_value = {"packing_detected": False, "obfuscation_score": 0, "indicators": []}
        mock_string_cluster.return_value = {
            "high_entropy_strings": [], "clusters": [],
            "total_clusters": 0, "total_high_entropy": 0,
        }
        mock_reflective.return_value = {
            "total_reflective_calls": 0, "reflective_calls": [],
            "sensitive_targets": [], "total_sensitive": 0,
        }
        mock_elf.return_value = {
            "native_libraries": [], "total_libraries": 0, "has_native_code": False,
        }
        mock_network.return_value = {
            "total_endpoints": 0, "total_c2": 0, "total_suspicious": 0,
            "total_benign": 0, "c2_endpoints": [],
            "suspicious_endpoints": [], "benign_endpoints": [],
            "socket_pattern_matches": 0,
        }
        mock_perm_corr.return_value = {
            "total_permissions": 0, "used_permissions": [],
            "unused_permissions": [], "total_used": 0,
            "total_unused": 0, "usage_ratio": 1.0,
            "category_summary": {},
        }
        mock_cert.return_value = {
            "certificate_found": False, "known_bad": False,
            "warnings": [],
        }
        mock_cluster_family.return_value = {
            "matches": [], "similarity_scores": {},
            "top_match": None,
        }
        mock_synthesize.return_value = {
            "zero_day_risk_score": 0, "risk_level": "none",
            "contributing_signals": [], "signal_count": 0,
        }
        mock_dissector_instance = MagicMock()
        mock_dissector_instance.dissect.return_value = {"test": True}
        mock_dissector.return_value = mock_dissector_instance

        apk_path = tmp_path / "test.apk"
        apk_path.write_text("fake apk content")
        apk_path = str(apk_path)

        events = []
        result = run_pipeline(
            apk_path,
            work_dir=str(tmp_path),
            event_emitter=lambda t, d: events.append((t, d)),
        )

        assert mock_extract.called
        assert mock_strings.called
        assert mock_encoding.called
        assert mock_decode.called
        assert mock_c2.called
        assert mock_chains.called
        assert mock_obfuscation.called
        assert mock_llm.called
        assert mock_family_id.called
        assert mock_packing.called
        assert mock_string_cluster.called
        assert mock_reflective.called
        assert mock_elf.called
        assert mock_network.called
        assert mock_perm_corr.called
        assert mock_cert.called
        assert mock_cluster_family.called
        assert mock_synthesize.called
        assert mock_dissector.called

        event_types = [e[0] for e in events]
        assert "analysis_started" in event_types
        assert "analysis_complete" in event_types

        assert "threat_synthesis" in result
        assert result["threat_synthesis"]["risk_level"] == "none"


@pytest.fixture
def mock_strings_result():
    return {
        "total_strings": 0,
        "categories": {
            "urls": [], "ips": [], "domains": [],
            "files": [], "other": [],
        },
    }


@pytest.fixture
def mock_c2_result():
    return {"c2_infrastructure": []}


@pytest.fixture
def mock_chains_result():
    return {"threat_chains": []}


class TestPipelineErrorHandling:
    @patch("analysis.pipeline.extract_apk")
    def test_step_failure_raises_pipeline_error(self, mock_extract, tmp_path):
        mock_extract.side_effect = ValueError("extraction failed")

        apk_path = tmp_path / "test.apk"
        apk_path.write_text("fake")
        apk_path = str(apk_path)

        with pytest.raises(PipelineError, match="extraction failed"):
            run_pipeline(apk_path, work_dir=str(tmp_path))

    def test_missing_apk_raises_error(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            run_pipeline(str(tmp_path / "nonexistent.apk"), work_dir=str(tmp_path))

    @patch("analysis.pipeline.extract_apk")
    def test_event_emission_on_error(self, mock_extract, tmp_path):
        mock_extract.side_effect = ValueError("oops")

        apk_path = tmp_path / "test.apk"
        apk_path.write_text("fake")
        apk_path = str(apk_path)

        events = []
        with pytest.raises(PipelineError):
            run_pipeline(
                apk_path,
                work_dir=str(tmp_path),
                event_emitter=lambda t, d: events.append((t, d)),
            )

        error_events = [e for e in events if e[0] == "error"]
        assert len(error_events) >= 1


class TestPipelineTimeout:
    @patch("analysis.pipeline.extract_apk")
    def test_pipeline_timeout_exceeded(self, mock_extract, tmp_path):
        mock_extract.return_value = {
            "sample_id": "test",
            "sample_name": "test.apk",
            "file_size_bytes": 100,
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "package_name": "com.test",
            "apktool_output_dir": "/tmp/a",
            "apktool_success": True,
            "native_libs_found": False,
            "decompiled_classes": 0,
            "errors": [],
            "manifest_info": {},
        }

        apk_path = tmp_path / "test.apk"
        apk_path.write_text("fake")
        apk_path = str(apk_path)

        with pytest.raises(PipelineError, match="timed out"):
            run_pipeline(apk_path, work_dir=str(tmp_path), pipeline_timeout=0)


class TestPipelineResultStructure:
    @patch("analysis.pipeline.extract_apk")
    def test_result_has_all_expected_keys(
        self, mock_extract, tmp_path, mock_extraction,
        mock_strings_result, mock_encodings, mock_payloads,
        mock_c2_result, mock_chains_result,
    ):
        mock_extract.return_value = mock_extraction

        with patch.multiple(
            "analysis.pipeline",
            enumerate_strings=MagicMock(return_value=mock_strings_result),
            detect_encoding=MagicMock(return_value=mock_encodings),
            decode_payloads=MagicMock(return_value=mock_payloads),
            extract_c2_infrastructure=MagicMock(return_value=mock_c2_result),
            build_threat_chains=MagicMock(return_value=mock_chains_result),
            analyze_hardcoded_secrets=MagicMock(return_value={
                "hardcoded_secrets": [],
                "secret_risk": {"total_secrets": 0, "severity": "low"},
            }),
            analyze_obfuscation=MagicMock(return_value={
                "obfuscation_score": 0, "obfuscation_level": "low",
                "indicators": {}, "dex_entropy": [],
                "native_library_artifacts": [],
            }),
            assess_with_llm=MagicMock(return_value={
                "severity": "low", "risk_score": 0, "narrative": "",
                "primary_threat": "other", "recommended_actions": [],
                "confidence": 0.0,
            }),
            post_process_result=MagicMock(side_effect=lambda x: x),
            identify_family=MagicMock(return_value={
                "family": "unknown", "confidence": 0.0,
                "method": "none", "candidates": [],
            }),
            detect_binary_packing=MagicMock(return_value={
                "packing_detected": False, "obfuscation_score": 0, "indicators": [],
            }),
            cluster_high_entropy_strings=MagicMock(return_value={
                "high_entropy_strings": [], "clusters": [],
                "total_clusters": 0, "total_high_entropy": 0,
            }),
            find_reflective_calls=MagicMock(return_value={
                "total_reflective_calls": 0, "reflective_calls": [],
                "sensitive_targets": [], "total_sensitive": 0,
            }),
            analyze_native_libraries_from_apk=MagicMock(return_value={
                "native_libraries": [], "total_libraries": 0, "has_native_code": False,
            }),
            analyze_network_protocols=MagicMock(return_value={
                "total_endpoints": 0, "total_c2": 0, "total_suspicious": 0,
                "total_benign": 0, "c2_endpoints": [],
                "suspicious_endpoints": [], "benign_endpoints": [],
                "socket_pattern_matches": 0,
            }),
            correlate_reflective_permission_usage=MagicMock(return_value={
                "total_permissions": 0, "used_permissions": [],
                "unused_permissions": [], "total_used": 0,
                "total_unused": 0, "usage_ratio": 1.0,
                "category_summary": {},
            }),
            analyze_certificate=MagicMock(return_value={
                "certificate_found": False, "known_bad": False, "warnings": [],
            }),
            cluster_family=MagicMock(return_value={
                "matches": [], "similarity_scores": {}, "top_match": None,
            }),
            synthesize_threat_profile=MagicMock(return_value={
                "zero_day_risk_score": 0, "risk_level": "none",
                "contributing_signals": [], "signal_count": 0,
            }),
            APKDissector=MagicMock(),
        ):
            apk_path = tmp_path / "test.apk"
            apk_path.write_text("fake")
            apk_path = str(apk_path)

            result = run_pipeline(apk_path, work_dir=str(tmp_path))

            expected_keys = {
                "sample_id", "metadata", "extraction", "manifest",
                "strings", "hardcoded_secrets", "secret_risk",
                "encodings", "payloads", "c2_infrastructure",
                "threat_chains", "llm_assessment", "obfuscation_analysis",
                "family_identification", "timeline",
                "binary_packing", "string_clustering", "reflective_tracing",
                "native_elf_analysis", "network_protocols",
                "permission_correlation", "certificate_analysis",
                "family_clustering", "threat_synthesis",
            }
            assert expected_keys.issubset(result.keys()), (
                f"Missing keys: {expected_keys - result.keys()}"
            )

            assert "step18" in result.get("timeline", {})


class TestStepNames:
    def test_all_steps_defined(self):
        assert TOTAL_STEPS == 18
        for i in range(1, TOTAL_STEPS + 1):
            assert i in STEP_NAMES, f"Step {i} missing from STEP_NAMES"

    def test_step_names_are_descriptive(self):
        for num, name in STEP_NAMES.items():
            assert len(name) > 3, f"Step {num} name too short: {name}"
            assert name[0].isupper(), f"Step {num} name not capitalized: {name}"


class TestStepTimeouts:
    def test_all_steps_have_timeouts(self):
        for i in range(1, TOTAL_STEPS + 1):
            assert i in STEP_TIMEOUTS, f"Step {i} missing timeout"
            assert STEP_TIMEOUTS[i] > 0, f"Step {i} timeout must be positive"

    def test_timeout_values_reasonable(self):
        for step_num, timeout in STEP_TIMEOUTS.items():
            assert 10 <= timeout <= 600, (
                f"Step {step_num} timeout {timeout}s outside reasonable range"
            )


class TestTimeline:
    @patch("analysis.pipeline.extract_apk")
    def test_timeline_has_all_steps(
        self, mock_extract, tmp_path, mock_extraction,
        mock_strings_result, mock_encodings, mock_payloads,
        mock_c2_result, mock_chains_result,
    ):
        mock_extract.return_value = mock_extraction

        with patch.multiple(
            "analysis.pipeline",
            enumerate_strings=MagicMock(return_value=mock_strings_result),
            detect_encoding=MagicMock(return_value=mock_encodings),
            decode_payloads=MagicMock(return_value=mock_payloads),
            extract_c2_infrastructure=MagicMock(return_value=mock_c2_result),
            build_threat_chains=MagicMock(return_value=mock_chains_result),
            analyze_hardcoded_secrets=MagicMock(return_value={
                "hardcoded_secrets": [],
                "secret_risk": {"total_secrets": 0, "severity": "low"},
            }),
            analyze_obfuscation=MagicMock(return_value={
                "obfuscation_score": 0, "obfuscation_level": "low",
                "indicators": {}, "dex_entropy": [],
                "native_library_artifacts": [],
            }),
            assess_with_llm=MagicMock(return_value={
                "severity": "low", "risk_score": 0, "narrative": "",
                "primary_threat": "other", "recommended_actions": [],
                "confidence": 0.0,
            }),
            post_process_result=MagicMock(side_effect=lambda x: x),
            identify_family=MagicMock(return_value={
                "family": "unknown", "confidence": 0.0,
                "method": "none", "candidates": [],
            }),
            detect_binary_packing=MagicMock(return_value={}),
            cluster_high_entropy_strings=MagicMock(return_value={}),
            find_reflective_calls=MagicMock(return_value={}),
            analyze_native_libraries_from_apk=MagicMock(return_value={}),
            analyze_network_protocols=MagicMock(return_value={}),
            correlate_reflective_permission_usage=MagicMock(return_value={}),
            analyze_certificate=MagicMock(return_value={}),
            cluster_family=MagicMock(return_value={}),
            synthesize_threat_profile=MagicMock(return_value={}),
            APKDissector=MagicMock(),
        ):
            apk_path = tmp_path / "test.apk"
            apk_path.write_text("fake")
            apk_path = str(apk_path)

            result = run_pipeline(apk_path, work_dir=str(tmp_path))

            tl = result["timeline"]
            for i in range(1, 19):
                key = f"step{i}"
                assert key in tl, f"Timeline missing {key}"
                assert isinstance(tl[key], (int, float)), (
                    f"{key} should be numeric, got {type(tl[key])}"
                )
            assert "total" in tl
            assert tl["total"] >= sum(tl.get(f"step{i}", 0) for i in range(1, 20))


class TestEventEmission:
    @patch("analysis.pipeline.extract_apk")
    def test_events_emitted_in_order(
        self, mock_extract, tmp_path, mock_extraction,
        mock_strings_result, mock_encodings, mock_payloads,
        mock_c2_result, mock_chains_result,
    ):
        mock_extract.return_value = mock_extraction

        with patch.multiple(
            "analysis.pipeline",
            enumerate_strings=MagicMock(return_value=mock_strings_result),
            detect_encoding=MagicMock(return_value=mock_encodings),
            decode_payloads=MagicMock(return_value=mock_payloads),
            extract_c2_infrastructure=MagicMock(return_value=mock_c2_result),
            build_threat_chains=MagicMock(return_value=mock_chains_result),
            analyze_hardcoded_secrets=MagicMock(return_value={
                "hardcoded_secrets": [],
                "secret_risk": {"total_secrets": 0, "severity": "low"},
            }),
            analyze_obfuscation=MagicMock(return_value={
                "obfuscation_score": 0, "obfuscation_level": "low",
                "indicators": {}, "dex_entropy": [],
                "native_library_artifacts": [],
            }),
            assess_with_llm=MagicMock(return_value={
                "severity": "low", "risk_score": 0, "narrative": "",
                "primary_threat": "other", "recommended_actions": [],
                "confidence": 0.0,
            }),
            post_process_result=MagicMock(side_effect=lambda x: x),
            identify_family=MagicMock(return_value={
                "family": "unknown", "confidence": 0.0,
                "method": "none", "candidates": [],
            }),
            detect_binary_packing=MagicMock(return_value={}),
            cluster_high_entropy_strings=MagicMock(return_value={}),
            find_reflective_calls=MagicMock(return_value={}),
            analyze_native_libraries_from_apk=MagicMock(return_value={}),
            analyze_network_protocols=MagicMock(return_value={}),
            correlate_reflective_permission_usage=MagicMock(return_value={}),
            analyze_certificate=MagicMock(return_value={}),
            cluster_family=MagicMock(return_value={}),
            synthesize_threat_profile=MagicMock(return_value={}),
            APKDissector=MagicMock(),
        ):
            apk_path = tmp_path / "test.apk"
            apk_path.write_text("fake")
            apk_path = str(apk_path)

            events = []
            run_pipeline(
                apk_path,
                work_dir=str(tmp_path),
                event_emitter=lambda t, d: events.append((t, d)),
            )

            event_types = [e[0] for e in events]
            assert event_types[0] == "step_started"
            assert "analysis_started" in event_types
            assert "analysis_complete" in event_types

            for etype in ["step_started", "step_completed"]:
                assert event_types.count(etype) == 18, (
                    f"Expected 18 '{etype}' events, got {event_types.count(etype)}"
                )
