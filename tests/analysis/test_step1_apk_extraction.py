"""Tests for Step 1 APK extraction diagnostics (dex_parse_errors, crypter_stub)."""

import zipfile
from pathlib import Path

import pytest

from analysis.step1_apk_extraction import (
    classify_extraction_status,
    run_androguard,
)


def _write_zip(path: Path, files: dict[str, bytes]) -> str:
    """Write a minimal APK-shaped zip with the given name -> bytes entries."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return str(path)


class TestCrypterStubDetection:
    def test_zero_byte_classes_dex_flags_stub(self, tmp_path):
        apk_path = _write_zip(
            tmp_path / "stub.apk",
            {"classes.dex": b"", "AndroidManifest.xml": b""},
        )
        result = run_androguard(apk_path)

        assert result["success"] is True
        assert result["class_count"] == 0
        assert result["crypter_stub"] is True
        assert result["dex_parse_errors"], "expected a DEX parse error for 0-byte dex"

    def test_no_dex_is_not_a_stub(self, tmp_path):
        apk_path = _write_zip(
            tmp_path / "nodex.apk",
            {"AndroidManifest.xml": b"", "res/x.png": b"\x89PNG"},
        )
        result = run_androguard(apk_path)

        assert result["success"] is True
        assert result["class_count"] == 0
        assert result["crypter_stub"] is False
        assert result["dex_parse_errors"] == []

    def test_corrupt_zip_does_not_flag_stub(self, tmp_path):
        apk_path = tmp_path / "corrupt.apk"
        apk_path.write_bytes(b"not a zip at all")
        result = run_androguard(apk_path)

        assert result["success"] is False
        assert result["crypter_stub"] is False


class TestErrorPropagation:
    def test_dex_parse_errors_propagate_to_step1_errors(self, tmp_path):
        from unittest.mock import patch

        from analysis.step1_apk_extraction import extract_apk

        apk_path = _write_zip(
            tmp_path / "stub.apk",
            {"classes.dex": b"", "AndroidManifest.xml": b""},
        )

        androguard_result = {
            "success": True,
            "class_count": 0,
            "dex_strings": [],
            "error": None,
            "dex_parse_errors": [
                "DEX section error (truncated): Not a DEX file, Header too small"
            ],
            "crypter_stub": True,
        }
        with patch("analysis.step1_apk_extraction.run_apktool") as mock_apktool, patch(
            "analysis.step1_apk_extraction.run_androguard",
            return_value=androguard_result,
        ):
            mock_apktool.return_value = {"success": True, "output_dir": "", "error": None}
            result = extract_apk(apk_path, work_dir=str(tmp_path / "work"))

        assert result["crypter_stub"] is True
        assert any("Header too small" in e for e in result["errors"])

    def test_no_dex_errors_keeps_errors_empty(self, tmp_path):
        from unittest.mock import patch

        from analysis.step1_apk_extraction import extract_apk

        apk_path = _write_zip(tmp_path / "ok.apk", {"AndroidManifest.xml": b""})
        androguard_result = {
            "success": True,
            "class_count": 5,
            "dex_strings": [],
            "error": None,
            "dex_parse_errors": [],
            "crypter_stub": False,
        }
        with patch("analysis.step1_apk_extraction.run_apktool") as mock_apktool, patch(
            "analysis.step1_apk_extraction.run_androguard",
            return_value=androguard_result,
        ):
            mock_apktool.return_value = {"success": True, "output_dir": "", "error": None}
            result = extract_apk(apk_path, work_dir=str(tmp_path / "work"))

        assert result["crypter_stub"] is False
        assert result["errors"] == []


class TestExtractionStatusClassification:
    def _classify(self, apk_path, classes=0, strings=0, crypter_stub=False):
        return classify_extraction_status(
            {
                "decompiled_classes": classes,
                "dex_strings_count": strings,
                "crypter_stub": crypter_stub,
            },
            str(apk_path),
        )

    def test_normal_extraction_is_ok(self, tmp_path):
        apk_path = _write_zip(
            tmp_path / "ok.apk",
            {"classes.dex": b"dex\n035", "AndroidManifest.xml": b""},
        )
        assert self._classify(apk_path, classes=42, strings=100) == "ok"

    def test_zero_byte_dex_is_crypter_stub(self, tmp_path):
        apk_path = _write_zip(tmp_path / "stub.apk", {"classes.dex": b""})
        assert self._classify(apk_path, crypter_stub=True) == "crypter_stub"

    def test_large_dummy_file_is_crypter_stub(self, tmp_path):
        # A single >50MB padding entry is a crypter anti-analysis signal.
        apk_path = _write_zip(
            tmp_path / "padded.apk",
            {"assets/pad.bin": b"\x00" * (51 * 1024 * 1024)},
        )
        assert self._classify(apk_path) == "crypter_stub"

    def test_nested_apk_is_detected(self, tmp_path):
        apk_path = _write_zip(
            tmp_path / "nested.apk",
            {"classes.dex": b"dex\n035", "assets/base.apk": b"PK\x03\x04 not a real apk"},
        )
        assert self._classify(apk_path) == "nested_apk"

    def test_corrupt_zip_is_detected(self, tmp_path):
        apk_path = tmp_path / "corrupt.apk"
        apk_path.write_bytes(b"this is definitely not a zip archive")
        assert self._classify(apk_path) == "corrupted_zip"

    def test_empty_extraction_without_known_pattern(self, tmp_path):
        # Valid zip, no code, no anti-analysis pattern -> honest fallback label.
        apk_path = _write_zip(
            tmp_path / "empty.apk",
            {"res/x.png": b"\x89PNG", "AndroidManifest.xml": b""},
        )
        assert self._classify(apk_path) == "empty_extraction"

    def test_extract_apk_writes_status_field(self, tmp_path):
        from unittest.mock import patch

        from analysis.step1_apk_extraction import extract_apk

        apk_path = _write_zip(
            tmp_path / "stub.apk",
            {"classes.dex": b"", "AndroidManifest.xml": b""},
        )
        androguard_result = {
            "success": True,
            "class_count": 0,
            "dex_strings": [],
            "error": None,
            "dex_parse_errors": ["DEX section error (truncated): Header too small"],
            "crypter_stub": True,
        }
        with patch("analysis.step1_apk_extraction.run_apktool") as mock_apktool, patch(
            "analysis.step1_apk_extraction.run_androguard",
            return_value=androguard_result,
        ):
            mock_apktool.return_value = {"success": True, "output_dir": "", "error": None}
            result = extract_apk(apk_path, work_dir=str(tmp_path / "work"))

        assert result["extraction_status"] == "crypter_stub"
