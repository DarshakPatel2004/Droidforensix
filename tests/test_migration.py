"""
Cross-platform migration tests for DroidForensix.

Tests verify that:
- Platform detection works correctly
- Tool paths resolve to the correct platform-specific binaries
- Cross-platform utility functions work on both Windows and Linux
"""

import sys
from pathlib import Path

import pytest


class TestPlatformDetection:
    """Test platform detection utilities."""

    def test_platform_detected(self):
        """Verify platform is either Windows or Linux."""
        assert sys.platform.startswith("win") or sys.platform.startswith("linux")

    def test_is_windows_flag(self):
        """Verify IS_WINDOWS is correctly set."""
        from tools import IS_WINDOWS

        if sys.platform.startswith("win"):
            assert IS_WINDOWS is True
        else:
            assert IS_WINDOWS is False

    def test_is_linux_flag(self):
        """Verify IS_LINUX is correctly set."""
        from tools import IS_LINUX

        if sys.platform.startswith("linux"):
            assert IS_LINUX is True
        else:
            assert IS_LINUX is False


class TestToolPaths:
    """Test that tool paths resolve to the correct platform-specific binaries."""

    def test_apktool_path_valid(self):
        """APKTOOL_PATH should point to a valid file or .jar."""
        from tools import get_tool_path

        apktool = get_tool_path("apktool")
        # Either .bat on Windows or .jar on Linux
        assert apktool is not None, "apktool not found in tools/ or on PATH"

    def test_seven_zip_path_valid(self):
        """SEVEN_ZIP_PATH should be set (either bundled or from PATH)."""
        from backend.config import settings

        # Either the path exists or '7z' is on system PATH
        import shutil

        seven_zip = Path(settings.SEVEN_ZIP_PATH)
        seven_zip_on_path = shutil.which(seven_zip.name if seven_zip.name else "7z")

        assert seven_zip.exists() or seven_zip_on_path, "7-Zip not found"

    def test_ollama_model_is_mistral_by_default(self):
        """OLLAMA_MODEL should default to mistral:3b (unless overridden in .env)."""
        from backend.config import Settings

        # Create fresh settings without loading .env to test default
        # The .env override is expected behavior, but default should be mistral:3b
        # We verify the default value in the class definition
        default_model = Settings.model_fields["OLLAMA_MODEL"].default
        assert default_model == "mistral:3b", f"Default model should be mistral:3b, got {default_model}"


class TestCrossPlatformUtils:
    """Test cross-platform utility functions."""

    def test_file_entropy_calculation(self):
        """Test entropy calculation works on both platforms."""
        from tools import get_file_entropy

        # Create a test file with known entropy
        test_file = Path("test_entropy_file.bin")
        try:
            # Low entropy: repeated bytes
            test_file.write_bytes(b"A" * 1000)
            entropy = get_file_entropy(test_file)
            assert entropy < 1.0, f"Low entropy expected for repeated data, got {entropy}"

            # High entropy: random-ish data
            import os

            test_file.write_bytes(os.urandom(1000))
            entropy = get_file_entropy(test_file)
            assert entropy > 5.0, f"High entropy expected for random data, got {entropy}"
        finally:
            if test_file.exists():
                test_file.unlink()

    def test_elf_detection(self):
        """Test ELF magic byte detection."""
        from tools import is_elf_file

        # Create a test ELF file
        test_file = Path("test.elf")
        try:
            # Write ELF magic bytes
            test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
            assert is_elf_file(test_file) is True, "Should detect ELF magic bytes"

            # Write non-ELF
            test_file.write_bytes(b"NOT_ELF" + b"\x00" * 100)
            assert is_elf_file(test_file) is False, "Should reject non-ELF"
        finally:
            if test_file.exists():
                test_file.unlink()

    def test_tool_availability_check(self):
        """Test is_tool_available function."""
        from tools import is_tool_available

        # Androguard is pure-Python (no external binary needed); apktool should be available
        assert is_tool_available("apktool") is True, "apktool should be available"

        # Non-existent tool should return False
        assert is_tool_available("nonexistent_tool_xyz") is False


class TestConfigDirectories:
    """Test that config directories are properly set up."""

    def test_work_dir_exists(self):
        """WORK_DIR should be created automatically."""
        from backend.config import settings

        assert settings.WORK_DIR.exists()
        assert settings.WORK_DIR.is_dir()

    def test_reports_dir_exists(self):
        """REPORTS_DIR should be created automatically."""
        from backend.config import settings

        assert settings.REPORTS_DIR.exists()
        assert settings.REPORTS_DIR.is_dir()

    def test_uploads_dir_exists(self):
        """UPLOADS_DIR should be created automatically."""
        from backend.config import settings

        assert settings.UPLOADS_DIR.exists()
        assert settings.UPLOADS_DIR.is_dir()

    def test_directories_are_absolute(self):
        """All directory paths should be absolute."""
        from backend.config import settings

        for attr in ["WORK_DIR", "REPORTS_DIR", "SAMPLES_DIR", "UPLOADS_DIR"]:
            path = getattr(settings, attr)
            assert path.is_absolute(), f"{attr} should be absolute: {path}"


class TestOllamaConnection:
    """Test Ollama connectivity (skip if not running)."""

    @pytest.mark.skipif(
        not sys.platform.startswith("win") and not sys.platform.startswith("linux"),
        reason="Only Windows/Linux supported"
    )
    def test_ollama_reachable(self):
        """Check if Ollama is running on localhost:11434."""
        import requests

        try:
            response = requests.get(
                "http://localhost:11434/api/tags",
                timeout=5,
            )
            assert response.status_code == 200, "Ollama should respond with 200"
        except requests.exceptions.ConnectionError:
            pytest.skip("Ollama not running on localhost:11434")
        except requests.exceptions.Timeout:
            pytest.skip("Ollama connection timed out")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])