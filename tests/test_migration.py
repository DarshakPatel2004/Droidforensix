"""
Cross-platform migration tests for DroidForensix.

Tests verify that:
- Platform detection works correctly
- Tool paths resolve to the correct platform-specific binaries
- Cross-platform utility functions work on both Windows and Linux
"""

import importlib.util
import sys
from pathlib import Path

import pytest

# `tools/` is gitignored (local-only); tests that import it skip on a clean clone.
needs_tools = pytest.mark.skipif(
    importlib.util.find_spec("tools") is None,
    reason="local-only tools/ package is absent (gitignored)",
)


class TestPlatformDetection:
    """Test platform detection utilities."""

    def test_platform_detected(self):
        """Verify platform is either Windows or Linux."""
        assert sys.platform.startswith("win") or sys.platform.startswith("linux")

    @needs_tools
    def test_is_windows_flag(self):
        """Verify IS_WINDOWS is correctly set."""
        from tools import IS_WINDOWS

        if sys.platform.startswith("win"):
            assert IS_WINDOWS is True
        else:
            assert IS_WINDOWS is False

    @needs_tools
    def test_is_linux_flag(self):
        """Verify IS_LINUX is correctly set."""
        from tools import IS_LINUX

        if sys.platform.startswith("linux"):
            assert IS_LINUX is True
        else:
            assert IS_LINUX is False


class TestToolPaths:
    """Test that tool paths resolve to the correct platform-specific binaries."""

    @needs_tools
    def test_apktool_path_valid(self):
        """APKTOOL_PATH should point to a valid file or .jar."""
        from tools import get_tool_path

        apktool = get_tool_path("apktool")
        # Either .bat on Windows or .jar on Linux
        assert apktool is not None, "apktool not found in tools/ or on PATH"

    def test_seven_zip_path_valid(self):
        """SEVEN_ZIP_PATH should be set (either bundled or from PATH)."""
        # Either the path exists or '7z' is on system PATH
        import shutil

        from backend.config import settings

        seven_zip = Path(settings.SEVEN_ZIP_PATH)
        seven_zip_on_path = shutil.which(seven_zip.name if seven_zip.name else "7z")

        assert seven_zip.exists() or seven_zip_on_path, "7-Zip not found"

    @needs_tools
    def test_file_entropy_calculation(self, tmp_path):
        """Test entropy calculation works on both platforms."""
        from tools import get_file_entropy

        # Create a test file with known entropy
        test_file = tmp_path / "test_entropy_file.bin"
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

    @needs_tools
    def test_elf_detection(self, tmp_path):
        """Test ELF magic byte detection."""
        from tools import is_elf_file

        # Create a test ELF file
        test_file = tmp_path / "test.elf"
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

    @needs_tools
    def test_tool_availability_check(self):
        """Test is_tool_available function."""
        from tools import is_tool_available

        # Androguard is pure-Python (no external binary needed); apktool should be available
        assert is_tool_available("apktool") is True, "apktool should be available"

        # Non-existent tool should return False
        assert is_tool_available("nonexistent_tool_xyz") is False


class TestOllamaConnection:
    """Test Ollama connectivity (skip if not running)."""

    @pytest.mark.slow
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