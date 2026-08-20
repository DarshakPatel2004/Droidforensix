"""
Step 1: APK Extraction & Decompilation

Unpacks APK using apktool, extracts DEX class/string data using Androguard,
extracts native library strings using the `strings` utility (Windows-native
when available via Git Bash or Sysinternals), and generates metadata.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Optional

from backend.config import settings

logger = logging.getLogger(__name__)


class APKExtractionError(Exception):
    """Raised when APK extraction fails."""
    pass


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_md5(file_path: str) -> str:
    """Compute MD5 hash of a file."""
    h = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _tool_cmd(path: str) -> list:
    """Return a subprocess-ready command list from a configured tool path."""
    tool = Path(path)
    return [str(tool)] if tool.exists() else [path]


def run_apktool(apk_path: str, output_dir: str) -> dict:
    """Run apktool to unpack APK. Returns result dict."""
    result = {"success": False, "output_dir": output_dir, "error": None}
    try:
        cmd = _tool_cmd(settings.APKTOOL_PATH) + ["d", "-f", "-o", output_dir, apk_path]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, shell=(os.name == "nt")
        )
        if proc.returncode == 0:
            result["success"] = True
        else:
            result["error"] = (
                f"apktool exit code {proc.returncode}.\n"
                f"stderr: {proc.stderr[:500]}\n\n"
                f"Possible causes:\n"
                f"  1. APK is corrupted or not a valid ZIP: re-download the sample\n"
                f"  2. APK uses unsupported compression: try a different sample\n"
                f"  3. apktool version too old: update from https://apktool.org"
            )
    except subprocess.TimeoutExpired:
        result["error"] = (
            f"apktool timed out after 120s on {apk_path}.\n\n"
            f"Options:\n"
            f"  1. Increase APKTOOL_TIMEOUT in config.py (default 120s)\n"
            f"  2. APK is very large or obfuscated — try running apktool manually:\n"
            f"     apktool d -f -o {output_dir} {apk_path}\n"
            f"  3. Use --use-androguard-only to skip apktool entirely"
        )
    except FileNotFoundError:
        result["error"] = (
            f"apktool not found.\n"
            f"Expected location: {settings.APKTOOL_PATH}\n\n"
            f"Fix:\n"
            f"  1. Download from: https://apktool.org (latest release)\n"
            f"  2. Place the jar at: tools/apktool/apktool.jar\n"
            f"  3. Or set APKTOOL_PATH in backend/config.py to your installation\n"
            f"  4. Then retry: python -m analysis.pipeline {apk_path}"
        )
    except Exception as e:
        result["error"] = (
            f"apktool unexpected error: {type(e).__name__}: {e}\n\n"
            f"If this persists, try running apktool manually:\n"
            f"  apktool d -f -o {output_dir} {apk_path}"
        )
    return result


def run_androguard(apk_path: str) -> dict:
    """Extract DEX-level info using Androguard (fast, pure Python)."""
    result = {
        "success": False, "class_count": 0, "dex_strings": [],
        "error": None, "dex_parse_errors": [], "crypter_stub": False,
    }
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
        apk = APK(str(apk_path))
        dex_strings = set()
        class_count = 0
        for dex_data in apk.get_all_dex():
            try:
                dex = DEX(dex_data)
                class_count += len(list(dex.get_classes()))
                for s in dex.get_strings():
                    if s:
                        dex_strings.add(s)
            except Exception as dex_err:
                dex_error_msg = str(dex_err)[:200]
                result["dex_parse_errors"].append(
                    f"DEX section error (truncated): {dex_error_msg}"
                )
        result["success"] = True
        result["class_count"] = class_count
        result["dex_strings"] = sorted(dex_strings)
        # Crypter stub detection: a 0-byte classes.dex means the APK is a
        # packer shell (e.g. SpyNote crypter) with no extractable code.
        try:
            with zipfile.ZipFile(str(apk_path)) as zf:
                result["crypter_stub"] = any(
                    info.filename.lower().endswith(".dex") and info.file_size == 0
                    for info in zf.infolist()
                )
        except zipfile.BadZipFile:
            result["crypter_stub"] = False
    except ImportError:
        result["error"] = (
            "Androguard not installed or missing dependencies.\n\n"
            "Fix:\n"
            "  1. Install: pip install androguard\n"
            "  2. Verify: python -c \"from androguard.core.apk import APK; print('OK')\"\n"
            "  3. If on Windows, you may need: pip install androguard[lxml]"
        )
    except Exception as e:
        err_name = type(e).__name__
        if "APK" in err_name:
            result["error"] = (
                f"APK parsing failed: Androguard rejected the APK format.\n"
                f"Details: {e}\n\n"
                f"Possible causes:\n"
                f"  1. File is not a valid APK/ZIP archive\n"
                f"  2. APK header is corrupted\n"
                f"  3. File is a duplicate or zero-byte file\n\n"
                f"Verify with: python -c \"from androguard.core.apk import APK; APK('{apk_path}')\""
            )
        else:
            result["error"] = (
                f"Androguard unexpected error: {err_name}: {e}\n\n"
                f"This usually indicates a corrupt or malformed APK.\n"
                f"Try verifying the file: python -c \"import zipfile; z = zipfile.ZipFile('{apk_path}'); print(len(z.namelist()), 'entries OK')\""
            )
    return result


# Size (bytes) above which a single ZIP entry is treated as a crypter padding
# file ("dummy file" used to bloat the APK past AV size limits).
DUMMY_FILE_SIZE_THRESHOLD = 50 * 1024 * 1024  # 50 MB


# ---------------------------------------------------------------------------
# Extraction-status classification
#
# Samples that yield classes=0 / strings=0 self-diagnose instead of silently
# failing. Status is one of:
#   "ok"               - code was extracted normally
#   "crypter_stub"     - 0-byte classes.dex or >50MB padding file (packer shell)
#   "nested_apk"       - real code ships inside assets/*.apk (dynamic loader)
#   "corrupted_zip"    - not a valid ZIP archive (corrupted download/header)
#   "empty_extraction" - no code and no known anti-analysis pattern
# ---------------------------------------------------------------------------


def _has_large_dummy_file(apk_path: str) -> bool:
    """True if any ZIP entry is larger than DUMMY_FILE_SIZE_THRESHOLD.

    Crypter stubs pad APKs with a single huge file to evade AV size limits;
    a >50MB entry in an otherwise-tiny app is a strong anti-analysis signal.
    """
    try:
        with zipfile.ZipFile(str(apk_path)) as zf:
            return any(
                info.file_size > DUMMY_FILE_SIZE_THRESHOLD
                for info in zf.infolist()
            )
    except (zipfile.BadZipFile, OSError):
        return False


def _has_nested_apk(apk_path: str) -> bool:
    """True if the APK bundles a payload APK under assets/ (e.g. assets/base.apk).

    Packers/droppers ship the real code as a nested APK that static DEX
    analysis never sees, so classes=0 is expected rather than a failure.
    """
    try:
        with zipfile.ZipFile(str(apk_path)) as zf:
            return any(
                info.filename.lower().startswith("assets/") and info.filename.lower().endswith(".apk")
                for info in zf.infolist()
            )
    except (zipfile.BadZipFile, OSError):
        return False


def _is_corrupted_zip(apk_path: str) -> bool:
    """True if the file cannot be opened as a valid ZIP archive.

    Note: ``testzip()`` decompresses every entry, so this is only worth the
    cost on samples that already produced zero classes/strings (the >50MB
    dummy-file short-circuit above usually fires first).
    """
    try:
        with zipfile.ZipFile(str(apk_path)) as zf:
            return zf.testzip() is not None  # first bad CRC entry, if any
    except (zipfile.BadZipFile, OSError, RuntimeError):
        # RuntimeError: testzip() raises it on encrypted ZIP entries
        # ("password required for extraction") — the code is unrecoverable
        # statically, so treat the archive as corrupted rather than crash.
        return True


def classify_extraction_status(result: dict, apk_path: str) -> str:
    """Classify why an extraction produced no code, for diagnostics.

    Order matters: a crypter stub may also embed a nested APK, so the most
    specific anti-analysis label wins. Returns "ok" whenever classes or
    strings were extracted at all.
    """
    if result.get("decompiled_classes", 0) > 0 or result.get("dex_strings_count", 0) > 0:
        return "ok"
    if result.get("crypter_stub") or _has_large_dummy_file(apk_path):
        return "crypter_stub"
    if _has_nested_apk(apk_path):
        return "nested_apk"
    if _is_corrupted_zip(apk_path):
        return "corrupted_zip"
    return "empty_extraction"


def _extract_printable_strings(data: bytes, min_len: int = 6) -> list:
    """Pure-Python fallback to extract printable ASCII strings."""
    strings = []
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                strings.append(current.decode("ascii", errors="ignore"))
            current.clear()
    if len(current) >= min_len:
        strings.append(current.decode("ascii", errors="ignore"))
    return strings


def extract_native_strings(apk_dir: str) -> list:
    """Extract strings from native .so libraries using r2, rabin2, strings, or a Python fallback."""
    strings = []
    lib_dir = Path(apk_dir) / "lib"
    if not lib_dir.exists():
        return strings

    strings_bin = shutil.which("strings")
    r2_bin = shutil.which("r2")
    rabin2_bin = shutil.which("rabin2")

    for so_file in lib_dir.rglob("*.so"):
        try:
            # Method 1: radare2 (r2)
            if r2_bin:
                cmd = [r2_bin, "-qq", "-c", "iz", str(so_file)]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=60, shell=(os.name == "nt")
                )
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        if '"' in line:
                            parts = line.split('"')
                            if len(parts) >= 2:
                                s = parts[1].strip()
                                if s:
                                    strings.append({
                                        "value": s,
                                        "source": so_file.relative_to(apk_dir).as_posix(),
                                    })
                    continue

            # Method 2: rabin2
            if rabin2_bin:
                cmd = [rabin2_bin, "-zz", str(so_file)]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=60, shell=(os.name == "nt")
                )
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        line = line.strip()
                        if line.startswith("0x") and "   " in line:
                            parts = line.split("   ", 1)
                            if len(parts) == 2:
                                s = parts[1].strip()
                                if s:
                                    strings.append({
                                        "value": s,
                                        "source": so_file.relative_to(apk_dir).as_posix(),
                                    })
                    continue

            # Method 3: strings command or Python fallback
            with open(so_file, "rb") as f:
                data = f.read()

            if strings_bin:
                proc = subprocess.run(
                    [strings_bin, "-n", "6", "-"],
                    input=data,
                    capture_output=True,
                    timeout=60,
                )
                text = proc.stdout.decode("utf-8", errors="ignore")
                lines = text.splitlines()
            else:
                lines = _extract_printable_strings(data, min_len=6)

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                strings.append({
                    "value": line,
                    "source": so_file.relative_to(apk_dir).as_posix(),
                })
        except subprocess.TimeoutExpired:
            logger.warning("Native string extraction timed out for: %s", so_file)
        except PermissionError:
            logger.warning("Permission denied reading native lib: %s", so_file)
        except OSError as e:
            logger.warning("I/O error reading native lib %s: %s", so_file, e)
        except Exception as e:
            logger.debug("Failed to extract strings from %s: %s: %s", so_file, type(e).__name__, e)
    return strings


def extract_package_name(apk_dir: str) -> str:
    """Extract package name from AndroidManifest.xml."""
    manifest_path = Path(apk_dir) / "AndroidManifest.xml"
    if not manifest_path.exists():
        return "unknown"
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            m = re.search(r'package="([^"]+)"', content)
            if m:
                return m.group(1)
    except Exception as e:
        logger.warning("Failed to parse package name from manifest: %s (%s: %s)", manifest_path, type(e).__name__, e)
    return "unknown"


def extract_manifest_info(apk_dir: str) -> dict:
    """Extract version, SDK levels, and permissions from AndroidManifest.xml."""
    manifest_path = Path(apk_dir) / "AndroidManifest.xml"
    info = {
        "version_name": None,
        "version_code": None,
        "target_sdk_version": None,
        "min_sdk_version": None,
        "uses_permissions": [],
    }
    if not manifest_path.exists():
        return info
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # Match manifest attributes
        m = re.search(r'android:versionName="([^"]+)"', content)
        if m:
            info["version_name"] = m.group(1)
        m = re.search(r'android:versionCode="(\d+)"', content)
        if m:
            info["version_code"] = int(m.group(1))
        m = re.search(r'android:targetSdkVersion="(\d+)"', content)
        if m:
            info["target_sdk_version"] = int(m.group(1))
        m = re.search(r'android:minSdkVersion="(\d+)"', content)
        if m:
            info["min_sdk_version"] = int(m.group(1))
        # Match uses-permission names
        for m in re.finditer(r'<uses-permission[^>]*android:name="([^"]+)"', content):
            info["uses_permissions"].append(m.group(1))
    except Exception as e:
        logger.warning("Failed to parse manifest info from %s (%s: %s)", manifest_path, type(e).__name__, e)
    return info


def extract_apk(apk_path: str, work_dir: Optional[str] = None) -> dict:
    """
    Full Step 1: Extract and decompile an APK.

    Args:
        apk_path: Path to the APK file.
        work_dir: Working directory for intermediate outputs. Defaults to
            settings.WORK_DIR.

    Returns:
        dict with extraction results, metadata, and status.
    """
    apk_path = Path(apk_path).resolve()
    if not apk_path.exists():
        raise APKExtractionError(f"APK not found: {apk_path}")

    work_dir = Path(work_dir) if work_dir else settings.WORK_DIR
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    sample_id = compute_sha256(str(apk_path))
    sample_work = work_dir / sample_id
    sample_work.mkdir(parents=True, exist_ok=True)

    apktool_dir = sample_work / "apktool"

    # Run apktool
    apktool_result = run_apktool(str(apk_path), str(apktool_dir))

    # Run Androguard (fast, pure Python — ~5s per APK)
    androguard_result = run_androguard(str(apk_path))

    # Extract native strings
    native_strings = []
    if apktool_result["success"]:
        native_strings = extract_native_strings(str(apktool_dir))

    # Metadata
    package_name = None
    manifest_info = {}
    if apktool_result["success"]:
        package_name = extract_package_name(str(apktool_dir))
        manifest_info = extract_manifest_info(str(apktool_dir))

    # Class count from Androguard
    decompiled_classes = androguard_result["class_count"]

    # Collect all DEX strings from Androguard
    dex_strings = androguard_result.get("dex_strings", [])

    result = {
        "sample_id": sample_id,
        "sample_name": apk_path.name,
        "file_size_bytes": apk_path.stat().st_size,
        "sha256": sample_id,
        "md5": compute_md5(str(apk_path)),
        "package_name": package_name,
        "manifest_info": manifest_info,
        "apktool_success": apktool_result["success"],
        "androguard_success": androguard_result["success"],
        "apktool_output_dir": str(apktool_dir) if apktool_result["success"] else None,
        "apk_path": str(apk_path),
        "native_libs_found": list(
            set(s["source"] for s in native_strings)
        ) if native_strings else [],
        "decompiled_classes": decompiled_classes,
        "native_strings_count": len(native_strings),
        "native_strings": native_strings,
        "dex_strings_count": len(dex_strings),
        "dex_strings": dex_strings,
        "crypter_stub": androguard_result.get("crypter_stub", False),
        "errors": [],
    }
    result["extraction_status"] = classify_extraction_status(result, str(apk_path))

    if not apktool_result["success"]:
        result["errors"].append(apktool_result["error"])
    if not androguard_result["success"]:
        result["errors"].append(androguard_result["error"])
    # Surface DEX-level parse failures (e.g. 0-byte classes.dex in crypter
    # stubs) instead of silently dropping them.
    for dex_err in androguard_result.get("dex_parse_errors", []):
        result["errors"].append(dex_err)

    # Save intermediate result
    result_path = sample_work / "step1_extraction.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python step1_apk_extraction.py <apk_path> [work_dir]")
        sys.exit(1)
    apk = sys.argv[1]
    work = sys.argv[2] if len(sys.argv) > 2 else str(settings.WORK_DIR)
    print(json.dumps(extract_apk(apk, work), indent=2))
