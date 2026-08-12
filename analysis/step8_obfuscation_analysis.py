"""
Step 8: Advanced Obfuscation Analysis

Uses Androguard DEX bytecode analysis, native library string extraction,
and DEX packing/entropy detection to catch obfuscation techniques that
static decompilation (apktool/jadx) misses.

Detects:
- Reflection usage
- Dynamic code loading (DexClassLoader, PathClassLoader, etc.)
- Native library loading (System.loadLibrary)
- Crypto/encryption API usage
- Suspicious permission + API combinations
- Packed/encrypted DEX via entropy analysis
- Native library strings (potential C2 in .so files)
"""

import json
import logging
import math
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Dict, List, Any, Optional

from backend.config import settings
from backend.elf_analyzer import ELFBreaker

logger = logging.getLogger(__name__)

# Suppress verbose Androguard logging
logging.getLogger("androguard").setLevel(logging.WARNING)
try:
    import loguru
    loguru.logger.remove()
except Exception:
    logger.debug("Loguru not available, skipping log removal")


class ObfuscationAnalysisError(Exception):
    """Raised when obfuscation analysis fails."""
    pass


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# API signatures applied to cross-reference targets. An app method is flagged
# only when it actually calls/uses one of these APIs, not merely because the
# APK contains a framework stub with a matching name.
REFLECTION_PATTERNS = [
    r"Ljava/lang/reflect/Method;->invoke",
    r"Ljava/lang/reflect/Constructor;->newInstance",
    r"Ljava/lang/reflect/Field;->(?:get|set)",
    r"Ljava/lang/reflect/AccessibleObject;->setAccessible",
    r"Ljava/lang/Class;->forName",
    r"Ljava/lang/Class;->(?:getMethod|getDeclaredMethod|getConstructor|getDeclaredConstructor|getField|getDeclaredField)",
]

DYNAMIC_LOADING_PATTERNS = [
    r"Ldalvik/system/DexClassLoader",
    r"Ldalvik/system/PathClassLoader",
    r"Ldalvik/system/InMemoryClassLoader",
    r"Ldalvik/system/DelegateLastClassLoader",
    r"Landroid/app/DexClassLoader",
    r"Ljava/lang/ClassLoader;->",
]

NATIVE_LOADING_PATTERNS = [
    r"Ljava/lang/System;->loadLibrary",
    r"Ljava/lang/System;->load",
    r"Ldalvik/system/Runtime;->loadLibrary",
]

CRYPTO_PATTERNS = [
    r"Ljavax/crypto/",
    r"Ljava/security/MessageDigest",
    r"Ljava/security/SecureRandom",
    r"Ljava/security/Signature",
    r"Ljava/security/Mac",
    r"Ljava/security/Key(?:Generator|PairGenerator|Store)?",
    r"Landroid/security/",
]

SUSPICIOUS_APIS = [
    r"Landroid/telephony/SmsManager;->sendTextMessage",
    r"Landroid/telephony/TelephonyManager;->getDeviceId",
    r"Landroid/telephony/TelephonyManager;->getSubscriberId",
    r"Landroid/telephony/TelephonyManager;->getLine1Number",
    r"Landroid/content/ContentResolver;->query",
    r"Landroid/provider/ContactsContract",
    r"Landroid/location/LocationManager;->getLastKnownLocation",
    r"Landroid/location/LocationManager;->requestLocationUpdates",
    r"Landroid/app/admin/DevicePolicyManager",
    r"Landroid/accessibilityservice/AccessibilityService",
    r"Landroid/media/projection/MediaProjectionManager",
    r"Landroid/content/pm/PackageManager;->setComponentEnabledSetting",
    r"Landroid/os/PowerManager\$WakeLock;->acquire",
    r"Landroid/net/wifi/WifiManager",
]

DANGEROUS_PERMISSIONS = [
    "SEND_SMS",
    "READ_SMS",
    "RECEIVE_SMS",
    "READ_PHONE_STATE",
    "READ_CONTACTS",
    "READ_CALL_LOG",
    "RECORD_AUDIO",
    "CAMERA",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES",
    "WRITE_EXTERNAL_STORAGE",
]

# Permission behavior groups: coordinated permission combinations that indicate
# specific malware intent beyond the sum of individual permissions. A sample
# requesting ALL permissions in a group gets a flat score boost.
PERMISSION_BEHAVIOR_GROUPS = {
    "sms_fraud": {
        "permissions": {"SEND_SMS", "READ_SMS", "RECEIVE_SMS"},
        "boost": 35,
        "description": "SMS hijacking/fraud (send + intercept)",
    },
    "phone_identity": {
        "permissions": {"READ_PHONE_STATE"},
        "boost": 15,
        "description": "Phone identity theft / device fingerprinting",
    },
    "location_surveillance": {
        "permissions": {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "RECORD_AUDIO"},
        "boost": 25,
        "description": "Coordinated location + audio surveillance",
    },
    "device_admin_abuse": {
        "permissions": {"BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW"},
        "boost": 20,
        "description": "Device admin abuse (persistence/control)",
    },
}

# Benign framework / support-library class prefixes. Reflection, crypto, and
# dynamic-loading usages inside these packages are overwhelmingly legitimate
# framework boilerplate (e.g. Fragment lifecycle, View inflation, Kotlin
# lambdas, Glide image hashing) and inflate the obfuscation score for benign
# apps. We filter the *source* method with these prefixes; the *called* API
# patterns below can still match framework methods (e.g. SmsManager) because
# they are applied to cross-reference targets, not to the source.
BENIGN_CLASS_PREFIXES = (
    "Landroid/",
    "Landroid/support/",
    "Landroidx/",
    "Ldalvik/",
    "Ljava/",
    "Ljavax/",
    "Lsun/",
    "Lcom/android/",
    "Lcom/google/android/",
    "Lcom/bumptech/glide/",
    "Lcom/facebook/",
    "Lcom/appsflyer/",
    "Lio/sentry/",
    "Lcom/adjust/",
    "Lcom/onesignal/",
    "Lcom/amplitude/",
    "Lcom/firebase/",
    "Lcom/google/firebase/",
    "Lorg/apache/",
    "Lorg/bouncycastle/",
    "Lorg/json/",
    "Lorg/xml/",
    "Lorg/w3c/",
    "Lorg/xmlpull/",
    "Lkotlin/",
    "Lkotlinx/",
    "Ljunit/",
    "Lokhttp3/",
    "Lretrofit2/",
    "Lcom/squareup/",
    "Lio/reactivex/",
)

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_benign_framework_method(method_name: str) -> bool:
    """Return True if method belongs to a known benign framework/library class."""
    for prefix in BENIGN_CLASS_PREFIXES:
        if method_name.startswith(prefix):
            return True
    return False


def _method_matches_any(method_name: str, patterns: List[str]) -> bool:
    """Return True if method_name matches any regex pattern."""
    for pattern in patterns:
        if re.search(pattern, method_name):
            return True
    return False


def _get_called_method_names(method: Any) -> List[str]:
    """Return full names of methods called by the given method."""
    names = []
    try:
        for xref in method.get_xref_to():
            # xref is typically (class_analysis, method_analysis, offset)
            if len(xref) >= 2:
                called = xref[1]
                called_name = getattr(called, "full_name", "")
                if called_name:
                    names.append(called_name)
    except Exception:
        logger.debug("Failed to get xref for method in %s", method)
    return names


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes."""
    if not data:
        return 0.0
    length = len(data)
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def analyze_assets(apk_path: Path) -> Dict[str, Any]:
    """
    Analyze asset files in the APK for encrypted-asset patterns.

    Detects:
    - Tiny stub DEX (< 10 KB) + large encrypted assets
    - High-entropy asset files (> 7.8 entropy)
    - Assets with specific size patterns (encrypted DEX payloads)
    - Native library names in lib/ directory (for correlation)

    Returns:
        dict with asset analysis results.
    """
    result = {
        "asset_files": [],
        "flags": [],
        "dex_files": [],
        "native_libs": [],
    }
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            for name in z.namelist():
                # Skip directories
                if name.endswith('/'):
                    continue

                try:
                    data = z.read(name)
                except RuntimeError:
                    # Skip encrypted entries (password-protected ZIP)
                    continue
                file_size = len(data)

                # Track DEX files
                if name.startswith('classes') and name.endswith('.dex'):
                    ent = shannon_entropy(data) if data else 0.0
                    result["dex_files"].append({
                        "file": name,
                        "size": file_size,
                        "entropy": round(ent, 4),
                    })

                # Track asset files
                elif name.startswith('assets/') and not name.endswith('/'):
                    ent = shannon_entropy(data) if data else 0.0
                    entry = {
                        "file": name,
                        "size": file_size,
                        "entropy": round(ent, 4),
                        "likely_encrypted": ent > 7.8,
                    }
                    result["asset_files"].append(entry)

                # Track native libraries
                elif name.endswith('.so'):
                    result["native_libs"].append({
                        "file": name,
                        "size": file_size,
                    })

    except Exception as e:
        logger.debug("Asset analysis failed: %s", e)
        return result

    # Detection: tiny DEX + large assets + native libs
    tiny_dexes = [d for d in result["dex_files"] if d["size"] < 10000]
    large_assets = [a for a in result["asset_files"] if a["size"] > 50000]
    has_native_libs = len(result["native_libs"]) > 0
    has_encrypted_assets = [a for a in result["asset_files"] if a.get("likely_encrypted")]

    if tiny_dexes and large_assets and has_native_libs:
        # Compute a confidence score for the encrypted-assets pattern
        total_asset_size = sum(a["size"] for a in large_assets)
        total_dex_size = sum(d["size"] for d in tiny_dexes)
        asset_to_dex_ratio = total_asset_size / total_dex_size if total_dex_size > 0 else 0

        flag_detail = (
            f"Tiny DEX ({len(tiny_dexes)} files, {total_dex_size}B total) + "
            f"large assets ({len(large_assets)} files, {total_asset_size}B total) + "
            f"native libs ({len(result['native_libs'])})"
        )

        severity = "high" if asset_to_dex_ratio > 100 and has_encrypted_assets else "medium"

        result["flags"].append({
            "type": "encrypted_assets_stub_dex",
            "severity": severity,
            "detail": flag_detail,
            "asset_to_dex_ratio": round(asset_to_dex_ratio, 1),
            "detected_encrypted_assets": len(has_encrypted_assets),
        })

    # Detection: stand-alone encrypted asset files (even without tiny DEX)
    for asset in has_encrypted_assets:
        # Very high entropy (> 7.95) in a large file = almost certainly encrypted
        if asset["entropy"] > 7.95 and asset["size"] > 100000:
            result["flags"].append({
                "type": "encrypted_asset",
                "severity": "high",
                "detail": f"{asset['file']}: {asset['size']}B, entropy={asset['entropy']}",
            })

    # Detection: asset files that are suspiciously large for their type
    # (e.g., .png files that are several MB with max entropy)
    for asset in result["asset_files"]:
        ext = Path(asset["file"]).suffix.lower()
        if ext in ('.png', '.jpg', '.jpeg', '.gif', '.mp3', '.mp4') and asset["size"] > 500000 and asset["entropy"] > 7.9:
            result["flags"].append({
                "type": "suspicious_media_asset",
                "severity": "medium",
                "detail": f"{asset['file']}: {asset['size']}B, entropy={asset['entropy']} (media type with max entropy)",
            })

    return result


def dex_entropy_from_apk(apk_path: Path) -> List[Dict[str, Any]]:
    """Compute entropy of each classes.dex entry in the APK."""
    results = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            for name in z.namelist():
                if name.startswith('classes') and name.endswith('.dex'):
                    data = z.read(name)
                    entropy = shannon_entropy(data)
                    results.append({
                        "file": name,
                        "size": len(data),
                        "entropy": round(entropy, 4),
                        "likely_packed": entropy > 7.5,
                    })
    except Exception:
        logger.debug("DEX entropy extraction failed for %s", apk_path)
    return results


def extract_native_strings(apk_path: Path) -> List[Dict[str, Any]]:
    """Extract printable strings from native .so libraries inside the APK."""
    findings = []
    strings_bin = shutil.which("strings")
    if not strings_bin:
        return findings

    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            for name in z.namelist():
                if not name.endswith('.so'):
                    continue
                try:
                    data = z.read(name)
                    if not data:
                        continue

                    # Run strings on the .so bytes
                    result = subprocess.run(
                        [strings_bin, "-n", "6", "-"],
                        input=data,
                        capture_output=True,
                        timeout=30,
                    )
                    text = result.stdout.decode("utf-8", errors="ignore")
                    lines = text.splitlines()

                    # Extract URLs/IPs/domains
                    artifacts = []
                    for line in lines:
                        for url in URL_RE.findall(line):
                            artifacts.append({"type": "url", "value": url})
                        for ip in IP_RE.findall(line):
                            artifacts.append({"type": "ip", "value": ip})
                        for domain in DOMAIN_RE.findall(line):
                            if '.' in domain and not domain.endswith(('.so', '.c', '.h', '.cpp')):
                                artifacts.append({"type": "domain", "value": domain})

                    # Deduplicate
                    seen = set()
                    unique = []
                    for a in artifacts:
                        key = (a["type"], a["value"])
                        if key not in seen:
                            seen.add(key)
                            unique.append(a)

                    if unique:
                        findings.append({
                            "library": name,
                            "total_strings": len(lines),
                            "artifacts": unique[:20],  # limit
                        })
                except Exception:
                    logger.debug("Failed to extract strings from .so: %s", name)
                    continue
    except Exception:
        logger.debug("Native string extraction failed for %s", apk_path)
    return findings


def _has_elf_symbols(so_data: bytes) -> bool:
    """Check whether an ELF .so retains its symbol table.

    Legitimate SDK libraries (OpenSSL, libc++, etc.) almost always
    include .strtab / .symtab sections.  Malware often strips them
    to slow reverse engineering.

    NOTE: This is a byte-level heuristic (scans for the string
    ".strtab" or ".symtab" anywhere in the binary), not a proper
    ELF section-header walk.  In practice, .strtab/.symtab are
    virtually never present as code strings in stripped binaries,
    so the FP rate is near zero.  A proper ELF parser would walk
    the section header table, but that would require pyelftools
    and adds no measurable precision benefit at this signal weight.
    """
    if so_data[:4] != b'\x7fELF':
        return False
    return b'.strtab' in so_data or b'.symtab' in so_data


def analyze_native_libraries(apk_path: Path) -> Dict[str, Any]:
    """Flag suspicious .so files by heuristics and full ELF break down.

    Returns a dict with keys:
      - "suspicious": list of {library, reason, detail} for flagged .so files
      - "summary": {"total_so": int, "flagged": int}
      - "elf_analysis": {lib_path: <full ELFBreaker result>, ...}
    """
    output: Dict[str, Any] = {"suspicious": [], "summary": {"total_so": 0, "flagged": 0}, "elf_analysis": {}}
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            for name in z.namelist():
                if not name.endswith('.so'):
                    continue
                output["summary"]["total_so"] += 1
                try:
                    data = z.read(name)
                    if not data:
                        continue

                    # Full ELF break down using ELFBreaker
                    lib_name = name.split('/')[-1]
                    if len(data) > 1_000_000:
                        elf_result = {
                            "name": lib_name,
                            "size_bytes": len(data),
                            "note": "skipped: file too large (>1MB)",
                        }
                    else:
                        breaker = ELFBreaker(lib_name, data)
                        elf_result = breaker.analyze()
                    output["elf_analysis"][name] = elf_result

                    # Heuristic 1: undersized .so (< 16 KB = likely loader stub)
                    if len(data) < 16384:
                        output["suspicious"].append({
                            "library": name,
                            "reason": "undersized",
                            "detail": f"{len(data)} bytes",
                        })
                        continue  # skip other checks for stubs

                    # Heuristic 2: high entropy (> 7.8) = packed / encrypted code
                    ent = shannon_entropy(data)
                    if ent > 7.8:
                        output["suspicious"].append({
                            "library": name,
                            "reason": "high_entropy",
                            "detail": f"entropy={ent:.2f}",
                        })

                    # Heuristic 3: stripped symbols (legit .so usually has them)
                    if not _has_elf_symbols(data):
                        output["suspicious"].append({
                            "library": name,
                            "reason": "stripped_symbols",
                            "detail": "no .strtab or .symtab",
                        })
                except Exception:
                    logger.debug("Failed to analyze native lib: %s", name)
                    continue
    except Exception:
        logger.debug("Native library analysis failed for %s", apk_path)

    output["summary"]["flagged"] = len(output["suspicious"])
    return output


def analyze_with_androguard(apk_path: Path) -> Dict[str, Any]:
    """Run Androguard analysis and return obfuscation indicators."""
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError as e:
        raise ObfuscationAnalysisError(f"Androguard not installed: {e}")

    try:
        a, d, dx = AnalyzeAPK(str(apk_path))
    except Exception as e:
        raise ObfuscationAnalysisError(f"Androguard failed to analyze APK: {e}")

    indicators = {
        "reflection": [],
        "dynamic_loading": [],
        "native_loading": [],
        "crypto_apis": [],
        "suspicious_apis": [],
        "dangerous_permissions": [],
        "native_libraries": [],
        "total_classes": 0,
        "total_methods": 0,
    }

    # Permissions
    perms = a.get_permissions() if hasattr(a, 'get_permissions') else []
    for perm in perms:
        for dangerous in DANGEROUS_PERMISSIONS:
            if dangerous in perm:
                indicators["dangerous_permissions"].append(perm)
                break

    # Native libraries declared in manifest/lib dirs
    libs = a.get_libraries() if hasattr(a, 'get_libraries') else []
    indicators["native_libraries"] = list(set(libs))

    # Total classes/methods
    try:
        indicators["total_classes"] = len(dx.get_classes())
        # Androguard 4 returns generators; materialize once for counting + iteration
        methods = list(dx.get_methods())
        indicators["total_methods"] = len(methods)
    except Exception:
        logger.debug("Failed to load methods from Androguard analysis")
        methods = []

    # Analyze methods for obfuscation indicators via cross-references.
    # We count an app method only when it actually calls/uses a sensitive API,
    # which eliminates false positives from framework method stubs and Kotlin
    # functional-interface boilerplate.
    for method in methods:
        try:
            method_name = method.full_name
            if not method_name:
                continue

            # Skip framework/library boilerplate that skews benign app scores
            if is_benign_framework_method(method_name):
                continue

            called_names = _get_called_method_names(method)
            if not called_names:
                continue

            if any(_method_matches_any(called, REFLECTION_PATTERNS) for called in called_names):
                indicators["reflection"].append(method_name)

            if any(_method_matches_any(called, DYNAMIC_LOADING_PATTERNS) for called in called_names):
                indicators["dynamic_loading"].append(method_name)

            if any(_method_matches_any(called, NATIVE_LOADING_PATTERNS) for called in called_names):
                indicators["native_loading"].append(method_name)

            if any(_method_matches_any(called, CRYPTO_PATTERNS) for called in called_names):
                indicators["crypto_apis"].append(method_name)

            if any(_method_matches_any(called, SUSPICIOUS_APIS) for called in called_names):
                indicators["suspicious_apis"].append(method_name)
        except Exception:
            logger.debug("Failed to analyze method: %s", getattr(method, 'full_name', 'unknown'))
            continue

    # Deduplicate and limit
    for key in ["reflection", "dynamic_loading", "native_loading", "crypto_apis", "suspicious_apis"]:
        indicators[key] = list(set(indicators[key]))[:50]
    indicators["dangerous_permissions"] = list(set(indicators["dangerous_permissions"]))

    return indicators


def _perm_short_name(perm: str) -> str:
    """Extract the short permission name from a full Android permission string.
    E.g. 'android.permission.SEND_SMS' -> 'SEND_SMS'.
    """
    return perm.split(".")[-1] if "." in perm else perm


def _match_behavior_groups(app_permissions: List[str]) -> List[Dict[str, Any]]:
    """Return list of matched behavior groups for the app's dangerous permissions."""
    short_names = {_perm_short_name(p) for p in app_permissions}
    matches = []
    for group_name, group_config in PERMISSION_BEHAVIOR_GROUPS.items():
        required = group_config["permissions"]
        if required.issubset(short_names):
            matches.append({
                "group": group_name,
                "description": group_config["description"],
                "boost": group_config["boost"],
                "matched_permissions": list(required),
            })
    return matches


def calculate_obfuscation_score(indicators: Dict[str, Any], dex_entropy: List[Dict[str, Any]], asset_analysis: Optional[Dict[str, Any]] = None) -> float:
    """Calculate a 0-100 obfuscation score with permission behavior grouping."""
    score = 0.0
    score += min(20, len(indicators.get("reflection", [])) * 2)
    score += min(20, len(indicators.get("dynamic_loading", [])) * 5)
    score += min(10, len(indicators.get("native_loading", [])) * 3)
    score += min(15, len(indicators.get("crypto_apis", [])) * 1.5)
    score += min(15, len(indicators.get("suspicious_apis", [])) * 1.5)
    score += min(10, len(indicators.get("dangerous_permissions", [])) * 2)
    score += min(10, indicators.get("suspicious_native_libs", 0) * 5)

    if any(d.get("likely_packed") for d in dex_entropy):
        score += 15
    if asset_analysis:
        for flag in asset_analysis.get("flags", []):
            if flag["type"] == "encrypted_assets_stub_dex" and flag["severity"] == "high":
                score += 25
            elif flag["type"] == "encrypted_assets_stub_dex" and flag["severity"] == "medium":
                score += 15
            elif flag["type"] == "encrypted_asset" and flag["severity"] == "high":
                score += 20
            elif flag["type"] == "suspicious_media_asset":
                score += 10

    # Permission behavior group boosts.
    # Only boost when the app has ZERO code-level signals (reflection, dynamic loading,
    # suspicious APIs, crypto). This pattern — requesting coordinated dangerous
    # permissions but never calling the corresponding APIs — distinguishes malware
    # that collects permissions "just in case" from legitimate apps that actually use them.
    dangerous_perms = indicators.get("dangerous_permissions", [])
    matched_groups = _match_behavior_groups(dangerous_perms)
    if matched_groups:
        indicators["permission_behaviors"] = matched_groups
        code_signals = (
            len(indicators.get("reflection", []))
            + len(indicators.get("dynamic_loading", []))
            + len(indicators.get("suspicious_apis", []))
            + len(indicators.get("crypto_apis", []))
        )
        if code_signals == 0:
            for group in matched_groups:
                score += group["boost"]

    return round(min(100, score), 2)


def _analyze_obfuscation_inner(apk_path: str, work_dir: Optional[str] = None, sample_id: Optional[str] = None) -> Dict[str, Any]:
    apk_path = Path(apk_path)
    if sample_id is None:
        sample_id = apk_path.stem
    out_dir = (Path(work_dir) if work_dir else settings.WORK_DIR) / sample_id
    out_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "sample_id": sample_id,
        "obfuscation_score": 0.0,
        "obfuscation_level": "low",
        "indicators": {},
        "dex_entropy": [],
        "native_library_artifacts": [],
        "notes": [],
    }

    # DEX entropy / packing detection
    result["dex_entropy"] = dex_entropy_from_apk(apk_path)

    # Asset analysis: detect encrypted assets, stub DEX files
    result["asset_analysis"] = analyze_assets(apk_path)

    # Native library strings
    result["native_library_artifacts"] = extract_native_strings(apk_path)

    # Native library metadata heuristics (entropy, symbols, size)
    result["native_library_analysis"] = analyze_native_libraries(apk_path)

    # Androguard DEX analysis
    try:
        result["indicators"] = analyze_with_androguard(apk_path)
    except Exception as e:
        result["notes"].append(f"Androguard analysis failed: {e}")
        result["indicators"] = {
            "reflection": [],
            "dynamic_loading": [],
            "native_loading": [],
            "crypto_apis": [],
            "suspicious_apis": [],
            "dangerous_permissions": [],
            "native_libraries": [],
            "total_classes": 0,
            "total_methods": 0,
        }

    # Pipe native library analysis into indicators for scoring
    if result.get("native_library_analysis"):
        result["indicators"]["suspicious_native_libs"] = result["native_library_analysis"]["summary"]["flagged"]

    # Score
    result["obfuscation_score"] = calculate_obfuscation_score(
        result["indicators"], result["dex_entropy"], result.get("asset_analysis")
    )

    if result["obfuscation_score"] >= 70:
        result["obfuscation_level"] = "high"
    elif result["obfuscation_score"] >= 40:
        result["obfuscation_level"] = "medium"
    else:
        result["obfuscation_level"] = "low"

    # Add encrypted-asset flags to notes for visibility
    if result.get("asset_analysis"):
        for flag in result["asset_analysis"].get("flags", []):
            result["notes"].append(f"[{flag['severity']}] {flag['type']}: {flag['detail']}")

    # Save intermediate result
    result_path = out_dir / "step8_obfuscation.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    return result


def analyze_obfuscation(apk_path: str, work_dir: Optional[str] = None, sample_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Full Step 8: Advanced obfuscation analysis.

    Args:
        apk_path: Path to APK file.
        work_dir: Working directory for intermediate outputs. Defaults to
            settings.WORK_DIR.
        sample_id: Optional sample identifier; falls back to APK filename stem.

    Returns:
        dict with obfuscation indicators, native strings, DEX entropy, and score.
    """
    import threading
    result_holder = {}
    exception_holder = {}

    def _worker():
        try:
            result_holder["result"] = _analyze_obfuscation_inner(apk_path, work_dir, sample_id)
        except Exception as e:
            exception_holder["exception"] = e

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join(timeout=180)

    if thread.is_alive():
        logger.warning("Step 8 timed out after 180s for %s, returning partial result", apk_path)
        return {
            "sample_id": sample_id or Path(apk_path).stem,
            "obfuscation_score": 0.0,
            "obfuscation_level": "low",
            "indicators": {},
            "dex_entropy": [],
            "native_library_artifacts": [],
            "notes": ["Step 8 timed out after 180s - analysis skipped"],
        }

    if "exception" in exception_holder:
        raise exception_holder["exception"]

    return result_holder.get("result", {})


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python step8_obfuscation_analysis.py <apk_path> [work_dir]")
        sys.exit(1)
    apk = sys.argv[1]
    work = sys.argv[2] if len(sys.argv) > 2 else str(settings.WORK_DIR)
    print(json.dumps(analyze_obfuscation(apk, work), indent=2, default=str))
