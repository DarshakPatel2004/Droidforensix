"""
DroidForensix 6-Stage Forensic Pipeline

Structured APK analysis pipeline producing publication-ready forensic reports:
  Stage 0: Pre-Flight & Metadata Extraction
  Stage 1: Threat Indicator Analysis
  Stage 2: Code Review (Androguard DEX Analysis)
  Stage 3: DNS Enrichment (CIRCL pDNS + Live DNS)
  Stage 4: Cross-Validation (Stage 2 ↔ AndroGuard DEX)
  Stage 5: Final Consolidation & PDF Report

All findings are routed through Ollama (Mistral 7B) for cross-verification,
false-positive reduction, and MITRE mapping.
"""

import hashlib
import json
import math
import os
import re
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent))

from backend.config import settings
from droidforensix_llm import LLMVerifier, get_verifier, set_verifier
from analysis.hardcoded_secrets import analyze_hardcoded_secrets, classify_risk, format_for_report


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOTAL_STAGES = 6

STAGE_NAMES = {
    0: "Pre-Flight & Metadata",
    1: "Threat Indicators",
    2: "Code Review",
    3: "DNS Enrichment",
    4: "Cross-Validation",
    5: "Final Consolidation",
}

IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')

SUSPICIOUS_APIS = [
    "Ljava/net/URL;->openConnection",
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Ljava/lang/Runtime;->exec",
    "Ldalvik/system/DexClassLoader;-><init>",
    "Ljava/lang/reflect/Method;->invoke",
    "Ljavax/crypto/Cipher;->getInstance",
]

SUSPICIOUS_PATTERNS = [
    ("reflection", ["invoke", "forName", "getMethod"]),
    ("dynamic_loading", ["DexClassLoader", "PathClassLoader"]),
    ("encryption", ["Cipher", "SecretKeySpec", "IvParameterSpec"]),
    ("network", ["HttpURLConnection", "URL", "Socket"]),
    ("execution", ["Runtime.exec", "ProcessBuilder"]),
]

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.PROCESS_OUTGOING_CALLS",
}


class ForensicPipelineError(Exception):
    """Raised when the forensic pipeline encounters an unrecoverable error."""
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(stage: int, msg: str):
    """Print a timestamped log message."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    name = STAGE_NAMES.get(stage, f"Stage {stage}")
    print(f"[{ts}] [Stage {stage}: {name}] {msg}")


def _extract_ips_from_text(text: str, source: str, source_file: str = "") -> List[Dict]:
    """Extract IP addresses from text with context."""
    results = []
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="ignore")
    for match in IP_PATTERN.finditer(text):
        ip = match.group()
        # Skip common non-C2 IPs
        if ip.startswith("127.") or ip.startswith("0.") or ip == "255.255.255.255":
            continue
        start = max(0, match.start() - 50)
        end = min(len(text), match.end() + 50)
        results.append({
            "ip": ip,
            "found_in": source,
            "context": text[start:end].strip()[:200],
            "source_file": source_file,
        })
    return results


# ===================================================================
# STAGE 0: Pre-Flight & Metadata Extraction
# ===================================================================

def stage_0_preflight_and_metadata(apk_path: str, work_dir: str, llm: LLMVerifier) -> Dict[str, Any]:
    """Stage 0: Check tool availability, extract APK metadata, entropy, manifest."""
    _log(0, "Starting pre-flight checks...")
    stage_start = time.time()

    # 0.0 — Pre-Flight Availability
    preflight = {
        "ollama_available": llm.is_ready(),
        "circl_available": bool(os.getenv("CIRCL_USERNAME") and os.getenv("CIRCL_PASSWORD")),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _log(0, f"Ollama={preflight['ollama_available']}, CIRCL={preflight['circl_available']}")

    # 0.1 — 7-Zip Structure Analysis
    seven_zip = _run_7zip_analysis(apk_path)

    # 0.1b — ZIP Header Tamper Detection
    # Tampered central directories (fake encryption flags / bogus compression
    # methods) break aapt/androguard downstream; must be flagged before 0.3.
    zip_tamper = _detect_zip_tampering(apk_path)
    if zip_tamper.get("tampered"):
        _log(0, f"ZIP TAMPERING detected: {zip_tamper['summary']}")

    # 0.2 — Entropy Check
    entropy = _calculate_entropy(apk_path)
    _log(0, f"Entropy: {entropy['entropy']:.4f} ({entropy['status']})")

    # 0.3 — AndroGuard Full Parse
    manifest = _androguard_parse(apk_path)
    _log(0, f"Package: {manifest.get('package_name', 'unknown')}, "
            f"Permissions: {len(manifest.get('permissions', []))}, "
            f"Dangerous: {len(manifest.get('dangerous_permissions', []))}")

    # 0.4 — IP Extraction from Manifest Strings
    manifest_ips = _extract_ips_from_manifest(apk_path)
    _log(0, f"IPs from manifest/strings: {len(manifest_ips)}")

    # 0.5 — LLM Cross-Verification
    llm_result = llm.verify_threat(
        stage="metadata",
        context="Initial APK metadata assessment",
        prompt=(
            f"APK: {manifest.get('package_name', 'unknown')}\n"
            f"Permissions: {', '.join(manifest.get('dangerous_permissions', [])[:10])}\n"
            f"Exported components: "
            f"{len(manifest.get('exported_activities', [])) + len(manifest.get('exported_services', []))} total\n"
            f"Native libraries: {len(manifest.get('native_libs', []))}\n"
            f"Entropy: {entropy['entropy']:.4f} ({entropy['status']})\n"
            f"ZIP tampering: {zip_tamper.get('summary', 'none detected')}\n"
            f"Certificate issuer: {manifest.get('certificate_issuer', 'unknown')}\n\n"
            f"Is this APK suspicious based on metadata alone?"
        ),
        verbose=True,
    )

    duration = round(time.time() - stage_start, 3)
    _log(0, f"Completed in {duration}s")

    return {
        "stage_0_preflight": preflight,
        "stage_0_metadata": {
            "file_hash_sha256": manifest.get("sha256", ""),
            "file_size_bytes": os.path.getsize(apk_path),
            "entropy": entropy["entropy"],
            "entropy_status": entropy["status"],
            "apk_structure": seven_zip,
            "zip_tampering": zip_tamper,
            "manifest_summary": manifest,
            "extracted_ips": manifest_ips,
            "llm_verification": llm_result,
            "duration_seconds": duration,
        },
    }


def _detect_zip_tampering(apk_path: str) -> Dict[str, Any]:
    """Detect ZIP central-directory tampering in an APK.

    Fraud-kit droppers corrupt entry headers (bogus compression methods,
    fake PKZIP encryption flags, wrong sizes) so aapt/unzip/androguard fail.
    Parses the central directory directly to flag such entries.
    """
    try:
        data = open(apk_path, "rb").read()
    except OSError as e:
        return {"tampered": False, "error": f"unreadable: {e}"}

    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        return {"tampered": False, "summary": "not a zip archive"}

    entry_count = struct.unpack_from("<H", data, eocd + 10)[0]
    bogus_methods: List[Dict[str, Any]] = []
    encrypted_entries: List[str] = []
    manifest_status = "absent"

    offset = struct.unpack_from("<I", data, eocd + 16)[0]
    for _ in range(entry_count):
        if data[offset:offset + 4] != b"PK\x01\x02":
            break
        method = struct.unpack_from("<H", data, offset + 10)[0]
        gp_flag = struct.unpack_from("<H", data, offset + 8)[0]
        name_len = struct.unpack_from("<H", data, offset + 28)[0]
        extra_len = struct.unpack_from("<H", data, offset + 30)[0]
        comment_len = struct.unpack_from("<H", data, offset + 32)[0]
        name = data[offset + 46:offset + 46 + name_len].decode("utf-8", "ignore")
        offset += 46 + name_len + extra_len + comment_len

        lowered = name.lower()
        if lowered == "androidmanifest.xml":
            manifest_status = ("encrypted" if gp_flag & 1 else
                               "bogus_method" if method not in (0, 8) else
                               "readable")
        if method not in (0, 8):
            bogus_methods.append({"name": name[:80], "method": hex(method)})
        if gp_flag & 1:
            encrypted_entries.append(name[:80])

    tampered = bool(bogus_methods or encrypted_entries)
    parts = []
    if bogus_methods:
        parts.append(f"{len(bogus_methods)} bogus-method entries")
    if encrypted_entries:
        parts.append(f"{len(encrypted_entries)} fake-encrypted entries")
    summary = "; ".join(parts) if tampered else "none detected"

    return {
        "tampered": tampered,
        "summary": summary,
        "manifest_status": manifest_status,
        "bogus_method_entries": bogus_methods[:10],
        "encrypted_flag_entries": encrypted_entries[:10],
    }


def _run_7zip_analysis(apk_path: str) -> Dict[str, Any]:
    """Analyze APK structure using 7-Zip."""
    seven_zip_path = settings.SEVEN_ZIP_PATH
    if not Path(seven_zip_path).exists():
        return {"error": f"7-Zip not found at {seven_zip_path}"}
    try:
        result = subprocess.run(
            [seven_zip_path, "l", apk_path],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout
        dex_count = output.lower().count(".dex")
        so_count = output.lower().count(".so")
        total_files = len([l for l in output.splitlines() if re.match(r'^\d{4}-\d{2}-\d{2}', l.strip())])
        return {
            "total_files": total_files,
            "dex_count": dex_count,
            "native_lib_count": so_count,
            "raw_output_lines": len(output.splitlines()),
        }
    except Exception as e:
        return {"error": str(e)}


def _calculate_entropy(apk_path: str) -> Dict[str, Any]:
    """Calculate Shannon entropy of the APK file."""
    try:
        data = open(apk_path, "rb").read()
        n = len(data)
        if n == 0:
            return {"entropy": 0.0, "status": "empty"}

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        entropy = -sum(
            (count / n) * math.log2(count / n)
            for count in freq if count > 0
        )

        if entropy > 7.5:
            status = "high_entropy_packed"
        elif entropy > 6.5:
            status = "moderate_suspicious"
        else:
            status = "normal"

        return {"entropy": round(entropy, 4), "status": status}
    except Exception as e:
        return {"entropy": 0.0, "status": f"error: {e}"}


def _androguard_parse(apk_path: str) -> Dict[str, Any]:
    """Full AndroGuard APK metadata extraction."""
    try:
        from androguard.core.apk import APK
        apk = APK(apk_path)

        sha256 = hashlib.sha256(open(apk_path, "rb").read()).hexdigest()
        permissions = apk.get_permissions()
        dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]

        # Certificate info
        cert_issuer = "unknown"
        try:
            certs = apk.get_certificates()
            if certs:
                # Extract issuer string cleanly; androguard's issuer object may have
                # unicode/garbled representation depending on certificate encoding.
                issuer_obj = certs[0].issuer
                if hasattr(issuer_obj, 'pretty_print'):
                    cert_issuer = issuer_obj.pretty_print()[1]
                else:
                    cert_issuer = str(issuer_obj)[:200]
        except Exception:
            pass

        return {
            "package_name": apk.get_package(),
            "version_code": apk.get_androidversion_code(),
            "version_name": apk.get_androidversion_name(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": permissions,
            "dangerous_permissions": dangerous,
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
            "providers": apk.get_providers(),
            "exported_activities": [a for a in apk.get_activities()
                                     if _is_exported(a, apk)],
            "exported_services": [s for s in apk.get_services()
                                   if _is_exported(s, apk)],
            "native_libs": [f for f in apk.get_files() if f.endswith(".so")],
            "certificate_issuer": cert_issuer,
            "sha256": sha256,
        }
    except ImportError:
        return {"error": "androguard not installed", "package_name": "unknown", "permissions": [], "dangerous_permissions": [], "native_libs": [], "sha256": hashlib.sha256(open(apk_path, "rb").read()).hexdigest()}
    except Exception as e:
        return {"error": str(e), "package_name": "unknown", "permissions": [], "dangerous_permissions": [], "native_libs": [], "sha256": hashlib.sha256(open(apk_path, "rb").read()).hexdigest()}


def _is_exported(component_name: str, apk) -> bool:
    """Check if an Android component is exported."""
    try:
        # Simple heuristic: components with intent filters are exported by default
        xml = apk.get_android_manifest_xml()
        if xml is not None:
            for elem in xml.iter():
                if elem.get("{http://schemas.android.com/apk/res/android}name") == component_name:
                    exported = elem.get("{http://schemas.android.com/apk/res/android}exported")
                    if exported == "true":
                        return True
                    if exported is None and len(list(elem.iter("intent-filter"))) > 0:
                        return True
        return False
    except Exception:
        return False


def _extract_ips_from_manifest(apk_path: str) -> List[Dict]:
    """Extract IPs from APK string resources."""
    ips = []
    try:
        from androguard.core.apk import APK
        apk = APK(apk_path)
        for s in apk.get_files():
            pass  # Just checking it loads
        # Extract from all resources and manifest strings
        try:
            manifest_xml = apk.get_android_manifest_axml().get_xml()
            if isinstance(manifest_xml, bytes):
                manifest_xml = manifest_xml.decode("utf-8", errors="ignore")
            ips.extend(_extract_ips_from_text(manifest_xml, "manifest/xml", "AndroidManifest.xml"))
        except Exception:
            pass
    except Exception:
        pass
    return ips


# ===================================================================
# STAGE 1: Threat Indicator Analysis
# ===================================================================

def stage_1_threat_indicators(apk_path: str, work_dir: str, stage0: Dict, llm: LLMVerifier) -> Dict[str, Any]:
    """Stage 1: Packer detection, YARA matching, suspicious API analysis."""
    _log(1, "Starting threat indicator analysis...")
    stage_start = time.time()

    # 1.1 — Detect It Easy (Packer/Compiler Detection)
    die_result = _run_die(apk_path)
    _log(1, f"DIE: {die_result.get('detections', 'N/A')}")

    # 1.2 — YARA Rule Matching
    yara_matches = _run_yara(apk_path)
    _log(1, f"YARA matches: {len(yara_matches)}")

    # 1.3 — AndroGuard Deep Static Analysis
    dex_stats, api_risk_map, anti_analysis, dex_ips = _androguard_deep_analysis(apk_path)
    _log(1, f"DEX classes={dex_stats.get('classes', 0)}, "
            f"Suspicious APIs={len(api_risk_map)}, "
            f"Anti-analysis={sum(anti_analysis.values())}")

    # 1.4 — Risk Score
    manifest = stage0.get("stage_0_metadata", {}).get("manifest_summary", {})
    risk_score = _calculate_risk_score(
        api_risk_map, yara_matches, anti_analysis,
        stage0.get("stage_0_metadata", {}).get("entropy", 0),
        manifest.get("dangerous_permissions", []),
    )
    _log(1, f"Risk score: {risk_score}/10")

    # 1.5 — LLM Cross-Verification
    top_apis = ", ".join([a["api"][:30] for a in api_risk_map[:3]]) if api_risk_map else "none"
    llm_result = llm.verify_threat(
        stage="threat_indicators",
        context="Static analysis threat assessment",
        prompt=(
            f"YARA matches: {len(yara_matches)}\n"
            f"Top match: {yara_matches[0].get('rule', 'none') if yara_matches else 'none'}\n"
            f"Suspicious APIs: {len(api_risk_map)} (e.g., {top_apis})\n"
            f"Anti-analysis indicators: {sum(anti_analysis.values())} detected\n"
            f"Multidex: {dex_stats.get('multidex', False)}\n"
            f"Risk score: {risk_score}/10\n\n"
            f"Based on these indicators, is this APK malicious?"
        ),
        verbose=True,
    )

    duration = round(time.time() - stage_start, 3)
    _log(1, f"Completed in {duration}s")

    return {
        "stage_1_threat_indicators": {
            "packer_analysis": die_result,
            "yara_matches": yara_matches,
            "dex_statistics": dex_stats,
            "api_risk_map": api_risk_map,
            "anti_analysis_indicators": anti_analysis,
            "risk_score": risk_score,
            "extracted_ips": dex_ips,
            "llm_verification": llm_result,
            "duration_seconds": duration,
        }
    }


def _run_die(apk_path: str) -> Dict[str, Any]:
    """Run Detect It Easy for packer/compiler detection."""
    die_path = settings.DIE_PATH
    if not Path(die_path).exists():
        return {"error": f"DIE not found at {die_path}", "detections": []}
    try:
        result = subprocess.run(
            [die_path, "-j", apk_path],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                parsed = json.loads(result.stdout)
                detections = []
                if isinstance(parsed, dict) and "detects" in parsed:
                    for d in parsed["detects"]:
                        if isinstance(d, dict) and "values" in d:
                            for v in d["values"]:
                                detections.append({
                                    "type": v.get("type", ""),
                                    "name": v.get("name", ""),
                                    "version": v.get("version", ""),
                                    "info": v.get("info", ""),
                                })
                return {"detections": detections, "raw": parsed}
            except json.JSONDecodeError:
                return {"detections": [], "raw_output": result.stdout[:500]}
        return {"detections": [], "raw_output": result.stdout[:500]}
    except Exception as e:
        return {"error": str(e), "detections": []}


def _run_yara(apk_path: str) -> List[Dict]:
    """Run YARA rules against the APK."""
    yara_path = settings.YARA_RULES_PATH
    if not Path(yara_path).exists():
        return []

    # 1. Attempt python yara library import
    try:
        import yara
        has_yara_library = True
    except ImportError:
        has_yara_library = False

    # 2. If library is not installed, fall back to yara64.exe CLI
    if not has_yara_library:
        try:
            result = subprocess.run(
                ["yara64.exe", "-r", "-g", yara_path, apk_path],
                capture_output=True, text=True, timeout=120,
            )
            matches = []
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    rule = parts[0]
                    if rule not in {m["rule"] for m in matches}:
                        matches.append({"rule": rule, "tags": [], "meta": {}})
            return matches
        except Exception as e:
            _log(1, f"YARA CLI fallback execution failed: {e}")
            return []

    # 3. Use python library for compilation and matching
    try:
        rules = yara.compile(filepath=yara_path)
        matches = rules.match(apk_path)
        results = []
        seen = set()
        for m in matches:
            if m.rule not in seen:
                seen.add(m.rule)
                results.append({
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags) if m.tags else [],
                    "meta": dict(m.meta) if m.meta else {},
                })
        return results
    except Exception as e:
        _log(1, f"YARA python compilation or matching failed: {e}")
        return []


def _androguard_deep_analysis(apk_path: str):
    """AndroGuard deep DEX analysis: stats, suspicious APIs, anti-analysis."""
    dex_stats = {"classes": 0, "methods": 0, "strings": 0, "multidex": False}
    api_risk_map = []
    anti_analysis = {
        "emulator_detection": False,
        "root_detection": False,
        "debugger_detection": False,
        "native_obfuscation": False,
    }
    dex_ips = []

    try:
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(apk_path)

        dex_stats = {
            "classes": sum(len(dex.get_classes()) for dex in d),
            "methods": sum(len(dex.get_methods()) for dex in d),
            "strings": sum(len(dex.get_strings()) for dex in d),
            "multidex": len(d) > 1,
        }

        # Suspicious API detection
        for api in SUSPICIOUS_APIS:
            methods = list(dx.find_methods(api))
            if methods:
                api_risk_map.append({
                    "api": api,
                    "invocation_count": len(methods),
                    "callers": [str(m.full_name)[:100] for m in methods[:10]],
                })

        # Anti-analysis detection
        all_strings = []
        for dex in d:
            all_strings.extend([str(s) for s in dex.get_strings()])
        all_strings_lower = " ".join(all_strings).lower()

        anti_analysis["emulator_detection"] = any(
            k in all_strings_lower for k in ["emulator", "qemu", "genymotion", "goldfish"]
        )
        anti_analysis["root_detection"] = any(
            k in all_strings_lower for k in ["su", "superuser", "magisk", "/system/xbin/su"]
        )
        anti_analysis["debugger_detection"] = any(
            k in all_strings_lower for k in ["frida", "xposed", "substrate"]
        )

        # Check native libs from stage 0
        try:
            native_libs = [f for f in a.get_files() if f.endswith(".so")]
            anti_analysis["native_obfuscation"] = len(native_libs) > 0
        except Exception:
            pass

        # IP extraction from DEX
        for dex_idx, dex in enumerate(d):
            for string in dex.get_strings():
                s = str(string)
                ips = _extract_ips_from_text(s, f"dex_{dex_idx}/strings", f"classes{dex_idx}.dex")
                dex_ips.extend(ips)

    except ImportError:
        _log(1, "[WARN] androguard not available for deep analysis")
    except Exception as e:
        _log(1, f"[WARN] AndroGuard deep analysis error: {e}")

    return dex_stats, api_risk_map, anti_analysis, dex_ips


def _calculate_risk_score(api_risk_map, yara_matches, anti_analysis, entropy, permissions) -> int:
    """Calculate initial risk score (1-10 scale)."""
    score = 0
    if len(api_risk_map) > 5:
        score += 3
    elif len(api_risk_map) > 0:
        score += 2
    if len(yara_matches) > 3:
        score += 3
    elif len(yara_matches) > 0:
        score += 2
    if sum(anti_analysis.values()) > 2:
        score += 2
    elif any(anti_analysis.values()):
        score += 1
    if entropy > 7.5:
        score += 1
    if len(permissions) > 5:
        score += 1
    return min(score, 10)


# ===================================================================
# STAGE 2: Code Review (Androguard DEX Analysis)
# ===================================================================

def stage_2_code_review(apk_path: str, work_dir: str, llm: LLMVerifier) -> Dict[str, Any]:
    """Stage 2: Analyze DEX bytecode with Androguard, scan for suspicious patterns and IPs."""
    _log(2, "Starting Androguard DEX code review...")
    stage_start = time.time()

    dex_stats, api_risk_map, anti_analysis, dex_ips = _androguard_deep_analysis(apk_path)
    decompilation_status = "success" if dex_stats.get("classes", 0) > 0 else "failed"
    _log(2, f"DEX analysis: {decompilation_status} ({dex_stats.get('classes', 0)} classes)")
    _log(2, f"IPs from DEX: {len(dex_ips)}")

    # 2.3 — Suspicious Class Detection
    suspicious_classes = _identify_suspicious_classes_from_dex(apk_path)
    _log(2, f"Suspicious classes: {len(suspicious_classes)}")

    # 2.4 — Hardcoded Secrets Detection from DEX Strings
    hardcoded_secrets = []
    secret_risk = {"severity": "none", "total_secrets": 0, "risk_score": 0}
    try:
        dex_strings = _collect_dex_strings(apk_path)
        strings_result = {
            "sample_id": "",
            "categories": {
                "string_literals": [{
                    "category": "string_literal",
                    "value": s,
                    "entropy": 0.0,
                    "source": "dex_strings",
                } for s in dex_strings]
            },
            "string_literals": dex_strings,
        }
        secrets_result = analyze_hardcoded_secrets(strings_result)
        hardcoded_secrets = secrets_result["hardcoded_secrets"]
        secret_risk = secrets_result["secret_risk"]
        _log(2, f"Hardcoded secrets: {secret_risk['total_secrets']} ({secret_risk['severity']})")
    except Exception as e:
        _log(2, f"[WARN] Secrets scan failed: {e}")

    # 2.5 — LLM Cross-Verification
    high_severity = [c for c in suspicious_classes if c.get("severity") == "high"]
    code_snippets = [f"- Class: {cls['class']}, Pattern: {cls['pattern']}"
                     for cls in high_severity[:5]]

    secrets_summary = ""
    if hardcoded_secrets:
        critical_high = [s for s in hardcoded_secrets if s.get("severity") in ("critical", "high")]
        if critical_high:
            secrets_summary = (
                f"\nHardcoded secrets: {len(hardcoded_secrets)} total, "
                f"{len(critical_high)} critical/high. "
                f"Types: {', '.join(set(s['secret_type'] for s in critical_high[:5]))}."
            )

    llm_result = llm.verify_threat(
        stage="code_review",
        context="DEX bytecode pattern analysis",
        prompt=(
            f"Suspicious classes identified:\n"
            f"{chr(10).join(code_snippets) if code_snippets else 'None'}\n\n"
            f"DEX analysis status: {decompilation_status}\n"
            f"High-severity patterns: {len(high_severity)}"
            f"{secrets_summary}\n\n"
            f"Are these patterns indicative of malware behavior?"
        ),
        verbose=True,
    )

    duration = round(time.time() - stage_start, 3)
    _log(2, f"Completed in {duration}s")

    return {
        "stage_2_jadx_analysis": {
            "decompilation_status": decompilation_status,
            "suspicious_classes": suspicious_classes,
            "extracted_ips": dex_ips,
            "hardcoded_secrets": hardcoded_secrets,
            "secret_risk": secret_risk,
            "llm_verification": llm_result,
            "duration_seconds": duration,
        }
    }


def _collect_dex_strings(apk_path: str) -> List[str]:
    """Collect all DEX string literals via Androguard."""
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX

        apk = APK(apk_path)
        strings = []
        for dex_data in apk.get_all_dex():
            try:
                dex = DEX(dex_data)
                strings.extend([str(s) for s in dex.get_strings()])
            except Exception:
                continue
        return strings
    except Exception:
        return []


def _identify_suspicious_classes_from_dex(apk_path: str) -> List[Dict]:
    """Find classes whose names or methods match suspicious code patterns."""
    suspicious = []
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX

        apk = APK(apk_path)
        for dex_data in apk.get_all_dex():
            try:
                dex = DEX(dex_data)
                for cls in dex.get_classes():
                    class_name = cls.get_name()
                    if class_name.startswith("L") and class_name.endswith(";"):
                        class_name = class_name[1:-1].replace("/", ".")
                    method_names = " ".join(m.get_name() for m in cls.get_methods())
                    haystack = f"{class_name} {method_names}"

                    for pattern_name, keywords in SUSPICIOUS_PATTERNS:
                        found_kw = [kw for kw in keywords if kw in haystack]
                        if found_kw:
                            suspicious.append({
                                "class": class_name,
                                "pattern": pattern_name,
                                "keywords_found": found_kw,
                                "severity": "high" if pattern_name in ("execution", "dynamic_loading") else "medium",
                            })
            except Exception:
                continue
    except Exception:
        _log(2, "[WARN] Androguard class pattern scan failed")
    return suspicious


# ===================================================================
# STAGE 3: DNS Enrichment
# ===================================================================

def stage_3_dns_enrichment(
    stage0: Dict, stage1: Dict, stage2: Dict, llm: LLMVerifier
) -> Dict[str, Any]:
    """Stage 3: Consolidate IPs from all stages, query CIRCL pDNS + live DNS."""
    _log(3, "Starting DNS enrichment...")
    stage_start = time.time()

    # 3.1 — Consolidate All Unique IPs
    all_ips = {}
    sources = [
        stage0.get("stage_0_metadata", {}).get("extracted_ips", []),
        stage1.get("stage_1_threat_indicators", {}).get("extracted_ips", []),
        stage2.get("stage_2_jadx_analysis", {}).get("extracted_ips", []),
    ]
    for ip_list in sources:
        for entry in ip_list:
            ip = entry["ip"]
            if ip not in all_ips:
                all_ips[ip] = {
                    "ip": ip,
                    "discovered_in": [],
                    "contexts": [],
                    "source_files": [],
                }
            all_ips[ip]["discovered_in"].append(entry.get("found_in", ""))
            all_ips[ip]["contexts"].append(entry.get("context", ""))
            all_ips[ip]["source_files"].append(entry.get("source_file", ""))

    # Deduplicate
    for ip in all_ips:
        all_ips[ip]["discovered_in"] = list(set(all_ips[ip]["discovered_in"]))
        all_ips[ip]["contexts"] = list(set(all_ips[ip]["contexts"]))[:5]
        all_ips[ip]["source_files"] = list(set(all_ips[ip]["source_files"]))[:5]

    _log(3, f"Total unique IPs: {len(all_ips)}")

    # 3.2 + 3.3 + 3.4 — Enrich each IP
    dns_results = []
    for ip in all_ips:
        _log(3, f"Enriching {ip}...")
        circl_result = _circl_pdns_query(ip)
        live_result = _live_dns_enrichment(ip)

        # Threat scoring
        threat_level = "unknown"
        if circl_result.get("record_count", 0) > 10:
            threat_level = "suspicious"
        if live_result.get("responsive") and len(live_result.get("open_ports", [])) > 0:
            threat_level = "suspicious"
        if any("malware" in str(r).lower() for r in circl_result.get("records", [])):
            threat_level = "malicious"

        dns_results.append({
            "ip": ip,
            "circl_pdns": circl_result,
            "live_dns": live_result,
            "discovered_in": all_ips[ip]["discovered_in"],
            "threat_level": threat_level,
            "provenance": {
                "contexts": all_ips[ip]["contexts"],
                "source_files": all_ips[ip]["source_files"],
            },
        })

    # 3.5 — LLM Cross-Verification
    suspicious_ips = [d for d in dns_results if d["threat_level"] in ("suspicious", "malicious")]

    llm_result = llm.verify_threat(
        stage="dns_enrichment",
        context="C2 infrastructure assessment via DNS enrichment",
        prompt=(
            f"Total IPs found: {len(dns_results)}\n"
            f"Suspicious IPs: {len(suspicious_ips)}\n"
            f"IPs with CIRCL records: {sum(1 for d in dns_results if d['circl_pdns'].get('record_count', 0) > 0)}\n"
            f"Responsive IPs: {sum(1 for d in dns_results if d['live_dns'].get('responsive'))}\n\n"
            f"Top suspicious IP: {suspicious_ips[0]['ip'] if suspicious_ips else 'none'}\n"
            f"Is this C2 infrastructure?"
        ),
        verbose=True,
    )

    duration = round(time.time() - stage_start, 3)
    _log(3, f"Completed in {duration}s")

    return {
        "stage_3_dns_enrichment": {
            "total_unique_ips": len(all_ips),
            "ips_with_circl_records": sum(1 for d in dns_results if d["circl_pdns"].get("record_count", 0) > 0),
            "responsive_ips": sum(1 for d in dns_results if d["live_dns"].get("responsive")),
            "ip_enrichment": dns_results,
            "llm_verification": llm_result,
            "duration_seconds": duration,
        }
    }


def _circl_pdns_query(query: str) -> Dict[str, Any]:
    """Query CIRCL pDNS for historical DNS records."""
    try:
        from backend.circl_client import CIRCLClient, CIRCLAuthError
        client = CIRCLClient()
        records = client.query_pdns(query)
        return {
            "query": query,
            "record_count": len(records) if records else 0,
            "records": records[:50] if records else [],
            "source": "CIRCL pDNS",
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {
            "query": query,
            "record_count": 0,
            "records": [],
            "error": str(e),
        }


def _live_dns_enrichment(ip: str) -> Dict[str, Any]:
    """Perform live DNS resolution and basic port scanning."""
    result = {
        "ip": ip,
        "reverse_dns": None,
        "responsive": False,
        "open_ports": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        result["reverse_dns"] = hostname
    except Exception:
        pass

    # Port scanning (common C2 ports)
    for port in [80, 443, 8080, 8443]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            if sock.connect_ex((ip, port)) == 0:
                result["open_ports"].append(port)
                result["responsive"] = True
            sock.close()
        except Exception:
            pass

    return result


# ===================================================================
# STAGE 4: Cross-Validation (Stage 2 ↔ AndroGuard DEX)
# ===================================================================

def stage_4_cross_validation(
    apk_path: str, stage1: Dict, stage2: Dict, llm: LLMVerifier
) -> Dict[str, Any]:
    """Stage 4: Validate stage 2 findings against AndroGuard DEX analysis."""
    _log(4, "Starting cross-validation...")
    stage_start = time.time()

    suspicious_classes = stage2.get("stage_2_jadx_analysis", {}).get("suspicious_classes", [])
    flagged_classes = list(set(c["class"] for c in suspicious_classes))

    validation_results = []
    try:
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(apk_path)

        for class_name in flagged_classes[:20]:  # Cap at 20 classes
            # Convert to smali-style class name
            call_class = "L" + class_name.lstrip(".").replace(".", "/") + ";"

            try:
                class_analysis = dx.get_class_analysis(call_class)
                if class_analysis:
                    methods = []
                    callers = []
                    for m in class_analysis.get_methods():
                        methods.append(str(m.name))
                        for c in m.get_xref_from():
                            callers.append(str(c[1].full_name)[:100])

                    validation_results.append({
                        "class": class_name,
                        "found_in_dex": True,
                        "method_count": len(methods),
                        "caller_count": len(callers),
                        "callers": callers[:10],
                        "status": "confirmed",
                    })
                else:
                    validation_results.append({
                        "class": class_name,
                        "found_in_dex": False,
                        "status": "discrepancy",
                        "note": "Class flagged in stage 2 but not found in AndroGuard DEX analysis",
                    })
            except Exception as e:
                validation_results.append({
                    "class": class_name,
                    "found_in_dex": False,
                    "status": "error",
                    "note": str(e)[:200],
                })

    except ImportError:
        _log(4, "[WARN] androguard not available for cross-validation")
    except Exception as e:
        _log(4, f"[WARN] Cross-validation error: {e}")

    confirmed = sum(1 for v in validation_results if v["status"] == "confirmed")
    discrepancies = sum(1 for v in validation_results if v["status"] == "discrepancy")
    _log(4, f"Validated: {confirmed} confirmed, {discrepancies} discrepancies")

    # LLM Cross-Verification
    llm_result = llm.verify_threat(
        stage="cross_validation",
        context="Stage 2 vs AndroGuard cross-validation",
        prompt=(
            f"Classes validated: {len(validation_results)}\n"
            f"Confirmed in DEX: {confirmed}\n"
            f"Discrepancies: {discrepancies}\n"
            f"Top confirmed class: {validation_results[0]['class'] if validation_results else 'none'}\n\n"
            f"Does the cross-validation support or refute the malware hypothesis?"
        ),
        verbose=True,
    )

    duration = round(time.time() - stage_start, 3)
    _log(4, f"Completed in {duration}s")

    return {
        "stage_4_cross_validation": {
            "total_classes_validated": len(validation_results),
            "confirmed": confirmed,
            "discrepancies": discrepancies,
            "validation_results": validation_results,
            "llm_verification": llm_result,
            "duration_seconds": duration,
        }
    }


# ===================================================================
# STAGE 5: Final Consolidation & Report
# ===================================================================

def stage_5_consolidation(
    apk_path: str, work_dir: str,
    stage0: Dict, stage1: Dict, stage2: Dict, stage3: Dict, stage4: Dict,
    llm: LLMVerifier,
) -> Dict[str, Any]:
    """Stage 5: Synthesize all findings, LLM final assessment, generate PDF."""
    _log(5, "Starting final consolidation...")
    stage_start = time.time()

    # Aggregate all LLM verdicts
    verdicts = []
    for stage_data in [stage0, stage1, stage2, stage3, stage4]:
        for key, val in stage_data.items():
            if isinstance(val, dict):
                llm_v = val.get("llm_verification", {})
                if llm_v.get("is_malicious") is not None:
                    verdicts.append(llm_v)

    # Majority vote
    malicious_count = sum(1 for v in verdicts if v.get("is_malicious") is True)
    benign_count = sum(1 for v in verdicts if v.get("is_malicious") is False)
    total_votes = malicious_count + benign_count

    if total_votes == 0:
        final_classification = "inconclusive"
    elif malicious_count > benign_count:
        final_classification = "malicious"
    elif benign_count > malicious_count:
        final_classification = "benign"
    else:
        final_classification = "suspicious"

    # Risk score aggregation
    risk_score = stage1.get("stage_1_threat_indicators", {}).get("risk_score", 0)

    # Collect all MITRE tactics
    all_tactics = set()
    for v in verdicts:
        for t in v.get("mitre_tactics", []):
            all_tactics.add(t)

    # Secret risk summary
    secret_risk = stage2.get("stage_2_jadx_analysis", {}).get("secret_risk", {})
    secret_summary = ""
    if secret_risk.get("total_secrets", 0):
        secret_summary = (
            f"Hardcoded secrets: {secret_risk['total_secrets']} found "
            f"({secret_risk['severity']}) — risk score {secret_risk['risk_score']}/100\n"
        )

    # Final LLM consolidation
    llm_result = llm.verify_threat(
        stage="final_consolidation",
        context="Final synthesis of all forensic findings",
        prompt=(
            f"Stage verdicts: {malicious_count} malicious, {benign_count} benign\n"
            f"Risk score: {risk_score}/10\n"
            f"YARA matches: {len(stage1.get('stage_1_threat_indicators', {}).get('yara_matches', []))}\n"
            f"Suspicious classes: {len(stage2.get('stage_2_jadx_analysis', {}).get('suspicious_classes', []))}\n"
            f"Suspicious IPs: {len([d for d in stage3.get('stage_3_dns_enrichment', {}).get('ip_enrichment', []) if d.get('threat_level') in ('suspicious', 'malicious')])}\n"
            f"Cross-validation confirmed: {stage4.get('stage_4_cross_validation', {}).get('confirmed', 0)}\n"
            f"{secret_summary}"
            f"MITRE tactics: {', '.join(all_tactics) if all_tactics else 'none'}\n\n"
            f"Provide the final threat assessment."
        ),
        verbose=True,
    )

    # Build full report
    manifest = stage0.get("stage_0_metadata", {}).get("manifest_summary", {})
    report = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "pipeline_version": "6-stage-forensic-v1.0",
            "apk_path": apk_path,
            "package_name": manifest.get("package_name", "unknown"),
            "sha256": manifest.get("sha256", ""),
        },
        "final_assessment": {
            "classification": final_classification,
            "risk_score": risk_score,
            "mitre_tactics": sorted(all_tactics),
            "stage_verdicts": {
                "malicious_votes": malicious_count,
                "benign_votes": benign_count,
                "total_stages_voted": total_votes,
            },
            "secret_risk": secret_risk,
            "llm_consolidation": llm_result,
        },
        **stage0,
        **stage1,
        **stage2,
        **stage3,
        **stage4,
    }

    # Save JSON report
    report_dir = Path(work_dir) / "forensic_report"
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = report_dir / "forensic_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    _log(5, f"JSON report: {json_path}")

    # Generate PDF report
    pdf_path = _generate_pdf_report(report, report_dir)
    if pdf_path:
        _log(5, f"PDF report: {pdf_path}")

    duration = round(time.time() - stage_start, 3)
    _log(5, f"Completed in {duration}s")

    report["report_metadata"]["json_path"] = str(json_path)
    report["report_metadata"]["pdf_path"] = str(pdf_path) if pdf_path else None
    report["report_metadata"]["total_duration_seconds"] = duration

    return report


def _generate_pdf_report(report: Dict, output_dir: Path) -> Optional[str]:
    """Generate PDF report using the existing ReportLab infrastructure."""
    try:
        from backend.pdf_report import generate_report

        # Transform forensic report into the format expected by generate_report
        secret_risk = report.get("final_assessment", {}).get("secret_risk", {})
        stage2_secrets = report.get("stage_2_jadx_analysis", {}).get("hardcoded_secrets", [])
        secrets_report = ""
        if stage2_secrets:
            secrets_report = format_for_report(stage2_secrets)
        result_compat = {
            "sample_id": report.get("report_metadata", {}).get("package_name", "forensic"),
            "metadata": {
                "sample_name": report.get("report_metadata", {}).get("package_name", "unknown"),
                "file_size_bytes": report.get("stage_0_metadata", {}).get("file_size_bytes", 0),
                "sha256": report.get("report_metadata", {}).get("sha256", ""),
                "md5": "",
                "package_name": report.get("report_metadata", {}).get("package_name", ""),
                "package": report.get("report_metadata", {}).get("package_name", ""),
            },
            "manifest": report.get("stage_0_metadata", {}).get("manifest_summary", {}),
            "llm_assessment": {
                "severity": "critical" if report.get("final_assessment", {}).get("risk_score", 0) >= 8
                            else "high" if report.get("final_assessment", {}).get("risk_score", 0) >= 6
                            else "medium" if report.get("final_assessment", {}).get("risk_score", 0) >= 4
                            else "low",
                "risk_score": report.get("final_assessment", {}).get("risk_score", 0) * 10,
                "narrative": report.get("final_assessment", {}).get("llm_consolidation", {}).get("reasoning", ""),
                "recommended_actions": [
                    report.get("final_assessment", {}).get("llm_consolidation", {}).get("recommendation", "Review manually"),
                ],
            },
            "c2_infrastructure": [],
            "threat_chains": [],
            "obfuscation_analysis": {
                "obfuscation_score": 0,
                "obfuscation_level": "unknown",
                "indicators": {},
            },
            "hardcoded_secrets": stage2_secrets,
            "secret_risk": secret_risk,
            "secret_report_text": secrets_report,
        }

        pdf_bytes = generate_report(result_compat)
        pdf_path = output_dir / "forensic_report.pdf"
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
        return str(pdf_path)
    except Exception as e:
        _log(5, f"[WARN] PDF generation failed: {e}")
        return None


# ===================================================================
# PIPELINE ORCHESTRATOR
# ===================================================================

def run_forensic_pipeline(
    apk_path: str,
    work_dir: str = None,
    llm_enabled: bool = True,
) -> Dict[str, Any]:
    """Run the full 6-stage forensic pipeline on an APK.

    Args:
        apk_path: Absolute path to the APK file.
        work_dir: Working directory for outputs. Defaults to settings.WORK_DIR.
        llm_enabled: Whether to enable LLM verification.

    Returns:
        Full forensic report as a dict.
    """
    if not Path(apk_path).exists():
        raise ForensicPipelineError(f"APK not found: {apk_path}")

    if work_dir is None:
        work_dir = str(settings.WORK_DIR)

    # Ensure output directory exists
    Path(work_dir).mkdir(parents=True, exist_ok=True)

    # Initialize LLM verifier
    llm = get_verifier()
    if llm_enabled and not llm.is_ready():
        # Try to start Ollama
        llm.start()

    pipeline_start = time.time()
    print("=" * 70)
    print(f"  DroidForensix 6-Stage Forensic Pipeline")
    print(f"  APK: {apk_path}")
    print(f"  Work Dir: {work_dir}")
    print(f"  LLM: {'enabled' if llm.is_ready() else 'disabled'}")
    print("=" * 70)

    # Stage 0: Pre-Flight & Metadata
    stage0 = stage_0_preflight_and_metadata(apk_path, work_dir, llm)

    # Stage 1: Threat Indicators
    stage1 = stage_1_threat_indicators(apk_path, work_dir, stage0, llm)

    # Stage 2: Code Review
    stage2 = stage_2_code_review(apk_path, work_dir, llm)

    # Stage 3: DNS Enrichment
    stage3 = stage_3_dns_enrichment(stage0, stage1, stage2, llm)

    # Stage 4: Cross-Validation
    stage4 = stage_4_cross_validation(apk_path, stage1, stage2, llm)

    # Stage 5: Final Consolidation
    report = stage_5_consolidation(apk_path, work_dir, stage0, stage1, stage2, stage3, stage4, llm)

    total_duration = round(time.time() - pipeline_start, 3)
    report["report_metadata"]["pipeline_total_duration"] = total_duration

    print("=" * 70)
    print(f"  Pipeline Complete in {total_duration}s")
    print(f"  Classification: {report.get('final_assessment', {}).get('classification', 'unknown')}")
    print(f"  Risk Score: {report.get('final_assessment', {}).get('risk_score', 0)}/10")
    print(f"  JSON: {report.get('report_metadata', {}).get('json_path', 'N/A')}")
    print(f"  PDF:  {report.get('report_metadata', {}).get('pdf_path', 'N/A')}")
    print("=" * 70)

    return report


# ===================================================================
# CLI Entry Point
# ===================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python forensic_pipeline.py <apk_path> [work_dir]")
        print("\nRuns the 6-stage forensic analysis pipeline on the given APK.")
        sys.exit(1)

    apk = sys.argv[1]
    work = sys.argv[2] if len(sys.argv) > 2 else str(settings.WORK_DIR)

    result = run_forensic_pipeline(apk, work)
    print(json.dumps(result.get("final_assessment", {}), indent=2, default=str))
