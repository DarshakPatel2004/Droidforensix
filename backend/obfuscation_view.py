"""
Obfuscation-analysis view builder for the frontend.

Transforms the raw Step 8 result into a dashboard-friendly structure with:
- Parsed indicator locations (smali method -> Java class/method/source lines)
- Detected obfuscation technique breakdown
- DEX entropy / packing summary
- Native-library artifact summary
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config import settings

logger = logging.getLogger(__name__)


# Mapping from indicator key to human-friendly obfuscation technique name.
_TECHNIQUE_NAMES = {
    "reflection": "Reflection",
    "dynamic_loading": "Dynamic Code Loading",
    "native_loading": "Native Library Loading",
    "crypto_apis": "Encryption / Crypto APIs",
    "suspicious_apis": "Sensitive API Abuse",
    "dangerous_permissions": "Dangerous Permissions",
    "encrypted_assets": "Encrypted / Stub-DEX Assets",
}

# Order in which techniques are displayed (most concerning first).
_TECHNIQUE_ORDER = [
    "encrypted_assets",
    "dynamic_loading",
    "native_loading",
    "reflection",
    "crypto_apis",
    "suspicious_apis",
    "dangerous_permissions",
]


def _parse_smali_method(full_name: str) -> Dict[str, Any]:
    """Parse a smali-style method reference into class/method parts."""
    # Format examples:
    #   Lcom/example/Main;->methodName()V
    #   Lcom/example/Main$Inner;->methodName(Ljava/lang/String;)V
    match = re.match(r"^L([^;]+);->([^\(]+)(\(.*\))?(.*)$", full_name)
    if not match:
        return {"raw": full_name, "class": "", "method": full_name, "descriptor": ""}
    smali_class = match.group(1)
    java_class = smali_class.replace("/", ".")
    return {
        "raw": full_name,
        "class": java_class,
        "method": match.group(2),
        "descriptor": (match.group(3) or "") + (match.group(4) or ""),
    }


def _find_source_lines(source: str, method_name: str) -> List[int]:
    """Return 1-based line numbers where a method declaration appears in Java source."""
    if not source:
        return []
    lines = []
    # Match "type methodName(" at start of line or after whitespace.
    pattern = re.compile(rf"(?:^|\s){re.escape(method_name)}\s*\(")
    for idx, line in enumerate(source.splitlines(), start=1):
        if pattern.search(line):
            lines.append(idx)
    return lines[:5]


def _load_obfuscation_result(sample_id: str) -> Optional[Dict[str, Any]]:
    """Load step8_obfuscation.json for a sample if it exists."""
    path = settings.WORK_DIR / sample_id / "step8_obfuscation.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def build_obfuscation_view(sample_id: str, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return a frontend-friendly obfuscation analysis view."""
    obf = result or _load_obfuscation_result(sample_id) or {}
    indicators = obf.get("indicators", {}) or {}
    dex_entropy = obf.get("dex_entropy", []) or []
    native_artifacts = obf.get("native_library_artifacts", []) or []
    notes = obf.get("notes", []) or []
    asset_analysis = obf.get("asset_analysis", {}) or {}

    # Build per-technique breakdown with parsed locations.
    techniques = []
    for key in _TECHNIQUE_ORDER:
        items = indicators.get(key, []) or []
        if not items:
            continue
        parsed_items = []
        for item in items:
            if isinstance(item, str):
                parsed = _parse_smali_method(item)
                parsed_items.append(parsed)
            else:
                # Already a dict (e.g. dangerous_permissions are plain strings).
                parsed_items.append({"raw": str(item), "class": "", "method": str(item), "descriptor": ""})
        techniques.append({
            "key": key,
            "name": _TECHNIQUE_NAMES.get(key, key),
            "count": len(parsed_items),
            "items": parsed_items,
        })

    # Encrypted / stub-DEX asset detection.
    asset_flags = asset_analysis.get("flags", [])
    if asset_flags:
        techniques.append({
            "key": "encrypted_assets",
            "name": _TECHNIQUE_NAMES["encrypted_assets"],
            "count": len(asset_flags),
            "items": [
                {
                    "severity": f.get("severity", "low"),
                    "type": f.get("type", ""),
                    "detail": f.get("detail", ""),
                    "asset_to_dex_ratio": f.get("asset_to_dex_ratio"),
                }
                for f in asset_flags
            ],
        })

    # DEX packing summary.
    packed_dex = [d for d in dex_entropy if d.get("likely_packed")]

    # Native library artifact summary.
    native_summary = []
    for artifact in native_artifacts:
        if isinstance(artifact, dict):
            native_summary.append({
                "library": artifact.get("library", "unknown"),
                "total_strings": artifact.get("total_strings", 0),
                "artifact_count": len(artifact.get("artifacts", [])),
            })

    # ELF analysis from native_library_analysis
    native_analysis = obf.get("native_library_analysis", {}) or {}
    elf_analysis = native_analysis.get("elf_analysis", {}) or {}

    # Build lightweight elf_summary per library for the frontend
    elf_summary = []
    for lib_path, analysis in elf_analysis.items():
        header = analysis.get("header", {})
        packing = analysis.get("packing", {})
        risk = analysis.get("risk_score", {})
        jni_count = len(analysis.get("jni_exports", []))
        anti_count = len(analysis.get("anti_analysis", []))
        suspicious_count = len(analysis.get("suspicious_strings", []))
        embedded_count = len(analysis.get("embedded_blobs", []))
        deob_count = len(analysis.get("deobfuscated_strings", []))

        entry = {
            "library": lib_path,
            "arch": header.get("arch", "unknown"),
            "class": header.get("class", "unknown"),
            "is_stripped": header.get("is_stripped", False),
            "entry_point": header.get("entry_point"),
            "jni_exports_count": jni_count,
            "anti_analysis_count": anti_count,
            "suspicious_strings_count": suspicious_count,
            "embedded_blobs_count": embedded_count,
            "deobfuscated_strings_count": deob_count,
            "packing_level": packing.get("level", "none"),
            "risk_level": risk.get("level", "LOW"),
            "risk_score": risk.get("score", 0),
        }

        if jni_count:
            entry["jni_exports"] = analysis["jni_exports"]
        if anti_count:
            entry["anti_analysis"] = analysis["anti_analysis"]
        if suspicious_count:
            entry["suspicious_strings"] = analysis["suspicious_strings"]
        if embedded_count:
            entry["embedded_blobs"] = analysis["embedded_blobs"]
        if deob_count:
            entry["deobfuscated_strings"] = analysis["deobfuscated_strings"]
        if analysis.get("sections"):
            entry["high_entropy_sections"] = [
                s for s in analysis["sections"]
                if s.get("entropy", 0) > 7.0
            ]
        if analysis.get("import_summary"):
            entry["import_summary"] = analysis["import_summary"]

        elf_summary.append(entry)

    return {
        "sample_id": sample_id,
        "obfuscation_score": obf.get("obfuscation_score", 0),
        "obfuscation_level": obf.get("obfuscation_level", "low"),
        "techniques": techniques,
        "dex_entropy": dex_entropy,
        "packed_dex": packed_dex,
        "native_library_artifacts": native_summary,
        "elf_analysis": elf_summary,
        "total_classes": indicators.get("total_classes", 0),
        "total_methods": indicators.get("total_methods", 0),
        "asset_analysis": {
            "dex_files": asset_analysis.get("dex_files", []),
            "asset_files": [
                {
                    "file": a["file"],
                    "size": a["size"],
                    "entropy": a["entropy"],
                }
                for a in asset_analysis.get("asset_files", [])
            ],
            "native_libs": asset_analysis.get("native_libs", []),
            "flags": asset_flags,
        },
        "notes": notes,
    }


def deobfuscate_text(text: str, hint: Optional[str] = None) -> Dict[str, Any]:
    """Best-effort deobfuscation of a user-supplied string."""
    from analysis.step4_decoding import decode_base64, decode_urlsafe_base64, decode_hex, decode_xor

    text = text.strip()
    if not text:
        return {"original": text, "results": []}

    results = []
    seen = set()

    def add_result(label: str, decoded: Any, status: str = "success"):
        key = f"{label}:{str(decoded)[:200]}"
        if key in seen:
            return
        seen.add(key)
        results.append({
            "type": label,
            "value": decoded if isinstance(decoded, str) else decoded.decode("utf-8", errors="ignore"),
            "raw_bytes": decoded.hex() if isinstance(decoded, bytes) else None,
            "status": status,
        })

    # Base64 variants
    for label, decoder in [("base64", decode_base64), ("urlsafe_base64", decode_urlsafe_base64)]:
        decoded = decoder(text)
        if decoded:
            try:
                add_result(label, decoded)
            except Exception:
                logger.debug("Failed to add base64 decode result")
                pass

    # Hex
    cleaned_hex = text.replace(" ", "").replace("0x", "")
    decoded = decode_hex(cleaned_hex)
    if decoded:
        add_result("hex", decoded)

    # URL decode
    try:
        from urllib.parse import unquote
        url_decoded = unquote(text)
        if url_decoded != text:
            add_result("url_decode", url_decoded.encode("utf-8"))
    except Exception:
        logger.debug("Failed to URL-decode text")
        pass

    # XOR brute force (common single-byte keys)
    for key in [1, 2, 13, 0x55, 0xAA]:
        decoded = decode_xor(text, key)
        if decoded:
            # Only keep printable results
            try:
                printable = decoded.decode("ascii")
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in printable):
                    add_result(f"xor_{key}", decoded)
            except Exception:
                logger.debug("Failed to decode XOR result")
                pass

    # If a hint is provided, try to surface the matching result first.
    if hint:
        hint_lower = hint.lower()
        results.sort(key=lambda r: hint_lower in r["type"].lower(), reverse=True)

    return {
        "original": text,
        "results": results,
    }
