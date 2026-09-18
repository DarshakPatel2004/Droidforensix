import logging
import math
import zipfile
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

PACKING_INDICATORS = [
    {"name": "oversized_dex_section", "weight": 30,
     "desc": "DEX section exceeds normal size threshold"},
    {"name": "high_entropy_code", "weight": 30,
     "desc": ".text section entropy > 7.0 (likely packed/encrypted)"},
    {"name": "dex_in_dex", "weight": 40,
     "desc": "Unexpected DEX-like entry inside APK (DEX nesting)"},
    {"name": "missing_dex", "weight": 25,
     "desc": "No classes.dex found (code in native lib or asset)"},
    {"name": "oversized_native_lib", "weight": 20,
     "desc": "Native .so file larger than expected"},
    {"name": "suspicious_dex_name", "weight": 15,
     "desc": "DEX file with non-standard name pattern"},
]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def analyze_dex_sections(sections: Dict[str, Dict]) -> Dict[str, Any]:
    indicators = []
    score = 0.0

    for name, info in sections.items():
        size = info.get("size", 0)
        entropy = info.get("entropy", 0.0)

        if name == ".text" and size > 300000:
            indicators.append({
                "type": "oversized_dex_section",
                "detail": f".text section {size} bytes (threshold: 300KB)",
            })
            score += 30

        if name == ".text" and entropy > 7.0:
            indicators.append({
                "type": "high_entropy_code",
                "detail": f".text entropy {entropy:.2f} (threshold: 7.0)",
            })
            score += 30

    return {
        "scored_indicators": indicators,
        "obfuscation_score": min(score, 100),
    }


def detect_dex_in_dex(entry_names: List[str]) -> Dict[str, Any]:
    suspicious = False
    indicators = []

    dex_files = [n for n in entry_names if n.endswith(".dex")]

    if not dex_files:
        indicators.append({
            "type": "missing_dex",
            "detail": "No classes.dex found in APK",
        })
        suspicious = True

    for name in dex_files:
        if name != "classes.dex" and not name.startswith("classes"):
            indicators.append({
                "type": "suspicious_dex_name",
                "detail": f"Unexpected DEX name: {name}",
            })
            suspicious = True

    return {
        "suspicious": suspicious,
        "indicators": [i["type"] for i in indicators],
        "scored_indicators": indicators,
    }


def detect_binary_packing(apk_info: Dict[str, Any]) -> Dict[str, Any]:
    apk_path = apk_info.get("apk_path", "")
    if not apk_path or not Path(apk_path).exists():
        return {
            "packing_detected": False,
            "obfuscation_score": 0.0,
            "indicators": [],
            "scored_indicators": [],
            "error": "apk_path not provided or does not exist",
        }

    all_indicators = []
    total_score = 0.0

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            entry_names = zf.namelist()

            dex_result = detect_dex_in_dex(entry_names)
            all_indicators.extend(dex_result.get("scored_indicators", []))

            sections = {}
            for name in entry_names:
                if name.endswith(".dex"):
                    info = zf.getinfo(name)
                    data = zf.read(name)
                    sections[name] = {
                        "size": info.file_size,
                        "entropy": shannon_entropy(data),
                    }

            section_result = analyze_dex_sections(sections)
            all_indicators.extend(section_result.get("scored_indicators", []))

            native_libs = [n for n in entry_names if n.endswith(".so")]
            for lib_name in native_libs:
                lib_info = zf.getinfo(lib_name)
                if lib_info.file_size > 5000000:
                    all_indicators.append({
                        "type": "oversized_native_lib",
                        "detail": f"{lib_name}: {lib_info.file_size} bytes",
                    })

    except zipfile.BadZipFile as e:
        return {
            "packing_detected": True,
            "obfuscation_score": 50.0,
            "indicators": [{"type": "bad_zip", "detail": str(e)}],
            "scored_indicators": [{"type": "bad_zip", "detail": str(e)}],
            "error": None,
        }
    except Exception as e:
        return {
            "packing_detected": False,
            "obfuscation_score": 0.0,
            "indicators": [],
            "scored_indicators": [],
            "error": str(e),
        }

    for ind in all_indicators:
        for pi in PACKING_INDICATORS:
            if ind["type"] == pi["name"]:
                total_score += pi["weight"]

    packing_detected = total_score >= 30

    return {
        "packing_detected": packing_detected,
        "obfuscation_score": min(total_score, 100),
        "indicators": [i["type"] for i in all_indicators],
        "scored_indicators": all_indicators,
        "error": None,
    }
