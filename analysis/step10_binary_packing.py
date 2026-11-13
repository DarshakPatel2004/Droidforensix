import json
import logging
import math
import zipfile
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

MAX_ENTRY_BYTES = 100 * 1024 * 1024
MARKERS_PATH = Path(__file__).resolve().parent.parent / "data" / "packer_markers.json"
MARKER_SCAN_BYTES = 256 * 1024  # per-DEX cap for marker scanning

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
    freq = Counter(data)  # counts in C; the per-byte Python loop was the slow part (L4)
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

        # Keys are DEX entry names (classes.dex, classes2.dex, ...) from detect_binary_packing.
        if name.endswith(".dex") and size > 300000:
            indicators.append({
                "type": "oversized_dex_section",
                "detail": f"{name} {size} bytes (threshold: 300KB)",
            })
            score += 30

        if name.endswith(".dex") and entropy > 7.0:
            indicators.append({
                "type": "high_entropy_code",
                "detail": f"{name} entropy {entropy:.2f} (threshold: 7.0)",
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


@lru_cache(maxsize=1)
def _load_brands() -> List[Dict[str, Any]]:
    """Load the packer brand markers from data/packer_markers.json."""
    try:
        with open(MARKERS_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("brands", [])
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("packer markers unavailable: %s", e)
        return []


def match_packer_brands(
    entry_names: List[str], dex_blobs: List[bytes]
) -> List[Dict[str, str]]:
    """Return [{"name", "markers"}] for brands whose markers appear in
    zip entry names or the first bytes of each DEX."""
    joined_names = " ".join(entry_names).lower()
    names_alt = joined_names.replace("/", ".")
    matched = []
    for brand in _load_brands():
        hits = []
        for marker in brand.get("markers", []):
            needle = marker.lower()
            if needle in joined_names or needle in names_alt or any(
                needle.encode() in blob.lower() for blob in dex_blobs
            ):
                hits.append(marker)
        if hits:
            matched.append({"name": brand["name"], "markers": hits})
    return matched


def detect_binary_packing(apk_info: Dict[str, Any]) -> Dict[str, Any]:
    apk_path = apk_info.get("apk_path", "")
    if not apk_path or not Path(apk_path).exists():
        return {
            "packing_detected": False,
            "obfuscation_score": 0.0,
            "indicators": [],
            "scored_indicators": [],
            "packer_brands": [],
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
            marker_blobs = []
            for name in entry_names:
                if name.endswith(".dex"):
                    info = zf.getinfo(name)
                    if info.file_size > MAX_ENTRY_BYTES:
                        continue  # zip-bomb guard: declared size checked before decompressing
                    data = zf.read(name)
                    sections[name] = {
                        "size": info.file_size,
                        "entropy": shannon_entropy(data),
                    }
                    marker_blobs.append(data[:MARKER_SCAN_BYTES])

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

        packer_brands = match_packer_brands(entry_names, marker_blobs)

    except zipfile.BadZipFile as e:
        return {
            "packing_detected": True,
            "obfuscation_score": 50.0,
            "indicators": [{"type": "bad_zip", "detail": str(e)}],
            "scored_indicators": [{"type": "bad_zip", "detail": str(e)}],
            "packer_brands": [],
            "error": None,
        }
    except Exception as e:
        return {
            "packing_detected": False,
            "obfuscation_score": 0.0,
            "indicators": [],
            "scored_indicators": [],
            "packer_brands": [],
            "error": str(e),
        }

    for ind in all_indicators:
        for pi in PACKING_INDICATORS:
            if ind["type"] == pi["name"]:
                total_score += pi["weight"]

    # M2: a matched commercial packer brand counts even when no structural indicator fired
    packing_detected = total_score >= 30 or bool(packer_brands)

    return {
        "packing_detected": packing_detected,
        "obfuscation_score": min(total_score, 100),
        "indicators": [i["type"] for i in all_indicators],
        "scored_indicators": all_indicators,
        "packer_brands": packer_brands,
        "error": None,
    }
