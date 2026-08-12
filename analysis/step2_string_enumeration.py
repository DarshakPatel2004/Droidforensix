"""
Step 2: String Enumeration & Entropy Analysis

Extracts all string literals, byte arrays, numeric constants, resource strings,
and native strings from decompiled APK output. Calculates Shannon entropy for
each extracted value and outputs structured JSON.
"""

import json
import math
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.config import settings


class StringEnumerationError(Exception):
    """Raised when string enumeration fails."""
    pass


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy H = -Σ p(x) log₂ p(x)."""
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


def entropy_of_string(s: str) -> float:
    """Calculate entropy of a string (as UTF-8 bytes)."""
    return shannon_entropy(s.encode("utf-8", errors="ignore"))


STRING_LITERAL_REGEX = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
BYTE_ARRAY_REGEX = re.compile(r'\{\s*(0x[0-9A-Fa-f]{2}\s*(?:,\s*0x[0-9A-Fa-f]{2})*)\s*\}')
NUMERIC_REGEX = re.compile(r'\b(\d{3,5})\b')
SMALI_STRING_REGEX = re.compile(r'const-string(?:/jumbo)?\s+[^,]+,\s*"([^"\\]*(?:\\.[^"\\]*)*)"')

# DEX-specific noise patterns (type descriptors, method signatures, field refs)
DEX_NOISE_RE = re.compile(
    r"^(L[a-zA-Z/;$]+;|\([^)]*\)[A-Z]|\[+L?[A-Z];|"
    r"[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\.)",  # short dotted refs
)
# Additional DEX noise: common Java type abbreviations in DEX format
DEX_TYPE_NAMES = frozenset({
    "V", "Z", "B", "S", "C", "I", "J", "F", "D",  # Java primitives
    "void", "boolean", "byte", "short", "char", "int", "long", "float", "double",
})
NOISE_STRINGS = {"null", "true", "false", "none", "yes", "no", "ok"}
NOISE_PREFIXES = (
    "android.", "com.android.", "java.", "javax.", "kotlin.", "kotlinx.", "androidx.",
    "dalvik.", "sun.", "org.xml.", "org.w3c.", "org.json.",
)
NOISE_PATTERNS = [
    re.compile(r'^[\s\\/:;,.\-_=+\*\|\(\)\[\]\{\}<>!?@#\$%^&~`"\'0-9]+$'),  # pure symbols/digits
    re.compile(r'^0x[0-9a-fA-F]+$'),  # hex constants
    re.compile(r'^\d{1,6}$'),  # small numbers
    re.compile(r'^[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$'),  # dotted package names
]


def is_noisy_string(value: str) -> bool:
    """Return True if a string literal is likely framework/SDK boilerplate or noise."""
    if not value or len(value) < 8:
        return True
    lowered = value.lower().strip()
    if lowered in NOISE_STRINGS:
        return True
    if lowered.startswith(NOISE_PREFIXES):
        return True
    for pat in NOISE_PATTERNS:
        if pat.match(value):
            return True
    # Filter single-word strings that look like English words or code identifiers
    # (no dots, no slashes, just alphanumeric) — these are never C2 domains
    if "." not in value and "/" not in value and value.replace("_", "").replace("-", "").isalnum():
        return True
    return False


def _extract_strings_from_text(text: str, source_prefix: str, source_path: Path, category: str = "string_literal") -> List[Dict[str, Any]]:
    """Generic helper to extract string literals from file text."""
    results = []
    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for match in STRING_LITERAL_REGEX.finditer(line):
            value = match.group(1)
            if is_noisy_string(value):
                continue
            results.append({
                "category": category,
                "value": value,
                "entropy": round(entropy_of_string(value), 4),
                "source": f"{source_prefix}:{line_no}",
            })
    return results


def extract_java_strings(source_dir: str) -> List[Dict[str, Any]]:
    """Extract string literals from Java source files."""
    results = []
    source_path = Path(source_dir)
    if not source_path.exists():
        return results

    for java_file in source_path.rglob("*.java"):
        try:
            with open(java_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            prefix = str(java_file.relative_to(source_path))
            results.extend(_extract_strings_from_text(content, prefix, source_path, "string_literal"))

            # Byte arrays
            lines = content.splitlines()
            for line_no, line in enumerate(lines, start=1):
                for match in BYTE_ARRAY_REGEX.finditer(line):
                    hex_str = match.group(1)
                    try:
                        bytes_values = [int(x.strip(), 16) for x in hex_str.split(",")]
                        byte_data = bytes(bytes_values)
                        hex_repr = byte_data.hex()
                        results.append({
                            "category": "byte_array",
                            "value": hex_repr,
                            "entropy": round(shannon_entropy(byte_data), 4),
                            "source": f"{prefix}:{line_no}",
                        })
                    except ValueError:
                        continue

                # Numeric constants
                for match in NUMERIC_REGEX.finditer(line):
                    value = int(match.group(1))
                    results.append({
                        "category": "numeric_constant",
                        "value": value,
                        "entropy": 0.0,
                        "source": f"{prefix}:{line_no}",
                    })
        except OSError as e:
            logger.debug("Error reading Java file %s: %s", java_file, e)
            continue

    return results


def extract_smali_strings(apktool_dir: str) -> List[Dict[str, Any]]:
    """Extract string literals from smali files as a fallback when JADX fails."""
    results = []
    smali_path = Path(apktool_dir) / "smali"
    if not smali_path.exists():
        return results

    for smali_file in smali_path.rglob("*.smali"):
        try:
            with open(smali_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()
            for line_no, line in enumerate(lines, start=1):
                for match in SMALI_STRING_REGEX.finditer(line):
                    value = match.group(1)
                    if is_noisy_string(value):
                        continue
                    results.append({
                        "category": "string_literal",
                        "value": value,
                        "entropy": round(entropy_of_string(value), 4),
                        "source": f"{smali_file.relative_to(smali_path)}:{line_no}",
                    })
        except (OSError, UnicodeDecodeError) as e:
            logger.debug("Error reading smali file %s: %s", smali_file, e)
            continue

    return results


def extract_resource_strings(apktool_dir: str) -> List[Dict[str, Any]]:
    """Extract strings from Android resources (strings.xml, raw/, values/*.xml)."""
    results = []
    apktool_path = Path(apktool_dir)
    if not apktool_path.exists():
        return results

    # Parse strings.xml
    strings_xml = apktool_path / "res" / "values" / "strings.xml"
    if strings_xml.exists():
        try:
            tree = ET.parse(str(strings_xml))
            root = tree.getroot()
            for child in root:
                if child.tag == "string" and child.text:
                    value = child.text
                    results.append({
                        "category": "resource_string",
                        "value": value,
                        "entropy": round(entropy_of_string(value), 4),
                        "source": f"res/values/strings.xml:{child.get('name', 'unknown')}",
                    })
        except Exception:
            pass

    # Read raw/ directory files
    raw_dir = apktool_path / "res" / "raw"
    if raw_dir.exists():
        for raw_file in raw_dir.iterdir():
            if raw_file.is_file():
                try:
                    with open(raw_file, "rb") as f:
                        data = f.read()
                    # Try to decode as text; fallback to hex
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        text = data.hex()
                    results.append({
                        "category": "resource_raw",
                        "value": text[:5000],  # Limit size
                        "entropy": round(shannon_entropy(data), 4),
                        "source": f"res/raw/{raw_file.name}",
                    })
                except Exception:
                    continue

    return results


def is_dex_noise(value: str) -> bool:
    """Return True if string is DEX-level noise (type descriptors, signatures, field refs)."""
    if value in DEX_TYPE_NAMES:
        return True
    if DEX_NOISE_RE.match(value):
        return True
    # Single-letter strings (DEX type abbreviations)
    if len(value) == 1 and value.isalpha():
        return True
    # Strings that look like file paths with .java/.kt/.class extensions
    if value.endswith((".java", ".kt", ".class", ".smali")):
        return True
    return False


def extract_androguard_strings(apk_path: str) -> List[Dict[str, Any]]:
    """Extract string literals from DEX bytecode using Androguard (fast primary path)."""
    results = []
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
        apk = APK(str(apk_path))
        seen = set()
        for dex_data in apk.get_all_dex():
            try:
                dex = DEX(dex_data)
                for string in dex.get_strings():
                    if not string:
                        continue
                    if string in seen:
                        continue
                    seen.add(string)
                    if is_noisy_string(string) or is_dex_noise(string):
                        continue
                    results.append({
                        "category": "string_literal",
                        "value": string,
                        "entropy": round(entropy_of_string(string), 4),
                        "source": "dex",
                    })
            except Exception:
                continue
    except Exception:
        pass
    return results


def enumerate_strings(extraction_result: dict) -> dict:
    """
    Full Step 2: Enumerate strings from extracted APK output.

    Args:
        extraction_result: Output dict from Step 1 (APK extraction).

    Returns:
        dict with categorized strings and metadata.
    """
    sample_id = extraction_result["sample_id"]
    apktool_output_dir = extraction_result.get("apktool_output_dir")
    if apktool_output_dir:
        work_dir = Path(apktool_output_dir).parent
    else:
        work_dir = settings.WORK_DIR / sample_id
    work_dir.mkdir(parents=True, exist_ok=True)

    apktool_dir = extraction_result.get("apktool_output_dir")
    jadx_dir = extraction_result.get("jadx_output_dir")
    native_strings = extraction_result.get("native_strings", [])
    apk_path = extraction_result.get("apk_path")

    all_strings = []

    # Primary: Androguard DEX strings (fast, ~5s)
    if apk_path:
        andro_strings = extract_androguard_strings(apk_path)
        all_strings.extend(andro_strings)

    # Secondary: JADX Java strings (enrichment, only if Androguard produced nothing)
    if jadx_dir and not all_strings:
        java_strings = extract_java_strings(jadx_dir)
        all_strings.extend(java_strings)

    # Fallback: smali strings from apktool if both Androguard and JADX failed
    if apktool_dir and not all_strings:
        smali_strings = extract_smali_strings(apktool_dir)
        all_strings.extend(smali_strings)

    # Resource strings from apktool output
    if apktool_dir:
        resource_strings = extract_resource_strings(apktool_dir)
        all_strings.extend(resource_strings)

    # Native strings
    for ns in native_strings:
        value = ns.get("value", "")
        if len(value) >= 3:
            all_strings.append({
                "category": "native_string",
                "value": value,
                "entropy": round(entropy_of_string(value), 4),
                "source": ns.get("source", "native"),
            })

    # Categorize results
    categorized = {
        "string_literals": [s for s in all_strings if s["category"] == "string_literal"],
        "byte_arrays": [s for s in all_strings if s["category"] == "byte_array"],
        "numeric_constants": [s for s in all_strings if s["category"] == "numeric_constant"],
        "resource_strings": [s for s in all_strings if s["category"] in ("resource_string", "resource_raw")],
        "native_strings": [s for s in all_strings if s["category"] == "native_string"],
    }

    result = {
        "sample_id": sample_id,
        "total_strings": len(all_strings),
        "categories": categorized,
        "summary": {k: len(v) for k, v in categorized.items()},
    }

    # Save intermediate result
    result_path = work_dir / "step2_strings.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python step2_string_enumeration.py <step1_extraction.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        extraction = json.load(f)
    print(json.dumps(enumerate_strings(extraction), indent=2))
