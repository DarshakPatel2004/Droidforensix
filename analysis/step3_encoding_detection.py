"""
Step 3: Encoding Detection & Classification

Detects Base64, URL-safe Base64, hex, XOR, and suspected custom encoding
in enumerated strings. Assigns confidence scores based on alphabet match,
decode success, meaningful output, and entropy alignment.
"""

import base64
import binascii
import json
import math
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from backend.config import settings

from analysis.decoding_engine import classify_entropy


class EncodingDetectionError(Exception):
    """Raised when encoding detection fails."""
    pass


# ---------------------------------------------------------------------------
# Patterns and constants
# ---------------------------------------------------------------------------

BASE64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
BASE64_URLSAFE_RE = re.compile(r'[A-Za-z0-9_-]{20,}')
HEX_RE = re.compile(r'[0-9A-Fa-f]{16,}')

URL_RE = re.compile(r'https?://[^\s"\']+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

HIGH_ENTROPY_THRESHOLD = 5.0
CUSTOM_ENCODING_THRESHOLD = 7.0
XOR_PRINTABLE_THRESHOLD = 0.70

# Maximum encodings kept per APK. Bounds the per-encoding work in steps 4-8
# (multi-layer decode, C2 extraction, threat chains, LLM) on very large APKs —
# no analyst reads thousands of near-duplicate chains.
MAX_ENCODINGS = 500

# Source locations that are framework / support-library boilerplate.
# Encodings found here are overwhelmingly false positives (class names, method
# names, constants) unless the decoded content itself is clearly malicious.
BENIGN_SOURCE_PATTERNS = [
    re.compile(r"android[\\/]support[\\/]", re.IGNORECASE),
    re.compile(r"androidx[\\/]", re.IGNORECASE),
    re.compile(r"com[\\/]google[\\/]", re.IGNORECASE),
    re.compile(r"com[\\/]android[\\/]", re.IGNORECASE),
    re.compile(r"org[\\/]apache[\\/]", re.IGNORECASE),
    re.compile(r"junit[\\/]", re.IGNORECASE),
    re.compile(r"okhttp[\\/]", re.IGNORECASE),
    re.compile(r"retrofit[\\/]", re.IGNORECASE),
    # Android resource files are not obfuscated payload sources.
    re.compile(r"res[\\/]raw[\\/]", re.IGNORECASE),
    re.compile(r"res[\\/]values[\\/]", re.IGNORECASE),
    re.compile(r"res[\\/]xml[\\/]", re.IGNORECASE),
    re.compile(r"AndroidManifest\.xml", re.IGNORECASE),
    # Utility/helper classes — constants, not payloads.
    re.compile(r"[\\/]utils?[\\/]", re.IGNORECASE),
    re.compile(r"[\\/]helpers?[\\/]", re.IGNORECASE),
    re.compile(r"[\\/]constants?[\\/]", re.IGNORECASE),
    re.compile(r"[\\/]BuildConfig\.", re.IGNORECASE),
    re.compile(r"[\\/]R\$", re.IGNORECASE),  # Android resource IDs
]

# Source locations that suggest the string is actually used as an obfuscated
# payload (decode/decrypt calls, reflection, dynamic loading, network, etc.).
SUSPICIOUS_SOURCE_PATTERNS = [
    re.compile(r"reflect", re.IGNORECASE),
    re.compile(r"crypto|cipher|encrypt|decrypt|decode|decipher", re.IGNORECASE),
    re.compile(r"loader|DexClassLoader|PathClassLoader", re.IGNORECASE),
    re.compile(r"payload|exploit|shell|command|exec", re.IGNORECASE),
    re.compile(r"network|http|socket|inet|urlconnection", re.IGNORECASE),
]

# Benign string patterns that are commonly misclassified as encodings.
BENIGN_VALUE_PATTERNS = [
    re.compile(r"^[0-9a-fA-F]{16}$"),  # Hex constants like 0123456789abcdef
    re.compile(r"^[A-Za-z][A-Za-z0-9_]*$"),  # CamelCase / PascalCase identifiers
    re.compile(r"^[a-z][a-z0-9_]*$"),  # snake_case identifiers
    re.compile(r"^[A-Z][A-Z0-9_]*$"),  # UPPER_SNAKE_CASE constants
    re.compile(r"^[a-z]+(_[a-z]+)+$"),  # lowercase_snake_case
    re.compile(r"^[A-Za-z0-9_]+\.[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$"),  # Dotted names
    re.compile(r"^[A-Za-z0-9+/]{20,}$"),  # Base64-like but no padding — often a constant
    re.compile(r"^[A-Za-z0-9_-]{20,}$"),  # URL-safe-base64-like — often a token
    re.compile(r"^[a-zA-Z]+$"),  # Plain alphabetic string (no digits, no special chars)
    re.compile(r"^[A-Z][A-Z_0-9]+$"),  # UPPER_CASE_WITH_DIGITS constants
    re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$"),  # package.name format
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy."""
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


def is_printable_ratio(data: bytes) -> float:
    """Return ratio of printable ASCII bytes."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def has_meaningful_content(text: str) -> bool:
    """Check if decoded text contains URLs, IPs, domains, or emails."""
    if URL_RE.search(text):
        return True
    if IP_RE.search(text):
        return True
    if DOMAIN_RE.search(text):
        return True
    if EMAIL_RE.search(text):
        return True
    return False


def looks_like_base64(s: str) -> bool:
    """Check if string looks like valid Base64."""
    if len(s) < 4:
        return False
    # Standard Base64 length multiple of 4 (with padding)
    if len(s) % 4 != 0 and not s.endswith('='):
        return False
    # Character set
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not set(s).issubset(allowed):
        return False
    return True


def looks_like_urlsafe_base64(s: str) -> bool:
    """Check if string looks like URL-safe Base64."""
    if len(s) < 4:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if not set(s).issubset(allowed):
        return False
    return True


def looks_like_hex(s: str) -> bool:
    """Check if string looks like hex."""
    if len(s) < 4 or len(s) % 2 != 0:
        return False
    allowed = set("0123456789ABCDEFabcdef")
    return set(s).issubset(allowed)


def is_benign_source(source: str) -> bool:
    """Return True if the source location is framework/library boilerplate."""
    if not source:
        return False
    source_lower = source.lower()
    return any(p.search(source_lower) for p in BENIGN_SOURCE_PATTERNS)


def is_suspicious_source(source: str) -> bool:
    """Return True if the source location suggests obfuscated payload use."""
    if not source:
        return False
    source_lower = source.lower()
    return any(p.search(source_lower) for p in SUSPICIOUS_SOURCE_PATTERNS)


def is_benign_value_pattern(value: str) -> bool:
    """Return True for common code identifiers/constants misclassified as encodings."""
    if not value:
        return False
    for pat in BENIGN_VALUE_PATTERNS:
        if pat.match(value):
            return True
    return False


def is_likely_obfuscated_payload(value: str, decoded: str, source: str,
                                  entropy: float) -> bool:
    """
    Decide whether a decoded candidate is a real obfuscated payload or a
    false positive.

    Rules (strict — biased toward fewer false positives):
      1. Meaningful decoded content (URL/IP/domain/email) → keep regardless.
      2. Suspicious source AND (high entropy OR meaningful) → keep.
      3. Benign source / benign value shape → reject.
      4. Short string (< 16 chars) in a utility class → reject (constants).
      5. High entropy alone → keep as uncertain (XOR candidates).
    """
    meaningful = has_meaningful_content(decoded)
    suspicious = is_suspicious_source(source)
    high_entropy = entropy > HIGH_ENTROPY_THRESHOLD

    # Rule 1: decoded content itself is clearly malicious → always keep.
    if meaningful:
        return True

    # Rule 2a: suspicious source with high entropy or meaningful content → keep.
    if suspicious and (high_entropy or meaningful):
        return True

    # Rule 2b: suspicious source alone (even without meaningful content/high entropy)
    # keeps the payload for further analysis — avoids false negatives on
    # multi-stage payloads where the decoded content is an intermediate stage.
    if suspicious:
        return True

    # Rule 3a: benign framework / library code → reject.
    if is_benign_source(source):
        return False

    # Rule 3b: common identifier shapes → reject.
    if is_benign_value_pattern(value):
        return False

    # Rule 4: short constant in a utility class → reject.
    if len(value) < 16 and ('utils' in source.lower() or 'util' in source.lower()):
        return False

    # Rule 5: high-entropy unknown → keep as uncertain (XOR candidates).
    if high_entropy:
        return True

    return False


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


def try_base64_decode(s: str) -> Optional[str]:
    """Try decoding standard Base64."""
    try:
        decoded = base64.b64decode(s, validate=True)
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.hex()
    except Exception:
        return None


def try_urlsafe_base64_decode(s: str) -> Optional[str]:
    """Try decoding URL-safe Base64."""
    try:
        # Add padding if needed
        padding = 4 - len(s) % 4
        if padding != 4:
            s += '=' * padding
        decoded = base64.urlsafe_b64decode(s)
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.hex()
    except Exception:
        return None


def try_hex_decode(s: str) -> Optional[str]:
    """Try decoding hex string."""
    try:
        decoded = binascii.unhexlify(s)
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.hex()
    except Exception:
        return None


def _has_strong_meaningful_content(text: str) -> bool:
    """Check for strong indicators: URLs, IPs, or emails (domains alone are too noisy for XOR)."""
    if URL_RE.search(text):
        return True
    if IP_RE.search(text):
        return True
    if EMAIL_RE.search(text):
        return True
    return False


def xor_brute_force(data: bytes) -> List[Tuple[int, str, float]]:
    """Brute-force XOR keys 1-255, return top candidates with printable ratio.

    Key 0 is excluded because XOR with 0 is identity and would always
    match printable inputs, producing false positives.
    """
    candidates = []
    for key in range(1, 256):
        decrypted = bytes(b ^ key for b in data)
        ratio = is_printable_ratio(decrypted)
        if ratio >= XOR_PRINTABLE_THRESHOLD:
            try:
                text = decrypted.decode("utf-8", errors="ignore")
                score = ratio
                # Strongly boost candidates that produce strong meaningful content
                if _has_strong_meaningful_content(text):
                    score += 0.30
                candidates.append((key, text, score))
            except UnicodeDecodeError:
                pass
    # Sort by score descending, return top 3
    candidates.sort(key=lambda x: x[2], reverse=True)
    return candidates[:3]


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------


def calculate_confidence(alphabet_match: float, decode_success: float,
                         meaningful: float, entropy_alignment: float) -> float:
    """Weighted confidence score."""
    score = (alphabet_match * 0.3 + decode_success * 0.3 +
             meaningful * 0.2 + entropy_alignment * 0.2)
    return round(min(1.0, max(0.0, score)), 4)


# ---------------------------------------------------------------------------
# Main detection
# ---------------------------------------------------------------------------


def detect_encoding(strings_result: dict) -> dict:
    """
    Full Step 3: Detect encodings in enumerated strings.

    Args:
        strings_result: Output dict from Step 2.

    Returns:
        dict with detected encodings.
    """
    sample_id = strings_result["sample_id"]
    work_dir = settings.WORK_DIR / sample_id
    work_dir.mkdir(parents=True, exist_ok=True)

    encodings = []
    encoding_id = 0

    # Flatten all strings to process
    all_strings = []
    categories = strings_result.get("categories", {})
    for category_name, items in categories.items():
        for item in items:
            value = item.get("value", "")
            if isinstance(value, str) and len(value) >= 8:
                all_strings.append({
                    "value": value,
                    "source": item.get("source", "unknown"),
                    "entropy": item.get("entropy", 0.0),
                    "category": category_name,
                })

    # Deduplicate by value
    seen_values = set()
    unique_strings = []
    for s in all_strings:
        if s["value"] not in seen_values:
            seen_values.add(s["value"])
            unique_strings.append(s)

    for s in unique_strings:
        value = s["value"]
        entropy = s.get("entropy", 0.0)
        source = s.get("source", "unknown")

        # Remove quotes/whitespace that might surround encoded data
        clean = value.strip().strip('"').strip("'")
        if len(clean) < 8:
            continue

        # Try Base64
        if BASE64_RE.search(clean) and looks_like_base64(clean):
            decoded = try_base64_decode(clean)
            if decoded is not None:
                meaningful = 1.0 if has_meaningful_content(decoded) else 0.3
                if not is_likely_obfuscated_payload(clean, decoded, source, entropy):
                    continue
                encodings.append({
                    "encoding_id": f"enc_{encoding_id:03d}",
                    "type": "base64",
                    "original_string": clean,
                    "confidence": calculate_confidence(1.0, 1.0, meaningful,
                                                        0.8 if 3.0 < entropy < 6.0 else 0.5),
                    "entropy": entropy,
                    "entropy_classification": classify_entropy(entropy),
                    "source_location": source,
                    "decoded_preview": decoded[:200],
                    "validation_status": "valid" if meaningful > 0.5 else "uncertain",
                })
                encoding_id += 1
                continue

        # Try Hex (before URL-safe Base64 because hex strings also match URL-safe B64 regex)
        if HEX_RE.search(clean) and looks_like_hex(clean):
            decoded = try_hex_decode(clean)
            if decoded is not None:
                meaningful = 1.0 if has_meaningful_content(decoded) else 0.3
                if not is_likely_obfuscated_payload(clean, decoded, source, entropy):
                    continue
                encodings.append({
                    "encoding_id": f"enc_{encoding_id:03d}",
                    "type": "hex",
                    "original_string": clean,
                    "confidence": calculate_confidence(1.0, 1.0, meaningful,
                                                        0.8 if 2.0 < entropy < 5.0 else 0.5),
                    "entropy": entropy,
                    "entropy_classification": classify_entropy(entropy),
                    "source_location": source,
                    "decoded_preview": decoded[:200],
                    "validation_status": "valid" if meaningful > 0.5 else "uncertain",
                })
                encoding_id += 1
                continue

        # Try URL-safe Base64
        if BASE64_URLSAFE_RE.search(clean) and looks_like_urlsafe_base64(clean):
            decoded = try_urlsafe_base64_decode(clean)
            if decoded is not None:
                meaningful = 1.0 if has_meaningful_content(decoded) else 0.3
                if not is_likely_obfuscated_payload(clean, decoded, source, entropy):
                    continue
                encodings.append({
                    "encoding_id": f"enc_{encoding_id:03d}",
                    "type": "base64_urlsafe",
                    "original_string": clean,
                    "confidence": calculate_confidence(1.0, 1.0, meaningful, 0.7),
                    "entropy": entropy,
                    "entropy_classification": classify_entropy(entropy),
                    "source_location": source,
                    "decoded_preview": decoded[:200],
                    "validation_status": "valid" if meaningful > 0.5 else "uncertain",
                })
                encoding_id += 1
                continue

        # XOR brute-force for high-entropy strings
        if entropy > HIGH_ENTROPY_THRESHOLD:
            try:
                # Use latin-1 to preserve byte values for XOR analysis
                data = clean.encode("latin-1", errors="ignore")
                if len(data) >= 8:
                    candidates = xor_brute_force(data)
                    if candidates:
                        best_key, best_text, best_score = candidates[0]
                        meaningful = 1.0 if has_meaningful_content(best_text) else 0.4
                        if not is_likely_obfuscated_payload(clean, best_text, source, entropy):
                            continue
                        encodings.append({
                            "encoding_id": f"enc_{encoding_id:03d}",
                            "type": "xor",
                            "original_string": clean,
                            "confidence": calculate_confidence(0.7, 0.9 if best_score > 0.8 else 0.6,
                                                                meaningful, 0.8),
                            "entropy": entropy,
                            "entropy_classification": classify_entropy(entropy),
                            "source_location": source,
                            "decoded_preview": best_text[:200],
                            "xor_key": best_key,
                            "xor_printable_ratio": round(best_score, 4),
                            "validation_status": "valid" if meaningful > 0.5 else "uncertain",
                        })
                        encoding_id += 1
                        continue
            except (UnicodeEncodeError, LookupError) as e:
                logger.debug("XOR skip %s: %s", clean[:30], e)

        # Custom encoding flag for very high entropy failures.
        # Require a suspicious source context; otherwise this is just noise.
        if entropy > CUSTOM_ENCODING_THRESHOLD and is_suspicious_source(source):
            encodings.append({
                "encoding_id": f"enc_{encoding_id:03d}",
                "type": "custom",
                "original_string": clean,
                "confidence": 0.4,
                "entropy": entropy,
                "entropy_classification": classify_entropy(entropy),
                "source_location": source,
                "decoded_preview": "",
                "validation_status": "uncertain",
            })
            encoding_id += 1

    # Cap: keep all custom-flagged encodings (manual review items) plus the
    # highest-confidence regular encodings up to MAX_ENCODINGS.
    if len(encodings) > MAX_ENCODINGS:
        custom_encodings = [e for e in encodings if e.get("type") == "custom"]
        regular_encodings = [e for e in encodings if e.get("type") != "custom"]
        regular_encodings.sort(key=lambda e: e.get("confidence", 0.0), reverse=True)
        encodings = custom_encodings + regular_encodings[:MAX_ENCODINGS - len(custom_encodings)]

    result = {
        "sample_id": sample_id,
        "total_encodings": len(encodings),
        "encodings": encodings,
    }

    # Save intermediate result
    result_path = work_dir / "step3_encodings.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python step3_encoding_detection.py <step2_strings.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        strings_data = json.load(f)
    print(json.dumps(detect_encoding(strings_data), indent=2))
