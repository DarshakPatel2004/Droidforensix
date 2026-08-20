"""
Step 4: Payload Decoding & Artifact Extraction

Decodes detected encodings, extracts artifacts (URLs, IPs, domains, emails,
phone numbers), detects binary payloads via magic bytes, and post-processes.
"""

import base64
import binascii
import json
import re
import socket
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

import phonenumbers

from analysis.decoding_engine import multi_layer_decode, repair_surrogates
from analysis.ip_validation import calculate_ip_legitimacy_score
from backend.config import settings


class DecodingError(Exception):
    """Raised when decoding fails."""
    pass


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
PHONE_RE = re.compile(r'[\+]?[1-9]?[0-9]{1,15}')

MAGIC_BYTES = {
    b'\x4d\x5a': 'windows_executable',
    b'\x7f\x45\x4c\x46': 'elf',
    b'\x50\x4b\x03\x04': 'zip_apk',
    b'%PDF': 'pdf',
    b'\x89PNG': 'png',
    b'\xff\xd8\xff': 'jpeg',
}


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


def decode_base64(s: str) -> Optional[bytes]:
    """Decode standard Base64."""
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def decode_urlsafe_base64(s: str) -> Optional[bytes]:
    """Decode URL-safe Base64."""
    try:
        padding = 4 - len(s) % 4
        if padding != 4:
            s += '=' * padding
        return base64.urlsafe_b64decode(s)
    except Exception:
        return None


def decode_hex(s: str) -> Optional[bytes]:
    """Decode hex string."""
    try:
        return binascii.unhexlify(s)
    except Exception:
        return None


def decode_xor(s: str, key: int) -> Optional[bytes]:
    """Decode XOR with given key."""
    try:
        data = s.encode("utf-8", errors="ignore")
        return bytes(b ^ key for b in data)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Artifact extraction
# ---------------------------------------------------------------------------


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    return list(set(URL_RE.findall(text)))


def extract_ips(text: str) -> List[str]:
    """Extract and validate IP addresses."""
    candidates = set(IP_RE.findall(text))
    valid = []
    for ip in candidates:
        try:
            socket.inet_aton(ip)
            # Reject private/loopback? Keep for now; Step 5 classifies
            valid.append(ip)
        except socket.error:
            continue
    return valid


def extract_domains(text: str) -> List[str]:
    """Extract domain names from text."""
    domains = set(DOMAIN_RE.findall(text))
    # Filter out common false positives
    filtered = [d for d in domains if '.' in d and not d.endswith(('.xml', '.java', '.html', '.json'))]
    return filtered


def extract_emails(text: str) -> List[str]:
    """Extract email addresses."""
    return list(set(EMAIL_RE.findall(text)))


def extract_phones(text: str) -> List[str]:
    """Extract and validate phone numbers."""
    valid = []
    for match in PHONE_RE.finditer(text):
        candidate = match.group(0)
        try:
            parsed = phonenumbers.parse(candidate, None)
            if phonenumbers.is_valid_number(parsed):
                valid.append(phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
        except Exception:
            continue
    return list(set(valid))


def detect_binary(data: bytes) -> Optional[str]:
    """Detect binary payload type via magic bytes."""
    if not data:
        return None
    for magic, btype in MAGIC_BYTES.items():
        if data.startswith(magic):
            return btype
    return None


def decode_payload(encoding: dict) -> Optional[bytes]:
    """Route encoding to appropriate decoder."""
    enc_type = encoding.get("type", "")
    original = encoding.get("original_string", "")

    if enc_type == "base64":
        return decode_base64(original)
    elif enc_type == "base64_urlsafe":
        return decode_urlsafe_base64(original)
    elif enc_type == "hex":
        return decode_hex(original)
    elif enc_type == "xor":
        key = encoding.get("xor_key", 0)
        return decode_xor(original, key)
    elif enc_type == "custom":
        return None
    return None


# ---------------------------------------------------------------------------
# Post-processing
# ---------------------------------------------------------------------------


def normalize_url(url: str) -> str:
    """Normalize URL: lowercase scheme/host, remove trailing slash."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip('/') if parsed.path != '/' else parsed.path
        return f"{parsed.scheme.lower()}://{netloc}{path}"
    except Exception:
        return url


# Fraction of null bytes (per 2-byte word) that implies UTF-16 text layout
UTF16_NULL_RATIO_THRESHOLD = 0.4


def decode_bytes_dynamic(data: bytes) -> str:
    """Decode payload bytes to text, detecting the actual encoding.

    Order of detection:
      1. UTF-16 via BOM (FF FE = LE, FE FF = BE)
      2. UTF-16 via null-byte layout when there is no BOM
      3. UTF-8
      4. Latin-1 (never fails; preserves byte values)
    """
    if not data:
        return ""
    if data[:2] == b"\xff\xfe":
        return data.decode("utf-16", errors="replace")
    if data[:2] == b"\xfe\xff":
        return data.decode("utf-16", errors="replace")
    if len(data) >= 4:
        words = len(data) // 2
        nulls_even = sum(1 for i in range(0, len(data) - 1, 2) if data[i] == 0)
        nulls_odd = sum(1 for i in range(1, len(data), 2) if data[i] == 0)
        if nulls_odd / words > UTF16_NULL_RATIO_THRESHOLD:
            return data.decode("utf-16le", errors="replace")
        if nulls_even / words > UTF16_NULL_RATIO_THRESHOLD:
            return data.decode("utf-16be", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="ignore")


def extract_artifacts(decoded_bytes: bytes, encoding_type: str) -> List[Dict[str, Any]]:
    """Extract artifacts from decoded bytes."""
    artifacts = []
    if not decoded_bytes:
        return artifacts

    # Detect actual encoding (UTF-16 BOM/layout, then UTF-8, then Latin-1)
    text = repair_surrogates(decode_bytes_dynamic(decoded_bytes))

    # URLs
    for url in extract_urls(text):
        normalized = normalize_url(url)
        artifacts.append({
            "type": "url",
            "value": normalized,
            "confidence": 0.95,
        })

    # IPs with legitimacy validation. Every extracted IP is emitted; the verdict
    # adjusts confidence so analysts and downstream steps can still distinguish
    # public, suspicious, and reserved ranges. Previously these IPs were
    # silently dropped when "likely_benign", which hid legitimate internal
    # C2 infrastructure (RFC 1918) from the report.
    IP_CONFIDENCE_BY_VERDICT = {
        "likely_malicious": 0.95,
        "uncertain": 0.75,
        "likely_benign": 0.50,
    }
    for ip in extract_ips(text):
        verdict = calculate_ip_legitimacy_score(ip, text, encoding_type)
        artifacts.append({
            "type": "ip",
            "value": ip,
            "confidence": round(IP_CONFIDENCE_BY_VERDICT.get(verdict["verdict"], 0.75), 4),
            "legitimacy_score": verdict["legitimacy_score"],
            "legitimacy_verdict": verdict["verdict"],
            "legitimacy_factors": verdict.get("factors"),
        })

    # Domains
    for domain in extract_domains(text):
        artifacts.append({
            "type": "domain",
            "value": domain,
            "confidence": 0.85,
        })

    # Emails
    for email in extract_emails(text):
        artifacts.append({
            "type": "email",
            "value": email,
            "confidence": 0.90,
        })

    # Phone numbers
    for phone in extract_phones(text):
        artifacts.append({
            "type": "phone",
            "value": phone,
            "confidence": 0.95,
        })

    # Binary detection
    binary_type = detect_binary(decoded_bytes)
    if binary_type:
        artifacts.append({
            "type": "binary",
            "value": f"{binary_type} ({len(decoded_bytes)} bytes)",
            "confidence": 0.95,
        })

    # Readable text (if no other artifacts found and content is mostly printable)
    if not artifacts:
        printable = sum(1 for b in decoded_bytes if 32 <= b <= 126 or b in (9, 10, 13))
        if len(decoded_bytes) > 0 and printable / len(decoded_bytes) > 0.8:
            artifacts.append({
                "type": "text",
                "value": text[:200],
                "confidence": 0.60,
            })

    # Deduplicate
    seen = set()
    unique = []
    for a in artifacts:
        key = (a["type"], a["value"])
        if key not in seen:
            seen.add(key)
            unique.append(a)

    return unique


# ---------------------------------------------------------------------------
# Main decoding
# ---------------------------------------------------------------------------


def decode_payloads(encodings_result: dict) -> dict:
    """
    Full Step 4: Decode payloads and extract artifacts.

    Args:
        encodings_result: Output dict from Step 3.

    Returns:
        dict with decoded payloads.
    """
    sample_id = encodings_result["sample_id"]
    work_dir = settings.WORK_DIR / sample_id
    work_dir.mkdir(parents=True, exist_ok=True)

    payloads = []
    payload_id = 0

    for encoding in encodings_result.get("encodings", []):
        enc_type = encoding.get("type", "")
        if enc_type == "custom":
            continue  # Skip custom encodings (manual review)

        decoded_bytes = decode_payload(encoding)
        if decoded_bytes is None:
            continue

        try:
            decoded_text = decode_bytes_dynamic(decoded_bytes)
        except Exception:
            decoded_text = decoded_bytes.hex()
        decoded_text = repair_surrogates(decoded_text)

        artifacts = extract_artifacts(decoded_bytes, enc_type)

        # Boost confidence if artifacts validate
        confidence = encoding.get("confidence", 0.5)
        if artifacts:
            artifact_types = {a["type"] for a in artifacts}
            if "url" in artifact_types or "ip" in artifact_types:
                confidence = min(1.0, confidence + 0.1)

        # --- Decoding Engine enrichment ---
        # multi_layer_decode() has already applied c2_confidence_boost to its
        # total_confidence, so we surface the engine's score rather than
        # re-bumping confidence here (which would double-count URL/IP
        # indicators against the boost at line 326).
        original = encoding.get("original_string", "")
        dec_engine = None
        heur_score = None
        c2_inds = None
        if original:
            ml_result = multi_layer_decode(original)
            if ml_result.get("layers"):
                heur_score = ml_result["heuristic_scores"][-1] if ml_result["heuristic_scores"] else None
                c2_inds = ml_result.get("c2_indicators")
                dec_engine = {
                    "original_entropy": ml_result["original_entropy"],
                    "original_entropy_classification": ml_result["original_entropy_classification"],
                    "chain_path": ml_result["chain_path"],
                    "num_layers": len(ml_result["layers"]),
                    "heuristic_score": heur_score,
                    "total_confidence": ml_result["total_confidence"],
                    "c2_indicators": c2_inds,
                    "c2_confidence_boost": ml_result.get("c2_confidence_boost", 0),
                }

        entry = {
            "payload_id": f"pld_{payload_id:03d}",
            "encoding_id": encoding.get("encoding_id", ""),
            "decoded_content": decoded_text[:1000],
            "decoded_bytes_length": len(decoded_bytes),
            "artifacts": artifacts,
            "source_location": encoding.get("source_location", "unknown"),
            "binary_detected": any(a["type"] == "binary" for a in artifacts),
            "magic_bytes": decoded_bytes[:4].hex() if decoded_bytes else None,
            "confidence": round(confidence, 4),
        }
        if dec_engine:
            entry["decoding_engine"] = dec_engine
        payloads.append(entry)
        payload_id += 1

    result = {
        "sample_id": sample_id,
        "total_payloads": len(payloads),
        "payloads": payloads,
    }

    # Save intermediate result
    result_path = work_dir / "step4_payloads.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python step4_decoding.py <step3_encodings.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        encodings_data = json.load(f)
    print(json.dumps(decode_payloads(encodings_data), indent=2))
