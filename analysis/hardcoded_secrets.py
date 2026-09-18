"""
Hardcoded Secrets Detection for Android APKs

Scans decompiled source code and extracted strings for embedded credentials,
API keys, tokens, cryptographic keys, and other secrets commonly found in
Android applications. Automatically decodes encoded values (Base64, hex, JWT,
URL-encoded) to reveal the underlying secret content.

Runs against both:
  - Enumerated string literals (from step2_string_enumeration)
  - Decompiled smali/source files (from apktool output)

Patterns cover: API keys, auth tokens, private keys, JWT, cloud service keys,
database connection strings, OAuth secrets, and Android-specific credentials.
"""

import base64
import binascii
import json
import os
import re
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple

from backend.config import settings


SECRET_PATTERNS: List[Dict[str, Any]] = [
    # ── Cloud Provider Keys ──────────────────────────────────────────
    {
        "name": "aws_access_key",
        "description": "AWS Access Key ID",
        "pattern": re.compile(r"(?<![a-zA-Z0-9])(AKIA[0-9A-Z]{16})(?![a-zA-Z0-9])"),
        "severity": "high",
        "validation": lambda m: len(m.group(1)) == 20,
    },
    {
        "name": "aws_secret_key",
        "description": "AWS Secret Access Key",
        "pattern": re.compile(r"(?<![a-zA-Z0-9/+=])([a-zA-Z0-9/+=]{40})(?![a-zA-Z0-9/+=])"),
        "severity": "high",
        "validation": lambda m: "/" in m.group(1) or "+" in m.group(1),
    },
    {
        "name": "google_api_key",
        "description": "Google API Key (AIza prefix)",
        "pattern": re.compile(r"(?<![a-zA-Z0-9])(AIza[0-9A-Za-z\-_]{35})(?![a-zA-Z0-9])"),
        "severity": "high",
        "validation": lambda m: len(m.group(1)) == 39,
    },
    {
        "name": "google_oauth_client_id",
        "description": "Google OAuth Client ID",
        "pattern": re.compile(r"\d{12,}-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com"),
        "severity": "medium",
    },
    {
        "name": "firebase_url",
        "description": "Firebase Database URL (contains project ID)",
        "pattern": re.compile(r"https://[a-zA-Z0-9-]+\.firebaseio\.com"),
        "severity": "medium",
    },
    {
        "name": "azure_connection_string",
        "description": "Azure Storage/ServiceBus Connection String",
        "pattern": re.compile(r"DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]{40,80}"),
        "severity": "high",
    },
    # ── Authentication Tokens ────────────────────────────────────────
    {
        "name": "jwt_token",
        "description": "JSON Web Token (JWT)",
        "pattern": re.compile(r"(?<![a-zA-Z0-9])(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})(?![a-zA-Z0-9])"),
        "severity": "high",
        "validation": lambda m: m.group(1).count(".") == 2,
    },
    {
        "name": "bearer_token",
        "description": "Bearer Authorization Token",
        "pattern": re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.~+/]{20,200}"),
        "severity": "high",
    },
    {
        "name": "oauth_access_token",
        "description": "OAuth Access Token",
        "pattern": re.compile(r"(?i)(access_token|oauth_token)\s*[=:]\s*['\"]([a-zA-Z0-9_\-\.~]+)['\"]"),
        "severity": "high",
        "key_group": 2,
    },
    {
        "name": "oauth_client_secret",
        "description": "OAuth Client Secret",
        "pattern": re.compile(r"(?i)(client_secret|client_secret)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]+)['\"]"),
        "severity": "high",
        "key_group": 2,
    },
    # ── Messaging / Communications Platform Keys ─────────────────────
    {
        "name": "slack_token",
        "description": "Slack Bot/App/User Token",
        "pattern": re.compile(r"(xox[baprs]-[0-9a-zA-Z\-]{10,48})"),
        "severity": "high",
    },
    {
        "name": "slack_webhook",
        "description": "Slack Webhook URL",
        "pattern": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}"),
        "severity": "high",
    },
    {
        "name": "github_token",
        "description": "GitHub Personal Access / Fine-Grained Token",
        "pattern": re.compile(r"(?<![a-zA-Z0-9])(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36})(?![a-zA-Z0-9])"),
        "severity": "high",
    },
    {
        "name": "github_old_token",
        "description": "GitHub OAuth / Old-Style Token",
        "pattern": re.compile(r"(?<![a-zA-Z0-9])([a-f0-9]{40})(?![a-zA-Z0-9])"),
        "severity": "medium",
        "validation": lambda m: _has_valid_entropy(m.group(1), 4.0),
    },
    {
        "name": "discord_webhook",
        "description": "Discord Webhook URL",
        "pattern": re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+"),
        "severity": "high",
    },
    {
        "name": "twilio_sid",
        "description": "Twilio Account SID",
        "pattern": re.compile(r"(?<![a-zA-Z0-9])(AC[a-f0-9]{32})(?![a-zA-Z0-9])"),
        "severity": "high",
    },
    {
        "name": "twilio_token",
        "description": "Twilio Auth Token",
        "pattern": re.compile(r"(?<![a-zA-Z0-9])([a-f0-9]{32})(?![a-zA-Z0-9])"),
        "severity": "high",
        "validation": None,
    },
    {
        "name": "sendgrid_api_key",
        "description": "SendGrid API Key",
        "pattern": re.compile(r"SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{22,}"),
        "severity": "high",
    },
    {
        "name": "mailchimp_api_key",
        "description": "Mailchimp API Key",
        "pattern": re.compile(r"[a-f0-9]{32}-us\d{1,2}"),
        "severity": "high",
        "validation": None,
    },
    # ── Cryptographic Keys ───────────────────────────────────────────
    {
        "name": "rsa_private_key",
        "description": "RSA Private Key",
        "pattern": re.compile(r"-----BEGIN\s+(RSA|DSA|EC|PGP|OPENSSH|SSH)\s+PRIVATE\s+KEY-----"),
        "severity": "critical",
    },
    {
        "name": "pkcs8_private_key",
        "description": "PKCS#8 Private Key",
        "pattern": re.compile(r"-----BEGIN\s+PRIVATE\s+KEY-----"),
        "severity": "critical",
    },
    {
        "name": "generic_api_key_named",
        "description": "Named API Key (api_key=... pattern)",
        "pattern": re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9_\-\.]{16,64})['\"]"),
        "severity": "high",
        "key_group": 2,
    },
    {
        "name": "secret_key_named",
        "description": "Named Secret Key (secret=..., secret_key=...)",
        "pattern": re.compile(r"(?i)((?:secret|secret[_-]key|app[_-]secret))\s*[=:]\s*['\"]([a-zA-Z0-9_\-\.+/=]{16,64})['\"]"),
        "severity": "high",
        "key_group": 2,
    },
    {
        "name": "password_string",
        "description": "Hardcoded Password",
        "pattern": re.compile(r"(?i)(password|pwd|passwd)\s*[=:]\s*['\"]([a-zA-Z0-9_\-\.!@#$%^&*]{6,64})['\"]"),
        "severity": "high",
        "key_group": 2,
    },
    # ── Database Connection Strings ──────────────────────────────────
    {
        "name": "mongodb_uri",
        "description": "MongoDB Connection String with Credentials",
        "pattern": re.compile(r"mongodb(?:\+srv)?://[a-zA-Z0-9_\-%]+:[a-zA-Z0-9_\-%]+@"),
        "severity": "high",
    },
    {
        "name": "mysql_uri",
        "description": "MySQL/PostgreSQL Connection String with Credentials",
        "pattern": re.compile(r"(?:mysql|postgres|postgresql)://[a-zA-Z0-9_\-%]+:[a-zA-Z0-9_\-%]+@"),
        "severity": "high",
    },
    {
        "name": "redis_uri",
        "description": "Redis Connection String with Credentials",
        "pattern": re.compile(r"redis://[a-zA-Z0-9_\-%]+:[a-zA-Z0-9_\-%]+@"),
        "severity": "high",
    },
    # ── URL-Embedded Credentials ─────────────────────────────────────
    {
        "name": "url_embedded_credentials",
        "description": "URL with Embedded Credentials (user:pass@host)",
        "pattern": re.compile(r"https?://[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.!@#$%^&*]+@[a-zA-Z0-9_\-\.]+"),
        "severity": "high",
    },
    # ── Android-Specific Secrets ─────────────────────────────────────
    {
        "name": "keystore_password",
        "description": "Android Keystore/JKS Password",
        "pattern": re.compile(r"(?i)(store[pP]assword|key[pP]assword|keystore[pP]assword)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{6,})['\"]"),
        "severity": "high",
        "key_group": 2,
    },
    {
        "name": "signing_config",
        "description": "Android Signing Configuration with Password",
        "pattern": re.compile(r"(?i)(storeFile|storePassword|keyAlias|keyPassword)\s*['\"]?[=:]\s*['\"]?[a-zA-Z0-9_\-\./\\]+['\"]?"),
        "severity": "high",
    },
    # ── Generic High-Entropy Secrets ─────────────────────────────────
    {
        "name": "high_entropy_base64",
        "description": "High-Entropy Base64 String (potential key/token)",
        "pattern": re.compile(r"(?<![a-zA-Z0-9])([a-zA-Z0-9+/=]{32,})(?![a-zA-Z0-9])"),
        "severity": "medium",
        "validation": None,
    },
]

# Patterns skipped in ALL string/source scans (high FP rate on generic patterns)
SKIP_PATTERNS_IN_ALL_SCANS = {
    "high_entropy_base64",
    "aws_secret_key",
    "github_old_token",
    "twilio_token",
    "mailchimp_api_key",
}

# Patterns whose matched string is the key itself (not extracted from a group)
DIRECT_MATCH_PATTERNS = {
    "aws_access_key", "google_api_key", "jwt_token", "slack_token",
    "slack_webhook", "github_token", "discord_webhook", "twilio_sid",
    "sendgrid_api_key", "rsa_private_key", "pkcs8_private_key",
    "mongodb_uri", "mysql_uri", "redis_uri", "firebase_url",
    "url_embedded_credentials", "azure_connection_string",
    "google_oauth_client_id",
}

SECRET_NOTEBOOKS = frozenset({
    "example.com", "example.org", "your-api-key", "your_secret",
    "your-password", "your-api-key-here", "replace_me", "changeme",
    "xxxxxxxxxxxx", "your_key", "YOUR_API_KEY", "your_secret_key",
    "test", "testing", "dummy", "placeholder",
})


def _is_placeholder(value: str) -> bool:
    lowered = value.lower().replace("-", "").replace("_", "").replace(" ", "")
    for p in SECRET_NOTEBOOKS:
        norm_p = p.lower().replace("-", "").replace("_", "").replace(" ", "")
        if "." in norm_p:
            if lowered == norm_p:
                return True
        else:
            if norm_p in lowered:
                return True
    return False


def _has_valid_entropy(value: str, min_entropy: float = 3.5) -> bool:
    if len(value) < 8:
        return False
    freq = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    n = len(value)
    entropy = -sum((c / n) * __import__("math").log2(c / n) for c in freq.values())
    return entropy >= min_entropy


# ── Auto-Decode Helpers ──────────────────────────────────────────────

BASE64_RX = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
BASE64URL_RX = re.compile(r'^[A-Za-z0-9_-]*$')
HEX_RX = re.compile(r'^[0-9A-Fa-f]+$')


def _is_printable_text(text: str, min_alpha_pct: float = 40.0) -> bool:
    """Return True if text is mostly printable ASCII with sufficient letter content."""
    if not text or len(text) < 6:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) <= 126 or c in "\t\n\r")
    alpha = sum(1 for c in text if c.isalpha())
    pct_printable = (printable / len(text)) * 100
    pct_alpha = (alpha / len(text)) * 100
    if pct_printable < 80 or pct_alpha < min_alpha_pct:
        return False
    # Shannon entropy: decoded secrets sit in 4.2–6.5 range.
    # Below 4.2: structured text (JSON, short English phrases).
    # Above 6.5: near-random bytes or compressed data — unlikely to be a real secret.
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    entropy = -sum((c / n) * __import__("math").log2(c / n) for c in freq.values())
    return 4.2 <= entropy <= 6.5


def _try_base64_decode(value: str) -> Optional[str]:
    """Try Base64 decode, return decoded text or None (only if readable text)."""
    for candidate in (value, value + "=" * (4 - len(value) % 4)):
        try:
            decoded = base64.b64decode(candidate, validate=True)
            text = decoded.decode("utf-8", errors="replace")
            if _is_printable_text(text):
                return text[:500]
        except Exception:
            continue
    return None


def _try_base64url_decode(value: str) -> Optional[str]:
    """Try Base64URL decode, return decoded text or None."""
    try:
        padded = value + "=" * (4 - len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        text = decoded.decode("utf-8", errors="replace")
        if _is_printable_text(text):
            return text[:500]
    except Exception:
        pass
    return None


def _try_hex_decode(value: str) -> Optional[str]:
    """Try hex decode, return decoded text or None."""
    try:
        decoded = binascii.unhexlify(value)
        text = decoded.decode("utf-8", errors="replace")
        if _is_printable_text(text):
            return text[:500]
    except Exception:
        pass
    return None


def _decode_jwt(value: str) -> Optional[str]:
    """Decode JWT payload (middle segment). Returns JSON preview."""
    parts = value.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        parsed = json.loads(decoded)
        return json.dumps(parsed, indent=2)[:500]
    except Exception:
        return decoded.decode("utf-8", errors="replace")[:500]


def _decode_url_credentials(value: str) -> Optional[str]:
    """Extract and URL-decode credentials from URLs (Basic Auth + query params)."""
    parts = []
    # Basic auth: https://user:pass@host
    m = re.match(r"https?://([^@]+)@", value)
    if m:
        user_pass = m.group(1)
        if ":" in user_pass:
            user, password = user_pass.split(":", 1)
            parts.append(f"user={urllib.parse.unquote(user)} pass={urllib.parse.unquote(password)}")
    # Query params: ?key=...&secret=...&token=...&api_key=...&password=...
    qm = value.find("?")
    if qm >= 0:
        for param in urllib.parse.parse_qs(value[qm + 1:]).items():
            if param[0].lower() in ("key", "secret", "token", "api_key", "api-key", "apikey", "password", "pass", "access_token"):
                parts.append(f"{param[0]}={param[1][0]}")
    return " | ".join(parts) if parts else None


def _decode_connection_string(value: str) -> Optional[str]:
    """Extract credentials from DB connection strings."""
    m = re.match(r"\w+://([^@]+)@", value)
    if not m:
        return None
    user_pass = m.group(1)
    if ":" not in user_pass:
        return None
    user, password = user_pass.split(":", 1)
    user_dec = urllib.parse.unquote(user)
    pass_dec = urllib.parse.unquote(password)
    return f"user={user_dec} pass={pass_dec}"


def auto_decode_secret(
    secret_type: str,
    raw_value: str,
    context: str = "",
) -> Optional[str]:
    """Auto-decode a secret value based on its type and content.

    Tries type-specific decoders first, then falls back to generic
    base64/hex detection on the value or its surrounding context.

    Returns:
        Decoded preview string, or None if no decoding was possible.
    """
    # Type-specific decoders
    if secret_type == "jwt_token":
        result = _decode_jwt(raw_value)
        if result:
            return result

    if secret_type == "url_embedded_credentials":
        result = _decode_url_credentials(raw_value)
        if result:
            return result

    if secret_type in ("mongodb_uri", "mysql_uri", "redis_uri"):
        result = _decode_connection_string(raw_value)
        if result:
            return result

    if secret_type == "rsa_private_key":
        return "(RSA private key header detected — full key omitted from preview)"

    if secret_type == "pkcs8_private_key":
        return "(PKCS#8 private key header detected — full key omitted from preview)"

    # Detect headerless PEM (long base64 blob, likely key material without header)
    stripped = raw_value.strip()
    if len(stripped) > 400 and BASE64_RX.match(stripped) and not _is_placeholder(stripped):
        try:
            decoded = base64.b64decode(stripped)
            if len(decoded) > 20 and decoded[0] == 0x30:
                return f"(potential headerless crypto key — {len(stripped)} chars base64)"
        except Exception:
            pass

    # Generic: if value looks like base64, try to decode
    if BASE64_RX.match(stripped) and len(stripped) >= 16:
        result = _try_base64_decode(stripped)
        if result:
            return result

    if BASE64URL_RX.match(stripped) and len(stripped) >= 16:
        result = _try_base64url_decode(stripped)
        if result:
            return result

    # Try hex
    if HEX_RX.match(stripped) and len(stripped) >= 16:
        result = _try_hex_decode(stripped)
        if result:
            return result

    # Try base64 decode on the raw value from context (some values arrive
    # with surrounding noise)
    if context:
        for token in re.findall(r'[A-Za-z0-9+/=]{20,}', context):
            if BASE64_RX.match(token):
                result = _try_base64_decode(token)
                if result and result not in (raw_value, stripped):
                    return result

    return None


def _dedup_and_enrich(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate by (type, decoded_value) and auto-decode each finding.

    Same secret found in multiple locations or encodings is merged into
    one finding with aggregated source locations.
    """
    groups = {}
    for f in findings:
        raw = f.get("value", "")
        ctx = f.get("context", "")
        decoded = auto_decode_secret(f["secret_type"], raw, ctx)
        if decoded:
            f["decoded"] = decoded

        # Dedup key: use decoded value when available, fall back to raw
        dedup_key = (f["secret_type"], decoded if decoded else raw)

        if dedup_key not in groups:
            f["locations"] = [{"source": f.get("source") or f.get("source_file", "?"),
                               "line": f.get("line_number")}]
            groups[dedup_key] = f
        else:
            existing = groups[dedup_key]
            loc = {"source": f.get("source") or f.get("source_file", "?"),
                   "line": f.get("line_number")}
            if loc not in existing["locations"]:
                existing["locations"].append(loc)

    result = list(groups.values())
    for f in result:
        if len(f["locations"]) > 1:
            f["occurrence_count"] = len(f["locations"])
            f["note"] = f"Found in {len(f['locations'])} locations"
    return result


def scan_strings(
    string_list: List[Dict[str, Any]],
    secret_notebooks: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Scan enumerated string literals for hardcoded secrets.

    Args:
        string_list: List of string dicts with keys 'value', 'source', 'category'.
        secret_notebooks: Optional set of known placeholder values to exclude.
            Uses built-in defaults if not provided.

    Returns:
        List of secret findings, each with name, value, severity, source, and context.
    """
    findings = []
    seen_values: Set[str] = set()
    notebooks = secret_notebooks or SECRET_NOTEBOOKS

    for entry in string_list:
        value = entry.get("value", "")
        if not isinstance(value, str) or len(value) < 6:
            continue
        if value in seen_values:
            continue
        if _is_placeholder(value):
            continue

        for pattern_def in SECRET_PATTERNS:
            if pattern_def.get("name") in SKIP_PATTERNS_IN_ALL_SCANS:
                continue

            match = pattern_def["pattern"].search(value)
            if not match:
                continue

            num_groups = len(match.groups())
            key_group = pattern_def.get("key_group", 1)
            if num_groups == 0:
                matched_value = match.group(0)
            else:
                matched_value = match.group(min(key_group, num_groups))
            if matched_value in seen_values:
                continue
            validation = pattern_def.get("validation")
            if validation and not validation(match):
                continue

            findings.append({
                "secret_type": pattern_def["name"],
                "description": pattern_def["description"],
                "value": matched_value[:80],
                "severity": pattern_def["severity"],
                "source": entry.get("source", "unknown"),
                "category": entry.get("category", "string_literal"),
                "context": value[:120],
            })
            seen_values.add(matched_value)

    return _dedup_and_enrich(findings)


def scan_source_files(
    source_dir: str,
    file_patterns: Tuple[str, ...] = ("*.java", "*.kt", "*.xml", "*.gradle", "*.properties", "*.smali"),
) -> List[Dict[str, Any]]:
    """Scan decompiled source files for hardcoded secrets.

    Scans apktool/smali output directories for secrets embedded in source code.

    Args:
        source_dir: Path to decompiled source root.
        file_patterns: File globs to scan.

    Returns:
        List of secret findings with file paths and line numbers.
    """
    findings = []
    seen_values: Set[str] = set()
    source_path = Path(source_dir)
    if not source_path.exists():
        return findings

    files_to_scan = []
    for pat in file_patterns:
        files_to_scan.extend(source_path.rglob(pat))

    for file_path in files_to_scan:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue

        rel_path = str(file_path.relative_to(source_path))
        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or len(stripped) < 10:
                continue
            if _is_placeholder(stripped):
                continue

            for pattern_def in SECRET_PATTERNS:
                if pattern_def.get("name") in SKIP_PATTERNS_IN_ALL_SCANS:
                    continue
                match = pattern_def["pattern"].search(stripped)
                if not match:
                    continue

                num_groups = len(match.groups())
                key_group = pattern_def.get("key_group", 1)
                if num_groups == 0:
                    matched_value = match.group(0)
                else:
                    matched_value = match.group(min(key_group, num_groups))

                if matched_value in seen_values:
                    continue
                if _is_placeholder(matched_value):
                    continue
                validation = pattern_def.get("validation")
                if validation and not validation(match):
                    continue

                findings.append({
                    "secret_type": pattern_def["name"],
                    "description": pattern_def["description"],
                    "value": matched_value[:80],
                    "severity": pattern_def["severity"],
                    "source_file": rel_path,
                    "line_number": line_no,
                    "context": stripped[:200],
                })
                seen_values.add(matched_value)

    return _dedup_and_enrich(findings)


def scan_high_entropy_strings(
    string_list: List[Dict[str, Any]],
    min_entropy: float = 4.0,
    min_length: int = 24,
    max_length: int = 120,
) -> List[Dict[str, Any]]:
    """Scan for high-entropy strings that may be obfuscated secrets or keys.

    High-entropy strings that are alphanumeric or base64-like can indicate
    embedded credentials, tokens, or keys that don't match known patterns.
    """
    findings = []
    seen_values: Set[str] = set()

    for entry in string_list:
        value = entry.get("value", "")
        if not isinstance(value, str):
            continue
        if len(value) < min_length or len(value) > max_length:
            continue
        if value in seen_values:
            continue
        if _is_placeholder(value):
            continue

        # Skip strings that are mostly hex (likely hashes)
        hex_ratio = sum(1 for c in value if c in "0123456789abcdefABCDEF") / len(value)
        if hex_ratio > 0.9:
            continue

        # Skip if already matched by a specific pattern
        entropy = __import__("analysis.step2_string_enumeration",
                            fromlist=["entropy_of_string"]).entropy_of_string(value)
        if entropy < min_entropy:
            continue

        # Check character variety (both upper, lower, and digits)
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        if not (has_upper and has_lower and has_digit):
            continue

        findings.append({
            "secret_type": "high_entropy_potential_key",
            "description": "High-entropy string (potential key or token)",
            "value": value[:80],
            "severity": "low",
            "entropy": round(entropy, 2),
            "source": entry.get("source", "unknown"),
            "category": entry.get("category", "string_literal"),
        })
        seen_values.add(value)

    return findings


def classify_risk(secret_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Classify the overall secret-leak risk level based on findings.

    Returns a dict with severity, count, score, and summary.
    """
    if not secret_findings:
        return {
            "severity": "none",
            "total_secrets": 0,
            "risk_score": 0,
            "summary": "No hardcoded secrets detected",
        }

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_severity = "low"
    for f in secret_findings:
        sv = f.get("severity", "low")
        if severity_order.get(sv, 0) > severity_order.get(max_severity, 0):
            max_severity = sv

    by_severity: Dict[str, int] = {}
    for f in secret_findings:
        sv = f.get("severity", "low")
        by_severity[sv] = by_severity.get(sv, 0) + 1

    score = by_severity.get("critical", 0) * 10 + by_severity.get("high", 0) * 5 + by_severity.get("medium", 0) * 2
    unique_types = len(set(f["secret_type"] for f in secret_findings))

    return {
        "severity": max_severity,
        "total_secrets": len(secret_findings),
        "unique_types": unique_types,
        "by_severity": by_severity,
        "risk_score": min(score, 100),
        "summary": (
            f"Found {len(secret_findings)} potential hardcoded secrets "
            f"({by_severity.get('critical', 0)} critical, "
            f"{by_severity.get('high', 0)} high, "
            f"{by_severity.get('medium', 0)} medium) "
            f"across {unique_types} types"
        ),
    }


def analyze_hardcoded_secrets(
    string_result: Dict[str, Any],
    scan_high_entropy: bool = False,
) -> Dict[str, Any]:
    """Main entry point: scan enumerated strings for hardcoded secrets.

    Args:
        string_result: Output from step2_string_enumeration.enumerate_strings().
        scan_high_entropy: Whether to include low-severity high-entropy candidate scan.

    Returns:
        Dict with 'findings', 'risk', and 'metadata'.
    """
    all_strings = []
    categories = string_result.get("categories", string_result)
    if isinstance(categories, dict):
        for cat_list in categories.values():
            if isinstance(cat_list, list):
                all_strings.extend(cat_list)

    if not all_strings:
        all_strings = string_result.get("string_literals", [])

    findings = scan_strings(all_strings)

    if scan_high_entropy:
        entropy_findings = scan_high_entropy_strings(all_strings)
        findings.extend(entropy_findings)

    risk = classify_risk(findings)

    return {
        "sample_id": string_result.get("sample_id", ""),
        "hardcoded_secrets": findings,
        "secret_risk": risk,
        "total_scanned": len(all_strings),
        "scan_sources": False,
    }


def format_for_report(findings: List[Dict[str, Any]], max_items: int = 30) -> str:
    """Format secret findings into a readable report section."""
    if not findings:
        return "No hardcoded secrets detected."

    lines = [f"## Hardcoded Secrets ({len(findings)} findings)"]
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    for f in findings:
        by_severity.setdefault(f.get("severity", "low"), []).append(f)

    for level in ("critical", "high", "medium", "low"):
        items = by_severity.get(level, [])
        if not items:
            continue
        lines.append(f"\n### {level.upper()} ({len(items)})")
        for f in items[:max_items]:
            sv = f.get("value", "")[:60]
            src = f.get("source") or f.get("source_file", "?")
            line = f.get("line_number", "")
            location = f"{src}:{line}" if line else src
            decoded = f.get("decoded", "")
            decoded_suffix = f" → {decoded[:60]}" if decoded else ""
            lines.append(f"- [{f['secret_type']}] {sv} ({location}){decoded_suffix}")

    if len(findings) > max_items:
        lines.append(f"\n... and {len(findings) - max_items} more findings")

    return "\n".join(lines)
