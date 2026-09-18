"""
Decoding Engine: Entropy-guided multi-layer decoding with heuristic scoring.

Enhancements for DroidForensix:
  1. Entropy-based decoder selection (prioritize decoders by input entropy)
  2. Multi-layer decoding chains (Base64 → XOR → plaintext)
  3. Heuristic scoring per decoded output (0-100 interpretable score)
  4. C2 indicator extraction (URLs, IPs, domains, commands, packages)
"""

import base64
import binascii
import json
import math
import re
from typing import Dict, List, Any, Optional, Tuple

from analysis.ip_validation import calculate_ip_legitimacy_score, is_reserved_ip


# ---------------------------------------------------------------------------
# Regex patterns for decoding quality assessment and C2 extraction
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?::\d+)?\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
PACKAGE_RE = re.compile(r'\bcom\.(?:[a-zA-Z0-9_]+\.)+[a-zA-Z0-9_]+')
METHOD_CALL_RE = re.compile(r'[a-z][a-zA-Z0-9]*\.[a-z][a-zA-Z0-9]*\(')
COMMAND_RE = re.compile(r'\b(PING|EXEC|UPLOAD|DOWNLOAD|UPDATE|SHELL|CMD|RUN|FETCH|SEND|RECV|CONNECT|DISCONNECT|HEARTBEAT)\b', re.IGNORECASE)
PROTOCOL_MARKER_RE = re.compile(r'\|\|[A-Z]+\|\||\[CMD\]|@CMD|~[A-Z]+~')
JARGON_RE = re.compile(r'[a-z]{4,}')  # Words of 4+ lowercase letters

# Encoded-string heuristics: strings that look like they MIGHT be
# something an attacker left behind.
ENCODED_HEURISTICS = [
    re.compile(r'^[A-Za-z0-9+/]{20,}=*$'),    # Base64-shaped
    re.compile(r'^[A-Za-z0-9_-]{20,}$'),        # B64URL-shaped
    re.compile(r'^[0-9A-Fa-f]{16,}$'),          # Hex-shaped
    re.compile(r'(?:[^\x20-\x7E]){4,}'),        # 4+ non-printable chars
]

# ---------------------------------------------------------------------------
# TLD list for domain validation
# ---------------------------------------------------------------------------
# Top ~150 English dictionary words for decoding quality validation
ENGLISH_DICTIONARY = {
    "a", "about", "after", "again", "all", "also", "an", "and", "any", "are",
    "as", "at", "back", "be", "because", "been", "before", "being", "between",
    "but", "by", "call", "can", "come", "could", "data", "did", "do", "down",
    "each", "end", "even", "first", "for", "from", "get", "go", "good", "had",
    "has", "have", "he", "her", "here", "him", "his", "how", "i", "if", "in",
    "into", "is", "it", "its", "just", "know", "like", "look", "made", "make",
    "man", "many", "may", "me", "more", "most", "much", "my", "new", "no",
    "not", "now", "of", "on", "one", "only", "or", "other", "our", "out",
    "over", "own", "part", "people", "public", "return", "said", "same", "see",
    "she", "should", "show", "so", "some", "state", "still", "such", "take",
    "than", "that", "the", "their", "them", "then", "there", "these", "they",
    "thing", "think", "this", "those", "three", "through", "time", "to", "two",
    "under", "up", "use", "used", "value", "very", "void", "was", "way", "we",
    "well", "were", "what", "when", "where", "which", "while", "who", "will",
    "with", "work", "world", "would", "year", "you", "your",
    # Java/Android-specific common tokens useful for decoded identifiers
    "abstract", "boolean", "break", "case", "catch", "char", "class", "const",
    "continue", "default", "do", "double", "else", "enum", "extends", "false",
    "final", "finally", "float", "for", "goto", "if", "implements", "import",
    "instanceof", "int", "interface", "long", "native", "new", "null", "package",
    "private", "protected", "short", "static", "strictfp", "super", "switch",
    "synchronized", "this", "throw", "throws", "transient", "true", "try",
    "void", "volatile", "while", "android", "app", "activity", "service",
    "content", "intent", "broadcast", "receiver", "provider", "manifest",
    "permission", "string", "object", "system", "context", "manager", "method",
}

COMMON_TLDS = {
    'com', 'net', 'org', 'io', 'co', 'cn', 'ru', 'de', 'jp', 'uk',
    'kr', 'br', 'fr', 'in', 'it', 'au', 'ca', 'nl', 'es', 'mx',
    'biz', 'info', 'tv', 'me', 'cc', 'xyz', 'top', 'club', 'win',
    'bid', 'loan', 'date', 'men', 'download', 'stream', 'ren',
    'tk', 'ml', 'ga', 'cf', 'click', 'link', 'site', 'online',
    'tech', 'store', 'blog', 'app', 'dev', 'cloud', 'host', 'fun',
    'space', 'live', 'pro', 'pub', 'wiki', 'name', 'mobi', 'tel',
}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
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


def printable_ratio(data: bytes) -> float:
    """Ratio of printable ASCII / whitespace bytes."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


# ---------------------------------------------------------------------------
# Decoder primitives
# ---------------------------------------------------------------------------

def decode_base64(s: str) -> Optional[bytes]:
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def decode_base64_urlsafe(s: str) -> Optional[bytes]:
    try:
        padding = 4 - len(s) % 4
        if padding != 4:
            s += '=' * padding
        return base64.urlsafe_b64decode(s)
    except Exception:
        return None


def decode_hex(s: str) -> Optional[bytes]:
    try:
        return binascii.unhexlify(s)
    except Exception:
        return None


def decode_xor(data: bytes, key: int) -> Optional[bytes]:
    try:
        return bytes(b ^ key for b in data)
    except Exception:
        return None


def xor_bruteforce(data: bytes, min_printable: float = 0.70) -> List[Tuple[int, bytes, float]]:
    """Brute-force single-byte XOR keys 1-255, return candidates scored by heuristic quality.

    Computes a composite score: printable_ratio * 0.4 + word_score * 0.6,
    to find the most linguistically meaningful key rather than just printable.
    """
    def reencodable(text: str) -> bool:
        cleaned = text.strip()
        if len(cleaned) < 16:
            return False
        for reg in DECODER_REGISTRY:
            if reg["name"] == "xor":
                continue
            try:
                if reg["detect"](cleaned):
                    return True
            except Exception:
                pass
        return False

    candidates = []
    for key in range(1, 256):
        decrypted = bytes(b ^ key for b in data)
        ratio = printable_ratio(decrypted)
        if ratio >= min_printable:
            try:
                text = decrypted.decode("utf-8", errors="replace")
            except Exception:
                text = decrypted.decode("latin-1", errors="replace")
            words = JARGON_RE.findall(text)
            word_score = len(words) * 2
            text_lower_words = set(text.lower().split())
            dict_score = len(text_lower_words & ENGLISH_DICTIONARY) * 5
            boost = 0.3 if reencodable(text) else 0.0
            composite = ratio * 0.25 + min(1.0, word_score / 20) * 0.25 + min(1.0, dict_score / 20) * 0.3 + boost * 0.2
            candidates.append((key, decrypted, round(composite, 4)))
    candidates.sort(key=lambda x: x[2], reverse=True)
    return candidates[:10]


# ---------------------------------------------------------------------------
# Decoder registry: name -> (detect, decode)
# ---------------------------------------------------------------------------

DECODER_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "base64",
        "detect": lambda s: bool(re.match(r'^[A-Za-z0-9+/]{8,}=*$', s))
            and not bool(re.match(r'^[0-9A-Fa-f]+$', s))  # exclude pure hex
            and (bool(re.search(r'[A-Z]', s)) or '+/' in s),  # must have uppercase or +/
        "decode": lambda s: decode_base64(s),
        "entropy_range": (3.5, 6.5),
        "input_type": "string",
        "priority": 0,  # highest: very specific character set + padding
    },
    {
        "name": "hex",
        "detect": lambda s: bool(re.match(r'^[0-9A-Fa-f]{4,}$', s)),
        "decode": lambda s: decode_hex(s),
        "entropy_range": (2.0, 4.5),
        "input_type": "string",
        "priority": 1,
    },
    {
        "name": "base64_urlsafe",
        "detect": lambda s: bool(re.match(r'^[A-Za-z0-9_-]{8,}$', s))
            and bool(re.search(r'[A-Z]', s))  # must have uppercase (true b64 always mixes case)
            and bool(re.search(r'[a-z]', s)),  # must have lowercase
        "decode": lambda s: decode_base64_urlsafe(s),
        "entropy_range": (3.5, 6.5),
        "input_type": "string",
        "priority": 2,
    },
    {
        "name": "xor",
        "detect": lambda s: True,  # XOR is tried when other decoders fail
        "decode": lambda s: xor_bruteforce(s.encode("latin-1")),
        "entropy_range": (2.0, 8.0),
        "input_type": "bytes",
        "multi_output": True,  # Returns list of candidates
        "priority": 3,  # lowest: everything matches detect()
    },
]


# ---------------------------------------------------------------------------
# Entropy-based decoder selection
# ---------------------------------------------------------------------------

def estimate_decoders_by_entropy(entropy: float) -> List[str]:
    """Return decoder names in priority order based on input entropy.

    Low entropy (< 2.5)    -> try xor first (substitution cipher likely)
    Medium entropy (2.5-4) -> try hex, then xor, then base64
    High entropy (4-6)     -> try base64 first (most likely encoding)
    Very high (> 6)        -> try base64, xor (possibly encrypted)
    """
    if entropy < 2.5:
        return ["xor", "hex", "base64", "base64_urlsafe"]
    elif entropy < 4.0:
        return ["hex", "xor", "base64", "base64_urlsafe"]
    elif entropy < 5.5:
        return ["base64", "base64_urlsafe", "hex", "xor"]
    else:
        return ["base64", "base64_urlsafe", "xor", "hex"]


def decoder_matches_entropy(decoder_name: str, entropy: float) -> bool:
    """Check if a decoder is a plausible match for the input entropy."""
    for reg in DECODER_REGISTRY:
        if reg["name"] == decoder_name:
            low, high = reg["entropy_range"]
            return low <= entropy <= high
    return False


# ---------------------------------------------------------------------------
# "Is decoded?" criteria
# ---------------------------------------------------------------------------

def is_decoded(text: str) -> Tuple[bool, float]:
    """Check if text looks fully decoded (readable, low entropy).

    Returns (is_decoded, confidence 0.0-1.0).
    """
    if not text:
        return False, 0.0

    raw = text.encode("utf-8", errors="replace")
    ent = shannon_entropy(raw)
    printable = printable_ratio(raw)
    numeric_ratio = sum(1 for c in text if c.isdigit() or c in ".,:;- ") / max(len(text), 1)

    signals = 0.0
    total_weight = 0.0

    # 1. Printable ASCII ratio
    weight = 0.20
    total_weight += weight
    if printable > 0.90:
        signals += weight * 1.0
    elif printable > 0.70:
        signals += weight * 0.5

    # 2. Low Shannon entropy
    weight = 0.15
    total_weight += weight
    if ent < 4.0:
        signals += weight * 1.0
    elif ent < 5.0:
        signals += weight * 0.5

    # 3. Contains recognizable lowercase words (minimum bar for "decoded")
    weight = 0.30
    total_weight += weight
    words = JARGON_RE.findall(text)
    if len(words) >= 4:
        signals += weight * 1.0
    elif len(words) >= 2:
        signals += weight * 0.6
    elif len(words) >= 1:
        signals += weight * 0.3

    # 4. Or has strong structural indicators (URLs, IPs, delimiters)
    weight = 0.20
    total_weight += weight
    has_url = bool(URL_RE.search(text))
    has_ip = bool(IP_RE.search(text))
    good_delimiters = bool(re.search(r'[/.:@()\[\]{}]', text))
    if has_url or has_ip:
        signals += weight * 1.0
    elif good_delimiters:
        signals += weight * 0.5

    # 5. Contains common programming/English words
    weight = 0.15
    total_weight += weight
    common = {"the", "this", "that", "with", "from", "class", "public",
              "static", "void", "int", "string", "boolean", "return",
              "null", "true", "false", "new", "import", "package", "android",
              "method", "function", "value", "name", "data", "type", "code"}
    words_set = set(text.lower().split())
    match = words_set & common
    if len(match) >= 2:
        signals += weight * 1.0
    elif len(match) >= 1:
        signals += weight * 0.5

    confidence = signals / total_weight if total_weight > 0 else 0.0

    # Hard requirement: must have at least some word-like content, URL/IP,
    # or strongly structured content (mostly digits, hex, or delimited) to be decoded
    is_structured = numeric_ratio > 0.85 and printable > 0.95
    is_somewhat_structured = numeric_ratio > 0.75 and printable > 0.9
    has_content = (len(JARGON_RE.findall(text)) >= 1 or has_url or has_ip or is_structured or is_somewhat_structured)
    if not has_content:
        return False, round(confidence, 4)

    # Numeric-only override: structured content at a slightly lower threshold
    if is_structured and confidence < 0.55:
        confidence = 0.55

    return confidence > 0.5, round(confidence, 4)


# ---------------------------------------------------------------------------
# Heuristic scoring
# ---------------------------------------------------------------------------

def heuristic_score(decoded: bytes, input_entropy: float, decoder_name: str) -> Dict[str, Any]:
    """Score a decoded output on readability, patterns, entropy, structure.

    Returns dict with total (0-100) and per-factor breakdown.
    """
    if not decoded:
        return {"total": 0, "readability": 0, "patterns": 0,
                "entropy": 0, "structure": 0, "consistency": 0}

    factors: Dict[str, float] = {}

    # Try to decode as text
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        text = decoded.decode("latin-1", errors="ignore")

    # -- Readability (0-35) --
    ascii_pct = printable_ratio(decoded)
    words = JARGON_RE.findall(text)
    word_count = len(words)
    avg_word_len = sum(len(w) for w in words) / max(word_count, 1)

    # Dictionary word matching (real words from English + Java/Android lexicon)
    text_lower_words = set(text.lower().split())
    dict_matches = text_lower_words & ENGLISH_DICTIONARY

    readability = 0.0
    readability += min(10, ascii_pct * 10)   # up to 10 for printable ratio
    readability += min(8, word_count * 2)     # up to 8 for word count (4+ words)
    readability += min(12, len(dict_matches) * 2)  # up to 12 for real dictionary words
    if 3 <= avg_word_len <= 10:
        readability += 5                      # good average word length
    factors["readability"] = round(min(35, readability), 1)

    # -- Pattern matching (0-25) --
    pattern_score = 0.0
    if URL_RE.search(text):
        pattern_score += 10
    if IP_RE.search(text):
        pattern_score += 10
    if DOMAIN_RE.search(text):
        pattern_score += 5
    if PACKAGE_RE.search(text):
        pattern_score += 10
    if METHOD_CALL_RE.search(text):
        pattern_score += 5
    if COMMAND_RE.search(text):
        pattern_score += 8
    if PROTOCOL_MARKER_RE.search(text):
        pattern_score += 10
    factors["patterns"] = round(min(25, pattern_score), 1)

    # -- Entropy of decoded output (0-15) --
    output_entropy = shannon_entropy(decoded)
    if 2.0 <= output_entropy <= 4.0:
        entropy_factor = 15.0       # good plaintext range
    elif 4.0 < output_entropy <= 5.0:
        entropy_factor = 10.0       # acceptable
    elif 5.0 < output_entropy <= 5.5:
        entropy_factor = 5.0        # marginal
    else:
        entropy_factor = 0.0        # still looks encoded or too simple
    factors["entropy"] = round(entropy_factor, 1)

    # -- Structural integrity (0-15) --
    structure = 0.0
    # Discount structure when few real words are present (avoids false positives)
    word_quality = min(1.0, len(dict_matches) * 0.25 + len(words) * 0.05)
    if word_quality < 0.3:
        word_quality = 0.0  # No structure credit for gibberish

    delimiters = [('(', ')'), ('[', ']'), ('{', '}')]
    for open_d, close_d in delimiters:
        o_count = text.count(open_d)
        c_count = text.count(close_d)
        if o_count > 0 and c_count > 0:
            structure += min(o_count, c_count) * 2 * word_quality
    structure = min(12, structure)

    # JSON/XML detection (only if dictionary words exist to confirm it's real)
    if len(dict_matches) >= 2:
        stripped = text.strip()
        if (stripped.startswith('{') and stripped.endswith('}')) or \
           (stripped.startswith('[') and stripped.endswith(']')):
            structure = max(structure, 8)
        elif stripped.startswith('<') and stripped.endswith('>'):
            structure = max(structure, 6)
    factors["structure"] = round(min(15, structure), 1)

    # -- Decoder consistency (0-15) --
    consistency = 0.0
    if decoder_matches_entropy(decoder_name, input_entropy):
        consistency += 10
    if output_entropy < input_entropy * 0.8:
        consistency += 5            # output is clearly less random than input
    factors["consistency"] = round(min(15, consistency), 1)

    total = sum(factors.values())
    return {
        "total": round(min(100, total), 1),
        **factors,
    }


# ---------------------------------------------------------------------------
# C2 indicator extraction
# ---------------------------------------------------------------------------

def is_valid_public_ip(ip_str: str) -> bool:
    """Check if IP is a valid public IPv4 address (not private/loopback).

    Delegates to the ip_validation module for comprehensive RFC range checking.
    """
    is_reserved, _ = is_reserved_ip(ip_str)
    return not is_reserved


def has_valid_tld(domain: str) -> bool:
    """Check if a domain ends with a known TLD."""
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return False
    return parts[-1] in COMMON_TLDS


def extract_c2_indicators(text: str) -> Dict[str, Any]:
    """Extract structured C2 indicators from decoded text.

    Returns dict with:
      - urls: List[str] — extracted URLs
      - ips: List[str] — non-benign IP strings (legitimacy_score >= 30)
      - ip_verdicts: List[Dict] — full IP legitimacy verdicts
      - domains: List[str] — extracted domains
      - packages: List[str] — package names
      - commands: List[str] — command keywords
      - protocol_markers: List[str] — protocol markers
    """
    indicators: Dict[str, Any] = {
        "urls": [],
        "ips": [],
        "ip_verdicts": [],
        "domains": [],
        "packages": [],
        "commands": [],
        "protocol_markers": [],
    }

    # URLs
    urls = list(set(URL_RE.findall(text)))
    indicators["urls"] = [u for u in urls if has_valid_tld(u.split("/")[2].split(":")[0])]

    # IPs with legitimacy scoring
    raw_ips = list(set(IP_RE.findall(text)))
    scored_ips = []
    for ip in raw_ips:
        verdict = calculate_ip_legitimacy_score(ip, text, "")
        if verdict["verdict"] != "likely_benign":
            scored_ips.append(ip)
        indicators["ip_verdicts"].append(verdict)
    indicators["ips"] = scored_ips

    # Domains (from domain regex, excluding URLs that were already captured)
    all_domains = list(set(DOMAIN_RE.findall(text)))
    indicators["domains"] = [
        d for d in all_domains
        if has_valid_tld(d) and not any(d in u for u in indicators["urls"])
    ]

    # Package names
    indicators["packages"] = list(set(PACKAGE_RE.findall(text)))

    # Commands
    indicators["commands"] = list(set(
        m.group(0).upper() for m in COMMAND_RE.finditer(text)
    ))

    # Protocol markers
    indicators["protocol_markers"] = list(set(
        m.group(0) for m in PROTOCOL_MARKER_RE.finditer(text)
    ))

    return indicators


def c2_confidence_boost(indicators: Dict[str, List[str]]) -> float:
    """Calculate confidence boost from C2 indicators (0.0-0.5)."""
    boost = 0.0
    if indicators["urls"]:
        boost += 0.15
    if indicators["ips"]:
        boost += 0.12
    if indicators["commands"]:
        boost += 0.20
    if indicators["protocol_markers"]:
        boost += 0.15
    if indicators["packages"]:
        boost += 0.08
    return round(min(0.5, boost), 4)


# ---------------------------------------------------------------------------
# Multi-layer decoding
# ---------------------------------------------------------------------------

def try_single_decode(decoder_name: str, raw_input: str, input_bytes: bytes) -> List[Dict[str, Any]]:
    """Try a single decoder and return list of (text, bytes, confidence) results."""
    results = []

    if decoder_name == "base64":
        decoded = decode_base64(raw_input)
        if decoded:
            results.append({
                "decoder": "base64",
                "output_bytes": decoded,
                "key": None,
            })

    elif decoder_name == "base64_urlsafe":
        decoded = decode_base64_urlsafe(raw_input)
        if decoded:
            results.append({
                "decoder": "base64_urlsafe",
                "output_bytes": decoded,
                "key": None,
            })

    elif decoder_name == "hex":
        decoded = decode_hex(raw_input)
        if decoded:
            results.append({
                "decoder": "hex",
                "output_bytes": decoded,
                "key": None,
            })

    elif decoder_name == "xor":
        candidates = xor_bruteforce(input_bytes)
        for key, decrypted, _ratio in candidates[:3]:
            results.append({
                "decoder": "xor",
                "output_bytes": decrypted,
                "key": key,
            })

    return results


def bytes_to_text(data: bytes) -> str:
    """Best-effort bytes to text."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except Exception:
            return data.hex()


def repair_surrogates(text: str) -> str:
    """Repair lone surrogates left over from MUTF-8/CESU-8 (DEX string) data.

    Android stores strings as Modified UTF-8, which encodes supplementary
    characters as surrogate pairs. When such data is decoded as plain UTF-8
    the halves survive as lone surrogates that crash strict UTF-8 encodes.
    Valid pairs are merged back into a single code point; remaining lone
    halves become U+FFFD so downstream encoding never fails.
    """
    has_surrogate = any(0xD800 <= ord(c) <= 0xDFFF for c in text)
    if not has_surrogate:
        return text
    chars = []
    i, n = 0, len(text)
    while i < n:
        code = ord(text[i])
        if 0xD800 <= code <= 0xDBFF and i + 1 < n and 0xDC00 <= ord(text[i + 1]) <= 0xDFFF:
            codepoint = 0x10000 + ((code - 0xD800) << 10) + (ord(text[i + 1]) - 0xDC00)
            chars.append(chr(codepoint))
            i += 2
        elif 0xD800 <= code <= 0xDFFF:
            chars.append("\ufffd")
            i += 1
        else:
            chars.append(text[i])
            i += 1
    return "".join(chars)


def _applicable_decoders(text: str, data: bytes, depth: int,
                         decoded_confidence: float = 0.0) -> List[str]:
    """Return decoders that could apply to this input, ordered by specificity.

    At depth 0, uses detect() as a hard pre-filter.
    At depth > 0, also tries XOR on raw bytes if output is not fully decoded.
    """
    # At depth > 0, check if we should try further decoding
    if depth > 0 and decoded_confidence < 0.5:
        clean_text = text.strip()
        no_ws = "".join(c for c in clean_text if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")

        # Try hex on cleaned text
        hex_ratio = sum(1 for c in clean_text if c in "0123456789abcdefABCDEF") / max(len(clean_text), 1)
        if hex_ratio >= 0.8 and len(clean_text) >= 8:
            return ["hex"]

        # Try base64-like on whitespace-stripped text
        if len(no_ws) >= 8:
            for reg in DECODER_REGISTRY:
                if reg["name"] in ("base64", "base64_urlsafe", "hex") and reg["detect"](no_ws):
                    base_candidates = [reg["name"]]
                    base_candidates.append("xor")
                    return base_candidates

        # Always try XOR as fallback for undecoded output
        return ["xor"]

    # Default: standard detect-filtered + priority-ordered
    applicable = []
    for reg in DECODER_REGISTRY:
        name = reg["name"]
        if depth > 0 and name == "xor":
            continue
        if depth > 0 and name == "hex":
            hex_ratio = sum(1 for c in text if c in "0123456789abcdefABCDEF") / max(len(text), 1)
            if hex_ratio < 0.8:
                continue
        if name == "xor" and depth == 0:
            # At depth 0, only try XOR if input does NOT already look decoded
            if decoded_confidence >= 0.5:
                continue
        if reg["detect"](text):
            applicable.append((reg.get("priority", 99), name))

    applicable.sort()
    return [name for _, name in applicable]


def multi_layer_decode(encoded_string: str, max_depth: int = 3,
                       min_score: float = 15.0) -> Dict[str, Any]:
    """Chain decoders intelligently to detect multi-layer encoding.

    At each layer, tries decoders in entropy-priority + detect-filter order.
    Stops when output looks fully decoded or max_depth reached.

    Returns dict with chain path, per-layer results, and final output.
    """
    # Repair lone surrogates (MUTF-8/CESU-8 from DEX) so strict UTF-8
    # encodes below never crash with UnicodeEncodeError.
    encoded_string = repair_surrogates(encoded_string)
    input_entropy = shannon_entropy(encoded_string.encode("utf-8", errors="replace"))

    result: Dict[str, Any] = {
        "original": encoded_string,
        "original_entropy": round(input_entropy, 4),
        "original_entropy_classification": classify_entropy(input_entropy),
        "layers": [],
        "final_output": None,
        "final_text": None,
        "chain_path": [],
        "heuristic_scores": [],
        "total_confidence": 0.0,
    }

    # Skip if too short (min 8 bytes after stripping and deducing)
    if len(encoded_string.strip().rstrip("=")) < 8:
        return result

    current_str = encoded_string
    current_bytes = encoded_string.encode("latin-1", errors="ignore")
    depth = 0

    while depth < max_depth:
        # Check if current output already looks decoded
        text_so_far = bytes_to_text(current_bytes)
        decoded_ok, decoded_conf = is_decoded(text_so_far)
        if decoded_ok and depth > 0:
            break

        # Get decoders that apply to this input
        _, decoded_conf = is_decoded(text_so_far)
        decoder_order = _applicable_decoders(current_str, current_bytes, depth, decoded_conf)

        decoded_this_layer = False
        best_output = None
        best_text = None
        best_score = None
        best_candidate = None

        for decoder_name in decoder_order:
            candidates = try_single_decode(decoder_name, current_str, current_bytes)
            for candidate in candidates:
                output = candidate["output_bytes"]
                output_text = bytes_to_text(output)
                score = heuristic_score(output, shannon_entropy(current_bytes), decoder_name)

                # Boost score if output is re-encodable (detected by another decoder)
                # This handles intermediate layers (e.g., XOR that produces base64)
                if decoder_name == "xor":
                    for reg in DECODER_REGISTRY:
                        if reg["name"] != "xor" and reg["detect"](output_text.strip()):
                            score["total"] = min(100, score["total"] + 20)
                            break

                if score["total"] < min_score:
                    continue

                # Apply decoder priority bonus: higher priority (lower number) gets a boost
                # This prevents lower-specificity decoders (like XOR) from beating
                # higher-specificity decoders (like base64) on accidental matches
                priority_bonus = 0.0
                for reg in DECODER_REGISTRY:
                    if reg["name"] == decoder_name:
                        priority_bonus = max(0, (3 - reg.get("priority", 3)) * 10)
                        break
                adjusted_total = score["total"] + priority_bonus

                if best_score is None or adjusted_total > best_score.get("adjusted", 0):
                    score["adjusted"] = adjusted_total
                    best_score = score
                    best_output = output
                    best_text = output_text
                    best_candidate = candidate
                    best_candidate["decoder_name"] = decoder_name

        if best_candidate is not None:
            # XOR output must look decoded (XOR has no real detect fn)
            if best_candidate.get("decoder_name") == "xor":
                output_ok, _ = is_decoded(best_text)
                if not output_ok:
                    # Accept only if the XOR output is re-encodable by a higher-specificity decoder
                    is_reencodable = False
                    for reg in DECODER_REGISTRY:
                        if reg["name"] != "xor" and reg["detect"](best_text.strip()):
                            is_reencodable = True
                            break
                    if not is_reencodable:
                        best_candidate = None

        if best_candidate is not None:
            layer_entry = {
                "depth": depth,
                "decoder": best_candidate["decoder_name"],
                "input_preview": current_str[:80],
                "output_preview": best_text[:200],
                "output_bytes_length": len(best_output),
                "heuristic_score": best_score,
                "xor_key": best_candidate.get("key"),
            }
            result["layers"].append(layer_entry)
            result["chain_path"].append(best_candidate["decoder_name"])
            result["heuristic_scores"].append(best_score["total"])

            current_str = best_text
            current_bytes = best_output
            decoded_this_layer = True

        if not decoded_this_layer:
            break  # No decoder succeeded at this layer

        depth += 1

    # Final output
    result["final_output"] = current_str[:1000]
    result["final_text"] = current_str[:1000]
    result["output_bytes"] = current_bytes

    # Calculate total confidence from heuristic scores
    if result["heuristic_scores"]:
        avg_score = sum(result["heuristic_scores"]) / len(result["heuristic_scores"])
        # Normalize to 0-1 (100 heuristic = 1.0 confidence)
        result["total_confidence"] = round(min(1.0, avg_score / 100.0), 4)

    # C2 indicator extraction from final output
    result["c2_indicators"] = extract_c2_indicators(current_str[:5000])

    # Confidence boost from C2 indicators
    c2_boost = c2_confidence_boost(result["c2_indicators"])
    result["c2_confidence_boost"] = c2_boost
    result["total_confidence"] = round(min(1.0, result["total_confidence"] + c2_boost), 4)

    return result


def classify_entropy(entropy: float) -> str:
    """Bucketize Shannon entropy into coarse classes.

    Canonical boundaries used across step3 (entropy_classification) and
    multi-layer decoding (original_entropy_classification). Single source of
    truth so both modules report the same label.
    """
    if entropy < 2.5:
        return "very_low"
    if entropy < 4.0:
        return "low"
    if entropy < 5.5:
        return "medium"
    if entropy < 6.5:
        return "high"
    return "very_high"


# Back-compat alias for existing callers.
_classify_entropy = classify_entropy


# ---------------------------------------------------------------------------
# Full pipeline integration
# ---------------------------------------------------------------------------

def run_decoding_engine(strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run the full decoding engine on a list of string entries.

    Each entry should have: value, entropy, source, category.

    Returns enhanced entries with multi-layer decode results, heuristic
    scores, C2 indicators, and confidence metadata.
    """
    results = []
    for s in strings:
        value = s.get("value", "")
        entropy = s.get("entropy", shannon_entropy(value.encode("utf-8", errors="replace")))
        if len(value) < 8:
            continue

        # Run multi-layer decoding
        ml_result = multi_layer_decode(value)

        entry = {
            "value": value,
            "entropy": entropy,
            "source": s.get("source", "unknown"),
            "category": s.get("category", "unknown"),
            "decoding": {
                "original_entropy": ml_result["original_entropy"],
                "original_entropy_classification": ml_result["original_entropy_classification"],
                "chain_path": ml_result["chain_path"],
                "layers": ml_result["layers"],
                "final_output": ml_result["final_output"],
                "heuristic_score": ml_result["heuristic_scores"][-1] if ml_result["heuristic_scores"] else 0,
                "total_confidence": ml_result["total_confidence"],
                "c2_indicators": ml_result["c2_indicators"],
                "c2_confidence_boost": ml_result["c2_confidence_boost"],
            }
        }

        # Simpler surface-level fields for backward compatibility
        if ml_result["layers"]:
            last_layer = ml_result["layers"][-1]
            entry["decoded_text"] = last_layer["output_preview"]
            entry["decoder_used"] = last_layer["decoder"]
            entry["decoder_key"] = last_layer.get("xor_key")
        else:
            entry["decoded_text"] = None
            entry["decoder_used"] = None
            entry["decoder_key"] = None

        results.append(entry)

    return results


if __name__ == "__main__":
    import sys
    # Demo mode: test decoding engine on provided strings
    test_strings = sys.argv[1:] if len(sys.argv) > 1 else [
        "aGVsbG8gd29ybGQ=",  # Base64 "hello world"
        "AAECAwQFBgcICQoLDA0ODw==",  # Base64 of sequential bytes
        "SGVsbG8gV29ybGQgMTIz",  # Base64 "Hello World 123"
        "48656c6c6f20576f726c64",  # Hex "Hello World"
    ]
    for s in test_strings:
        result = run_decoding_engine([{"value": s, "entropy": shannon_entropy(s.encode("utf-8"))}])
        r = result[0]["decoding"]
        print(f"\n=== {s[:40]} ===")
        print(f"  Entropy: {r['original_entropy']} ({r['original_entropy_classification']})")
        print(f"  Chain: {' -> '.join(r['chain_path']) or 'none'}")
        print(f"  Final: {r['final_output'][:80]}")
        print(f"  Heuristic: {r['heuristic_score']}/100")
        print(f"  Confidence: {r['total_confidence']}")
        if r['c2_indicators']['urls'] or r['c2_indicators']['ips']:
            print(f"  C2 URLs: {r['c2_indicators']['urls']}")
            print(f"  C2 IPs: {r['c2_indicators']['ips']}")
        if r['c2_indicators']['commands']:
            print(f"  C2 Commands: {r['c2_indicators']['commands']}")
