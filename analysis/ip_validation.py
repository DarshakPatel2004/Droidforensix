"""
IP Legitimacy Validation Framework

Multi-layer validation strategy for reducing false positives in C2 IP detection:
  Layer 2: Reserved/private range filtering
  Layer 3: Contextual analysis (port, protocol, source context)
  Layer 5: Behavioral indicators (C2 keywords, encryption, obfuscation)
"""

import re
from typing import Dict, List, Tuple, Optional


# ---------------------------------------------------------------------------
# Layer 2: Reserved / Private IP Range Definitions
# ---------------------------------------------------------------------------

RESERVED_IP_RANGES: Dict[str, List[Tuple[str, str]]] = {
    'private': [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
    ],
    'localhost': [
        ('127.0.0.0', '127.255.255.255'),
    ],
    'link_local': [
        ('169.254.0.0', '169.254.255.255'),
    ],
    'documentation': [
        ('192.0.2.0', '192.0.2.255'),          # TEST-NET-1 (RFC 5737)
        ('198.51.100.0', '198.51.100.255'),    # TEST-NET-2
        ('203.0.113.0', '203.0.113.255'),      # TEST-NET-3
    ],
    'multicast': [
        ('224.0.0.0', '255.255.255.255'),
    ],
    'reserved': [
        ('0.0.0.0', '0.255.255.255'),
        ('240.0.0.0', '255.255.255.255'),
    ],
}


def ip_to_int(ip_str: str) -> int:
    """Convert dotted-decimal IP string to integer."""
    parts = [int(p) for p in ip_str.split('.')]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def is_reserved_ip(ip_str: str) -> Tuple[bool, str]:
    """
    Layer 2: Check if IP falls in reserved/private ranges.

    Returns:
        (is_reserved, reason) where is_reserved=True means reject
    """
    ip_str = ip_str.split(':')[0]
    try:
        parts = [int(p) for p in ip_str.split('.')]
        if len(parts) != 4:
            return True, "Malformed IP"
        if not all(0 <= p <= 255 for p in parts):
            return True, "Out of range"
        ip_int = ip_to_int(ip_str)
    except (ValueError, IndexError):
        return True, "Invalid format"

    for range_type, ranges in RESERVED_IP_RANGES.items():
        for start, end in ranges:
            start_int = ip_to_int(start)
            end_int = ip_to_int(end)
            if start_int <= ip_int <= end_int:
                return True, f"Reserved ({range_type})"

    return False, "Public IP"


# ---------------------------------------------------------------------------
# Layer 3: Contextual Analysis
# ---------------------------------------------------------------------------


def contextual_score(ip_str: str, full_decoded_string: str, source_location: str) -> int:
    """
    Layer 3: Score IP based on context in which it appears.

    Returns:
        0-20: contextual confidence points (added to final score)
    """
    score = 0
    decoded_lower = full_decoded_string.lower()
    source_lower = source_location.lower()

    # 1. Port number present?
    if re.search(rf'{re.escape(ip_str)}:\d+', full_decoded_string):
        score += 10

    # 2. Preceded by protocol/connection indicator?
    protocol_patterns = [
        r'https?://',
        r'socket',
        r'connect',
        r'establish',
        r'host\s*:',
        r'server\s*:',
        r'endpoint',
        r'gateway',
    ]

    for pattern in protocol_patterns:
        if re.search(pattern + r'\s*' + re.escape(ip_str), decoded_lower):
            score += 15
            break

    # 3. In suspicious method/class context?
    suspicious_contexts = [
        'c2', 'command', 'control', 'botnet',
        'payload', 'exfiltrate', 'backdoor',
        'trojan', 'rat', 'remote', 'beacon',
        'infect', 'malware', 'virus',
    ]

    for context in suspicious_contexts:
        if context in source_lower:
            score += 10
            break

    # 4. Repeated multiple times?
    ip_count = full_decoded_string.count(ip_str)
    if ip_count > 1:
        score += min(5, ip_count - 1)

    # 5. In encryption/obfuscation code?
    crypto_patterns = [
        r'encrypt', r'decrypt', r'cipher', r'aes', r'des', r'rsa',
        r'hash', r'sha', r'md5', r'hmac', r'ssl', r'tls',
    ]

    for pattern in crypto_patterns:
        if re.search(pattern, decoded_lower):
            score += 5
            break

    return min(score, 20)


# ---------------------------------------------------------------------------
# Layer 5: Behavioral Context Scoring
# ---------------------------------------------------------------------------


def behavioral_context_score(ip_str: str, full_decoded: str) -> int:
    """
    Layer 5: Score based on behavioral indicators in decoded artifact.

    Returns:
        0-30: behavioral confidence points
    """
    score = 0
    decoded_lower = full_decoded.lower()

    # Legitimate indicators (reduce score)
    legitimate_patterns = [
        r'ntp\s+server',
        r'dns\s+resolver',
        r'time\s+server',
        r'pool\.ntp',
        r'google\.com',
        r'cloudflare\.com',
        r'openssl',
        r'certificate',
        r'update\s+check',
        r'version\s+check',
    ]

    for pattern in legitimate_patterns:
        if re.search(pattern, decoded_lower):
            return 0

    # Malicious indicators (boost score)
    malicious_patterns = [
        (r'backdoor|trojan|rat|botnet', 25),
        (r'command.*execute|execute.*command', 20),
        (r'exfiltrat|steal|upload.*data|log.*key', 20),
        (r'encrypt.*payload|obfuscat', 15),
        (r'c2|cmd|control|beacon|heartbeat', 20),
        (r'reverse\s*shell|remote\s*access', 20),
        (r'privilege\s*escalat', 15),
        (r'persist|autostart|startup', 15),
        (r'socks|proxy|tunnel', 10),
    ]

    for pattern, points in malicious_patterns:
        if re.search(pattern, decoded_lower):
            score += points
            break

    return min(score, 30)


# ---------------------------------------------------------------------------
# Version number false positive filter
# ---------------------------------------------------------------------------

VERSION_IP_PATTERN = re.compile(
    r'(?:v|version|release)\s*\.?\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    re.IGNORECASE,
)


def is_version_number(ip_str: str, full_context: str) -> bool:
    """Check if IP-like pattern is actually a version number."""
    return bool(VERSION_IP_PATTERN.search(full_context))


# ---------------------------------------------------------------------------
# Final IP Legitimacy Score
# ---------------------------------------------------------------------------


def calculate_ip_legitimacy_score(
    ip_str: str,
    full_decoded_string: str,
    source_location: str,
    asn_info: Optional[Dict] = None,
) -> Dict:
    """
    Comprehensive IP legitimacy scoring across all layers.

    Returns:
        {
            'ip': str,
            'legitimacy_score': int (0-100),
            'verdict': 'likely_benign' | 'uncertain' | 'likely_malicious',
            'factors': dict,
        }
    """
    score = 0
    factors: Dict = {}

    ip_clean = ip_str.split(':')[0]

    # Version number check (instant reject)
    if is_version_number(ip_clean, full_decoded_string):
        return {
            'ip': ip_str,
            'legitimacy_score': 0,
            'verdict': 'likely_benign',
            'reason': 'Version number (not an IP)',
            'factors': {'version_check': {'reason': 'version_pattern', 'points': 0}},
        }

    # Layer 2: Reserved ranges (automatic rejection)
    is_reserved, reason = is_reserved_ip(ip_clean)
    if is_reserved:
        return {
            'ip': ip_str,
            'legitimacy_score': 0,
            'verdict': 'likely_benign',
            'reason': reason,
            'factors': {'reserved_check': {'reason': reason, 'points': 0}},
        }
    factors['reserved_check'] = {'passed': True, 'points': 5}
    score += 5

    # Layer 3: Contextual analysis
    context_pts = contextual_score(ip_clean, full_decoded_string, source_location)
    factors['contextual'] = {'points': context_pts}
    score += context_pts

    # Layer 5: Behavioral context
    behav_pts = behavioral_context_score(ip_clean, full_decoded_string)
    factors['behavioral'] = {'points': behav_pts}
    score += behav_pts

    # Layer 4: ASN lookup (if available)
    asn_pts = 0
    if asn_info:
        org_type = asn_info.get('type', 'unknown')
        risk_level = asn_info.get('risk_level', 'unknown')
        if org_type == 'cdn':
            asn_pts = 0
        elif org_type == 'datacenter':
            asn_pts = 15
        elif risk_level == 'high':
            asn_pts = 20
        else:
            asn_pts = 10

        factors['asn'] = {
            'org': asn_info.get('org', ''),
            'type': org_type,
            'risk_level': risk_level,
            'points': asn_pts,
        }
    else:
        factors['asn'] = {'points': 0, 'reason': 'no_lookup'}

    score += asn_pts

    # Normalize to 0-100
    max_score = 5 + 20 + 30 + 20
    legitimacy_score = min(100, int((score / max_score) * 100))

    if legitimacy_score < 30:
        verdict = 'likely_benign'
    elif legitimacy_score < 60:
        verdict = 'uncertain'
    else:
        verdict = 'likely_malicious'

    return {
        'ip': ip_str,
        'legitimacy_score': legitimacy_score,
        'verdict': verdict,
        'factors': factors,
        'confidence': score,
    }
