import logging
import math
import re
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{20,}=*$')
HEX_PATTERN = re.compile(r'^[0-9A-Fa-f]{16,}$')


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def string_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    set_a, set_b = set(a), set(b)
    if not set_a or not set_b:
        return 0.0
    j = len(set_a & set_b) / len(set_a | set_b)
    return j


def classify_obfuscation_type(s: str) -> str:
    if BASE64_PATTERN.match(s):
        return "base64"
    if HEX_PATTERN.match(s):
        return "hex"
    high_entropy = shannon_entropy(s)
    if high_entropy > 6.5:
        return "encrypted_or_packed"
    contains_binary = any(ord(c) < 32 and ord(c) not in (9, 10, 13) for c in s)
    if contains_binary:
        return "binary"
    return "plaintext"


def cluster_high_entropy_strings(
    strings: List[str],
    entropy_threshold: float = 5.5,
    similarity_threshold: float = 0.6,
) -> Dict[str, Any]:
    if not strings:
        return {"clusters": [], "total_clusters": 0, "high_entropy_strings": []}
    if not isinstance(strings, list):
        return {"clusters": [], "total_clusters": 0, "high_entropy_strings": []}

    high_entropy = []
    for s in strings:
        ent = shannon_entropy(s)
        if ent >= entropy_threshold:
            high_entropy.append({
                "value": s[:200],
                "entropy": round(ent, 2),
                "length": len(s),
                "type": classify_obfuscation_type(s),
            })

    clusters = []
    assigned = set()
    for i, a in enumerate(high_entropy):
        if i in assigned:
            continue
        cluster = [high_entropy[i]]
        assigned.add(i)
        for j, b in enumerate(high_entropy):
            if j in assigned:
                continue
            sim = string_similarity(a["value"], b["value"])
            if sim >= similarity_threshold:
                cluster.append(high_entropy[j])
                assigned.add(j)
        if len(cluster) > 1:
            clusters.append({
                "size": len(cluster),
                "avg_entropy": round(sum(m["entropy"] for m in cluster) / len(cluster), 2),
                "dominant_type": max(set(m["type"] for m in cluster),
                                     key=lambda t: sum(1 for m in cluster if m["type"] == t)),
                "members": [m["value"] for m in cluster],
            })

    clusters.sort(key=lambda c: -c["size"])

    return {
        "high_entropy_strings": high_entropy,
        "clusters": clusters,
        "total_clusters": len(clusters),
        "total_high_entropy": len(high_entropy),
    }
