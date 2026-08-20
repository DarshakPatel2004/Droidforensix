"""
Step 17: Code Similarity & Malware Family Clustering.

Uses MinHash (128 permutations, SHA-256 based) over method signatures
to estimate Jaccard similarity between APK samples. The similarity
estimate is unbiased and independent of method count.
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Dict, List, Any

from backend.config import settings
from analysis.cross_sample_index import load_index, add_to_index

logger = logging.getLogger(__name__)

NUM_PERMUTATIONS = 128
_MAX_HASH = 1 << 256


class MinHash:
    def __init__(self, num_perm: int = NUM_PERMUTATIONS, seed: int = 42):
        self.num_perm = num_perm
        self.seeds = [
            hashlib.sha256(f"{seed}:{i}".encode()).hexdigest() for i in range(num_perm)
        ]
        self.hash_values = [_MAX_HASH] * num_perm

    def update(self, signature: str):
        for i, seed_hex in enumerate(self.seeds):
            h = int(hashlib.sha256(f"{signature}:{seed_hex}".encode('utf-8')).hexdigest(), 16)
            if h < self.hash_values[i]:
                self.hash_values[i] = h

    def jaccard(self, other: 'MinHash') -> float:
        if self.num_perm != other.num_perm:
            raise ValueError("MinHash instances must have same num_perm")
        return sum(1 for a, b in zip(self.hash_values, other.hash_values) if a == b) / self.num_perm


def hash_method_signature(full_signature: str) -> str:
    return hashlib.sha256(full_signature.encode("utf-8")).hexdigest()


def extract_methods_from_source(extracted_path: str) -> List[Dict[str, Any]]:
    methods = []
    base = Path(extracted_path)
    source_dirs = [d for d in [base / "sources", base / "smali"] if d.is_dir()]

    method_pattern = re.compile(r'\.method\s+(?:public|private|protected|static|final)?\s*(.+?)$', re.MULTILINE)
    class_pattern = re.compile(r'\.class\s+(?:public|private|protected|static|final)?\s*(.+?)$', re.MULTILINE)

    for src_dir in source_dirs:
        for fpath in src_dir.rglob("*.smali"):
            try:
                text = fpath.read_text("utf-8", errors="ignore")
                current_class = ""
                for match in class_pattern.finditer(text):
                    current_class = match.group(1).strip()
                for match in method_pattern.finditer(text):
                    sig = match.group(1).strip()
                    if sig and len(sig) > 3:
                        methods.append({
                            "class": current_class or str(fpath.stem),
                            "method": sig.split("(")[0] if "(" in sig else sig.split()[0] if sig.split() else sig,
                            "descriptor": sig,
                        })
            except Exception:
                continue

    return methods


def build_sample_signature(methods: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not methods:
        return {"method_signatures": [], "minhash_values": [], "total_methods": 0}

    signatures = []
    minhash = MinHash()
    for m in methods:
        full = f"{m.get('class', '')}->{m.get('method', '')}{m.get('descriptor', '')}"
        signatures.append(hash_method_signature(full))
        minhash.update(full)

    return {
        "method_signatures": signatures,
        "minhash_values": minhash.hash_values,
        "total_methods": len(methods),
    }


def jaccard_similarity(a: List[int], b: List[int]) -> float:
    if not a or not b:
        return 0.0
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


def match_against_index(
    query_signature: Dict[str, Any],
    index: Dict[str, Any],
    threshold: float = 0.3,
) -> Dict[str, Any]:
    query_minhash = query_signature.get("minhash_values", [])
    if not query_minhash:
        return {"matches": [], "best_match": None}

    matches = []
    for sample_id, entry in index.get("samples", {}).items():
        sample_minhash = entry.get("minhash_values", [])
        if not sample_minhash:
            continue
        similarity = jaccard_similarity(query_minhash, sample_minhash)
        if similarity >= threshold:
            matches.append({
                "sample_id": sample_id,
                "family": entry.get("family", "unknown"),
                "similarity": round(similarity, 4),
                "method_count": entry.get("signature_count", 0),
            })

    matches.sort(key=lambda m: -m["similarity"])
    best = matches[0] if matches else None

    return {"matches": matches, "best_match": best}


def load_or_build_index() -> Dict[str, Any]:
    return load_index()


def cluster_family(
    sample_id: str,
    apk_info: Dict[str, Any],
    result: Dict[str, Any],
) -> Dict[str, Any]:
    extracted_path = apk_info.get("extracted_path") or apk_info.get("work_dir", "")
    if not extracted_path:
        return {"matches": [], "best_match": None, "total_matches": 0}

    methods = extract_methods_from_source(extracted_path)
    signature = build_sample_signature(methods)
    index = load_index()
    match_result = match_against_index(signature, index)

    family = result.get("family_identification", {}).get("family", "unknown")
    add_to_index(sample_id, family, signature)

    return {
        "total_methods_extracted": signature["total_methods"],
        "total_signatures": len(signature["method_signatures"]),
        "best_match": match_result["best_match"],
        "matches": match_result["matches"][:20],
        "total_matches": len(match_result["matches"]),
        "index_size": len(index.get("samples", {})),
    }


def get_family_graph_data() -> Dict[str, Any]:
    """
    NOTE: O(n²) pairwise edge-building over the entire index. Needs a cap
    or incremental-update strategy once the index passes a few thousand
    samples.
    """
    index = load_index()
    nodes = []
    edges = []

    samples = index.get("samples", {})
    for sid, entry in samples.items():
        nodes.append({
            "id": sid,
            "family": entry.get("family", "unknown"),
            "method_count": entry.get("signature_count", 0),
        })

    ids = list(samples.keys())
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a_minhash = samples[ids[i]].get("minhash_values", [])
            b_minhash = samples[ids[j]].get("minhash_values", [])
            sim = jaccard_similarity(a_minhash, b_minhash)
            if sim >= 0.3:
                edges.append({
                    "source": ids[i],
                    "target": ids[j],
                    "similarity": round(sim, 4),
                })

    return {"nodes": nodes, "edges": edges, "total_samples": len(nodes)}
