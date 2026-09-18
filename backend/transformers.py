"""
Data transformers for DroidForensix backend.

Converts pipeline_result.json into frontend-friendly formats:
- 3D graph nodes/edges
- Clustering data (3D scatter)
- Timeline data (attack progression)
"""

import hashlib
import json
import logging
import math
import time
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Any, Optional

from backend.config import settings

logger = logging.getLogger(__name__)


WORK_DIR = settings.WORK_DIR


_ALL_RESULTS_CACHE: list | None = None
_ALL_RESULTS_MTIME: float = 0
_ALL_RESULTS_TTL = 300  # seconds before re-scanning disk (pipeline results are immutable)

# Lightweight family index: sample_id -> family
_FAMILY_INDEX_CACHE: dict[str, str] | None = None
_FAMILY_INDEX_MTIME: float = 0
_FAMILY_INDEX_TTL = 300


# ---------------------------------------------------------------------------
# Color palette for node types
# ---------------------------------------------------------------------------

NODE_COLORS = {
    "encoded_string": "#FF6B6B",      # Red
    "decoding_function": "#4ECDC4",   # Teal
    "decoded_artifact": "#45B7D1",    # Blue
    "usage": "#96CEB4",               # Green
    "c2_infrastructure": "#FFEAA7",   # Yellow
    "config": "#DDA0DD",              # Plum
    "sample": "#A29BFE",              # Purple
}

EDGE_COLORS = {
    "decode": "#4ECDC4",
    "usage": "#96CEB4",
    "exfiltration": "#FF6B6B",
}


# ---------------------------------------------------------------------------
# Surrogate sanitizer
# ---------------------------------------------------------------------------


def _strip_surrogates(obj):
    """Recursively replace lone surrogates with U+FFFD.

    Binary APK data decoded as UTF-8 can leave lone surrogates in strings.
    Python's json.dump tolerates them, but Pydantic's JSON serializer
    (used by FastAPI) raises UnicodeEncodeError on them.
    """
    if isinstance(obj, str):
        return obj.encode("utf-8", "surrogatepass").decode("utf-8", "ignore")
    if isinstance(obj, dict):
        return {k: _strip_surrogates(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_surrogates(v) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# Load helpers
# ---------------------------------------------------------------------------


def load_result(sample_id: str) -> Optional[Dict[str, Any]]:
    """Load pipeline_result.json for a sample."""
    path = WORK_DIR / sample_id / "pipeline_result.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            result = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        # Corrupt/truncated result (e.g. interrupted write): treat as not found
        # so callers degrade to 404 instead of crashing with 500.
        logger.warning("Skipping corrupt pipeline result: %s", path)
        return None

    # Strip lone surrogates so Pydantic/JSON serialization never fails
    result = _strip_surrogates(result)

    # Backfill family identification for legacy results
    if result and "family_identification" not in result:
        try:
            from backend.family_id import identify_family
            result["family_identification"] = identify_family(sample_id, result, use_llm=True, use_cache=True)
        except Exception:
            result["family_identification"] = {
                "family": "unknown",
                "confidence": 0.0,
                "method": "none",
                "reasoning": "backfill failed",
                "candidates": [],
            }
    return result


def load_all_results() -> List[Dict[str, Any]]:
    """Load all available pipeline results (cached, re-scans every 5s)."""
    global _ALL_RESULTS_CACHE, _ALL_RESULTS_MTIME
    now = time.time()
    if _ALL_RESULTS_CACHE is not None and (now - _ALL_RESULTS_MTIME) < _ALL_RESULTS_TTL:
        return _ALL_RESULTS_CACHE
    results = []
    if not WORK_DIR.exists():
        _ALL_RESULTS_CACHE = results
        _ALL_RESULTS_MTIME = now
        return results
    for sample_dir in WORK_DIR.iterdir():
        result_path = sample_dir / "pipeline_result.json"
        if result_path.exists():
            try:
                with open(result_path, "r", encoding="utf-8") as f:
                    results.append(_strip_surrogates(json.load(f)))
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                # One corrupt file must not take down every consumer of the corpus.
                logger.warning("Skipping corrupt pipeline result: %s", result_path)
    _ALL_RESULTS_CACHE = results
    _ALL_RESULTS_MTIME = now
    return results


def load_family_index() -> dict[str, str]:
    """Load lightweight sample_id -> family mapping from family.json files (cached)."""
    global _FAMILY_INDEX_CACHE, _FAMILY_INDEX_MTIME
    now = time.time()
    if _FAMILY_INDEX_CACHE is not None and (now - _FAMILY_INDEX_MTIME) < _FAMILY_INDEX_TTL:
        return _FAMILY_INDEX_CACHE
    index: dict[str, str] = {}
    if not WORK_DIR.exists():
        _FAMILY_INDEX_CACHE = index
        _FAMILY_INDEX_MTIME = now
        return index
    for sample_dir in WORK_DIR.iterdir():
        family_path = sample_dir / "family.json"
        if family_path.exists():
            try:
                with open(family_path, "r", encoding="utf-8") as f:
                    fd = json.load(f)
                    sid = fd.get("sample_id") or sample_dir.name
                    fam = fd.get("family", "unknown")
                    index[sid] = fam.lower()
            except Exception:
                pass
    _FAMILY_INDEX_CACHE = index
    _FAMILY_INDEX_MTIME = now
    return index


# ---------------------------------------------------------------------------
# Graph transformer
# ---------------------------------------------------------------------------


def transform_graph(result: Dict[str, Any]) -> Dict[str, Any]:
    """Convert threat chains to 3D graph nodes and edges."""
    nodes = []
    edges = []
    node_ids = set()

    sample_id = result.get("sample_id", "unknown")
    sample_name = result.get("metadata", {}).get("sample_name", sample_id)

    # Root sample node
    sample_node_id = f"sample:{sample_id}"
    nodes.append({
        "id": sample_node_id,
        "type": "sample",
        "label": sample_name[:40],
        "confidence": 1.0,
        "color": NODE_COLORS["sample"],
    })
    node_ids.add(sample_node_id)

    for chain in result.get("threat_chains", []):
        prev_node_id = sample_node_id

        for step in chain.get("steps", []):
            step_type = step.get("type", "unknown")
            artifact = str(step.get("artifact", ""))[:60]
            confidence = step.get("confidence", 0.5)
            source = step.get("source_location", "")

            # Create deterministic unique node ID
            node_id = f"{step_type}:{hashlib.md5((artifact + source).encode('utf-8')).hexdigest()[:16]}"
            if node_id not in node_ids:
                node_ids.add(node_id)
                nodes.append({
                    "id": node_id,
                    "type": step_type,
                    "label": artifact,
                    "confidence": confidence,
                    "color": NODE_COLORS.get(step_type, "#CCCCCC"),
                    "source_location": source,
                    "chain_id": chain.get("chain_id"),
                    "severity": chain.get("severity"),
                })

            # Edge from previous to current
            edge_type = "decode" if step_type in ("decoded_artifact",) else "usage"
            if step_type == "c2_infrastructure":
                edge_type = "exfiltration"

            edges.append({
                "source": prev_node_id,
                "target": node_id,
                "type": edge_type,
                "color": EDGE_COLORS.get(edge_type, "#999999"),
            })

            prev_node_id = node_id

    return {
        "sample_id": sample_id,
        "sample_name": sample_name,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


# ---------------------------------------------------------------------------
# Clustering transformer
# ---------------------------------------------------------------------------


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def transform_clusters(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Convert sample results to 3D clustering data.

    Axes:
    - x: encoding complexity (avg entropy of encoded strings)
    - y: C2 sophistication (# unique C2 indicators + protocol diversity)
    - z: exfiltration volume (# payloads + # threat chains)
    """
    samples = []

    for result in results:
        sample_id = result.get("sample_id", "unknown")
        metadata = result.get("metadata", {})
        sample_name = metadata.get("sample_name", sample_id)

        # X: encoding complexity
        encodings = result.get("encodings", [])
        if encodings:
            entropies = [
                e.get("entropy", 0) if isinstance(e, dict) else 0
                for e in encodings
            ]
            avg_entropy = sum(entropies) / len(encodings)
            encoding_count = len(encodings)
        else:
            avg_entropy = 0.0
            encoding_count = 0
        x = avg_entropy + math.log1p(encoding_count)

        # Y: C2 sophistication
        c2s = result.get("c2_infrastructure", [])
        protocols = set(c.get("protocol") for c in c2s if c.get("protocol"))
        domains = set(c.get("domain") for c in c2s if c.get("domain"))
        ips = set(c.get("ip") for c in c2s if c.get("ip"))
        y = len(c2s) + len(protocols) * 2 + len(domains) + len(ips)

        # Z: exfiltration volume + obfuscation
        payloads = result.get("payloads", [])
        chains = result.get("threat_chains", [])
        obfuscation = result.get("obfuscation_analysis", {})
        z = len(payloads) + len(chains) + (obfuscation.get("obfuscation_score", 0) / 25)

        assessment = result.get("llm_assessment", {})
        risk_score = assessment.get("risk_score", 0)
        severity = assessment.get("severity", "low")

        # Family from family_identification, sample_name or package_name
        family_info = result.get("family_identification", {})
        family = family_info.get("family") or metadata.get("package_name", "unknown")
        if family == "unknown" and "." in sample_name:
            family = sample_name.split(".")[0]

        samples.append({
            "id": sample_id,
            "name": sample_name[:40],
            "x": round(x, 3),
            "y": round(y, 3),
            "z": round(z, 3),
            "family": family,
            "severity": severity,
            "risk_score": risk_score,
            "confidence": assessment.get("confidence", 0.5),
            "encoding_count": encoding_count,
            "c2_count": len(c2s),
            "payload_count": len(payloads),
            "chain_count": len(chains),
        })

    return {
        "total_samples": len(samples),
        "samples": samples,
    }


# ---------------------------------------------------------------------------
# Timeline transformer
# ---------------------------------------------------------------------------


def transform_timeline(result: Dict[str, Any]) -> Dict[str, Any]:
    """Convert threat chains to timeline data."""
    chains = []

    for chain in result.get("threat_chains", []):
        steps = []
        for step in chain.get("steps", []):
            steps.append({
                "step": step.get("step", 0),
                "time": step.get("step", 0),  # Use step number as temporal proxy
                "type": step.get("type", "unknown"),
                "artifact": str(step.get("artifact", ""))[:80],
                "confidence": step.get("confidence", 0.5),
                "source_location": step.get("source_location", ""),
            })

        chains.append({
            "chain_id": chain.get("chain_id", "unknown"),
            "severity": chain.get("severity", "low"),
            "confidence": chain.get("confidence", 0.5),
            "steps": steps,
        })

    return {
        "sample_id": result.get("sample_id", "unknown"),
        "sample_name": result.get("metadata", {}).get("sample_name", ""),
        "total_chains": len(chains),
        "chains": chains,
    }


# ---------------------------------------------------------------------------
# Samples list transformer
# ---------------------------------------------------------------------------


def transform_samples_list(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert results to lightweight sample list."""
    samples = []
    for result in results:
        metadata = result.get("metadata", {})
        assessment = result.get("llm_assessment", {})
        obfuscation = result.get("obfuscation_analysis", {})
        family_info = result.get("family_identification", {})
        family = family_info.get("family") or metadata.get("package_name", "unknown")
        if family == "unknown" and "." in metadata.get("sample_name", ""):
            family = metadata.get("sample_name", "").split(".")[0]
        samples.append({
            "id": result.get("sample_id", ""),
            "name": metadata.get("sample_name", ""),
            "sha256": metadata.get("sha256", ""),
            "package_name": metadata.get("package_name", ""),
            "file_size_bytes": metadata.get("file_size_bytes", 0),
            "status": "analyzed",
            "severity": assessment.get("severity", "low"),
            "risk_score": assessment.get("risk_score", 0),
            "primary_threat": assessment.get("primary_threat", "other"),
            "obfuscation_score": obfuscation.get("obfuscation_score", 0),
            "obfuscation_level": obfuscation.get("obfuscation_level", "low"),
            "family": family,
            "family_confidence": family_info.get("confidence", 0.0),
            "encodings_count": len(result.get("encodings", [])),
            "payloads_count": len(result.get("payloads", [])),
            "c2_count": len(result.get("c2_infrastructure", [])),
            "chains_count": len(result.get("threat_chains", [])),
            "zero_day_risk_score": result.get("threat_synthesis", {}).get("zero_day_risk_score", 0),
            "zero_day_risk_level": result.get("threat_synthesis", {}).get("risk_level", "none"),
            "packing_detected": result.get("binary_packing", {}).get("packing_detected", False),
            "reflective_calls": result.get("reflective_tracing", {}).get("total_reflective_calls", 0),
            "c2_endpoints": result.get("network_protocols", {}).get("total_c2", 0),
            "certificate_found": result.get("certificate_analysis", {}).get("certificate_found", False),
        })
    return samples
