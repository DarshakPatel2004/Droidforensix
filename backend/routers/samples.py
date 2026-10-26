"""Sample listing, detail, attribution, and threat-summary routes."""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Set

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from analysis.custody import read_entries
from analysis.custody import verify as verify_custody
from backend import family_id as family_id_module
from backend.community_intel import get_cached_community_intel
from backend.config import settings
from backend.family_id import identify_family
from backend.obfuscation_view import build_obfuscation_view
from backend.transformers import (
    load_all_results,
    load_result,
    transform_clusters,
    transform_graph,
    transform_samples_list,
    transform_timeline,
)
from backend.validators import validate_sample_id

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/samples")
async def api_list_samples() -> dict:
    """List all analyzed samples with summary fields."""
    results = load_all_results()
    samples = transform_samples_list(results)
    return {"samples": samples, "total": len(samples)}


@router.get("/api/sample/{sample_id}")
async def api_get_sample(sample_id: str) -> dict:
    """Get full analysis report for a sample."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return result


@router.get("/api/graph/{sample_id}")
async def api_get_graph(sample_id: str) -> dict:
    """Get 3D graph nodes/edges for a sample."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return transform_graph(result)


@router.get("/api/clusters")
async def api_get_clusters() -> dict:
    """Get 3D clustering data for all samples."""
    results = load_all_results()
    return transform_clusters(results)


@router.get("/api/timeline/{sample_id}")
async def api_get_timeline(sample_id: str) -> dict:
    """Get timeline/attack-chain progression for a sample."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return transform_timeline(result)


class CustodyVerification(BaseModel):
    valid: bool
    entries: int
    head_hash: Optional[str]
    broken_at: Optional[int]
    reason: str


class CustodyResponse(BaseModel):
    verification: CustodyVerification
    entries: List[dict]


@router.get("/api/sample/{sample_id}/custody", response_model=CustodyResponse)
async def api_get_custody(sample_id: str) -> dict:
    """Chain-of-custody log for a sample, re-verified on every request."""
    try:
        validate_sample_id(sample_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid sample_id") from exc
    sample_dir = settings.WORK_DIR / sample_id
    if not sample_dir.is_dir():
        raise HTTPException(status_code=404, detail="Sample not found")
    return {"verification": verify_custody(sample_dir), "entries": read_entries(sample_dir)}


@router.get("/api/sample/{sample_id}/family")
async def api_get_family(sample_id: str) -> dict:
    """Malware family identification (deterministic + LLM)."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return identify_family(sample_id, result)


@router.get("/api/sample/{sample_id}/obfuscation")
async def api_get_obfuscation(sample_id: str) -> dict:
    """Obfuscation analysis view: techniques, DEX entropy, native artifacts."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    obf = build_obfuscation_view(sample_id, result.get("obfuscation_analysis"))
    return obf


# ---------------------------------------------------------------------------
# Attribution & Threat Summary endpoints
# ---------------------------------------------------------------------------


@router.get("/api/sample/{sample_id}/attribution")
async def api_get_attribution(sample_id: str) -> dict:
    """MAFIA confidence breakdown: permissions match, C2 overlap, obfuscation pattern, code similarity."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    cache_path = settings.WORK_DIR / sample_id / "attribution_cache.json"
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            # v3: C2 signal text now reports baseline overlap; older caches hold the old wording.
            if cached.get("schema_version") == 3:
                return cached
        except Exception:
            logger.warning("Failed to read attribution cache for %s, recomputing", sample_id)

    # Family identification
    family_data = identify_family(sample_id, result)
    family = family_data.get("family", "unknown")
    confidence = family_data.get("confidence", 0.0)

    breakdown = _compute_confidence_breakdown(result, family)

    related = _find_related_samples(sample_id, family, result)
    supporting_signals = _build_supporting_signals(result, family_data, breakdown)

    payload = {
        "schema_version": 3,
        "family": family,
        "confidence": round(confidence, 2),
        "confidence_breakdown": breakdown,
        "supporting_signals": supporting_signals,
        "related_samples": related,
        "code_references": _build_code_references(result),
    }

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
    except Exception:
        logger.warning("Failed to write attribution cache for %s", sample_id)

    return payload


def _compute_confidence_breakdown(result: dict, family: str) -> dict:
    """Compute per-dimension confidence scores."""
    # Permissions match: compare the sample's declared permissions against the
    # signature of the family it was attributed to. Production pipeline results
    # store permissions under manifest.uses_permissions (and as a flat
    # result["permissions"] in the cache format) - not under metadata.
    declared_perms = family_id_module._extract_permissions(result)
    family_perms = _family_permission_baseline(family)
    if family_perms and declared_perms:
        overlap = len(declared_perms & family_perms)
        permissions_match = round(overlap / len(family_perms), 2)
    else:
        # No baseline for this family (or no declared permissions): the axis is
        # unknown, so report 0.0 rather than a fabricated mid-point.
        permissions_match = 0.0

    # C2 overlap score
    c2_list = result.get("c2_infrastructure", [])
    c2_domains = {c.get("domain", "") for c in c2_list if c.get("domain")}
    family_c2s = _family_c2_baseline(family)
    if family_c2s and c2_domains:
        overlap = len(c2_domains & family_c2s)
        c2_overlap = round(overlap / len(c2_domains), 2)
    else:
        c2_overlap = 0.0

    # Obfuscation pattern score
    obfuscation = result.get("obfuscation_analysis", {})
    obf_score = obfuscation.get("obfuscation_score", 0)
    obf_pattern = round(min(obf_score / 100, 1.0), 2)

    # Code similarity: derived from the LLM/heuristic risk score that the
    # pipeline actually writes. Production results have no top-level
    # "heuristic"; llm_assessment is the authoritative scored verdict.
    heuristic_score = 0
    llm = result.get("llm_assessment", {})
    if isinstance(llm, dict):
        heuristic_score = llm.get("risk_score", 0) or 0
    if not heuristic_score:
        assessment = result.get("assessment", {})
        if isinstance(assessment, dict):
            heuristic_score = assessment.get("risk_score", 0) or 0
    try:
        heuristic_score = float(heuristic_score)
    except (TypeError, ValueError):
        heuristic_score = 0.0
    code_similarity = round(min(heuristic_score / 100, 1.0), 2)

    return {
        "permissions_match": permissions_match,
        "c2_overlap": c2_overlap,
        "obfuscation_pattern": obf_pattern,
        "code_similarity": code_similarity,
    }


def _family_permission_baseline(family: str) -> Set[str]:
    """Permissions declared by a family's signature, or empty if unknown."""
    if not family or family == "unknown":
        return set()
    for sig in family_id_module.FAMILY_SIGNATURES:
        if sig.family_name.lower() == family.lower():
            return {p.short_name() for p in sig.permission_sigs}
    return set()


def _family_c2_baseline(family: str) -> Set[str]:
    """C2 patterns declared by a family's signature, or empty if unknown."""
    if not family or family == "unknown":
        return set()
    for sig in family_id_module.FAMILY_SIGNATURES:
        if sig.family_name.lower() == family.lower():
            return {p.pattern.lower() for p in sig.c2_patterns}
    return set()


def _build_supporting_signals(result: dict, family_data: dict, breakdown: dict) -> List[str]:
    """Generate human-readable supporting signals from the data."""
    signals = []
    c2_list = result.get("c2_infrastructure", [])
    obfuscation = result.get("obfuscation_analysis", {})

    perm_match_pct = round(breakdown["permissions_match"] * 100)
    if perm_match_pct > 0:
        signals.append(f"{perm_match_pct}% permissions match family baseline")

    c2_domains = {c.get("domain") for c in c2_list if c.get("domain")}
    if c2_domains:
        # Same overlap the c2_overlap score uses in _compute_confidence_breakdown.
        family_c2s = _family_c2_baseline(family_data.get("family", "unknown"))
        if family_c2s:
            c2_match_count = len(c2_domains & family_c2s)
            signals.append(
                f"{c2_match_count} of {len(c2_domains)} C2 indicators match the family baseline"
            )
        else:
            signals.append("no family baseline to compare against")

    obf_level = obfuscation.get("obfuscation_level", "low")
    if obf_level != "low":
        signals.append(f"Obfuscation pattern: {obf_level.upper()}")

    family = family_data.get("family", "unknown")
    if family != "unknown":
        signals.append(f"Code structure consistent with {family}")

    llm = result.get("llm_assessment", {})
    method = llm.get("method") if isinstance(llm, dict) else None
    if method:
        signals.append(f"Detection method: {method}")

    return signals


def _find_related_samples(sample_id: str, family: str, result: dict) -> List[dict]:
    """Find samples related to the current one.

    Two tiers, so matching works even when family identification failed:
    1. Same-family samples (family identification is the strongest signal).
    2. Cross-family similarity (permissions, C2, package name, size, native
       libs) — used for unknown families and to surface lookalikes.

    Returns up to 10 samples ranked by similarity, each enriched with its
    family and package name for display.
    """
    from backend.transformers import load_all_results

    others = [o for o in load_all_results() if (o.get("sample_id") or "") != sample_id]
    if not others:
        return []

    family_lower = family.lower()
    same_family = []
    similar = []
    for other in others:
        other_family = (
            (other.get("family_identification", {}) or {}).get("family", "unknown") or "unknown"
        ).lower()
        similarity = _compute_similarity(result, other)
        entry = {
            "sample_id": other.get("sample_id", ""),
            "similarity": similarity,
            "family": other_family,
            "package_name": (other.get("metadata", {}) or {}).get("package_name", ""),
        }
        if family_lower != "unknown" and other_family == family_lower:
            # Same family is definitionally related — similarity floors at 0.5
            entry["similarity"] = max(similarity, 0.5)
            same_family.append(entry)
        elif similarity >= 0.2:
            similar.append(entry)

    merged = sorted(same_family + similar, key=lambda r: r["similarity"], reverse=True)
    return merged[:10]


def _compute_similarity(a: dict, b: dict) -> float:
    """Similarity between two samples across independent signal axes.

    Axes (Jaccard overlap unless noted):
      - permissions (0.40)
      - C2 domains (0.30)
      - identical package name (0.10)
      - file size ratio (0.10)
      - native libraries (0.10)

    Returns a score in 0..1. Samples sharing nothing score 0.
    """
    score = 0.0
    weight_total = 0.0

    def jaccard(x: Set[str], y: Set[str]) -> float:
        if not x or not y:
            return 0.0
        union = x | y
        return len(x & y) / len(union) if union else 0.0

    a_perms = family_id_module._extract_permissions(a)
    b_perms = family_id_module._extract_permissions(b)
    score += jaccard(a_perms, b_perms) * 0.40
    weight_total += 0.40

    a_c2 = {c.get("domain", "") for c in a.get("c2_infrastructure", []) if c.get("domain")}
    b_c2 = {c.get("domain", "") for c in b.get("c2_infrastructure", []) if c.get("domain")}
    score += jaccard(a_c2, b_c2) * 0.30
    weight_total += 0.30

    a_pkg = (a.get("metadata", {}) or {}).get("package_name", "")
    b_pkg = (b.get("metadata", {}) or {}).get("package_name", "")
    if a_pkg and b_pkg and a_pkg == b_pkg:
        score += 0.10
    weight_total += 0.10

    a_size = (a.get("metadata", {}) or {}).get("file_size_bytes", 0) or 1
    b_size = (b.get("metadata", {}) or {}).get("file_size_bytes", 0) or 1
    score += (min(a_size, b_size) / max(a_size, b_size)) * 0.10
    weight_total += 0.10

    a_libs = set((a.get("extraction", {}) or {}).get("native_libs_found", []) or [])
    b_libs = set((b.get("extraction", {}) or {}).get("native_libs_found", []) or [])
    score += jaccard(a_libs, b_libs) * 0.10
    weight_total += 0.10

    if weight_total == 0:
        return 0.0
    return round(score / weight_total, 2)


def _build_code_references(result: dict) -> dict:
    """Notable strings + category counts for the attribution panel.

    Bounded to the 100 highest-entropy printable strings to keep the payload
    small even for APKs with tens of thousands of strings.
    """
    strings = result.get("strings", {}) or {}
    literals = strings.get("string_literals", []) or []

    categories: Dict[str, int] = {}
    by_value: Dict[str, dict] = {}
    for item in literals:
        value = item.get("value") if isinstance(item, dict) else item
        if not isinstance(value, str):
            continue
        category = (item.get("category") if isinstance(item, dict) else None) or "string_literal"
        categories[category] = categories.get(category, 0) + 1
        if len(value) < 4 or any(ord(c) < 32 for c in value):
            continue
        entropy = round((item.get("entropy") if isinstance(item, dict) else 0.0) or 0.0, 2)
        existing = by_value.get(value)
        if existing is None or entropy > existing["entropy"]:
            by_value[value] = {
                "value": value[:200],
                "entropy": entropy,
                "category": category,
            }

    ranked = sorted(by_value.values(), key=lambda e: -e["entropy"])
    return {
        "total_strings": len(literals),
        "by_category": dict(sorted(categories.items(), key=lambda kv: -kv[1])),
        "notable_strings": ranked[:100],
    }


@router.get("/api/sample/{sample_id}/threat-summary")
async def api_get_threat_summary(sample_id: str) -> dict:
    """Glance-level threat summary with threat score, red flags, and key indicators."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    metadata = result.get("metadata", {})
    assessment = result.get("llm_assessment", {})
    obfuscation = result.get("obfuscation_analysis", {})
    c2_list = result.get("c2_infrastructure", [])
    family_data = result.get("family_identification", {})
    heuristic = result.get("heuristic", {})

    risk_score = assessment.get("risk_score", 0)
    if not risk_score and isinstance(heuristic, dict):
        risk_score = heuristic.get("score", 0)
    severity = assessment.get("severity", "low")

    permissions = sorted(family_id_module._extract_permissions(result))
    dangerous_count = sum(
        1 for p in permissions
        if p.split(".")[-1] in {
            "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "CALL_PHONE",
            "READ_CONTACTS", "ACCESS_FINE_LOCATION", "CAMERA",
            "RECORD_AUDIO", "READ_PHONE_STATE", "WRITE_EXTERNAL_STORAGE",
        }
    )

    # c2[].status is written only after live-DNS enrichment has run for this
    # sample. Before that the key is absent across the whole c2 list, which is
    # "not yet classified", not "zero active endpoints".
    status_known = any("status" in c for c in c2_list)
    c2_active = sum(1 for c in c2_list if c.get("status") == "active") if status_known else None
    obf_level = obfuscation.get("obfuscation_level", "low")

    techniques = obfuscation.get("indicators", {}) or {}
    evasion_count = sum(len(v) if isinstance(v, (list, tuple, set)) else (v if isinstance(v, int) else 0) for v in techniques.values())

    threat_level = "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW"

    family_name = family_data.get("family", "unknown")
    family_conf = family_data.get("confidence", 0.0)

    similar_count = _count_similar(family_name, sample_id)

    return {
        "sample_id": sample_id,
        "package_name": metadata.get("package_name", ""),
        "version_name": metadata.get("version_name", ""),
        "threat_score": risk_score,
        "threat_level": threat_level,
        "severity": severity,
        "red_flags": [
            {"type": "dangerous_permissions", "count": dangerous_count},
            *([{"type": "active_c2_endpoints", "count": c2_active}]
              if c2_active is not None else
              [{"type": "active_c2_endpoints", "status": "not_enriched"}]),
            {"type": "obfuscation", "level": obf_level.upper()},
            {"type": "evasion_techniques", "count": evasion_count},
        ],
        "family": family_name,
        "confidence": round(family_conf, 2),
        "similar_samples_count": similar_count,
        "c2_count": len(c2_list),
        "obfuscation_score": obfuscation.get("obfuscation_score", 0),
    }


def _count_similar(family: str, exclude_id: str) -> int:
    """Count samples in the same family (excluding the current one)."""
    if family == "unknown":
        return 0
    from backend.transformers import load_all_results
    count = 0
    for other in load_all_results():
        if other.get("sample_id", "") == exclude_id:
            continue
        of = other.get("family_identification", {}).get("family", "unknown")
        if of == family:
            count += 1
    return count


@router.get("/api/sample/{sample_id}/community-intel")
async def api_get_community_intel(sample_id: str) -> dict:
    """Search online forums/communities for gossip about the APK or its family.

    Sources: Reddit, Hacker News, DuckDuckGo (all free, no API keys).
    Results are cached in memory for 10 minutes.
    """
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    package_name = (result.get("metadata", {}) or {}).get("package_name", "")
    family_data = identify_family(sample_id, result)
    family = family_data.get("family", "unknown")

    loop = asyncio.get_event_loop()
    try:
        payload = await loop.run_in_executor(
            None, get_cached_community_intel, sample_id, package_name, family
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Community intel search failed: {e}") from e

    return payload
