"""Report model: the single source of truth for a sample report (see docs/report-rework/EXPORT.md).

Every value carries its status (OBSERVED, INFERRED, UNVERIFIED, MODEL, LEAD) so that
no renderer can present a model guess or an unverified indicator as a finding.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict

from analysis.c2_corroboration import is_behavior_confirmed, is_corroborated_endpoint
from analysis.custody import verify as verify_custody
from backend import family_id, family_profiles
from backend import threat_intel as ti
from backend.config import settings
from backend.obfuscation_view import build_obfuscation_view

MODEL_VERSION = 1


def _family_status(family: Dict[str, Any]) -> str:
    if not family or not family.get("family") or family.get("family", "").lower() == "unknown":
        return "NO_ATTRIBUTION"
    if family.get("method") == "signature_v3" and float(family.get("confidence") or 0) >= 0.8:
        return "SUPPORTED_BY_SIGNATURE"
    return "LEAD"


def _endpoint(c2: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "endpoint": c2.get("raw_url") or c2.get("domain") or c2.get("ip"),
        "source": c2.get("source_location"),
        "confidence": c2.get("confidence"),
        "category": c2.get("threat_category", "unverified"),
        "status": "UNVERIFIED",           # never observed live; string-extracted only
        "corroborated": is_corroborated_endpoint(c2),
        # True only when code referencing this host also reads a device identifier (see c2_corroboration).
        "behavior_confirmed": is_behavior_confirmed(c2),
    }


def build_report_model(sample_id: str) -> Dict[str, Any]:
    """Build the report model from a sample's pipeline outputs. Makes no network calls."""
    sample_dir = settings.WORK_DIR / sample_id
    result = json.loads((sample_dir / "pipeline_result.json").read_text(encoding="utf-8"))
    meta = result.get("metadata", {}) or {}
    llm = result.get("llm_assessment", {}) or {}
    manifest = result.get("manifest", {}) or {}
    family = family_id.identify_family(sample_id, result, use_llm=False)
    threat = ti.build_threat_intel(result, sample_id)
    obf = build_obfuscation_view(sample_id, result.get("obfuscation_analysis")) or {}
    custody = verify_custody(sample_dir)

    endpoints = [_endpoint(c) for c in result.get("c2_infrastructure", []) or []]
    return {
        "model_version": MODEL_VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sample": {
            "sha256": sample_id,
            "package": meta.get("package_name") or meta.get("package"),
            "md5": meta.get("md5"),
            "size_bytes": meta.get("file_size_bytes"),
            "min_sdk": manifest.get("min_sdk_version"),
            "target_sdk": manifest.get("target_sdk_version"),
        },
        "custody": {
            "valid": custody.get("valid"),
            "records": custody.get("entries"),
            "head_hash": custody.get("head_hash"),
            "broken_at": custody.get("broken_at"),
        },
        "verdict": {
            "severity": llm.get("severity"),
            "risk_score": llm.get("risk_score"),
            "primary_threat": {"status": "MODEL", "value": llm.get("primary_threat")},
            "confidence": {"status": "MODEL_SELF_REPORTED", "value": llm.get("confidence")},
            "sanity_notes": llm.get("sanity_notes", []),
            "narrative": {"status": "MODEL", "value": llm.get("narrative", "")},
        },
        "family": {
            "name": family.get("family"),
            "status": _family_status(family),
            "method": family.get("method"),
            "confidence": family.get("confidence"),
            "reasoning": family.get("reasoning"),
            "evidence": family_profiles.evidence_lines(family.get("reasoning")),
            "profile": family_profiles.describe_family(family.get("family")),
        },
        "endpoints": endpoints,
        "endpoints_summary": {
            "total": len(endpoints),
            "corroborated": sum(1 for e in endpoints if e["corroborated"]),
            "verified": 0,
        },
        "permissions": manifest.get("uses_permissions", []) or [],
        "obfuscation": {
            "score": obf.get("obfuscation_score"),
            "level": obf.get("obfuscation_level"),
            "techniques": [{"key": t.get("key"), "count": t.get("count")} for t in obf.get("techniques", [])],
        },
        "threat_intel_c2_count": len(threat.get("c2s", []) or []),
        "limitations": [
            "Static analysis only. No dynamic run, no network capture.",
            "Endpoints come from string extraction and have not been observed live.",
            "Family attribution is a hypothesis unless status is SUPPORTED_BY_SIGNATURE.",
            "Model narrative is drafted by a language model and is not evidence.",
        ],
    }
