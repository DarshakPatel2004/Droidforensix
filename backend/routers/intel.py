"""Threat-intelligence view and CSV, STIX, YARA, and Suricata exports."""

import asyncio
import json
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, Response

from backend import threat_intel as ti
from backend.family_id import identify_family
from backend.transformers import (
    load_result,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Threat intelligence endpoints (Phase 2 enrichment + family identification)
# ---------------------------------------------------------------------------

@router.get("/api/sample/{sample_id}/threat-intel")
async def api_get_threat_intel(sample_id: str) -> dict:
    """Aggregated C2 threat-intel: DNS status, classification, geo, and family."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    # build_threat_intel performs blocking DNS/HTTP lookups (rate-limited), so it
    # must not run on the event loop. identify_family is also CPU-heavy.
    def _build():
        data = ti.build_threat_intel(result, sample_id)
        try:
            data["family"] = identify_family(sample_id, result)
        except Exception as e:  # family ID must never break the dashboard
            data["family"] = {"family": "unknown", "confidence": 0.0,
                              "method": "error", "reasoning": str(e), "candidates": []}
        return data

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _build)


@router.get("/api/sample/{sample_id}/threat-intel/export/csv")
async def api_export_threat_intel_csv(sample_id: str):
    """Export C2 indicators as a CSV blocklist."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    csv_text = ti.to_csv(result)
    return PlainTextResponse(
        csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="droidforensix_{sample_id[:16]}_blocklist.csv"'},
    )


@router.get("/api/sample/{sample_id}/threat-intel/export/stix")
async def api_export_threat_intel_stix(sample_id: str):
    """Export C2 indicators as a STIX 2.0 bundle."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    bundle = ti.to_stix(result, sample_id)
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="droidforensix_{sample_id[:16]}_stix.json"'},
    )


@router.get("/api/sample/{sample_id}/threat-intel/export/yara")
async def api_export_threat_intel_yara(sample_id: str):
    """Export a per-sample YARA rule built from extracted C2 indicators."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    yara_text = ti.to_yara(result, sample_id)
    return PlainTextResponse(
        yara_text,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="droidforensix_{sample_id[:16]}.yar"'},
    )


@router.get("/api/sample/{sample_id}/threat-intel/export/suricata")
async def api_export_threat_intel_suricata(sample_id: str):
    """Export Suricata rules that alert on this sample's C2 domains and addresses."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return PlainTextResponse(
        ti.to_suricata(result, sample_id),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="droidforensix_{sample_id[:16]}.rules"'},
    )
