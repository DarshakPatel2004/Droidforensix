"""PDF report, LLM explanation, and deobfuscation routes."""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from analysis.step7_llm_assessment import explain_method, explain_threat_chain
from backend import threat_intel as ti
from backend.dissection import APKDissector
from backend.obfuscation_view import build_obfuscation_view, deobfuscate_text
from backend.pdf_report import generate_report
from backend.routers import dissection as dissection_routes
from backend.transformers import (
    load_result,
)

logger = logging.getLogger(__name__)
router = APIRouter()


class DeobfuscateRequest(BaseModel):
    text: str
    hint: Optional[str] = None


class ExplainChainRequest(BaseModel):
    chain: dict


@router.post("/api/sample/{sample_id}/explain-chain")
async def api_explain_chain(sample_id: str, request: ExplainChainRequest) -> dict:
    """Return LLM explanation for a threat chain."""
    loop = asyncio.get_event_loop()
    try:
        llm_result = await loop.run_in_executor(
            None, lambda: explain_threat_chain(request.chain),
        )
    except Exception as e:
        llm_result = {
            "summary": f"Chain explanation unavailable: {e}",
            "threat_type": "unknown",
            "confidence": 0.0,
        }
    return {"chain_id": request.chain.get("chain_id"), "llm": llm_result}


@router.post("/api/sample/{sample_id}/report/pdf")
async def api_generate_pdf_report(sample_id: str, request: dict) -> Response:
    """
    Generate a full forensic PDF report for a sample.

    Body: { "mode": "quick" | "full", "sections": { "metadata": true, ... } }
    - quick: LLM summaries for top 30 suspicious methods by suspicion score
      - sections: optional dict toggling which sections appear. Supported keys:
        metadata, llm_assessment, obfuscation, c2_infrastructure, suspicious_methods.
        Unknown keys are ignored. Cover page + executive summary always render.
    - full:  LLM summaries for all suspicious methods (may be slow); all sections on.
    """
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    mode = request.get("mode", "quick")
    sections = request.get("sections") if mode == "quick" else None

    def _gather_report_data():
        """Build everything the PDF needs. Runs in an executor: it performs
        blocking DNS/LLM calls and Androguard work and must not touch the loop."""
        threat = ti.build_threat_intel(result, sample_id)
        try:
            obf = build_obfuscation_view(sample_id, result.get("obfuscation_analysis"))
        except Exception:
            logger.debug("Failed to build obfuscation view for PDF report")
            obf = {}

        apk = dissection_routes._get_sample_apk_path(sample_id)
        methods = []

        if apk:
            try:
                dissector = APKDissector(str(apk), work_dir=str(dissection_routes.WORK_DIR), cache=dissection_routes._dissection_cache)
                classes = dissector.list_decompiled_class_objects()

                SUSPICIOUS_KEYWORDS = [
                    'invoke', 'Cipher', 'ClassLoader', 'reflect', 'DexClassLoader',
                    'Runtime.exec', 'ProcessBuilder', 'HttpURLConnection', 'Base64',
                    'decode', 'encrypt', 'socket', 'intent', 'permission',
                ]
                UNWANTED_PATTERNS = [
                    'android.support.', 'androidx.', 'com.android.internal.',
                    'kotlin.', 'com.google.android.',
                    'com.facebook.', 'com.appsflyer.', 'io.sentry.',
                    'com.adjust.', 'com.onesignal.', 'com.amplitude.',
                    'com.firebase.', 'com.google.firebase.',
                ]

                def suspicion_score(cls_data):
                    score = 0
                    for method in cls_data.get('methods', []):
                        body = method.get('body', '') or ''
                        name = method.get('name', '') or ''
                        for kw in SUSPICIOUS_KEYWORDS:
                            if kw.lower() in name.lower():
                                score += 2
                            if kw.lower() in body.lower():
                                score += 1
                    return score

                # Filter boilerplate and sort by suspicion
                suspicious = [
                    c for c in classes
                    if suspicion_score(c) > 0
                    and not any(p in c.get('name', '') for p in UNWANTED_PATTERNS)
                ]
                suspicious.sort(key=suspicion_score, reverse=True)

                method_limit = None if mode == 'full' else 30
                processed = 0

                for cls in suspicious:
                    if method_limit and processed >= method_limit:
                        break
                    cls_name = cls.get('name', '')
                    for method in cls.get('methods', []):
                        if method_limit and processed >= method_limit:
                            break
                        body = method.get('body', '') or ''
                        name = method.get('name', '') or ''
                        flags = [kw for kw in SUSPICIOUS_KEYWORDS
                                 if kw.lower() in name.lower() or kw.lower() in body.lower()]
                        if not flags:
                            continue

                        # Static annotations
                        line_annotations = dissection_routes._annotate_lines(body)

                        # Blocking LLM call; safe here because this whole
                        # function runs in an executor thread.
                        llm_result = explain_method(cls_name, name, body, flags)

                        methods.append({
                            'class_name':       cls_name,
                            'method_name':      name,
                            'flags':            flags,
                            'line_annotations': line_annotations,
                            'llm':              llm_result,
                        })
                        processed += 1

            except Exception as e:
                logger.exception("Method annotation failed during PDF generation (sample %s): %s", sample_id, e)

        return threat, obf, methods

    loop = asyncio.get_event_loop()
    threat_data, obfuscation, annotated_methods = await loop.run_in_executor(None, _gather_report_data)
    try:
        pdf_bytes = await loop.run_in_executor(
            None,
            lambda: generate_report(
                sample_id=sample_id,
                sample_result=result,
                threat_data=threat_data,
                obfuscation=obfuscation,
                annotated_methods=annotated_methods,
                mode=mode,
                selected_sections=sections,
            )
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}") from e

    filename = f"droidforensix_{sample_id[:12]}_{mode}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/api/sample/{sample_id}/deobfuscate")
async def api_deobfuscate(sample_id: str, request: DeobfuscateRequest) -> dict:
    """Best-effort deobfuscation of a user-supplied string."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    return deobfuscate_text(request.text, request.hint)
