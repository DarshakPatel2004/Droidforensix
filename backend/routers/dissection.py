"""Dissection and code-inspection routes over a sample's APK."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from analysis.step7_llm_assessment import explain_method, summarize_dissection
from backend.code_analysis import CodeAnalyzer
from backend.config import settings
from backend.dissection import APKDissector, SampleAPKCache, load_dissection
from backend.transformers import (
    load_result,
)
from backend.validators import validate_sample_id

logger = logging.getLogger(__name__)
router = APIRouter()


# Shared APK parse cache — one parse per sample across all endpoints
_dissection_cache = SampleAPKCache()


# ---------------------------------------------------------------------------
# APK dissection endpoints
# ---------------------------------------------------------------------------

WORK_DIR = settings.WORK_DIR


def _get_sample_apk_path(sample_id: str) -> Optional[Path]:
    """Find the original APK path for a sample from its work directory."""
    result = load_result(sample_id)
    if result is None:
        return None

    # Prefer the exact path recorded during analysis.
    recorded_apk = result.get("metadata", {}).get("apk_path")
    if recorded_apk and Path(recorded_apk).exists():
        return Path(recorded_apk)

    sample_name = result.get("metadata", {}).get("sample_name")
    if not sample_name:
        return None

    # Fast paths: common locations
    candidates = [
        WORK_DIR / sample_id / sample_name,
        settings.UPLOADS_DIR / sample_id / sample_name,
        settings.UPLOADS_DIR / sample_id / "file.apk",
        settings.SAMPLES_DIR / "malware" / sample_name,
        settings.SAMPLES_DIR / "malware" / "androzoo_drebin" / sample_name,
        settings.SAMPLES_DIR / "malware" / "bazaar" / sample_name,
        settings.SAMPLES_DIR / "malware" / "contagio" / sample_name,
        settings.SAMPLES_DIR / "malware" / "github" / sample_name,
        settings.SAMPLES_DIR / "malware" / "koodous" / sample_name,
        settings.SAMPLES_DIR / "legitimate" / sample_name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    # Fallback: recursive search under samples/ and uploads/ (slower but thorough)
    for base_dir in (settings.SAMPLES_DIR, settings.UPLOADS_DIR):
        if base_dir.exists():
            for candidate in base_dir.rglob(sample_name):
                if candidate.is_file():
                    return candidate
            for candidate in base_dir.rglob("file.apk"):
                if candidate.is_file():
                    return candidate

    return None


async def _get_or_create_dissection(sample_id: str, refresh: bool = False) -> dict:
    """Return cached dissection.json or generate and cache it.

    Async because generating a dissection re-parses the APK with Androguard
    (seconds), which must not run on the event loop.
    """
    if refresh:
        from backend.dissection import _DISSECTION_CACHE
        _dissection_cache.invalidate(sample_id)
        _DISSECTION_CACHE.pop(sample_id, None)
        # A traversal sample_id would delete a dissection.json outside WORK_DIR.
        # load_result() normally 404s first, but this delete must not depend on
        # that: verified that removing this guard lets "..\outside" unlink a
        # file above WORK_DIR.
        try:
            validate_sample_id(sample_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid sample_id")
        dissection_path = WORK_DIR / sample_id / "dissection.json"
        if dissection_path.exists():
            try:
                dissection_path.unlink()
            except Exception as e:
                logger.debug("Failed to remove stale dissection cache: %s", e)

    cached = load_dissection(str(WORK_DIR), sample_id)
    if cached is not None:
        return cached

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    def _build() -> dict:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR), cache=_dissection_cache)
        data = dissector.dissect()
        # Cache for future requests
        dissection_path = WORK_DIR / sample_id / "dissection.json"
        try:
            with open(dissection_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as ex:
            logger.debug("Failed to cache dissection to disk: %s", ex)
        return data

    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _build)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@router.get("/api/sample/{sample_id}/dissection")
async def api_get_dissection(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get full dissected APK structure (cached or on-demand)."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    return await _get_or_create_dissection(sample_id, refresh=refresh)


@router.get("/api/sample/{sample_id}/dissection/manifest")
async def api_get_dissection_manifest(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get parsed AndroidManifest.xml (raw_manifest truncated to 5KB)."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = await _get_or_create_dissection(sample_id, refresh=refresh)
    manifest = data.get("manifest", {})
    if isinstance(manifest.get("raw_manifest"), str) and len(manifest["raw_manifest"]) > 5000:
        manifest = {**manifest, "raw_manifest": manifest["raw_manifest"][:5000]}
    return {"manifest": manifest}


@router.get("/api/sample/{sample_id}/dissection/permissions")
async def api_get_dissection_permissions(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get declared permissions with risk levels."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = await _get_or_create_dissection(sample_id, refresh=refresh)
    return {"permissions": data.get("permissions", [])}


@router.get("/api/sample/{sample_id}/dissection/components")
async def api_get_dissection_components(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get activities, services, receivers, providers."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = await _get_or_create_dissection(sample_id, refresh=refresh)
    return {"components": data.get("components", {})}


@router.get("/api/sample/{sample_id}/dissection/dex")
async def api_get_dissection_dex(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get DEX statistics."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = await _get_or_create_dissection(sample_id, refresh=refresh)
    return {"dex_stats": data.get("dex_stats", {})}


@router.get("/api/sample/{sample_id}/dissection/classes")
async def api_get_dissection_classes(
    sample_id: str,
    refresh: bool = Query(False),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    """Get list of decompiled Java classes (lightweight — no method bodies).
    Method bodies are fetched on demand via /dissection/class-methods.
    Supports pagination via offset/limit.
    """
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    if refresh:
        _dissection_cache.invalidate(sample_id)
        classes_cache = WORK_DIR / sample_id / "dissection_classes_cache.json"
        if classes_cache.exists():
            try:
                classes_cache.unlink()
            except Exception as ex:
                logger.debug("Failed to remove classes cache: %s", ex)

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR), cache=_dissection_cache)
        loop = asyncio.get_event_loop()
        all_classes = await loop.run_in_executor(None, lambda: dissector.list_decompiled_class_objects(refresh=refresh))

        # Strip method bodies to reduce payload size — return only names + metadata
        lightweight = []
        for cls in all_classes:
            lightweight.append({
                "name": cls["name"],
                "method_count": len(cls.get("methods", [])),
                "method_names": [m["name"] for m in cls.get("methods", [])],
                "network_calls": cls.get("network_calls", []),
                "permissions_used": cls.get("permissions_used", []),
            })

        total = len(lightweight)
        page = lightweight[offset:offset + limit]
        return {"classes": page, "total": total, "offset": offset, "limit": limit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@router.get("/api/sample/{sample_id}/dissection/class-methods/{class_name:path}")
async def api_get_class_methods(sample_id: str, class_name: str, refresh: bool = Query(False)) -> dict:
    """Return method bodies for a single class on demand.
    Uses the cached class objects to avoid re-reading source files.
    """
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    if refresh:
        _dissection_cache.invalidate(sample_id)
        classes_cache = WORK_DIR / sample_id / "dissection_classes_cache.json"
        if classes_cache.exists():
            try:
                classes_cache.unlink()
            except Exception as ex:
                logger.debug("Failed to remove classes cache: %s", ex)

    try:
        from backend.dissection import get_class_methods_lite
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR), cache=_dissection_cache)
        loop = asyncio.get_event_loop()
        all_classes = await loop.run_in_executor(None, lambda: dissector.list_decompiled_class_objects(refresh=refresh))

        cls = get_class_methods_lite(all_classes, class_name)
        if cls is None:
            raise HTTPException(status_code=404, detail=f"Class '{class_name}' not found")
        return {"class_name": class_name, "methods": cls.get("methods", [])}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load class methods: {e}")


@router.get("/api/sample/{sample_id}/dissection/code/{class_name:path}")
async def api_get_class_code(sample_id: str, class_name: str, refresh: bool = Query(False)) -> dict:
    """Get decompiled source for a specific Java class."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")

    if refresh:
        _dissection_cache.invalidate(sample_id)

    try:
        dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR), cache=_dissection_cache)
        # read_class_source re-parses DEX via Androguard (seconds per class on a
        # multi-dex APK) and must not run on the event loop.
        loop = asyncio.get_event_loop()
        code = await loop.run_in_executor(None, dissector.read_class_source, class_name)
        if code is None:
            raise HTTPException(status_code=404, detail="Class source not found")
        return {"class_name": class_name, "code": code}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@router.get("/api/sample/{sample_id}/dissection/strings")
async def api_get_dissection_strings(sample_id: str):
    """Get extracted strings from Step 2 result."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    strings_path = WORK_DIR / sample_id / "step2_strings.json"
    if not strings_path.exists():
        raise HTTPException(status_code=404, detail="Strings not found for sample")

    try:
        raw = strings_path.read_bytes()
        data = json.loads(raw)

        def _clean(obj):
            if isinstance(obj, str):
                return obj.encode("utf-8", errors="replace").decode("utf-8")
            if isinstance(obj, dict):
                return {k: _clean(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_clean(v) for v in obj]
            return obj

        return JSONResponse(content=_clean(data))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse strings JSON: {e}")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Failed to read strings file: {e}")


class ExplainMethodRequest(BaseModel):
    class_name: str
    method_name: str
    method_code: str
    flags: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Code Analysis endpoints
# ---------------------------------------------------------------------------


def _get_code_analyzer(sample_id: str) -> CodeAnalyzer:
    """Create a CodeAnalyzer for a sample, raising 404 if APK not found."""
    apk_path = _get_sample_apk_path(sample_id)
    if apk_path is None:
        raise HTTPException(status_code=404, detail="APK file not found for sample")
    return CodeAnalyzer(str(apk_path), str(WORK_DIR), sample_id, cache=_dissection_cache)


@router.get("/api/sample/{sample_id}/code-analysis/{class_name:path}")
async def api_get_code_analysis(sample_id: str, class_name: str) -> dict:
    """Method-level risk assessment, suspicious lines, and attack flow for a class."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    analyzer = _get_code_analyzer(sample_id)
    loop = asyncio.get_event_loop()
    try:
        analysis = await loop.run_in_executor(None, analyzer.analyze_class, class_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Code analysis failed: {e}")

    if analysis is None:
        raise HTTPException(status_code=404, detail=f"Class '{class_name}' not found or has no decompiled source")

    return analysis


@router.get("/api/sample/{sample_id}/string-references/{string_value:path}")
async def api_get_string_references(sample_id: str, string_value: str) -> dict:
    """Find all usages of a specific string value across all decompiled classes."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    analyzer = _get_code_analyzer(sample_id)
    loop = asyncio.get_event_loop()
    try:
        refs = await loop.run_in_executor(None, analyzer.get_string_references, string_value)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"String reference lookup failed: {e}")

    if refs is None:
        return {"string": string_value, "usages": []}

    return refs


# Static pattern map: keyword → analyst label
_STATIC_PATTERN_LABELS: dict = {
    "invoke": ("reflection", "Dynamic method invocation via reflection"),
    "classloader": ("dynamic_loading", "Runtime class loading — common in dropper/loader malware"),
    "dexclassloader": ("dynamic_loading", "Loads DEX/APK from disk at runtime — strong dropper indicator"),
    "cipher": ("crypto", "Cryptographic operation — check for data encryption/decryption"),
    "base64": ("encoding", "Base64 encoding/decoding — often used to obfuscate payloads"),
    "decode": ("encoding", "Decoding operation — may unwrap an obfuscated payload"),
    "encrypt": ("crypto", "Explicit encryption — check what data is being encrypted and why"),
    "runtime.exec": ("command_exec", "Shell command execution — high-severity indicator"),
    "processbuilder": ("command_exec", "Process spawning — shell command execution path"),
    "httpurlconnection": ("network", "HTTP network call — check destination and payload"),
    "socket": ("network", "Raw socket usage — potential C2 communication channel"),
    "reflect": ("reflection", "Java reflection API — used to hide method calls from static analysis"),
    "permission": ("permissions", "Runtime permission check — note which permission is being gated"),
}


def _annotate_lines(code: str) -> Dict[int, dict]:
    """
    Scan code lines for suspicious patterns.
    Returns {line_index: {type, label}} for any line that matches.
    Zero-indexed to match frontend array indexing.
    """
    annotations = {}
    for i, line in enumerate(code.splitlines()):
        lower = line.lower()
        for keyword, (pattern_type, label) in _STATIC_PATTERN_LABELS.items():
            if keyword in lower:
                # First match wins per line — use the most specific keyword
                annotations[i] = {"type": pattern_type, "label": label, "keyword": keyword}
                break
    return annotations


@router.post("/api/sample/{sample_id}/dissection/explain-method")
async def api_explain_method(sample_id: str, request: ExplainMethodRequest) -> dict:
    """
    Return static line annotations (instant) + async LLM summary for a method.
    Static annotations are always present; LLM summary may be empty if LLM is unavailable.
    """
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Layer 1: static pattern annotations — synchronous, no LLM
    line_annotations = _annotate_lines(request.method_code)

    # Layer 2: LLM explanation — run in thread pool so we don't block the event loop
    loop = asyncio.get_event_loop()
    try:
        llm_result = await loop.run_in_executor(
            None,
            lambda: explain_method(
                request.class_name,
                request.method_name,
                request.method_code,
                request.flags or [],
            ),
        )
    except Exception as e:
        llm_result = {
            "summary": f"LLM unavailable: {e}",
            "threat_type": "unknown",
            "confidence": 0.0,
        }

    return {
        "class_name": request.class_name,
        "method_name": request.method_name,
        "line_annotations": line_annotations,
        "llm": llm_result,
    }


@router.get("/api/sample/{sample_id}/dissection/summary")
async def api_get_dissection_summary(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Return an LLM-generated threat assessment from the dissection data."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Check for cached summary (unless refresh requested)
    summary_path = WORK_DIR / sample_id / "dissection_summary.json"
    if not refresh and summary_path.exists():
        try:
            with open(summary_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            logger.debug("Failed to load cached summary, regenerating")

    # Load dissection data
    dissection = load_dissection(str(WORK_DIR), sample_id)
    if dissection is None:
        # Generate on the fly (shared helper runs it off the event loop)
        dissection = await _get_or_create_dissection(sample_id)

    # Load class objects for suspicious class analysis
    apk_path = _get_sample_apk_path(sample_id)
    class_objects = None
    if apk_path is not None:
        try:
            dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR), cache=_dissection_cache)
            loop = asyncio.get_event_loop()
            class_objects = await loop.run_in_executor(None, dissector.list_decompiled_class_objects)
        except Exception:
            logger.debug("Failed to load class objects for summary, continuing without")

    # Call LLM
    loop = asyncio.get_event_loop()
    try:
        summary = await loop.run_in_executor(
            None, lambda: summarize_dissection(dissection, class_objects),
        )
    except Exception as e:
        summary = {
            "threat_level": "unknown",
            "risk_score": 0,
            "summary": f"LLM summary unavailable: {e}",
            "key_behaviors": [],
            "suspicious_methods": [],
            "c2_indicators": [],
            "recommended_focus": [],
            "status": "error",
        }

    # Cache the summary
    try:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str)
    except Exception:
        logger.debug("Failed to cache summary to disk")

    return summary
