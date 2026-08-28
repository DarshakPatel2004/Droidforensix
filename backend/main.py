"""
DroidForensix FastAPI Backend

Provides REST API and WebSocket endpoint for real-time analysis streaming.
"""

import asyncio
import json
import logging
import os
import shutil
import sys
import time

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

# Ensure project root is in path so imports work from any directory (backend/ or root)
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel
import hashlib
import subprocess
import uuid

from analysis.pipeline import run_pipeline
from analysis.step7_llm_assessment import explain_method, explain_threat_chain, summarize_dissection, _ollama_available, _normalize_ollama_host
from droidforensix_llm import LLMVerifier, get_verifier, set_verifier
from backend.pdf_report import generate_report
from backend.config import settings
from backend.events import WebSocketEvent, VALID_EVENT_TYPES
from backend.validators import validate_event
from backend.transformers import (
    load_result,
    load_all_results,
    transform_graph,
    transform_clusters,
    transform_timeline,
    transform_samples_list,
)
from backend.dissection import APKDissector, SampleAPKCache, load_dissection
from backend import threat_intel as ti
from backend.family_id import identify_family
from backend.obfuscation_view import build_obfuscation_view, deobfuscate_text
from backend.code_analysis import CodeAnalyzer
from backend.community_intel import get_cached_community_intel
from backend.core.apk_processor import APKProcessor
from backend.core.androguard_analyzer import APKAnalyzer


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ollama Lifecycle (via LLMVerifier)
# ---------------------------------------------------------------------------

# The global LLMVerifier manages Ollama start/stop with the backend.
# On startup: starts Ollama if not already running.
# On shutdown: stops the Ollama process if we started it.

def ensure_ollama_running():
    """Start Ollama via LLMVerifier. Blocks until ready or timeout."""
    if os.environ.get("DROIDFORENSIX_TESTING"):
        return
    verifier = LLMVerifier(
        enabled=True,
        model=os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL),
        timeout=30,
        cache_enabled=True,
    )
    set_verifier(verifier)
    
    if not verifier.start():
        print("[STARTUP] [WARN] Ollama could not be started — LLM features may fail")
    else:
        print(f"[STARTUP] [OK] Ollama ready (model: {verifier.model})")


def stop_ollama():
    """Stop Ollama via LLMVerifier on backend shutdown."""
    try:
        verifier = get_verifier()
        verifier.stop()
    except Exception as e:
        print(f"[SHUTDOWN] [WARN] Error stopping Ollama: {e}")


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return
        text = json.dumps(message, default=str)
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_text(text)
            except Exception as e:
                logger.debug("Broadcast failed, removing connection: %s", e)
                disconnected.add(connection)
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()

# Shared APK parse cache — one parse per sample across all endpoints
_dissection_cache = SampleAPKCache()

# In-memory store for upload -> sample mapping and analysis status
upload_registry: Dict[str, dict] = {}
sample_status: Dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------

def make_event_emitter(loop: asyncio.AbstractEventLoop):
    """Create a callback that emits pipeline events via WebSocket."""
    def emit(event_type: str, data: dict):
        print(f"[EMITTER] {event_type} connections={len(manager.active_connections)}")
        if event_type not in VALID_EVENT_TYPES:
            print(f"[EMITTER] invalid type {event_type}")
            return
        event = WebSocketEvent(event_type=event_type, data=data)
        event_dict = event.to_dict()
        print(f"[EMITTER] event_dict valid={validate_event(event_dict)}")
        if validate_event(event_dict):
            # Schedule broadcast on the event loop
            fut = asyncio.run_coroutine_threadsafe(
                manager.broadcast(event_dict), loop
            )
            fut.add_done_callback(lambda f: print(f"[EMITTER] broadcast done err={f.exception()}"))
    return emit


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    apk_path: str


class SampleInfo(BaseModel):
    id: str
    name: str
    status: str
    timestamp: str


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("[STARTUP] Initializing DroidForensix backend...")
    settings.WORK_DIR.mkdir(parents=True, exist_ok=True)
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    settings.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    settings.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Ensure Ollama is running (required for LLM-based features)
    ensure_ollama_running()
    
    print("[STARTUP] [OK] Backend ready")
    yield
    
    # Shutdown
    print("[SHUTDOWN] Cleaning up connections...")
    manager.active_connections.clear()
    
    # Stop Ollama (if we started it)
    stop_ollama()
    print("[SHUTDOWN] [OK] Ollama stopped")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="DroidForensix Backend", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins + [settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def health_check():
    return {"status": "ok", "version": "1.0.0", "api_prefix": "/api"}


@app.get("/api/samples")
async def api_list_samples() -> dict:
    """List all analyzed samples with summary fields."""
    results = load_all_results()
    samples = transform_samples_list(results)
    return {"samples": samples, "total": len(samples)}


@app.get("/api/sample/{sample_id}")
async def api_get_sample(sample_id: str) -> dict:
    """Get full analysis report for a sample."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return result


@app.get("/api/graph/{sample_id}")
async def api_get_graph(sample_id: str) -> dict:
    """Get 3D graph nodes/edges for a sample."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return transform_graph(result)


@app.get("/api/clusters")
async def api_get_clusters() -> dict:
    """Get 3D clustering data for all samples."""
    results = load_all_results()
    return transform_clusters(results)


@app.get("/api/timeline/{sample_id}")
async def api_get_timeline(sample_id: str) -> dict:
    """Get timeline/attack-chain progression for a sample."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return transform_timeline(result)


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


def _get_or_create_dissection(sample_id: str, refresh: bool = False) -> dict:
    """Return cached dissection.json or generate and cache it."""
    if refresh:
        from backend.dissection import _DISSECTION_CACHE
        _dissection_cache.invalidate(sample_id)
        _DISSECTION_CACHE.pop(sample_id, None)
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

    try:
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection")
async def api_get_dissection(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get full dissected APK structure (cached or on-demand)."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    return _get_or_create_dissection(sample_id, refresh=refresh)


@app.get("/api/sample/{sample_id}/dissection/manifest")
async def api_get_dissection_manifest(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get parsed AndroidManifest.xml (raw_manifest truncated to 5KB)."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = _get_or_create_dissection(sample_id, refresh=refresh)
    manifest = data.get("manifest", {})
    if isinstance(manifest.get("raw_manifest"), str) and len(manifest["raw_manifest"]) > 5000:
        manifest = {**manifest, "raw_manifest": manifest["raw_manifest"][:5000]}
    return {"manifest": manifest}


@app.get("/api/sample/{sample_id}/dissection/permissions")
async def api_get_dissection_permissions(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get declared permissions with risk levels."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = _get_or_create_dissection(sample_id, refresh=refresh)
    return {"permissions": data.get("permissions", [])}


@app.get("/api/sample/{sample_id}/dissection/components")
async def api_get_dissection_components(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get activities, services, receivers, providers."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = _get_or_create_dissection(sample_id, refresh=refresh)
    return {"components": data.get("components", {})}


@app.get("/api/sample/{sample_id}/dissection/dex")
async def api_get_dissection_dex(sample_id: str, refresh: bool = Query(False)) -> dict:
    """Get DEX statistics."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = _get_or_create_dissection(sample_id, refresh=refresh)
    return {"dex_stats": data.get("dex_stats", {})}


@app.get("/api/sample/{sample_id}/dissection/classes")
async def api_get_dissection_classes(
    sample_id: str,
    refresh: bool = Query(False),
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=10000),
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


@app.get("/api/sample/{sample_id}/dissection/class-methods/{class_name:path}")
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


@app.get("/api/sample/{sample_id}/dissection/code/{class_name:path}")
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
        code = dissector.read_class_source(class_name)
        if code is None:
            raise HTTPException(status_code=404, detail="Class source not found")
        return {"class_name": class_name, "code": code}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")


@app.get("/api/sample/{sample_id}/dissection/strings")
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


# ---------------------------------------------------------------------------
# Threat intelligence endpoints (Phase 2 enrichment + family identification)
# ---------------------------------------------------------------------------

@app.get("/api/sample/{sample_id}/threat-intel")
async def api_get_threat_intel(sample_id: str) -> dict:
    """Aggregated C2 threat-intel: DNS status, classification, geo, and family."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    data = ti.build_threat_intel(result, sample_id)
    try:
        data["family"] = identify_family(sample_id, result)
    except Exception as e:  # family ID must never break the dashboard
        data["family"] = {"family": "unknown", "confidence": 0.0,
                          "method": "error", "reasoning": str(e), "candidates": []}
    return data


@app.get("/api/sample/{sample_id}/family")
async def api_get_family(sample_id: str) -> dict:
    """Malware family identification (deterministic + LLM)."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return identify_family(sample_id, result)


@app.get("/api/sample/{sample_id}/obfuscation")
async def api_get_obfuscation(sample_id: str) -> dict:
    """Obfuscation analysis view: techniques, DEX entropy, native artifacts."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    obf = build_obfuscation_view(sample_id, result.get("obfuscation_analysis"))
    return obf


class DeobfuscateRequest(BaseModel):
    text: str
    hint: Optional[str] = None


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


@app.get("/api/sample/{sample_id}/code-analysis/{class_name:path}")
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


@app.get("/api/sample/{sample_id}/string-references/{string_value:path}")
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


# ---------------------------------------------------------------------------
# Attribution & Threat Summary endpoints
# ---------------------------------------------------------------------------


@app.get("/api/sample/{sample_id}/attribution")
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
            if cached.get("schema_version") == 2:
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
        "schema_version": 2,
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
    # Permissions match score
    metadata = result.get("metadata", {})
    declared_perms = set(metadata.get("permissions", []))
    family_id_result = result.get("family_identification", {})
    family_perms = set(family_id_result.get("matched_permissions", []))
    if family_perms:
        overlap = len(declared_perms & family_perms)
        permissions_match = round(overlap / len(family_perms), 2) if family_perms else 0.0
    else:
        permissions_match = 0.5

    # C2 overlap score
    c2_list = result.get("c2_infrastructure", [])
    c2_domains = {c.get("domain", "") for c in c2_list if c.get("domain")}
    c2_overlap = 0.5
    if c2_domains and family_id_result:
        family_c2s = set(family_id_result.get("matched_c2", []))
        if family_c2s:
            overlap = len(c2_domains & family_c2s)
            c2_overlap = round(overlap / len(c2_domains), 2) if c2_domains else 0.5

    # Obfuscation pattern score
    obfuscation = result.get("obfuscation_analysis", {})
    obf_score = obfuscation.get("obfuscation_score", 0)
    obf_pattern = round(min(obf_score / 100, 1.0), 2)

    # Code similarity (simplified: use overall heuristic score)
    heuristic = result.get("heuristic", {})
    heuristic_score = heuristic.get("score", 0) if isinstance(heuristic, dict) else 0
    code_similarity = round(min(heuristic_score / 100, 1.0), 2)

    return {
        "permissions_match": permissions_match,
        "c2_overlap": c2_overlap,
        "obfuscation_pattern": obf_pattern,
        "code_similarity": code_similarity,
    }


def _build_supporting_signals(result: dict, family_data: dict, breakdown: dict) -> List[str]:
    """Generate human-readable supporting signals from the data."""
    signals = []
    metadata = result.get("metadata", {})
    permissions = metadata.get("permissions", [])
    c2_list = result.get("c2_infrastructure", [])
    obfuscation = result.get("obfuscation_analysis", {})

    perm_match_pct = round(breakdown["permissions_match"] * 100)
    if perm_match_pct > 0:
        signals.append(f"{perm_match_pct}% permissions match family baseline")

    c2_domains = {c.get("domain") for c in c2_list if c.get("domain")}
    if c2_domains:
        signals.append(f"C2 indicators overlap with {len(c2_domains)} known indicators")

    obf_level = obfuscation.get("obfuscation_level", "low")
    if obf_level != "low":
        signals.append(f"Obfuscation pattern: {obf_level.upper()}")

    family = family_data.get("family", "unknown")
    if family != "unknown":
        signals.append(f"Code structure consistent with {family}")

    heuristic = result.get("heuristic", {})
    if isinstance(heuristic, dict) and heuristic.get("method"):
        signals.append(f"Detection method: {heuristic['method']}")

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

    a_perms = set((a.get("metadata", {}) or {}).get("permissions", []))
    b_perms = set((b.get("metadata", {}) or {}).get("permissions", []))
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


@app.get("/api/sample/{sample_id}/threat-summary")
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

    permissions = metadata.get("permissions", [])
    dangerous_count = sum(
        1 for p in permissions
        if p.startswith("android.permission.")
        and p.split(".")[-1] in {
            "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "CALL_PHONE",
            "READ_CONTACTS", "ACCESS_FINE_LOCATION", "CAMERA",
            "RECORD_AUDIO", "READ_PHONE_STATE", "WRITE_EXTERNAL_STORAGE",
        }
    )

    c2_active = sum(1 for c in c2_list if c.get("status") == "active")
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
            {"type": "active_c2_endpoints", "count": c2_active},
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


@app.get("/api/sample/{sample_id}/community-intel")
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
        raise HTTPException(status_code=500, detail=f"Community intel search failed: {e}")

    return payload


class ExplainChainRequest(BaseModel):
    chain: dict


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


@app.post("/api/sample/{sample_id}/dissection/explain-method")
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


@app.post("/api/sample/{sample_id}/explain-chain")
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


@app.get("/api/sample/{sample_id}/dissection/summary")
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
        # Try to generate dissection on the fly
        apk_path = _get_sample_apk_path(sample_id)
        if apk_path is None:
            raise HTTPException(status_code=404, detail="APK file not found for sample")
        try:
            dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR), cache=_dissection_cache)
            dissection = dissector.dissect()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Dissection failed: {e}")

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


@app.post("/api/sample/{sample_id}/report/pdf")
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

    # Gather supporting data
    threat_data = ti.build_threat_intel(result, sample_id)
    try:
        obfuscation = build_obfuscation_view(sample_id, result.get("obfuscation_analysis"))
    except Exception:
        logger.debug("Failed to build obfuscation view for PDF report")
        obfuscation = {}

    # Get suspicious classes + methods
    apk_path = _get_sample_apk_path(sample_id)
    annotated_methods = []

    if apk_path:
        try:
            dissector = APKDissector(str(apk_path), work_dir=str(WORK_DIR), cache=_dissection_cache)
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
                    line_annotations = _annotate_lines(body)

                    # LLM summary — run synchronously here (we're already in executor context)
                    llm_result = explain_method(cls_name, name, body, flags)

                    annotated_methods.append({
                        'class_name':       cls_name,
                        'method_name':      name,
                        'flags':            flags,
                        'line_annotations': line_annotations,
                        'llm':              llm_result,
                    })
                    processed += 1

        except Exception as e:
            logger.exception("Method annotation failed during PDF generation (sample %s): %s", sample_id, e)

    # Generate PDF
    loop = asyncio.get_event_loop()
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
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    filename = f"droidforensix_{sample_id[:12]}_{mode}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/sample/{sample_id}/deobfuscate")
async def api_deobfuscate(sample_id: str, request: DeobfuscateRequest) -> dict:
    """Best-effort deobfuscation of a user-supplied string."""
    result = load_result(sample_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Sample not found")

    return deobfuscate_text(request.text, request.hint)


@app.get("/api/sample/{sample_id}/threat-intel/export/csv")
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


@app.get("/api/sample/{sample_id}/threat-intel/export/stix")
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


@app.get("/api/sample/{sample_id}/threat-intel/export/yara")
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


# Legacy endpoints (kept for backward compatibility)
@app.get("/samples")
async def list_samples() -> dict:
    """List all processed samples (legacy)."""
    return await api_list_samples()


@app.get("/samples/{sample_id}")
async def get_sample(sample_id: str) -> dict:
    """Get analysis result for a sample (legacy)."""
    return await api_get_sample(sample_id)


# ---------------------------------------------------------------------------
# Upload and analysis endpoints
# ---------------------------------------------------------------------------

def _check_disk_space(min_bytes: int) -> None:
    """Raise 507 if insufficient disk space for the upload."""
    try:
        usage = shutil.disk_usage(str(settings.UPLOADS_DIR))
        if usage.free < min_bytes:
            free_mb = usage.free / (1024 * 1024)
            raise HTTPException(
                status_code=507,
                detail=f"Insufficient disk space ({free_mb:.0f}MB free). Need at least {min_bytes / (1024 * 1024):.0f}MB.",
            )
    except HTTPException:
        raise
    except Exception:
        logger.debug("Disk space check failed, continuing")  # Non-critical


# Deduplicated uploads keyed by SHA-256 so re-uploads are cheap.
_sha256_to_upload: Dict[str, str] = {}  # sha256 → upload_id


@app.post("/api/upload")
async def api_upload_file(file: UploadFile = File(...)) -> dict:
    """Upload an APK file and return an upload ID for analysis."""
    # --- Phase 3: structured server-side validation ---

    # Filename validation
    if not file.filename or not file.filename.strip():
        raise HTTPException(status_code=400, detail="Invalid filename: filename is empty")
    if any(c in file.filename for c in '<>:"|?*\x00'):
        raise HTTPException(status_code=400, detail=f"Invalid filename: {file.filename}")

    # File size check
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if file.size and file.size > max_bytes:
        size_mb = file.size / (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({size_mb:.1f}MB). Maximum allowed: {settings.MAX_UPLOAD_SIZE_MB}MB",
        )

    # Empty file check
    if file.size is not None and file.size == 0:
        raise HTTPException(status_code=400, detail="File is empty")

    # Disk space check (require upload size + 10MB headroom for work copies)
    min_space = (file.size or 0) + 10 * 1024 * 1024
    _check_disk_space(min_space)

    upload_id = str(uuid.uuid4())
    upload_dir = settings.UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    dest_path = upload_dir / "file.apk"
    sha256_hash = hashlib.sha256()
    try:
        with open(dest_path, "wb") as f:
            while True:
                chunk = await asyncio.wait_for(file.read(64 * 1024), timeout=60.0)
                if not chunk:
                    break
                f.write(chunk)
                sha256_hash.update(chunk)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail="Upload timed out after 60 seconds")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")

    sha256 = sha256_hash.hexdigest()

    # Validate ZIP/APK magic bytes (PK\x03\x04)
    try:
        with open(dest_path, "rb") as f:
            header = f.read(4)
        if len(header) < 4 or header[:4] != b"PK\x03\x04":
            # Clean up invalid file
            try:
                dest_path.unlink()
                upload_dir.rmdir()
            except Exception:
                logger.debug("Failed to clean up after invalid upload")
            raise HTTPException(status_code=400, detail="Invalid APK file: not a valid ZIP archive (bad header)")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to validate file: {e}")

    # SHA-256 dedup: if this exact file was uploaded before, return existing upload_id
    if sha256 in _sha256_to_upload:
        existing_id = _sha256_to_upload[sha256]
        # Clean up the duplicate file
        try:
            dest_path.unlink()
            upload_dir.rmdir()
        except Exception:
            logger.debug("Failed to clean up duplicate upload directory")
        return {
            "upload_id": existing_id,
            "filename": file.filename,
            "sha256": sha256,
            "status": "uploaded",
            "deduplicated": True,
            "message": "File already uploaded. Reusing existing upload.",
        }

    _sha256_to_upload[sha256] = upload_id
    upload_registry[upload_id] = {
        "upload_id": upload_id,
        "filename": file.filename,
        "sha256": sha256,
        "path": str(dest_path),
        "status": "uploaded",
    }

    return {
        "upload_id": upload_id,
        "filename": file.filename,
        "sha256": sha256,
        "status": "uploaded",
        "message": "File uploaded successfully. Use POST /api/analyze/{upload_id} to start analysis.",
    }


@app.post("/api/analyze/{upload_id}")
async def api_analyze_upload(upload_id: str) -> dict:
    """Trigger analysis for a previously uploaded APK."""
    upload = upload_registry.get(upload_id)
    if upload is None:
        raise HTTPException(status_code=404, detail="Upload not found")

    apk_path = upload["path"]
    if not Path(apk_path).exists():
        raise HTTPException(status_code=400, detail="Uploaded APK file no longer exists")

    loop = asyncio.get_event_loop()

    def run_analysis():
        emitter = make_event_emitter(loop)
        try:
            sample_status[upload_id] = {"status": "analyzing", "sample_id": None, "error": None, "started_at": datetime.now(timezone.utc).isoformat()}
            result = run_pipeline(apk_path, event_emitter=emitter)
            sample_id = result.get("sample_id")
            # Map upload_id to final sample_id for status lookups
            sample_status[upload_id] = {"status": "completed", "sample_id": sample_id, "error": None, "started_at": sample_status[upload_id].get("started_at")}
            if sample_id:
                upload["sample_id"] = sample_id
            return result
        except Exception as e:
            sample_status[upload_id] = {"status": "failed", "sample_id": None, "error": str(e)}
            raise

    async def run_analysis_async():
        future = loop.run_in_executor(None, run_analysis)
        try:
            return await asyncio.wait_for(future, timeout=300)
        except asyncio.TimeoutError:
            sample_status[upload_id] = {"status": "error", "sample_id": None, "error": "pipeline timed out"}
            raise

    asyncio.create_task(run_analysis_async())
    upload["status"] = "queued"

    return {
        "upload_id": upload_id,
        "status": "queued",
        "message": "Analysis started. Poll GET /api/sample/{sample_id}/status or listen on /ws for progress.",
    }


@app.post("/analyze")
async def analyze(request: AnalyzeRequest) -> dict:
    """Trigger analysis of an APK by local path (REST fallback / backward compatibility)."""
    apk_path = request.apk_path
    if not Path(apk_path).exists():
        raise HTTPException(status_code=400, detail=f"APK not found: {apk_path}")

    loop = asyncio.get_event_loop()
    job_id = str(uuid.uuid4())

    def run_analysis():
        emitter = make_event_emitter(loop)
        try:
            sample_status[job_id] = {"status": "analyzing", "sample_id": None, "error": None, "started_at": datetime.now(timezone.utc).isoformat()}
            result = run_pipeline(apk_path, event_emitter=emitter)
            sample_id = result.get("sample_id")
            sample_status[job_id] = {"status": "completed", "sample_id": sample_id, "error": None, "started_at": sample_status[job_id].get("started_at")}
            return result
        except Exception as e:
            sample_status[job_id] = {"status": "failed", "sample_id": None, "error": str(e)}
            raise

    async def run_analysis_async():
        return await loop.run_in_executor(None, run_analysis)

    asyncio.create_task(run_analysis_async())

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Analysis started. Poll GET /api/sample/{sample_id}/status or listen on /ws for progress.",
    }


@app.get("/api/sample/{sample_id}/status")
async def api_get_sample_status(sample_id: str) -> dict:
    """Get analysis status for a sample or upload/job ID."""
    # Check upload/job status first
    if sample_id in sample_status:
        info = sample_status[sample_id]
        return {
            "sample_id": info.get("sample_id") or sample_id,
            "status": info["status"],
            "error": info.get("error"),
            "started_at": info.get("started_at"),
        }

    # Check if final result exists
    result = load_result(sample_id)
    if result is not None:
        return {
            "sample_id": sample_id,
            "status": "completed",
            "severity": result.get("llm_assessment", {}).get("severity"),
            "risk_score": result.get("llm_assessment", {}).get("risk_score"),
        }

    raise HTTPException(status_code=404, detail="Sample or job not found")


@app.post("/api/analysis/full")
async def api_full_analysis(file: UploadFile = File(...)):
    """Execute full 7-step pipeline using APKProcessor."""
    apk_path = settings.UPLOADS_DIR / file.filename
    try:
        with open(apk_path, "wb") as f:
            f.write(await file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")
    
    processor = APKProcessor(str(apk_path))
    results = processor.process()
    
    return {
        'status': 'success',
        'data': results if results['success'] else {'error': results.get('error')}
    }


@app.post("/api/analysis/androguard-only")
async def api_androguard_analysis(file: UploadFile = File(...)):
    """Run just the Androguard static analysis."""
    apk_path = settings.UPLOADS_DIR / file.filename
    try:
        with open(apk_path, "wb") as f:
            f.write(await file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")
    
    analyzer = APKAnalyzer(str(apk_path))
    results = analyzer.run()
    
    return results


# ---------------------------------------------------------------------------
# Client-side error logging
# ---------------------------------------------------------------------------

@app.post("/api/log-error")
async def log_error(payload: dict):
    logger.warning("Client-side error: %s", payload.get("message", "No message"))
    if payload.get("stack"):
        logger.debug("Client-side stack trace: %s", payload["stack"])
    return {"ok": True}


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Receive client messages (ping/subscribe)
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                action = message.get("action")
                if action == "ping":
                    await websocket.send_text(json.dumps({"event_type": "pong", "timestamp": ""}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.debug("WebSocket error: %s", e)
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)