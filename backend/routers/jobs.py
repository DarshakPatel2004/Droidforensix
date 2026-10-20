"""Upload, analysis start, and analysis status routes."""

import asyncio
import hashlib
import logging
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from analysis.pipeline import run_pipeline
from backend.config import settings
from backend.core.androguard_analyzer import APKAnalyzer
from backend.core.apk_processor import APKProcessor
from backend.realtime import make_event_emitter
from backend.transformers import (
    load_result,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# In-memory store for upload -> sample mapping and analysis status
upload_registry: Dict[str, dict] = {}
sample_status: Dict[str, dict] = {}

# How long an HTTP request waits on a queued analysis before returning. This is a
# client-facing bound only: the pipeline's own limit (run_pipeline's
# pipeline_timeout, default 600s) is authoritative and the worker thread keeps
# running after this expires, so exceeding it is not a failure.
ANALYSIS_AWAIT_TIMEOUT_S = 300

# Strong references to fire-and-forget analysis tasks, so they are not
# garbage-collected mid-flight and their exceptions stay retrievable.
_background_tasks: set = set()


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


def _resolve_upload_path(filename: Optional[str]) -> Path:
    """Map a client-supplied multipart filename to a path inside UPLOADS_DIR.

    The multipart filename is attacker-controlled: Starlette passes it through
    verbatim, and python-multipart strips only a leading drive/UNC prefix, so a
    `..`-relative name survives. Joining it unchecked lets an upload truncate or
    create a file anywhere the service account can write - including backend/*.py,
    which uvicorn --reload would then import. So resolve, then verify containment
    against the resolved root (a string prefix check alone is defeated by a
    sibling directory such as `uploads_evil`).
    """
    if not filename or not filename.strip():
        raise HTTPException(status_code=400, detail="Invalid filename: filename is empty")

    uploads_root = Path(settings.UPLOADS_DIR).resolve()
    candidate = (uploads_root / filename).resolve()

    if candidate != uploads_root and uploads_root not in candidate.parents:
        raise HTTPException(status_code=400, detail="Invalid filename: path traversal rejected")

    # Containment is proven, so the original name is safe to keep - callers that
    # report it back still see what the client sent.
    return uploads_root / filename


@router.post("/api/upload")
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
        # Partial upload: remove the directory so stalled transfers do not
        # accumulate unreferenced files on disk.
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(status_code=408, detail="Upload timed out after 60 seconds")
    except Exception as e:
        shutil.rmtree(upload_dir, ignore_errors=True)
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


@router.post("/api/analyze/{upload_id}")
async def api_analyze_upload(upload_id: str) -> dict:
    """Trigger analysis for a previously uploaded APK."""
    upload = upload_registry.get(upload_id)
    if upload is None:
        raise HTTPException(status_code=404, detail="Upload not found")

    apk_path = upload["path"]
    if not Path(apk_path).exists():
        raise HTTPException(status_code=400, detail="Uploaded APK file no longer exists")

    # Idempotency guard: a retry (frontend ErrorState button, dedup re-upload) must
    # not start a second run_pipeline against the same work directory - the two
    # writers would interleave json.dump into pipeline_result.json and corrupt it.
    existing = sample_status.get(upload_id, {})
    if existing.get("status") in ("queued", "analyzing"):
        return {
            "upload_id": upload_id,
            "status": existing["status"],
            "message": "Analysis already in progress for this upload.",
        }

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
            return await asyncio.wait_for(future, timeout=ANALYSIS_AWAIT_TIMEOUT_S)
        except asyncio.TimeoutError:
            # The executor thread keeps running (asyncio cannot cancel it), and the
            # pipeline's own limit is higher, so this is NOT a terminal failure.
            # Leave the status as "analyzing"; run_analysis writes the real outcome.
            logger.warning(
                "Analysis for upload %s exceeded %.0fs and is still running in the background",
                upload_id, ANALYSIS_AWAIT_TIMEOUT_S)
            raise

    # Keep a reference so the task is not garbage-collected mid-flight and its
    # exception is retrievable.
    t = asyncio.create_task(run_analysis_async())
    _background_tasks.add(t)
    t.add_done_callback(_background_tasks.discard)
    upload["status"] = "queued"

    return {
        "upload_id": upload_id,
        "status": "queued",
        "message": "Analysis started. Poll GET /api/sample/{sample_id}/status or listen on /ws for progress.",
    }


@router.post("/analyze")
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

    t = asyncio.create_task(run_analysis_async())
    _background_tasks.add(t)
    t.add_done_callback(_background_tasks.discard)

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Analysis started. Poll GET /api/sample/{sample_id}/status or listen on /ws for progress.",
    }


@router.get("/api/sample/{sample_id}/status")
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


@router.post("/api/analysis/full")
async def api_full_analysis(file: UploadFile = File(...)):
    """Execute full 7-step pipeline using APKProcessor."""
    apk_path = _resolve_upload_path(file.filename)
    try:
        with open(apk_path, "wb") as f:
            f.write(await file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")
    
    processor = APKProcessor(str(apk_path))
    results = processor.process()

    if not results['success']:
        # Never report success for an analysis that failed.
        return {'status': 'error', 'data': {'error': results.get('error')}}

    if results.get('partial'):
        # Some steps failed; the payload is usable but must say so.
        return {
            'status': 'partial',
            'failed_steps': results.get('failed_steps', []),
            'data': results.get('data'),
        }

    return {
        'status': 'success',
        'data': results.get('data'),
    }


@router.post("/api/analysis/androguard-only")
async def api_androguard_analysis(file: UploadFile = File(...)):
    """Run just the Androguard static analysis."""
    apk_path = _resolve_upload_path(file.filename)
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

@router.post("/api/log-error")
async def log_error(payload: dict):
    logger.warning("Client-side error: %s", payload.get("message", "No message"))
    if payload.get("stack"):
        logger.debug("Client-side stack trace: %s", payload["stack"])
    return {"ok": True}
