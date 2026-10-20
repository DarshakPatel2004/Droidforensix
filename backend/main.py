"""
DroidForensix FastAPI Backend

Provides REST API and WebSocket endpoint for real-time analysis streaming.
"""

import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure project root is in path so imports work from any directory (backend/ or root)
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from droidforensix_llm import LLMVerifier, get_verifier, set_verifier

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
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def health_check():
    return {"status": "ok", "version": "1.0.0", "api_prefix": "/api"}


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


from backend.realtime import manager  # noqa: E402

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
from backend.routers import analyst, dissection, intel, jobs, reports, samples  # noqa: E402

for _router in (samples.router, dissection.router, intel.router, reports.router, jobs.router, analyst.router):
    app.include_router(_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
