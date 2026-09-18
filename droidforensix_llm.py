"""
DroidForensix LLM Verifier Module

Provides the LLMVerifier class for cross-verifying forensic findings through
Ollama (Mistral 7B). Supports:
- Ollama lifecycle management (start/stop with backend)
- Per-stage threat verification with structured JSON output
- Response caching to avoid redundant LLM calls
- Graceful fallback when Ollama is unavailable
"""

import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.config import settings


# ---------------------------------------------------------------------------
# Ollama host helpers (reused from step7_llm_assessment)
# ---------------------------------------------------------------------------

def _normalize_ollama_host(host: str) -> str:
    """Normalize Ollama host so it is reachable on Windows."""
    if not host:
        return "http://127.0.0.1:11434"
    parsed = urllib.parse.urlparse(host)
    hostname = parsed.hostname or "127.0.0.1"
    if hostname in ("0.0.0.0", "::"):
        hostname = "127.0.0.1"
    port = parsed.port or 11434
    scheme = parsed.scheme or "http"
    return f"{scheme}://{hostname}:{port}"


def _ollama_available(host: str, timeout: float = 2.0) -> bool:
    """Quick TCP check if Ollama is reachable."""
    host = _normalize_ollama_host(host)
    parsed = urllib.parse.urlparse(host)
    netloc = parsed.hostname or "127.0.0.1"
    port = parsed.port or 11434
    try:
        s = socket.create_connection((netloc, port), timeout=timeout)
        s.close()
        return True
    except (OSError, socket.error):
        return False


# ---------------------------------------------------------------------------
# Verification response parsing
# ---------------------------------------------------------------------------

VERIFY_SYSTEM_PROMPT = """/no_think

You are a mobile forensic analyst verifying APK analysis findings.
Given the stage context and findings, assess whether the APK is malicious.

Output must be valid JSON only. No markdown, no preamble. Schema:
{
  "is_malicious": true/false/null,
  "confidence": "high"/"medium"/"low"/"unknown",
  "false_positive_likelihood": "high"/"medium"/"low",
  "reasoning": "2-4 sentence explanation",
  "mitre_tactics": ["T1234", ...],
  "recommendation": "1-2 sentence next step"
}
"""


def _parse_verify_json(raw: str) -> Optional[Dict[str, Any]]:
    """Extract and parse JSON from LLM verification output."""
    raw = raw.strip()
    # Remove markdown code blocks
    if raw.startswith("```"):
        lines = raw.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()
    # Try full parse
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # Try extracting JSON object
    match = re.search(r'\{.*\}', raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def _fallback_response(status: str = "ollama_disabled") -> Dict[str, Any]:
    """Return a safe fallback when LLM verification is unavailable."""
    return {
        "is_malicious": None,
        "confidence": "unknown",
        "false_positive_likelihood": "unknown",
        "reasoning": "LLM verification unavailable",
        "mitre_tactics": [],
        "recommendation": "Manual review required",
        "status": status,
    }


# ---------------------------------------------------------------------------
# LLMVerifier
# ---------------------------------------------------------------------------

class LLMVerifier:
    """Cross-verification engine for forensic pipeline stages.

    Manages the Ollama process lifecycle and provides per-stage threat
    verification via Mistral 7B.

    Usage:
        verifier = LLMVerifier(enabled=True)
        verifier.start()           # Starts Ollama if not running
        result = verifier.verify_threat(stage="metadata", ...)
        verifier.stop()            # Terminates the Ollama process we started
    """

    def __init__(
        self,
        enabled: bool = True,
        model: str = None,
        timeout: int = 30,
        cache_enabled: bool = True,
    ):
        self.enabled = enabled
        self.model = model or os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL)
        self.timeout = timeout
        self.cache_enabled = cache_enabled
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._ollama_process: Optional[subprocess.Popen] = None
        self._ollama_host = _normalize_ollama_host(
            os.environ.get("OLLAMA_HOST", settings.OLLAMA_HOST)
        )

    # ------------------------------------------------------------------
    # Lifecycle: start / stop Ollama with the backend
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start Ollama if not already running. Returns True if Ollama is ready."""
        if not self.enabled:
            print("[LLMVerifier] Disabled — skipping Ollama startup")
            return False

        # Already running?
        if _ollama_available(self._ollama_host, timeout=1.0):
            print(f"[LLMVerifier] Ollama already running at {self._ollama_host}")
            return True

        print(f"[LLMVerifier] Starting Ollama at {self._ollama_host}...")
        try:
            if sys.platform == "win32":
                # Start Ollama as a child process — will be killed on stop()
                self._ollama_process = subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                )
            else:
                self._ollama_process = subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                )

            # Wait for Ollama to be ready (up to 15 seconds)
            for attempt in range(15):
                time.sleep(1)
                if _ollama_available(self._ollama_host, timeout=1.0):
                    print(f"[LLMVerifier] Ollama started (PID {self._ollama_process.pid})")
                    return True

            print("[LLMVerifier] [WARN] Ollama took >15s to start")
            return _ollama_available(self._ollama_host, timeout=2.0)

        except FileNotFoundError:
            print("[LLMVerifier] [FAIL] Ollama executable not found. Install from https://ollama.ai")
            return False
        except Exception as e:
            print(f"[LLMVerifier] [FAIL] Failed to start Ollama: {e}")
            return False

    def stop(self):
        """Stop the Ollama process if we started it."""
        if self._ollama_process is None:
            print("[LLMVerifier] No Ollama process to stop (was already running or not started)")
            return

        pid = self._ollama_process.pid
        print(f"[LLMVerifier] Stopping Ollama (PID {pid})...")

        try:
            if sys.platform == "win32":
                # On Windows, terminate the process tree
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                    timeout=10,
                )
            else:
                # On Linux/Mac, kill the process group
                os.killpg(os.getpgid(pid), signal.SIGTERM)

            self._ollama_process.wait(timeout=5)
            print(f"[LLMVerifier] Ollama stopped (PID {pid})")
        except Exception as e:
            print(f"[LLMVerifier] [WARN] Error stopping Ollama: {e}")
            try:
                self._ollama_process.kill()
            except Exception:
                pass

        self._ollama_process = None

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------

    def is_ready(self) -> bool:
        """Check if Ollama is reachable and the verifier is enabled."""
        if not self.enabled:
            return False
        return _ollama_available(self._ollama_host, timeout=2.0)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_threat(
        self,
        stage: str,
        context: str,
        prompt: str,
        verbose: bool = False,
    ) -> Dict[str, Any]:
        """Call Ollama to cross-verify forensic findings.

        Args:
            stage: Pipeline stage name (e.g. "metadata", "threat_indicators").
            context: Brief description of what's being verified.
            prompt: Detailed prompt with findings to verify.
            verbose: Print debug output.

        Returns:
            Dict with is_malicious, confidence, false_positive_likelihood,
            reasoning, mitre_tactics, recommendation.
        """
        if not self.enabled or not self.is_ready():
            return _fallback_response("ollama_disabled")

        # Check cache
        cache_key = self._cache_key(stage, prompt)
        if self.cache_enabled and cache_key in self._cache:
            if verbose:
                print(f"  [LLM] Cache hit for stage={stage}")
            return self._cache[cache_key]

        # Build prompt
        full_prompt = (
            f"{VERIFY_SYSTEM_PROMPT}\n\n"
            f"STAGE: {stage}\n"
            f"CONTEXT: {context}\n\n"
            f"FINDINGS:\n{prompt}\n\n"
            f"VERIFICATION:"
        )

        if verbose:
            print(f"  [LLM] Verifying stage={stage} model={self.model}")

        try:
            import ollama as _ollama

            client = _ollama.Client(
                host=self._ollama_host,
                timeout=self.timeout,
            )
            response = client.generate(
                model=self.model,
                prompt=full_prompt,
                format="json",
                options={"num_ctx": 4096, "temperature": 0.1},
            )
            raw_output = response.get("response", "")

            parsed = _parse_verify_json(raw_output)
            if parsed and "is_malicious" in parsed:
                result = {
                    "is_malicious": parsed.get("is_malicious"),
                    "confidence": str(parsed.get("confidence", "unknown")),
                    "false_positive_likelihood": str(parsed.get("false_positive_likelihood", "unknown")),
                    "reasoning": str(parsed.get("reasoning", ""))[:500],
                    "mitre_tactics": parsed.get("mitre_tactics", []),
                    "recommendation": str(parsed.get("recommendation", ""))[:300],
                    "status": "verified",
                }
            else:
                result = _fallback_response("parse_error")
                result["raw_output"] = raw_output[:500]

            # Cache result
            if self.cache_enabled:
                self._cache[cache_key] = result

            if verbose:
                print(f"  [LLM] Verdict: is_malicious={result.get('is_malicious')} "
                      f"confidence={result.get('confidence')}")

            return result

        except ImportError:
            return _fallback_response("ollama_package_missing")
        except Exception as e:
            if verbose:
                print(f"  [LLM] Error: {e}")
            return _fallback_response(f"error: {str(e)[:100]}")

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_key(self, stage: str, prompt: str) -> str:
        """Generate a deterministic cache key from stage + prompt."""
        content = f"{stage}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def clear_cache(self):
        """Clear all cached verification results."""
        self._cache.clear()

    @property
    def cache_size(self) -> int:
        """Number of cached results."""
        return len(self._cache)


# ---------------------------------------------------------------------------
# Module-level singleton for use across the pipeline
# ---------------------------------------------------------------------------

_global_verifier: Optional[LLMVerifier] = None


def get_verifier() -> LLMVerifier:
    """Get the global LLMVerifier singleton."""
    global _global_verifier
    if _global_verifier is None:
        _global_verifier = LLMVerifier(
            enabled=True,
            model=os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL),
            timeout=30,
            cache_enabled=True,
        )
    return _global_verifier


def set_verifier(verifier: LLMVerifier):
    """Replace the global LLMVerifier singleton."""
    global _global_verifier
    _global_verifier = verifier
