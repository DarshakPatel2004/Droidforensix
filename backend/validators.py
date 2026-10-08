"""
JSON schema validation for backend events and API payloads.
"""

import re
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator

# A sample_id is always the SHA-256 of the APK (analysis/step1_apk_extraction.py
# compute_sha256), so a bare 64-char lowercase hex string is the only legitimate
# value. Validating it keeps a ".."-relative path segment from selecting a
# directory outside WORK_DIR, which roughly fifteen call sites relied on being
# harmless.
_SAMPLE_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def validate_sample_id(sample_id: str) -> str:
    """Return sample_id if it is a bare 64-char lowercase SHA-256, else raise.

    Raises ValueError rather than sanitising: silently rewriting a traversal
    attempt would hide the attack and could resolve to a real sample.
    """
    if not isinstance(sample_id, str) or not _SAMPLE_ID_RE.match(sample_id):
        raise ValueError("sample_id must be a 64-character lowercase hex SHA-256")
    return sample_id




class AnalyzeRequest(BaseModel):
    """Request body for POST /analyze."""
    apk_path: str = Field(..., min_length=1)


class SampleStatus(BaseModel):
    """Sample status response."""
    sample_id: str
    status: str
    error: Optional[str] = None


class UploadResponse(BaseModel):
    """Response for file upload endpoint."""
    upload_id: str
    filename: str
    sha256: str
    status: str
    message: str


class AnalyzeResponse(BaseModel):
    """Response for analysis trigger endpoints."""
    upload_id: Optional[str] = None
    job_id: Optional[str] = None
    status: str
    message: str


class WebSocketEventValidator(BaseModel):
    """Validator for WebSocket events emitted by the pipeline."""
    event_type: str
    timestamp: str
    data: Dict[str, Any]

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        from backend.events import VALID_EVENT_TYPES
        if v not in VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event type: {v}")
        return v


def validate_event(event: dict) -> bool:
    """Validate a WebSocket event dict."""
    try:
        WebSocketEventValidator(**event)
        return True
    except Exception:
        return False
