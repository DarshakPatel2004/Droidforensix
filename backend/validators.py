"""
JSON schema validation for backend events and API payloads.
"""

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


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
