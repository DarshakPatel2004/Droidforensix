"""Analyst-owned state per sample: status, tags, and notes."""

from typing import Annotated, List, Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend import analyst_store
from backend.config import settings
from backend.validators import validate_sample_id

router = APIRouter()

Status = Literal["new", "reviewing", "closed"]
Tag = Annotated[str, Field(min_length=1, max_length=40)]


class AnalystState(BaseModel):
    sample_id: str
    status: Status
    tags: List[str]
    notes: str
    updated_utc: Optional[str]


class AnalystStateUpdate(BaseModel):
    status: Status
    tags: List[Tag] = Field(default_factory=list, max_length=20)
    notes: str = Field(default="", max_length=10000)


def _require_sample(sample_id: str) -> None:
    try:
        validate_sample_id(sample_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid sample_id") from exc
    if not (settings.WORK_DIR / sample_id).is_dir():
        raise HTTPException(status_code=404, detail="Sample not found")


@router.get("/api/sample/{sample_id}/analyst-state", response_model=AnalystState)
async def api_get_analyst_state(sample_id: str) -> dict:
    """Analyst status, tags, and notes for a sample."""
    _require_sample(sample_id)
    return analyst_store.get_state(settings.WORK_DIR, sample_id)


@router.put("/api/sample/{sample_id}/analyst-state", response_model=AnalystState)
async def api_put_analyst_state(sample_id: str, update: AnalystStateUpdate) -> dict:
    """Replace the analyst status, tags, and notes for a sample."""
    _require_sample(sample_id)
    return analyst_store.put_state(settings.WORK_DIR, sample_id, update.status, update.tags, update.notes)


@router.get("/api/analyst-state", response_model=List[AnalystState])
async def api_list_analyst_states(status: Optional[Status] = Query(None)) -> list:
    """Every recorded analyst state, newest first, optionally filtered by status."""
    return analyst_store.list_states(settings.WORK_DIR, status)
