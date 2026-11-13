"""SQLite store for analyst-owned state on each sample: status, tags, and notes.

Status, tags, and notes belong to the analyst, not the pipeline, so they live in
their own database under WORK_DIR. Re-running the pipeline rewrites
pipeline_result.json and leaves these rows alone.
"""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_NAME = "analyst_state.sqlite3"
STATUSES = ("new", "reviewing", "closed", "confirmed", "false positive")
DEFAULT_STATUS = "new"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyst_state (
    sample_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    tags TEXT NOT NULL,
    notes TEXT NOT NULL,
    updated_utc TEXT NOT NULL
)
"""


def _connect(work_dir: Path) -> sqlite3.Connection:
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(work_dir / DB_NAME)
    conn.execute(_SCHEMA)
    return conn


def _as_state(sample_id: str, status: str, tags: str, notes: str, updated_utc: Optional[str]) -> Dict[str, Any]:
    return {
        "sample_id": sample_id,
        "status": status,
        "tags": json.loads(tags),
        "notes": notes,
        "updated_utc": updated_utc,
    }


def _normalise_tags(tags: List[str]) -> List[str]:
    seen: List[str] = []
    for tag in tags:
        tag = tag.strip()
        if tag and tag not in seen:
            seen.append(tag)
    return seen


def get_state(work_dir: Path, sample_id: str) -> Dict[str, Any]:
    """Current analyst state for a sample; defaults when nothing has been recorded."""
    with closing(_connect(work_dir)) as conn:
        row = conn.execute(
            "SELECT status, tags, notes, updated_utc FROM analyst_state WHERE sample_id = ?",
            (sample_id,),
        ).fetchone()
    if row is None:
        return _as_state(sample_id, DEFAULT_STATUS, "[]", "", None)
    return _as_state(sample_id, *row)


def put_state(work_dir: Path, sample_id: str, status: str, tags: List[str], notes: str) -> Dict[str, Any]:
    """Replace the analyst state for a sample and return what was stored."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    tags_json = json.dumps(_normalise_tags(tags))
    updated = datetime.now(timezone.utc).isoformat()
    with closing(_connect(work_dir)) as conn, conn:
        conn.execute(
            "INSERT INTO analyst_state (sample_id, status, tags, notes, updated_utc) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(sample_id) DO UPDATE SET status = excluded.status, tags = excluded.tags, "
            "notes = excluded.notes, updated_utc = excluded.updated_utc",
            (sample_id, status, tags_json, notes, updated),
        )
    return _as_state(sample_id, status, tags_json, notes, updated)


def list_states(work_dir: Path, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """All recorded analyst states, newest first, optionally filtered by status."""
    sql = "SELECT sample_id, status, tags, notes, updated_utc FROM analyst_state"
    args: tuple = ()
    if status is not None:
        sql += " WHERE status = ?"
        args = (status,)
    sql += " ORDER BY updated_utc DESC"
    with closing(_connect(work_dir)) as conn:
        rows = conn.execute(sql, args).fetchall()
    return [_as_state(*row) for row in rows]
